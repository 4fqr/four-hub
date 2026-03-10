// ─── Four-Hub · src/pcap_ffi.rs ───────────────────────────────────────────────
//! Safe Rust wrapper for the C packet capture extension (libpcap).

use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

// ── Raw FFI declarations ──────────────────────────────────────────────────────

const FH_SNAPLEN: usize = 65535;

#[repr(C)]
struct FhPacketT {
    ts_sec:  u64,
    ts_usec: u32,
    caplen:  u32,
    origlen: u32,
    data:    [u8; 65535],
}

#[repr(C)]
struct FhCapture {
    _priv: [u8; 0],
}

extern "C" {
    fn fh_capture_open(
        iface:   *const libc::c_char,
        snaplen: libc::c_int,
        promisc: libc::c_int,
        errbuf:  *mut libc::c_char,
    ) -> *mut FhCapture;

    fn fh_capture_next(cap: *mut FhCapture, out: *mut FhPacketT) -> libc::c_int;

    fn fh_capture_set_filter(
        cap:        *mut FhCapture,
        filter_str: *const libc::c_char,
    ) -> libc::c_int;

    fn fh_capture_close(cap: *mut FhCapture);

    fn fh_capture_stats(
        cap:     *mut FhCapture,
        ps_recv: *mut u64,
        ps_drop: *mut u64,
    );
}

// ── Safe wrapper ─────────────────────────────────────────────────────────────

/// A live packet capture session on one network interface.
pub struct CaptureSession {
    handle: *mut FhCapture,
}

// Safety: The handle is not shared across threads in this single-producer design.
unsafe impl Send for CaptureSession {}

/// A single captured packet.
#[derive(Debug)]
pub struct Packet {
    pub ts_sec:  u64,
    pub ts_usec: u32,
    pub caplen:  u32,
    pub origlen: u32,
    pub data:    Vec<u8>,
}

impl CaptureSession {
    /// Open a live capture on `iface`.  `promisc = true` enables promiscuous mode.
    pub fn open(iface: &str, promisc: bool) -> Result<Self> {
        let c_iface = CString::new(iface)?;
        let mut errbuf = vec![0i8; 256];

        let handle = unsafe {
            fh_capture_open(
                c_iface.as_ptr(),
                FH_SNAPLEN as libc::c_int,
                if promisc { 1 } else { 0 },
                errbuf.as_mut_ptr(),
            )
        };

        if handle.is_null() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            bail!("pcap open failed: {msg}");
        }

        Ok(Self { handle })
    }

    /// Apply a BPF `filter` string (e.g. `"tcp port 80"`).
    pub fn set_filter(&self, filter: &str) -> Result<()> {
        let c_filter = CString::new(filter)?;
        let rc = unsafe { fh_capture_set_filter(self.handle, c_filter.as_ptr()) };
        if rc != 0 {
            bail!("set_filter failed");
        }
        Ok(())
    }

    /// Block until the next packet arrives (up to ~1 s).
    /// Returns `None` on timeout, `Some(Packet)` on success.
    pub fn next_packet(&self) -> Result<Option<Packet>> {
        let mut raw = std::mem::MaybeUninit::<FhPacketT>::uninit();
        let rc = unsafe { fh_capture_next(self.handle, raw.as_mut_ptr()) };
        match rc {
            1 => {
                let pkt = unsafe { raw.assume_init() };
                let data = pkt.data[..pkt.caplen as usize].to_vec();
                Ok(Some(Packet {
                    ts_sec:  pkt.ts_sec,
                    ts_usec: pkt.ts_usec,
                    caplen:  pkt.caplen,
                    origlen: pkt.origlen,
                    data,
                }))
            }
            0  => Ok(None),
            _  => bail!("pcap_next_ex error"),
        }
    }

    /// Return `(received, dropped)` packet counts.
    pub fn stats(&self) -> (u64, u64) {
        let (mut recv, mut drop) = (0u64, 0u64);
        unsafe { fh_capture_stats(self.handle, &mut recv, &mut drop); }
        (recv, drop)
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { fh_capture_close(self.handle); }
            self.handle = std::ptr::null_mut();
        }
    }
}
