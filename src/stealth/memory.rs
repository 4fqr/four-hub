// ─── Four-Hub · stealth/memory.rs ────────────────────────────────────────────
//! mlock helpers – keep sensitive pages out of swap.

use tracing::warn;

/// Lock `size` bytes starting at `ptr` into physical RAM.
/// Only meaningful on Linux and requires sufficient privileges for large regions;
/// non-fatal on failure (swapping sensitive memory is a security degradation
/// but not a crash condition).
pub fn lock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, size) };
        if rc != 0 {
            warn!("mlock({} bytes) failed (errno {})", size, unsafe { *libc::__errno_location() });
        }
    }
}

/// Unlock a previously mlock'd region (allowing the OS to swap it again).
pub fn unlock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::munlock(ptr as *const libc::c_void, size); }
    }
}
