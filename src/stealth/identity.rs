// ─── Four-Hub · stealth/identity.rs ──────────────────────────────────────────
//! Process-name spoofing and identity obfuscation.

use std::ffi::CString;
// tracing imported where needed below

/// Attempt to overwrite argv[0] with `name` so that `ps` shows the spoofed name.
/// This is a best-effort operation on Linux.
pub fn spoof_process_name(name: &str) {
    #[cfg(target_os = "linux")]
    {
        // prctl PR_SET_NAME (max 15 bytes on Linux).
        let trimmed = &name[..name.len().min(15)];
        if let Ok(c) = CString::new(trimmed) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, c.as_ptr() as libc::c_ulong, 0, 0, 0);
            }
        }
    }
}

/// Return the effective user-id (0 = root).
pub fn effective_uid() -> u32 {
    #[cfg(unix)]
    unsafe { libc::geteuid() }
    #[cfg(not(unix))]
    0
}

pub fn is_root() -> bool { effective_uid() == 0 }
