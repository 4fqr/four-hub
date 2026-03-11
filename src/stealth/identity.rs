
use std::ffi::CString;
pub fn spoof_process_name(name: &str) {
    #[cfg(target_os = "linux")]
    {
        let trimmed = &name[..name.len().min(15)];
        if let Ok(c) = CString::new(trimmed) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, c.as_ptr() as libc::c_ulong, 0, 0, 0);
            }
        }
    }
}
pub fn effective_uid() -> u32 {
    #[cfg(unix)]
    unsafe { libc::geteuid() }
    #[cfg(not(unix))]
    0
}

pub fn is_root() -> bool { effective_uid() == 0 }
