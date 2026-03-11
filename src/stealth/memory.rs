
use tracing::warn;
pub fn lock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, size) };
        if rc != 0 {
            warn!("mlock({} bytes) failed (errno {})", size, unsafe { *libc::__errno_location() });
        }
    }
}
pub fn unlock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::munlock(ptr as *const libc::c_void, size); }
    }
}
