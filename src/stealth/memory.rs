use zeroize::Zeroize;

pub fn lock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, size);
    }
}

pub fn unlock_region(ptr: *const u8, size: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, size);
    }
}

pub fn lock_all() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

pub fn volatile_zero_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8); }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn volatile_zero_ptr(ptr: *mut u8, len: usize) {
    for i in 0..len {
        unsafe { std::ptr::write_volatile(ptr.add(i), 0u8); }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

pub struct LockedBuffer {
    data: Vec<u8>,
}

impl LockedBuffer {
    pub fn new(size: usize) -> Self {
        let data = vec![0u8; size];
        lock_region(data.as_ptr(), size);
        Self { data }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        volatile_zero_slice(&mut self.data);
        unlock_region(self.data.as_ptr(), self.data.len());
        self.data.zeroize();
    }
}
