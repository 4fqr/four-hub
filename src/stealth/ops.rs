use std::{env, fs, process::Command, time::Duration};

pub struct StealthEngine;

impl StealthEngine {
    pub fn engage_all() {
        layer01_memory_lock();
        layer02_spoof_identity();
        layer03_wipe_cmdline();
        layer04_sanitize_env();
        layer05_secure_umask();
        layer06_disable_core_dumps();
        layer07_process_hardening();
        layer08_anti_ptrace();
        layer09_wipe_environ();
        layer10_coredump_filter();
        layer11_oom_immunity();
        layer12_disable_ipv6();
        layer13_resource_limits();
        layer14_entropy_pool();
        layer15_verify_tor_routing();
        layer16_timing_jitter_boot();
    }

    pub fn randomise_mac(iface: &str) -> anyhow::Result<()> {
        crate::stealth::network::randomise_mac(iface)
    }

    pub fn wipe_artefacts() {
        crate::stealth::anti_forensics::wipe_on_exit();
    }

    pub fn delay_jitter_ms() -> u64 {
        crypto_jitter_ms()
    }

    pub fn route_via_tor() -> bool {
        layer15_verify_tor_routing()
    }

    pub fn lock_sensitive<T>(val: &T) {
        let ptr = val as *const T as *const u8;
        let size = std::mem::size_of::<T>();
        crate::stealth::memory::lock_region(ptr, size);
    }

    pub fn spoof_dns_via_doh(domain: &str) -> Option<String> {
        doh_resolve(domain)
    }

    pub fn harden_process() {
        layer07_process_hardening();
        layer08_anti_ptrace();
    }

    pub fn is_traced() -> bool {
        detect_tracer()
    }

    pub fn kill_if_traced() {
        if detect_tracer() {
            secure_exit(1);
        }
    }

    pub fn disable_ipv6_leaks() {
        layer12_disable_ipv6();
    }

    pub fn forge_timestamps(path: &str) {
        crate::stealth::anti_forensics::randomize_timestamps(path);
    }
}

fn layer01_memory_lock() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

fn layer02_spoof_identity() {
    crate::stealth::identity::spoof_process_name("[kworker/0:2]");
    crate::stealth::identity::spoof_argv();
}

fn layer03_wipe_cmdline() {
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/comm", "[kworker/0:2]");
        let _ = fs::write("/proc/self/attr/exec", "");
    }
}

fn layer04_sanitize_env() {
    let dangerous = [
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "LD_DEBUG", "LD_BIND_NOW", "LD_PROFILE",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONDONTWRITEBYTECODE",
        "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH",
        "PERL5OPT", "PERL5LIB",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
        "GDB_AUTOLOAD_PATH", "GDBHISTFILE",
        "TERM_PROGRAM", "COLORTERM",
        "DEBUG", "TRACE",
    ];
    for var in dangerous {
        env::remove_var(var);
    }
    env::set_var("HISTSIZE", "0");
    env::set_var("HISTFILESIZE", "0");
    env::set_var("HISTFILE", "/dev/null");
    env::set_var("LESSHISTFILE", "/dev/null");
    env::set_var("MYSQL_HISTFILE", "/dev/null");
    env::set_var("SQLITE_HISTORY", "/dev/null");
    env::set_var("PSQL_HISTORY", "/dev/null");
}

fn layer05_secure_umask() {
    #[cfg(unix)]
    unsafe { libc::umask(0o077); }
}

fn layer06_disable_core_dumps() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/coredump_filter", "0x00");
    }
}

fn layer07_process_hardening() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::prctl(libc::PR_MCE_KILL, libc::PR_MCE_KILL_SET as libc::c_ulong, libc::PR_MCE_KILL_EARLY as libc::c_ulong, 0, 0);
    }
}

fn layer08_anti_ptrace() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let rc = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
        if rc < 0 {
            secure_exit(0);
        } else {
            libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
        }
    }
}

fn layer09_wipe_environ() {
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/environ", "");
    }
    for (key, _) in env::vars() {
        if key.starts_with("npm_") || key.starts_with("JAVA_")
            || key.starts_with("ANDROID_") || key.starts_with("GO")
            || key.starts_with("RUST_LOG") || key.starts_with("RUST_BACKTRACE")
        {
            env::remove_var(&key);
        }
    }
}

fn layer10_coredump_filter() {
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/coredump_filter", "0x00");
        let _ = Command::new("sh")
            .args(["-c", "sysctl -w kernel.core_pattern=/dev/null 2>/dev/null"])
            .output();
    }
}

fn layer11_oom_immunity() {
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/oom_score_adj", "-1000");
        let _ = fs::write("/proc/self/oom_adj", "-17");
    }
}

fn layer12_disable_ipv6() {
    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null",
            "sysctl -w net.ipv6.conf.lo.disable_ipv6=1 2>/dev/null",
        ];
        for cmd in cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }
    }
}

fn layer13_resource_limits() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);

        let pipe_lim = libc::rlimit {
            rlim_cur: 8 * 1024 * 1024,
            rlim_max: 8 * 1024 * 1024,
        };
        libc::setrlimit(libc::RLIMIT_MSGQUEUE, &pipe_lim);
    }
}

fn layer14_entropy_pool() {
    #[cfg(target_os = "linux")]
    {
        let mut buf = [0u8; 256];
        let _ = getrandom::getrandom(&mut buf);
        volatile_zero(&mut buf);
    }
}

fn layer15_verify_tor_routing() -> bool {
    let out = Command::new("sh")
        .args(["-c", "curl -s --max-time 5 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null"])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("\"IsTor\":true")
        }
        Err(_) => false,
    }
}

fn layer16_timing_jitter_boot() {
    let ms = crypto_jitter_ms();
    std::thread::sleep(Duration::from_millis(ms));
}

fn crypto_jitter_ms() -> u64 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).unwrap_or(());
    let raw = u32::from_le_bytes(buf);
    50 + (raw as u64 % 450)
}

fn doh_resolve(domain: &str) -> Option<String> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", domain);
    let out = Command::new("curl")
        .args(["-sf", "--max-time", "5", "-H", "accept: application/dns-json", &url])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.split("\"data\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string())
}

fn detect_tracer() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid: i64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if pid != 0 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn secure_exit(code: i32) {
    crate::stealth::anti_forensics::wipe_on_exit();
    std::process::exit(code);
}

pub fn apply_timing_jitter() {
    let ms = crypto_jitter_ms();
    std::thread::sleep(Duration::from_millis(ms));
}

fn volatile_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8); }
    }
}
