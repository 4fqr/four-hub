use std::{env, fs, process::Command, time::Duration};
use rand::Rng;
use tracing::{info, warn};

pub struct StealthEngine;

impl StealthEngine {
    pub fn engage_all() {
        layer1_memory_lock();
        layer2_spoof_identity();
        layer3_sanitize_env();
        layer4_secure_umask();
        layer5_wipe_cmdline();
        layer7_disable_core_dumps();
    }

    pub fn randomise_mac(iface: &str) -> anyhow::Result<()> {
        crate::stealth::network::randomise_mac(iface)
    }

    pub fn wipe_artefacts() {
        crate::stealth::anti_forensics::wipe_on_exit();
    }

    pub fn delay_jitter_ms() -> u64 {
        layer6_timing_jitter()
    }

    pub fn route_via_tor() -> bool {
        layer8_verify_tor_routing()
    }

    pub fn lock_sensitive<T>(val: &T) {
        let ptr = val as *const T as *const u8;
        let size = std::mem::size_of::<T>();
        crate::stealth::memory::lock_region(ptr, size);
    }

    pub fn spoof_dns_via_doh(domain: &str) -> Option<String> {
        layer9_doh_resolve(domain)
    }

    pub fn harden_process() {
        layer10_process_hardening();
    }
}

fn layer1_memory_lock() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
    info!("Layer 1: memory locked");
}

fn layer2_spoof_identity() {
    crate::stealth::identity::spoof_process_name("[kworker/0:2]");
    info!("Layer 2: identity spoofed");
}

fn layer3_sanitize_env() {
    let dangerous = [
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES", "PYTHONPATH",
        "RUBYOPT", "NODE_OPTIONS", "PERL5OPT",
    ];
    for var in dangerous {
        if env::var_os(var).is_some() {
            env::remove_var(var);
            warn!("Layer 3: removed dangerous env var {}", var);
        }
    }
    env::set_var("HISTSIZE", "0");
    env::set_var("HISTFILESIZE", "0");
    env::set_var("HISTFILE", "/dev/null");
    info!("Layer 3: environment sanitized");
}

fn layer4_secure_umask() {
    #[cfg(unix)]
    unsafe { libc::umask(0o077); }
    info!("Layer 4: umask set to 077");
}

fn layer5_wipe_cmdline() {
    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/comm", "[kworker/0:2]");
    }
    info!("Layer 5: /proc cmdline obfuscated");
}

fn layer6_timing_jitter() -> u64 {
    let mut rng = rand::thread_rng();
    let jitter_ms: u64 = rng.gen_range(50..350);
    info!("Layer 6: timing jitter {}ms", jitter_ms);
    jitter_ms
}

fn layer7_disable_core_dumps() {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    info!("Layer 7: core dumps disabled");
}

fn layer8_verify_tor_routing() -> bool {
    let out = Command::new("sh")
        .args(["-c", "curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null"])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let is_tor = text.contains("\"IsTor\":true");
            if is_tor {
                info!("Layer 8: Tor routing confirmed");
            } else {
                warn!("Layer 8: Tor NOT active — traffic may be unmasked");
            }
            is_tor
        }
        Err(_) => {
            warn!("Layer 8: Tor check failed (tor not running?)");
            false
        }
    }
}

fn layer9_doh_resolve(domain: &str) -> Option<String> {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=A",
        domain
    );
    let out = Command::new("curl")
        .args(["-sf", "-H", "accept: application/dns-json", &url])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let ip = text.split("\"data\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string());
    if let Some(ref a) = ip {
        info!("Layer 9: DoH resolved {} → {}", domain, a);
    }
    ip
}

fn layer10_process_hardening() {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
    }
    info!("Layer 10: process hardened (no-dump, no-new-privs)");
}

pub fn apply_timing_jitter() {
    let ms = layer6_timing_jitter();
    std::thread::sleep(Duration::from_millis(ms));
}
