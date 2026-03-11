use std::process::Command;

pub fn randomise_mac(iface: &str) -> anyhow::Result<()> {
    if which::which("macchanger").is_ok() {
        let out = Command::new("macchanger").args(["-r", iface]).output()?;
        if out.status.success() {
            return Ok(());
        }
    }
    let mac = random_mac();
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "down"]).output()?;
    let out = Command::new("ip")
        .args(["link", "set", "dev", iface, "address", &mac])
        .output()?;
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "up"]).output();
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("MAC randomisation failed on {iface}")
    }
}

pub fn flush_dns_cache() {
    let cmds = [
        "systemd-resolve --flush-caches 2>/dev/null",
        "service nscd restart 2>/dev/null",
        "service dnsmasq restart 2>/dev/null",
        "rndc flush 2>/dev/null",
    ];
    for cmd in cmds {
        let _ = Command::new("sh").args(["-c", cmd]).output();
    }
}

pub fn route_all_through_tor() -> anyhow::Result<()> {
    let rules = [
        "iptables -F OUTPUT 2>/dev/null",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null",
        "iptables -A OUTPUT -j REJECT 2>/dev/null",
        "iptables -I OUTPUT -o lo -j ACCEPT 2>/dev/null",
        "iptables -I OUTPUT -p tcp --dport 9050 -j ACCEPT 2>/dev/null",
        "iptables -I OUTPUT -p tcp -j REDIRECT --to-ports 9040 2>/dev/null",
    ];
    for rule in rules {
        let _ = Command::new("sh").args(["-c", rule]).output();
    }
    Ok(())
}

pub fn flush_iptables_output() {
    let _ = Command::new("sh")
        .args(["-c", "iptables -F OUTPUT 2>/dev/null"])
        .output();
}

pub fn block_ipv6_leaks() {
    let cmds = [
        "ip6tables -P INPUT DROP 2>/dev/null",
        "ip6tables -P OUTPUT DROP 2>/dev/null",
        "ip6tables -P FORWARD DROP 2>/dev/null",
    ];
    for cmd in cmds {
        let _ = Command::new("sh").args(["-c", cmd]).output();
    }
}

pub fn is_tor_active() -> bool {
    let out = Command::new("sh")
        .args(["-c", "curl -s --max-time 5 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null"])
        .output();
    matches!(out, Ok(o) if String::from_utf8_lossy(&o.stdout).contains("\"IsTor\":true"))
}

fn random_mac() -> String {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes).unwrap_or(());
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}
