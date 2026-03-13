
use crate::{
    db::{Finding, Host, Port, Severity},
    tools::spec::ToolSpec,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;
#[derive(Debug, Clone)]
pub enum ParsedRecord {
    Finding(Finding),
    NewHost(Host),
    NewPort { port: Port, host_addr: String },
}
static RE_NMAP_HOST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?").unwrap()
});
static RE_NMAP_PORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$").unwrap()
});
static RE_NMAP_OS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"OS details:\s+(.+)").unwrap()
});
static RE_NMAP_CVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(CVE-\d{4}-\d{4,})").unwrap()
});
static RE_NIKTO_VULN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\+\s+(?:(OSVDB-\d+|CVE-[\d-]+):?\s+)?(.+)$").unwrap()
});
static RE_HYDRA_CRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)").unwrap()
});
static RE_SQLMAP_PARAM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Parameter '([^']+)' (?:is vulnerable|appears to be '([^']+)' injectable)").unwrap()
});
static RE_GOBUSTER_DIR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(/\S*)\s+\(Status:\s*(\d+)\)").unwrap()
});
static RE_FFUF_HIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""url"\s*:\s*"([^"]+)"\s*,\s*"status"\s*:\s*(\d+)"#).unwrap()
});
static RE_ENUM4LINUX_SHARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//(\S+)/(\S+)").unwrap()
});
static RE_CME_CRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[\+\]\s+(\S+)\s+\d+\s+\S+\s+(\S+):(\S+)\b").unwrap()
});
static RE_MASSCAN_PORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Discovered open port (\d+)/(\w+) on (\d+\.\d+\.\d+\.\d+)").unwrap()
});
static RE_FEROXBUSTER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+https?://\S+(/\S*)").unwrap()
});
static RE_DIRB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\+ (https?://\S+) \(CODE:(\d+)\|SIZE:\d+\)").unwrap()
});
static RE_NUCLEI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[([\w:-]+)\] \[(\w+)\] \[(\w+)\] ([^\[]+)").unwrap()
});
static RE_AMASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([\w.-]+\.[a-zA-Z]{2,})\s*$").unwrap()
});
static RE_WHATWEB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^https?://(\S+)\s+\[(\d+)[^\]]*\]\s+(.+)$").unwrap()
});
static RE_DNSRECON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[([\+\*!])\]\s+(A|AAAA|CNAME|MX|NS|TXT|SRV)\s+(\S+)\s+(\S+)").unwrap()
});
static RE_SEARCHSPLOIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s+(.+?)\s{2,}\|\s+(exploits/\S+|shellcodes/\S+)").unwrap()
});
static RE_RESPONDER_HASH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(\w+)\]\s+\[NTLM").unwrap()
});
static RE_JOHN_CRACKED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\S+)\s+\((\S+)\)\s*$").unwrap()
});
static RE_HASHCAT_CRACKED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Fa-f0-9]{32,128}):(.+)$").unwrap()
});
static RE_IMPACKET_HASH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\S+)::(\S+):([A-Fa-f0-9]{32}):([A-Fa-f0-9]{32}):([A-Fa-f0-9]{16})").unwrap()
});
static RE_WAFW00F: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"The site .+ is behind (.+?) WAF").unwrap()
});
static RE_WPSCAN_VULN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\[!\]\s+(.+)").unwrap()
});
static RE_4NMAP_PORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Port (\d+) is OPEN").unwrap()
});
static RE_4NMAP_SERVICE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[Service\] (\d+): (.+)").unwrap()
});
static RE_4NMAP_VULN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[VULNERABILITY\] (\d+): (.+)").unwrap()
});
static RE_4NMAP_OS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Fingerprint: (.+)").unwrap()
});
static RE_4GOBUSTER_HIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[\+\] (\S+)\s+\(Status: (\d+), Size: (\d+)\)").unwrap()
});
static RE_4HYDRA_SUCCESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[SUCCESS\] Valid (\S+) credentials: (\S+):(\S+)").unwrap()
});
static RE_4NIKTO_VULN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[VULNERABILITY\] (.+) at (https?://\S+)").unwrap()
});
pub fn parse_line(spec: &ToolSpec, line: &str, target: &str) -> Vec<ParsedRecord> {
    match spec.name.as_str() {
        "nmap"                              => parse_nmap(line, target),
        "masscan"                           => parse_masscan(line, target),
        "nikto"                             => parse_nikto(line, target),
        "hydra" | "ncrack"                  => parse_hydra(line, target),
        "sqlmap"                            => parse_sqlmap(line, target),
        "gobuster"                          => parse_gobuster(line, target),
        "feroxbuster"                       => parse_feroxbuster(line, target),
        "dirb"                              => parse_dirb(line, target),
        "dirsearch"                         => parse_dirsearch(line, target),
        "4nmap"                             => parse_4nmap(line, target),
        "4gobuster"                         => parse_4gobuster(line, target),
        "4hydra"                            => parse_4hydra(line, target),
        "ffuf"                              => parse_ffuf(line, target),
        "enum4linux" | "enum4linux-ng"      => parse_enum4linux(line, target),
        "crackmapexec" | "netexec" | "nxc"  => parse_cme(line, target),
        "wpscan"                            => parse_wpscan(line, target),
        "nuclei"                            => parse_nuclei(line, target),
        "amass" | "sublist3r" | "subfinder" => parse_amass(line, target),
        "whatweb"                           => parse_whatweb(line, target),
        "dnsrecon" | "dnsenum"              => parse_dnsrecon(line, target),
        "searchsploit"                      => parse_searchsploit(line, target),
        "responder"                         => parse_responder(line, target),
        "john"                              => parse_john(line, target),
        "hashcat"                           => parse_hashcat(line, target),
        "evil-winrm"                        => parse_evil_winrm(line, target),
        "impacket-secretsdump" | "secretsdump" => parse_impacket(line, target),
        "wafw00f"                           => parse_wafw00f(line, target),
        "snmpwalk" | "snmpbulkwalk" | "onesixtyone" => parse_snmp(line, target),
        _                                   => vec![],
    }
}

fn finding(tool: &str, title: &str, description: &str, sev: Severity, host: &str, evidence: &str) -> ParsedRecord {
    ParsedRecord::Finding(Finding {
        id:          Uuid::new_v4().to_string(),
        host_id:     None,
        port_id:     None,
        tool:        tool.to_string(),
        title:       title.to_string(),
        description: description.to_string(),
        severity:    sev,
        host:        host.to_string(),
        evidence:    Some(evidence.to_string()),
        metadata:    None,
        created_at:  Utc::now(),
    })
}

fn parse_nmap(line: &str, target: &str) -> Vec<ParsedRecord> {
    let mut out = Vec::new();
    let trimmed = line.trim();

    if let Some(caps) = RE_NMAP_HOST.captures(trimmed) {
        let hostname = caps.get(1).map(|m| m.as_str().to_string());
        let addr     = caps.get(2).map_or(target, |m| m.as_str());
        out.push(ParsedRecord::NewHost(Host {
            id: Uuid::new_v4().to_string(), address: addr.to_string(),
            hostname, os: None, notes: None, discovered_at: Utc::now(),
        }));
        return out;
    }
    if let Some(caps) = RE_NMAP_PORT.captures(trimmed) {
        let pnum  = caps.get(1).map_or("0", |m| m.as_str());
        let proto = caps.get(2).map_or("tcp", |m| m.as_str());
        let state = caps.get(3).map_or("open", |m| m.as_str());
        let svc   = caps.get(4).map_or("unknown", |m| m.as_str());
        let ver   = caps.get(5).map(|m| m.as_str().to_string());
        if state == "open" {
            let pid = Uuid::new_v4().to_string();
            out.push(ParsedRecord::NewPort {
                host_addr: target.to_string(),
                port: Port { id: pid.clone(), host_id: String::new(),
                    port: pnum.parse().unwrap_or(0), protocol: proto.to_string(),
                    service: Some(svc.to_string()), version: ver, state: "open".into(), banner: None },
            });
            out.push(finding("nmap", &format!("Open {pnum}/{proto} on {target} ({svc})"),
                &format!("Port {pnum}/{proto} open on {target}\nService: {svc}"),
                Severity::Info, trimmed));
        }
        return out;
    }
    if let Some(caps) = RE_NMAP_OS.captures(trimmed) {
        out.push(finding("nmap", &format!("OS: {} on {target}", caps.get(1).map_or("", |m| m.as_str())),
            &format!("Nmap OS detection: {}", caps.get(1).map_or("", |m| m.as_str())),
            Severity::Info, trimmed));
        return out;
    }
    if let Some(caps) = RE_NMAP_CVE.captures(trimmed) {
        out.push(finding("nmap", &format!("Script CVE on {target}: {}", caps.get(1).map_or("", |m| m.as_str())),
            &format!("Nmap script output:\n{trimmed}"), Severity::High, trimmed));
    }
    out
}

fn parse_masscan(line: &str, target: &str) -> Vec<ParsedRecord> {
    let mut out = Vec::new();
    if let Some(caps) = RE_MASSCAN_PORT.captures(line) {
        let pnum  = caps.get(1).map_or("0",   |m| m.as_str());
        let proto = caps.get(2).map_or("tcp", |m| m.as_str());
        let host  = caps.get(3).map_or(target,|m| m.as_str()).to_string();
        let pid   = Uuid::new_v4().to_string();
        out.push(ParsedRecord::NewHost(Host { id: Uuid::new_v4().to_string(), address: host.clone(),
            hostname: None, os: None, notes: None, discovered_at: Utc::now() }));
        out.push(ParsedRecord::NewPort { host_addr: host.clone(),
            port: Port { id: pid.clone(), host_id: String::new(),
                port: pnum.parse().unwrap_or(0), protocol: proto.to_string(),
                service: None, version: None, state: "open".into(), banner: None } });
        out.push(finding("masscan", &format!("Open {pnum}/{proto} on {host}"),
            &format!("Masscan found {pnum}/{proto} on {host}"), Severity::Info, line));
    }
    out
}

fn parse_nikto(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_NIKTO_VULN.captures(line) {
        let id  = caps.get(1).map_or("", |m| m.as_str());
        let msg = caps.get(2).map_or("", |m| m.as_str()).trim();
        if msg.len() > 12 {
            let sev = if id.starts_with("CVE") || msg.to_lowercase().contains("inject")
                         || msg.to_lowercase().contains("rce") { Severity::High }
                      else { Severity::Medium };
            return vec![finding("nikto", &format!("Nikto: {}", &msg[..msg.len().min(70)]),
                &format!("Target: {target}\nRef: {id}\n{msg}"), sev, line)];
        }
    }
    vec![]
}

fn parse_hydra(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_HYDRA_CRED.captures(line) {
        let svc   = caps.get(2).map_or("", |m| m.as_str());
        let host  = caps.get(3).map_or("", |m| m.as_str());
        let login = caps.get(4).map_or("", |m| m.as_str());
        let pass  = caps.get(5).map_or("", |m| m.as_str());
        return vec![finding("hydra",
            &format!("Credential found [{svc}] {host}: {login}:{pass}"),
            &format!("Hydra found valid creds:\nService: {svc}\nHost: {host}\nLogin: {login}\nPassword: {pass}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_sqlmap(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_SQLMAP_PARAM.captures(line) {
        let param = caps.get(1).map_or("?", |m| m.as_str());
        let kind  = caps.get(2).map_or("SQLi", |m| m.as_str());
        return vec![finding("sqlmap",
            &format!("SQLi in '{param}' ({kind})"),
            &format!("SQLmap confirmed injection in '{param}' at {target}\nType: {kind}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_gobuster(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_GOBUSTER_DIR.captures(line.trim()) {
        let path   = caps.get(1).map_or("/", |m| m.as_str());
        let status = caps.get(2).map_or("200", |m| m.as_str());
        return vec![finding("gobuster",
            &format!("Dir: {path} ({status})"),
            &format!("gobuster found {path} on {target} — HTTP {status}"),
            Severity::Info, line)];
    }
    vec![]
}

fn parse_feroxbuster(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_FEROXBUSTER.captures(line) {
        let status = caps.get(1).map_or("200", |m| m.as_str());
        let path   = caps.get(2).map_or("/", |m| m.as_str());
        return vec![finding("feroxbuster", &format!("{path} ({status})"),
            &format!("feroxbuster: {path} on {target} — HTTP {status}"), Severity::Info, line)];
    }
    vec![]
}

fn parse_dirb(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_DIRB.captures(line) {
        let url    = caps.get(1).map_or("", |m| m.as_str());
        let status = caps.get(2).map_or("200", |m| m.as_str());
        return vec![finding("dirb", &format!("{url} ({status})"),
            &format!("DIRB found: {url} — HTTP {status}"), Severity::Info, line)];
    }
    vec![]
}

fn parse_dirsearch(line: &str, _target: &str) -> Vec<ParsedRecord> {
    let re = Regex::new(r"^\s*(\d{3})\s+\S+\s+(https?://\S+)").unwrap();
    if let Some(caps) = re.captures(line) {
        let status = caps.get(1).map_or("200", |m| m.as_str());
        let url    = caps.get(2).map_or("", |m| m.as_str());
        return vec![finding("dirsearch", &format!("{url} ({status})"),
            &format!("dirsearch: {url} — HTTP {status}"), Severity::Info, line)];
    }
    vec![]
}

fn parse_ffuf(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_FFUF_HIT.captures(line) {
        let url    = caps.get(1).map_or("", |m| m.as_str());
        let status = caps.get(2).map_or("200", |m| m.as_str());
        return vec![finding("ffuf", &format!("FFUF: {url} ({status})"),
            &format!("ffuf hit: {url} — HTTP {status}"), Severity::Info, line)];
    }
    vec![]
}

fn parse_enum4linux(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_ENUM4LINUX_SHARE.captures(line) {
        let host  = caps.get(1).map_or(target, |m| m.as_str());
        let share = caps.get(2).map_or("", |m| m.as_str());
        return vec![finding("enum4linux",
            &format!("SMB share: \\\\{host}\\{share}"),
            &format!("Accessible SMB share on {target}: \\\\{host}\\{share}"),
            Severity::Medium, line)];
    }
    if line.contains("user:") && line.contains("rid:") {
        return vec![finding("enum4linux",
            &format!("User enumerated: {}", &line.trim()[..line.trim().len().min(60)]),
            &format!("User enumerated on {target}:\n{}", line.trim()),
            Severity::Medium, line)];
    }
    vec![]
}

fn parse_cme(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_CME_CRED.captures(line) {
        let host = caps.get(1).map_or(target, |m| m.as_str());
        let user = caps.get(2).map_or("", |m| m.as_str());
        let pass = caps.get(3).map_or("", |m| m.as_str());
        return vec![finding("crackmapexec",
            &format!("Valid cred: {user}:{pass} @ {host}"),
            &format!("CrackMapExec confirmed: {user}:{pass} on {host}"),
            Severity::Critical, line)];
    }
    if line.contains("Pwn3d!") {
        return vec![finding("crackmapexec",
            &format!("ADMIN ACCESS on {target}"),
            &format!("CrackMapExec: local admin confirmed (Pwn3d!) on {target}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_wpscan(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_WPSCAN_VULN.captures(line) {
        let msg = caps.get(1).map_or("", |m| m.as_str()).trim();
        if !msg.is_empty() {
            return vec![finding("wpscan",
                &format!("WPScan: {}", &msg[..msg.len().min(70)]),
                &format!("WordPress vuln on {target}:\n{msg}"), Severity::High, line)];
        }
    }
    if line.contains("[i] Plugin:") {
        let name = line.trim_start_matches("[i] Plugin:").trim();
        return vec![finding("wpscan", &format!("WP Plugin: {name}"),
            &format!("WPScan detected plugin on {target}: {name}"), Severity::Info, line)];
    }
    vec![]
}

fn parse_nuclei(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_NUCLEI.captures(line) {
        let template = caps.get(1).map_or("", |m| m.as_str());
        let severity  = caps.get(3).map_or("info", |m| m.as_str());
        let detail    = caps.get(4).map_or("", |m| m.as_str()).trim();
        return vec![finding("nuclei",
            &format!("[{template}] {}", &detail[..detail.len().min(60)]),
            &format!("Nuclei template [{template}] matched on {target}\n{detail}"),
            Severity::from_str(severity), line)];
    }
    vec![]
}

fn parse_amass(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_AMASS.captures(line.trim()) {
        let sub = caps.get(1).map_or("", |m| m.as_str());
        if sub.contains('.') && !sub.starts_with('[') && !sub.starts_with('#') {
            return vec![finding("amass", &format!("Subdomain: {sub}"),
                &format!("Subdomain of {target}: {sub}"), Severity::Info, line)];
        }
    }
    vec![]
}

fn parse_whatweb(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_WHATWEB.captures(line) {
        let host  = caps.get(1).map_or("", |m| m.as_str());
        let code  = caps.get(2).map_or("", |m| m.as_str());
        let techs = caps.get(3).map_or("", |m| m.as_str());
        return vec![finding("whatweb",
            &format!("WhatWeb: {host} [{code}]"),
            &format!("Technologies on {host} (HTTP {code}):\n{techs}"),
            Severity::Info, line)];
    }
    vec![]
}

fn parse_dnsrecon(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_DNSRECON.captures(line) {
        let rtype = caps.get(2).map_or("?",   |m| m.as_str());
        let name  = caps.get(3).map_or("",    |m| m.as_str());
        let value = caps.get(4).map_or("",    |m| m.as_str());
        return vec![finding("dnsrecon",
            &format!("DNS {rtype}: {name} → {value}"),
            &format!("DNS record for {target}:\n{rtype} {name} → {value}"),
            Severity::Info, line)];
    }
    vec![]
}

fn parse_searchsploit(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_SEARCHSPLOIT.captures(line) {
        let title = caps.get(1).map_or("", |m| m.as_str()).trim();
        let path  = caps.get(2).map_or("", |m| m.as_str());
        if !title.is_empty() && title != "Title" {
            return vec![finding("searchsploit",
                &format!("Exploit: {}", &title[..title.len().min(70)]),
                &format!("SearchSploit match for '{target}':\n{title}\nFile: {path}"),
                Severity::High, line)];
        }
    }
    vec![]
}

fn parse_responder(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if RE_RESPONDER_HASH.is_match(line) {
        let content = line.trim();
        return vec![finding("responder",
            &format!("Hash captured: {}", &content[..content.len().min(60)]),
            &format!("Responder captured hash:\n{content}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_john(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_JOHN_CRACKED.captures(line) {
        let pass = caps.get(1).map_or("", |m| m.as_str());
        let user = caps.get(2).map_or(target, |m| m.as_str());
        if !pass.is_empty() && pass != "Loaded" && pass != "No" {
            return vec![finding("john",
                &format!("Cracked '{user}': {pass}"),
                &format!("John cracked password for '{user}':\nPassword: {pass}"),
                Severity::Critical, line)];
        }
    }
    vec![]
}

fn parse_hashcat(line: &str, _target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_HASHCAT_CRACKED.captures(line) {
        let hash = caps.get(1).map_or("", |m| m.as_str());
        let pass = caps.get(2).map_or("", |m| m.as_str()).trim();
        if !pass.is_empty() && !pass.contains("Cracked") {
            return vec![finding("hashcat",
                &format!("Hash cracked: {}:{pass}", &hash[hash.len().saturating_sub(8)..]),
                &format!("Hashcat cracked:\nHash: {hash}\nPassword: {pass}"),
                Severity::Critical, line)];
        }
    }
    vec![]
}

fn parse_evil_winrm(line: &str, target: &str) -> Vec<ParsedRecord> {
    if line.contains("Established connection") || line.contains("Establishing connection") {
        return vec![finding("evil-winrm",
            &format!("WinRM shell on {target}"),
            &format!("Evil-WinRM connected to {target}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_impacket(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_IMPACKET_HASH.captures(line) {
        let user   = caps.get(1).map_or("", |m| m.as_str());
        let domain = caps.get(2).map_or("", |m| m.as_str());
        return vec![finding("secretsdump",
            &format!("NTLM hash: {domain}\\{user}"),
            &format!("secretsdump extracted NTLM hash from {target}:\n{line}"),
            Severity::Critical, line)];
    }
    if line.contains(":$DCC2$") {
        return vec![finding("secretsdump",
            &format!("DCC2 hash on {target}"),
            &format!("secretsdump: DCC2 hash found:\n{line}"),
            Severity::Critical, line)];
    }
    vec![]
}

fn parse_wafw00f(line: &str, target: &str) -> Vec<ParsedRecord> {
    if let Some(caps) = RE_WAFW00F.captures(line) {
        let waf = caps.get(1).map_or("unknown", |m| m.as_str());
        return vec![finding("wafw00f",
            &format!("WAF: {waf}"),
            &format!("{target} is behind {waf} WAF"),
            Severity::Medium, line)];
    }
    vec![]
}

fn parse_snmp(line: &str, target: &str) -> Vec<ParsedRecord> {
    let re = Regex::new(r"(\d+\.\d+\.\d+\.\d+)\s+\[(.+)\]").unwrap();
    if let Some(caps) = re.captures(line) {
        let host = caps.get(1).map_or(target, |m| m.as_str());
        let comm = caps.get(2).map_or("public", |m| m.as_str());
        return vec![finding("snmpwalk",
            &format!("SNMP community '{comm}' on {host}"),
            &format!("SNMP community string found on {host}: '{comm}'"),
            Severity::High, line)];
    }
    vec![]
}
pub fn parse_nmap_xml(xml_path: &str, _target: &str) -> Vec<ParsedRecord> {
    let xml = match std::fs::read_to_string(xml_path) {
        Ok(s) => s, Err(_) => return vec![],
    };
    let mut out = Vec::new();
    let mut current_ip   = String::new();
    let mut current_hn   = Option::<String>::None;
    let mut current_hid  = Uuid::new_v4().to_string();
    let mut host_emitted = false;

    for line in xml.lines() {
        let line = line.trim();
        if line.starts_with("<host ") {
            current_ip.clear(); current_hn = None;
            current_hid  = Uuid::new_v4().to_string();
            host_emitted = false;
        }
        if (line.contains("addrtype=\"ipv4\"") || line.contains("addrtype='ipv4'"))
            && line.contains("addr=")
        {
            if let Some(s) = attr(line, "addr") { current_ip = s; }
        }
        if line.contains("<hostname ") {
            if let Some(s) = attr(line, "name") { current_hn = Some(s); }
        }
        if (line.contains("</hostnames>") || line.contains("<ports>")) && !current_ip.is_empty() && !host_emitted {
            out.push(ParsedRecord::NewHost(Host {
                id: current_hid.clone(), address: current_ip.clone(),
                hostname: current_hn.clone(), os: None, notes: None, discovered_at: Utc::now(),
            }));
            host_emitted = true;
        }
        if line.starts_with("<port ") {
            let proto = attr(line, "protocol").unwrap_or_else(|| "tcp".into());
            let pid_str = attr(line, "portid").unwrap_or_else(|| "0".into());
            let pnum: u16 = pid_str.parse().unwrap_or(0);
            out.push(ParsedRecord::NewPort {
                host_addr: current_ip.clone(),
                port: Port { id: Uuid::new_v4().to_string(), host_id: current_hid.clone(),
                    port: pnum, protocol: proto, service: None, version: None,
                    state: "open".into(), banner: None },
            });
        }
        if line.starts_with("<service ") {
            let svc = attr(line, "name");
            let ver = {
                let prod = attr(line, "product");
                let ver2 = attr(line, "version");
                match (prod, ver2) {
                    (Some(p), Some(v)) => Some(format!("{p} {v}")),
                    (Some(p), None)    => Some(p),
                    (None, Some(v))    => Some(v),
                    _                  => None,
                }
            };
            for rec in out.iter_mut().rev() {
                if let ParsedRecord::NewPort { port, .. } = rec {
                    if port.service.is_none() { port.service = svc.clone(); port.version = ver.clone(); break; }
                }
            }
        }
        if line.starts_with("<osmatch ") {
            if let Some(name) = attr(line, "name") {
                out.push(ParsedRecord::Finding(Finding {
                    id: Uuid::new_v4().to_string(), 
                    host_id: Some(current_hid.clone()),
                    port_id: None, 
                    tool: "nmap".into(),
                    title: format!("OS: {name} @ {}", current_ip),
                    description: format!("Nmap OS: {name}"), 
                    severity: Severity::Info,
                    host: current_ip.clone(),
                    evidence: Some(line.to_string()), 
                    metadata: None,
                    created_at: Utc::now(),
                }));
            }
        }
    }
    out
}

fn attr(line: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start  = line.find(&needle)?;
    let rest   = &line[start + needle.len()..];
    let end    = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_4nmap(line: &str, target: &str) -> Vec<ParsedRecord> {
    let mut out = Vec::new();
    if let Some(caps) = RE_4NMAP_PORT.captures(line) {
        let pnum: u16 = caps[1].parse().unwrap_or(0);
        out.push(ParsedRecord::NewPort {
            host_addr: target.to_string(),
            port: Port { 
                id: Uuid::new_v4().to_string(), host_id: String::new(),
                port: pnum, protocol: "tcp".into(), service: None, 
                version: None, state: "open".into(), banner: None 
            },
        });
    }
    if let Some(caps) = RE_4NMAP_SERVICE.captures(line) {
        let pnum: u16 = caps[1].parse().unwrap_or(0);
        let svc = caps[2].to_string();
        out.push(ParsedRecord::NewPort {
            host_addr: target.to_string(),
            port: Port { 
                id: Uuid::new_v4().to_string(), host_id: String::new(),
                port: pnum, protocol: "tcp".into(), service: Some(svc), 
                version: None, state: "open".into(), banner: None 
            },
        });
    }
    if let Some(caps) = RE_4NMAP_VULN.captures(line) {
        let pnum = &caps[1];
        let desc = &caps[2];
        out.push(ParsedRecord::Finding(Finding {
            id: Uuid::new_v4().to_string(), 
            host_id: None, 
            port_id: None,
            tool: "4nmap".into(), 
            title: format!("Vuln on Port {}", pnum),
            description: desc.to_string(), 
            severity: Severity::High,
            host: String::new(), // To be patched by orchestrator if possible
            evidence: Some(line.to_string()), 
            metadata: None,
            created_at: Utc::now(),
        }));
    }
    if let Some(caps) = RE_4NMAP_OS.captures(line) {
        let os = caps[1].to_string();
        out.push(finding("4nmap", "OS Fingerprint", &format!("Detected: {os}"), Severity::Info, "", line));
    }
    out
}

fn parse_4gobuster(line: &str, target: &str) -> Vec<ParsedRecord> {
    let mut results = Vec::new();
    if let Some(caps) = RE_4GOBUSTER_HIT.captures(line) {
        let path = caps[1].to_string();
        let code = caps[2].to_string();
        let size = caps[3].to_string();
        results.push(ParsedRecord::Finding(Finding {
            id: Uuid::new_v4().to_string(),
            title: format!("Web Path Found: {}", path),
            description: format!("Status: {}, Size: {}", code, size),
            severity: if code == "200" { Severity::Medium } else { Severity::Info },
            tool: "4gobuster".into(),
            host: target.to_string(),
            created_at: Utc::now(),
            evidence: Some(line.to_string()),
            ..Default::default()
        }));
    }
    results
}

fn parse_4hydra(line: &str, target: &str) -> Vec<ParsedRecord> {
    let mut results = Vec::new();
    if let Some(caps) = RE_4HYDRA_SUCCESS.captures(line) {
        let proto = caps[1].to_string();
        let user  = caps[2].to_string();
        let pass  = caps[3].to_string();
        results.push(ParsedRecord::Finding(Finding {
            id: Uuid::new_v4().to_string(),
            title: format!("Cracked Credentials ({})", proto),
            description: format!("Found valid login for {} on {}", user, target),
            severity: Severity::Critical,
            tool: "4hydra".into(),
            host: target.to_string(),
            created_at: Utc::now(),
            metadata: Some(format!("{{\"user\": \"{}\", \"pass\": \"{}\"}}", user, pass)),
            ..Default::default()
        }));
    }
    results
}

fn parse_4nikto(line: &str, _target: &str) -> Vec<ParsedRecord> {
    let mut results = Vec::new();
    if let Some(caps) = RE_4NIKTO_VULN.captures(line) {
        let desc = caps[1].to_string();
        let url  = caps[2].to_string();
        results.push(ParsedRecord::Finding(Finding {
            id: Uuid::new_v4().to_string(),
            title: desc,
            description: format!("Discovered via 4nikto scan"),
            severity: Severity::High,
            tool: "4nikto".into(),
            host: url.clone(),
            created_at: Utc::now(),
            metadata: None,
            evidence: Some(url),
            host_id: None,
            port_id: None,
        }));
    }
    results
}
