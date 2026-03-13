use crate::{config::AppConfig, tools::spec::{TargetType, ToolSpec}};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, warn};
use which::which;

pub struct ToolRegistry {
    categories: HashMap<String, Vec<ToolSpec>>,
}

macro_rules! tool {
    ($name:expr, $bin:expr, $desc:expr, $cat:expr, $tt:expr, $args:expr, $root:expr) => {
        ToolSpec {
            name:         $name.into(),
            binary:       $bin.into(),
            description:  $desc.into(),
            category:     $cat.into(),
            target_type:  $tt,
            target_hint:  String::new(),
            default_args: $args.iter().map(|s: &&str| s.to_string()).collect(),
            wrapper:      None,
            needs_root:   $root,
            proxychains:  true,
            interactive:  false,
            tags:         vec![],
            is_builtin:   false,
        }
    };
}

macro_rules! builtin_tool {
    ($name:expr, $desc:expr, $cat:expr, $tt:expr, $args:expr) => {
        ToolSpec {
            name:         $name.into(),
            binary:       format!("builtin:{}", $name),
            description:  $desc.into(),
            category:     $cat.into(),
            target_type:  $tt,
            target_hint:  String::new(),
            default_args: $args.iter().map(|s: &&str| s.to_string()).collect(),
            wrapper:      None,
            needs_root:   false,
            proxychains:  false,
            interactive:  false,
            tags:         vec!["builtin".into(), "null".into()],
            is_builtin:   true,
        }
    };
}

impl ToolRegistry {
    pub async fn load(cfg: &AppConfig) -> Result<Self> {
        let mut categories: HashMap<String, Vec<ToolSpec>> = HashMap::new();
        for spec in builtin_tools() {
            categories.entry(spec.category.clone()).or_default().push(spec);
        }
        let tools_dir = cfg.tools_dir();
        if tools_dir.exists() {
            let mut rd = tokio::fs::read_dir(&tools_dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                    match tokio::fs::read_to_string(&path).await {
                        Ok(raw) => match toml::from_str::<Vec<ToolSpec>>(&raw) {
                            Ok(specs) => {
                                for spec in specs {
                                    info!(tool = %spec.name, "loaded from {}", path.display());
                                    categories.entry(spec.category.clone()).or_default().push(spec);
                                }
                            }
                            Err(e) => warn!(path = %path.display(), err = %e, "bad manifest"),
                        },
                        Err(e) => warn!(path = %path.display(), err = %e, "read error"),
                    }
                }
            }
        }
        for tools in categories.values_mut() {
            tools.sort_by(|a, b| a.name.cmp(&b.name));
        }
        info!(categories = categories.len(), "registry loaded");
        Ok(Self { categories })
    }

    pub fn category_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.categories.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn tools_in(&self, category: &str) -> Vec<ToolSpec> {
        self.categories.get(category).cloned().unwrap_or_default()
    }

    pub fn find(&self, name: &str) -> Option<ToolSpec> {
        self.categories.values().flat_map(|v| v.iter())
            .find(|t| t.name.eq_ignore_ascii_case(name)).cloned()
    }

    pub fn availability_check(&self) -> HashMap<String, bool> {
        self.categories.values().flat_map(|v| v.iter())
            .map(|t| (t.name.clone(), which(&t.binary).is_ok()))
            .collect()
    }

    pub fn export_all(&self) -> HashMap<String, Vec<ToolSpec>> {
        self.categories.clone()
    }

    pub fn all_tools(&self) -> Vec<ToolSpec> {
        self.categories.values().flat_map(|v| v.iter()).cloned().collect()
    }

    pub fn find_by_id(&self, name: &str) -> Option<ToolSpec> { self.find(name) }
}

fn builtin_tools() -> Vec<ToolSpec> {
    vec![
        builtin_tool!("4nmap",     "Null-Optimized Port Scanner (High-speed Rust SYN/TCP)", 
                      "Null", TargetType::IpOrCidr,  &["--top-ports", "1000", "--threads", "100", "{target}"]),
        builtin_tool!("4gobuster", "Null-Speed Web Fuzzer (Recursive, Concurrent)", 
                      "Null", TargetType::Url,         &["-w", "{wordlist}", "-t", "100", "{target}"]),
        builtin_tool!("4hydra",    "Null-Force Login Brute-forcer (Optimized)", 
                      "Null", TargetType::IpPort,      &["-u", "admin", "-w", "{wordlist}", "{target}"]),
        builtin_tool!("4nikto",    "Null-Scan Web Vulnerability Scanner", 
                      "Null", TargetType::Url,         &["{target}"]),
        builtin_tool!("4subfinder", "Null-Enumeration Subdomain Finder",
                      "Null", TargetType::Domain,      &["-w", "{wordlist}", "{target}"]),
        
        tool!("nmap",       "nmap",       "Network mapper — port/service/OS detection",
              "Recon", TargetType::IpOrCidr,  &["-sV", "-sC", "-O", "--open", "{target}"], true),
        tool!("masscan",    "masscan",    "Fastest port scanner — full Internet-speed",
              "Recon", TargetType::IpOrCidr,  &["-p1-65535", "--rate=1000", "{target}"], true),
        tool!("nmap-udp",   "nmap",       "UDP port scan (top 100 UDP ports)",
              "Recon", TargetType::IpOrCidr,  &["-sU", "--top-ports", "100", "-T4", "{target}"], true),
        tool!("nmap-vuln",  "nmap",       "Nmap vulnerability scripts scan",
              "Recon", TargetType::IpOrCidr,  &["-sV", "--script=vuln", "{target}"], true),
        tool!("nmap-full",  "nmap",       "Full TCP/UDP + scripts + OS + traceroute",
              "Recon", TargetType::IpOrCidr,  &["-sS", "-sU", "-A", "-p-", "-T4", "{target}"], true),
        tool!("amass",      "amass",      "Subdomain enumeration and DNS reconnaissance",
              "Recon", TargetType::Domain,    &["enum", "-passive", "-d", "{target}"], false),
        tool!("amass-active","amass",     "Active subdomain enumeration with brute force",
              "Recon", TargetType::Domain,    &["enum", "-active", "-brute", "-d", "{target}"], false),
        tool!("subfinder",  "subfinder",  "Fast passive subdomain enumeration",
              "Recon", TargetType::Domain,    &["-d", "{target}", "-silent"], false),
        tool!("dnsrecon",   "dnsrecon",   "DNS enumeration: zone transfers, brute force, std records",
              "Recon", TargetType::Domain,    &["-d", "{target}", "-t", "std,brt,axfr,srv,rvl"], false),
        tool!("fierce",     "fierce",     "DNS brute force scanner",
              "Recon", TargetType::Domain,    &["--domain", "{target}"], false),
        tool!("dnsx",       "dnsx",       "Fast mass DNS toolkit",
              "Recon", TargetType::Domain,    &["-silent", "-resp", "-a", "-domain", "{target}"], false),
        tool!("theHarvester","theHarvester","Email, subdomain and people OSINT harvester",
              "Recon", TargetType::Domain,    &["-d", "{target}", "-l", "500", "-b", "all"], false),
        tool!("whois",      "whois",      "WHOIS domain / IP registration lookup",
              "Recon", TargetType::IpOrDomain, &["{target}"], false),
        tool!("netdiscover","netdiscover","ARP-based LAN host discovery",
              "Recon", TargetType::IpOrCidr,  &["-r", "{target}"], true),
        tool!("arp-scan",   "arp-scan",   "ARP host discovery on local network",
              "Recon", TargetType::IpOrCidr,  &["--localnet", "--interface=eth0"], true),
        tool!("shodan-cli", "shodan",     "Shodan query for a host or term",
              "Recon", TargetType::IpOrDomain, &["host", "{target}"], false),
        tool!("recon-ng",   "recon-ng",   "Recon-ng modular OSINT framework",
              "Recon", TargetType::Domain,    &[], false),
        tool!("maltego",    "maltego",    "Visual link analysis and OSINT tool",
              "Recon", TargetType::Domain,    &[], false),
        tool!("spiderfoot", "spiderfoot", "Automated OSINT Spider",
              "Recon", TargetType::Domain,    &["-s", "{target}", "-m", "ALL", "-q"], false),
        tool!("sublist3r",  "sublist3r",  "Subdomain brute-force enumeration via OSINT sources",
              "Recon", TargetType::Domain,    &["-d", "{target}", "-o", "/tmp/sublist3r.txt"], false),
        tool!("dnsenum",    "dnsenum",    "DNS enumeration and zone transfer tool",
              "Recon", TargetType::Domain,    &["--noreverse", "--nocolor", "{target}"], false),
        tool!("nikto",      "nikto",      "Web server vulnerability scanner",
              "Web", TargetType::Url,         &["-h", "{target}", "-Format", "txt"], false),
        tool!("sqlmap",     "sqlmap",     "Automated SQL injection detection and exploitation",
              "Web", TargetType::Url,         &["-u", "{target}", "--batch", "--level=3", "--risk=2"], false),
        tool!("sqlmap-crawl","sqlmap",    "SQLmap with full crawl and form detection",
              "Web", TargetType::Url,         &["-u", "{target}", "--crawl=3", "--batch", "--forms"], false),
        tool!("gobuster",   "gobuster",   "Directory/file brute-force (http/dns/vhost)",
              "Web", TargetType::Url,         &["dir", "-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50", "-x", "php,html,txt,js,aspx,bak"], false),
        tool!("gobuster-dns","gobuster",  "DNS subdomain brute-force",
              "Web", TargetType::Domain,      &["dns", "-d", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50"], false),
        tool!("ffuf",       "ffuf",       "Fast web fuzzer for content discovery",
              "Web", TargetType::Url,         &["-w", "/usr/share/wordlists/dirb/common.txt", "-u", "{target}/FUZZ", "-mc", "200,301,302,403", "-t", "50"], false),
        tool!("feroxbuster","feroxbuster","Recursive content discovery scanner",
              "Web", TargetType::Url,         &["-u", "{target}", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "--auto-tune"], false),
        tool!("dirb",       "dirb",       "Web content scanner with dictionary attack",
              "Web", TargetType::Url,         &["{target}", "/usr/share/dirb/wordlists/common.txt"], false),
        tool!("wpscan",     "wpscan",     "WordPress vulnerability scanner",
              "Web", TargetType::Url,         &["--url", "{target}", "--enumerate", "ap,at,u,tt", "--detection-mode", "aggressive"], false),
        tool!("joomscan",   "joomscan",   "Joomla CMS vulnerability scanner",
              "Web", TargetType::Url,         &["--url", "{target}"], false),
        tool!("nuclei",     "nuclei",     "Template-based vulnerability scanner",
              "Web", TargetType::Url,         &["-u", "{target}", "-severity", "critical,high,medium", "-silent"], false),
        tool!("nuclei-cves","nuclei",     "Nuclei CVE-only scan",
              "Web", TargetType::Url,         &["-u", "{target}", "-t", "cves/", "-silent"], false),
        tool!("wafw00f",    "wafw00f",    "Web application firewall detection",
              "Web", TargetType::Url,         &["{target}", "-a"], false),
        tool!("whatweb",    "whatweb",    "Web technology fingerprinting",
              "Web", TargetType::Url,         &["-a3", "--colour=never", "{target}"], false),
        tool!("wget-spider","wget",       "Recursive web spider / mirror",
              "Web", TargetType::Url,         &["--spider", "--recursive", "--level=3", "{target}"], false),
        tool!("httpx",      "httpx",      "Fast HTTP probing and tech stack detection",
              "Web", TargetType::Domain,      &["-u", "{target}", "-tech-detect", "-status-code", "-title", "-silent"], false),
        tool!("arjun",      "arjun",      "HTTP parameter discovery for hidden parameters",
              "Web", TargetType::Url,         &["-u", "{target}", "--stable"], false),
        tool!("xsstrike",   "xsstrike",   "Advanced XSS scanning and exploitation",
              "Web", TargetType::Url,         &["-u", "{target}", "--crawl", "--blind"], false),
        tool!("dalfox",     "dalfox",     "Fast parameter-based XSS scanner",
              "Web", TargetType::Url,         &["url", "{target}", "--skip-bav", "-o", "/tmp/dalfox.txt"], false),
        tool!("commix",     "commix",     "Command injection discovery and exploitation",
              "Web", TargetType::Url,         &["--url", "{target}", "--batch"], false),
        tool!("dirsearch",  "dirsearch",  "Advanced web path discovery",
              "Web", TargetType::Url,         &["-u", "{target}", "-e", "php,html,js,aspx,bak,zip,txt", "-t", "40"], false),
        tool!("msfconsole", "msfconsole", "Metasploit Framework interactive console",
              "Exploitation", TargetType::IpOrDomain, &["-q"], false),
        tool!("msfvenom",   "msfvenom",   "Metasploit payload generator",
              "Exploitation", TargetType::Custom,     &["-p", "linux/x64/meterpreter/reverse_tcp", "LHOST={target}", "LPORT=4444", "-f", "elf"], false),
        tool!("searchsploit","searchsploit","ExploitDB offline search",
              "Exploitation", TargetType::Custom,     &["--nmap", "{target}"], false),
        tool!("exploit-suggester","linux-exploit-suggester","Linux kernel privilege escalation suggester",
              "Exploitation", TargetType::File,       &["--uname", "{target}"], false),
        tool!("beef-xss",   "beef",       "Browser exploitation framework (BeEF)",
              "Exploitation", TargetType::Url,        &[], false),
        tool!("set",        "setoolkit",  "Social Engineering Toolkit",
              "Exploitation", TargetType::Custom,     &[], false),
        tool!("evil-winrm", "evil-winrm", "WinRM shell for penetration testing",
              "Exploitation", TargetType::IpPort,     &["-i", "{target}", "-u", "Administrator"], false),
        tool!("impacket-psexec","psexec.py","Impacket PsExec — SMB command execution",
              "Exploitation", TargetType::IpOrDomain, &["{target}/administrator:Password@{target}"], false),
        tool!("impacket-wmiexec","wmiexec.py","Impacket WMI exec",
              "Exploitation", TargetType::IpOrDomain, &["{target}/administrator:Password@{target}"], false),
        tool!("impacket-smbexec","smbexec.py","Impacket SMB exec",
              "Exploitation", TargetType::IpOrDomain, &["{target}/administrator:Password@{target}"], false),
        tool!("impacket-secretsdump","secretsdump.py","Dump cached credentials via Impacket",
              "Exploitation", TargetType::IpOrDomain, &["{target}/administrator:Password@{target}"], false),
        tool!("crackmapexec-smb","cme","CME SMB lateral movement and post-ex",
              "Exploitation", TargetType::IpOrCidr,   &["smb", "{target}", "-u", "Administrator", "-p", "Password"], false),
        tool!("crackmapexec-winrm","cme","CME WinRM authentication and exec",
              "Exploitation", TargetType::IpOrCidr,   &["winrm", "{target}", "-u", "Administrator", "-p", "Password"], false),
        tool!("mimikatz",   "mimikatz",   "Windows credential extraction",
              "Exploitation", TargetType::Custom,     &[], true),
        tool!("responder",  "responder",  "LLMNR/NBT-NS/mDNS poisoner and credential harvester",
              "Exploitation", TargetType::Interface,  &["-I", "{target}", "-rdw"], true),
        tool!("wireshark",  "wireshark",  "Graphical network protocol analyser",
              "Network", TargetType::Interface,       &["-i", "{target}"], true),
        tool!("tcpdump",    "tcpdump",    "Command-line packet capture",
              "Network", TargetType::Interface,       &["-i", "{target}", "-w", "/tmp/fh-cap.pcap", "-v"], true),
        tool!("tshark",     "tshark",     "Terminal Wireshark — live capture + filter",
              "Network", TargetType::Interface,       &["-i", "{target}", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport"], true),
        tool!("ettercap",   "ettercap",   "Man-in-the-middle ARP poisoning and sniffing",
              "Network", TargetType::Interface,       &["-T", "-q", "-i", "{target}", "-M", "arp:remote"], true),
        tool!("bettercap",  "bettercap",  "Advanced MITM, sniffing and network manipulation",
              "Network", TargetType::Interface,       &["-iface", "{target}", "-eval", "net.probe on; arp.spoof on"], true),
        tool!("arpspoof",   "arpspoof",   "ARP spoofing for MITM attacks",
              "Network", TargetType::IpOrDomain,      &["-i", "eth0", "{target}"], true),
        tool!("netcat",     "nc",         "TCP/UDP networking Swiss army knife",
              "Network", TargetType::IpPort,          &["-v", "-n", "-z", "{target}"], false),
        tool!("socat",      "socat",      "Multipurpose relay for bidirectional data transfer",
              "Network", TargetType::IpPort,          &["TCP4:{target}", "STDOUT"], false),
        tool!("chisel",     "chisel",     "Fast TCP/UDP tunnel over HTTP",
              "Network", TargetType::IpPort,          &["client", "{target}", "R:1080:socks"], false),
        tool!("proxychains","proxychains4","Route any tool through SOCKS/HTTP proxies",
              "Network", TargetType::Custom,          &["{target}"], false),
        tool!("mitmproxy",  "mitmproxy",  "Interactive TLS man-in-the-middle proxy",
              "Network", TargetType::Port,            &["--listen-port", "8080"], false),
        tool!("snmpwalk",   "snmpwalk",   "SNMP MIB tree walker",
              "Network", TargetType::IpOrDomain,      &["-v2c", "-c", "public", "{target}"], false),
        tool!("onesixtyone","onesixtyone","SNMP community string scanner",
              "Network", TargetType::IpOrCidr,        &["-c", "/usr/share/seclists/Discovery/SNMP/snmp.txt", "{target}"], false),
        tool!("dnschef",    "dnschef",    "DNS proxy — fake responses for testing",
              "Network", TargetType::Interface,       &["--interface", "{target}", "--fakeip", "127.0.0.1"], true),
        tool!("sslscan",    "sslscan",    "SSL/TLS cipher and certificate scanner",
              "Network", TargetType::IpPort,          &["--show-certificate", "--no-colour", "{target}"], false),
        tool!("testssl",    "testssl.sh", "Comprehensive TLS/SSL server test",
              "Network", TargetType::IpPort,          &["--color", "0", "{target}"], false),
        tool!("netdiscover2","netdiscover","Passive ARP recon on local subnet",
              "Network", TargetType::Interface,       &["-i", "{target}", "-P"], true),
        tool!("hydra",      "hydra",      "Network login brute-force supporting 50+ protocols",
              "Password", TargetType::IpOrDomain,     &["-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "{target}", "ssh"], false),
        tool!("hydra-http", "hydra",      "HTTP(S) form brute-force with Hydra",
              "Password", TargetType::Url,            &["-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "-s", "80", "-f", "{target}", "http-post-form", "/login:user=^USER^&pass=^PASS^:F=invalid"], false),
        tool!("medusa",     "medusa",     "Parallel brute-force login tool",
              "Password", TargetType::IpOrDomain,     &["-h", "{target}", "-u", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "-M", "ssh"], false),
        tool!("ncrack",     "ncrack",     "Rapid network auth cracking",
              "Password", TargetType::IpPort,         &["-v", "{target}"], false),
        tool!("john",       "john",       "John the Ripper — advanced password hash cracker",
              "Password", TargetType::File,           &["--wordlist=/usr/share/wordlists/rockyou.txt", "{target}"], false),
        tool!("john-show",  "john",       "Show cracked passwords from pot file",
              "Password", TargetType::File,           &["--show", "{target}"], false),
        tool!("hashcat",    "hashcat",    "GPU-accelerated hash cracker",
              "Password", TargetType::File,           &["-m", "0", "-a", "0", "{target}", "/usr/share/wordlists/rockyou.txt", "--force"], false),
        tool!("hashcat-ntlm","hashcat",   "NTLM hash cracking",
              "Password", TargetType::File,           &["-m", "1000", "-a", "0", "{target}", "/usr/share/wordlists/rockyou.txt", "--force"], false),
        tool!("crunch",     "crunch",     "Custom wordlist generator",
              "Password", TargetType::Custom,         &["8", "10", "abcdefghijklmnopqrstuvwxyz0123456789", "-o", "/tmp/wordlist.txt"], false),
        tool!("cewl",       "cewl",       "Website wordlist generator from crawled pages",
              "Password", TargetType::Url,            &["-d", "3", "-m", "6", "-w", "/tmp/cewl.txt", "{target}"], false),
        tool!("cupp",       "cupp",       "Common user passwords profiler",
              "Password", TargetType::Custom,         &["-i"], false),
        tool!("credcrack",  "credcrack",  "SMB credential validation via Impacket",
              "Password", TargetType::IpOrDomain,     &[], false),
        tool!("aircrack-ng","aircrack-ng","WPA/WEP key recovery",
              "Wireless", TargetType::File,           &["-w", "/usr/share/wordlists/rockyou.txt", "{target}"], false),
        tool!("airodump-ng","airodump-ng","Wireless packet capture and AP discovery",
              "Wireless", TargetType::Interface,      &["{target}"], true),
        tool!("aireplay-ng","aireplay-ng","Wireless packet injection and deauth",
              "Wireless", TargetType::Interface,      &["-0", "10", "-a", "00:11:22:33:44:55", "{target}"], true),
        tool!("airmon-ng",  "airmon-ng",  "Enable/disable monitor mode on wireless interfaces",
              "Wireless", TargetType::Interface,      &["start", "{target}"], true),
        tool!("reaver",     "reaver",     "WPS brute-force attack",
              "Wireless", TargetType::Interface,      &["-i", "{target}", "-b", "00:11:22:33:44:55", "-vv"], true),
        tool!("bully",      "bully",      "WPS brute-force (alternative to Reaver)",
              "Wireless", TargetType::Interface,      &["-b", "00:11:22:33:44:55", "{target}", "-d"], true),
        tool!("wifite",     "wifite",     "Automated wireless auditing tool",
              "Wireless", TargetType::Interface,      &["--interface", "{target}", "--kill"], true),
        tool!("kismet",     "kismet",     "Wireless network detector, sniffer and IDS",
              "Wireless", TargetType::Interface,      &["--no-ncurses", "-c", "{target}"], true),
        tool!("fern-wifi",  "fern-wifi-cracker","Graphical wireless auditing tool",
              "Wireless", TargetType::Interface,      &[], true),
        tool!("hcxdumptool","hcxdumptool","Advanced PMKID/handshake capture",
              "Wireless", TargetType::Interface,      &["-i", "{target}", "-o", "/tmp/hcxdump.pcapng", "--enable_status=15"], true),
        tool!("hcxtools",   "hcxpcapngtool","Convert capture to hashcat format",
              "Wireless", TargetType::File,           &["{target}", "-o", "/tmp/hash.hc22000"], false),
        tool!("volatility",  "vol3",      "Windows/Linux memory forensics",
              "Forensics", TargetType::File,          &["-f", "{target}", "windows.pslist"], false),
        tool!("volatility-mac","vol3",    "macOS memory forensics",
              "Forensics", TargetType::File,          &["-f", "{target}", "mac.pslist"], false),
        tool!("binwalk",    "binwalk",    "Firmware analysis and embedded file extractor",
              "Forensics", TargetType::File,          &["-e", "-M", "{target}"], false),
        tool!("foremost",   "foremost",   "File carving from disk/memory images",
              "Forensics", TargetType::File,          &["-i", "{target}", "-o", "/tmp/foremost-out"], false),
        tool!("scalpel",    "scalpel",    "Header/footer-based file carving tool",
              "Forensics", TargetType::File,          &["{target}", "-o", "/tmp/scalpel-out"], false),
        tool!("autopsy",    "autopsy",    "GUI digital forensics platform",
              "Forensics", TargetType::File,          &[], false),
        tool!("exiftool",   "exiftool",   "Metadata reader/writer for media files",
              "Forensics", TargetType::File,          &["-a", "-u", "-g1", "{target}"], false),
        tool!("steghide",   "steghide",   "Steganography detection and extraction",
              "Forensics", TargetType::File,          &["extract", "-sf", "{target}"], false),
        tool!("stegseek",   "stegseek",   "Lightning-fast steghide brute-force",
              "Forensics", TargetType::File,          &["{target}", "/usr/share/wordlists/rockyou.txt"], false),
        tool!("bulk-extractor","bulk_extractor","Extracts emails/URLs/CCs from disk images",
              "Forensics", TargetType::File,          &["-o", "/tmp/bulk-out", "{target}"], false),
        tool!("strings-analysis","strings","Extract printable strings from binary",
              "Forensics", TargetType::File,          &["-n", "8", "{target}"], false),
        tool!("pspy",       "pspy64",     "Unprivileged process monitor — no root",
              "Forensics", TargetType::Custom,        &["-pf", "-i", "1000"], false),
        tool!("linpeas",    "linpeas",    "Linux privilege escalation auditing script",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("winpeas",    "winpeas.exe","Windows privilege escalation auditing script",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("les",        "linux-exploit-suggester","Linux exploit suggester based on kernel version",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("les2",       "linux-exploit-suggester-2","Linux exploit suggester v2",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("wesng",      "wes.py",     "Windows exploit suggester (next-gen)",
              "PrivEsc", TargetType::File,            &["{target}", "-i", "all"], false),
        tool!("sudo-killer","sudo_killer.sh","Misconfigured sudo privilege escalation",
              "PrivEsc", TargetType::Custom,          &["-i"], false),
        tool!("g0tmi1k-priv","g0tmi1k",  "Linux post-exploitation and privesc script",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("BeRoot",     "beroot.py",  "Windows/Linux privilege escalation finder",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("GTFOBins-check","gtfobins-check.sh","Check for GTFObins local privesc vectors",
              "PrivEsc", TargetType::Custom,          &[], false),
        tool!("enum4linux",  "enum4linux", "Windows/Samba enumeration via null sessions",
              "SMB/AD", TargetType::IpOrDomain,       &["-a", "{target}"], false),
        tool!("enum4linux-ng","enum4linux-ng","Modern enum4linux rewrite with JSON output",
              "SMB/AD", TargetType::IpOrDomain,       &["-A", "-oA", "/tmp/enum4linux", "{target}"], false),
        tool!("smbclient",  "smbclient",  "SMB share browser and file transfer",
              "SMB/AD", TargetType::IpOrDomain,       &["-L", "//{target}"], false),
        tool!("smbmap",     "smbmap",     "SMB share enumeration with permissions",
              "SMB/AD", TargetType::IpOrDomain,       &["-H", "{target}", "--no-banner"], false),
        tool!("rpcclient",  "rpcclient",  "Samba RPC client for AD enumeration",
              "SMB/AD", TargetType::IpOrDomain,       &["-U", "", "{target}", "-c", "enumdomusers"], false),
        tool!("ldapsearch", "ldapsearch", "LDAP directory search and enumeration",
              "SMB/AD", TargetType::IpOrDomain,       &["-x", "-H", "ldap://{target}"], false),
        tool!("bloodhound-py","bloodhound-python","BloodHound data ingestor for AD mapping",
              "SMB/AD", TargetType::IpOrDomain,       &["-d", "{target}", "-u", "user", "-p", "pass", "-c", "all", "-ns", "{target}"], false),
        tool!("kerbrute",   "kerbrute",   "Kerberos username enum and brute-force",
              "SMB/AD", TargetType::IpOrDomain,       &["userenum", "-d", "{target}", "--dc", "{target}", "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"], false),
        tool!("GetNPUsers", "GetNPUsers.py","Kerberoast — AS-REP roasting",
              "SMB/AD", TargetType::IpOrDomain,       &["{target}/", "-dc-ip", "{target}", "-no-pass", "-usersfile", "/tmp/users.txt"], false),
        tool!("GetSPNs",    "GetUserSPNs.py","Request service tickets for SPN accounts",
              "SMB/AD", TargetType::IpOrDomain,       &["{target}/user:pass", "-dc-ip", "{target}", "-request"], false),
        tool!("sqlmap-dump","sqlmap",     "Database dump after injection confirmation",
              "Database", TargetType::Url,            &["-u", "{target}", "--dump-all", "--batch", "--threads=5"], false),
        tool!("msssqlclient","mssqlclient.py","Connect to MSSQL via Impacket",
              "Database", TargetType::IpPort,         &["{target}", "-windows-auth"], false),
        tool!("mysql-enum", "nmap",       "MySQL version and auth enumeration",
              "Database", TargetType::IpOrDomain,     &["--script=mysql-*", "-p3306", "{target}"], false),
        tool!("mongodb-enum","nmap",      "MongoDB open access scanner",
              "Database", TargetType::IpOrDomain,     &["--script=mongodb-*", "-p27017", "{target}"], false),
        tool!("redis-cli",  "redis-cli",  "Redis unauthorized access check",
              "Database", TargetType::IpPort,         &["-h", "{target}", "INFO", "server"], false),
        tool!("ghidra",     "ghidra",     "NSA reverse engineering and decompilation suite",
              "RE", TargetType::File,                 &["{target}"], false),
        tool!("radare2",    "r2",         "Advanced binary analysis framework",
              "RE", TargetType::File,                 &["-A", "{target}"], false),
        tool!("gdb",        "gdb",        "GNU debugger with PEDA/pwndbg/gef",
              "RE", TargetType::File,                 &["{target}"], false),
        tool!("objdump",    "objdump",    "Binary disassembler",
              "RE", TargetType::File,                 &["-d", "-M", "intel", "{target}"], false),
        tool!("strace",     "strace",     "System call tracer",
              "RE", TargetType::File,                 &["-f", "-e", "trace=network,file", "{target}"], false),
        tool!("ltrace",     "ltrace",     "Library call tracer",
              "RE", TargetType::File,                 &["{target}"], false),
        tool!("file-analyze","file",      "File type identification",
              "RE", TargetType::File,                 &["{target}"], false),
        tool!("ldd",        "ldd",        "Shared library dependencies",
              "RE", TargetType::File,                 &["{target}"], false),
        tool!("checksec",   "checksec",   "Binary security mitigations check",
              "RE", TargetType::File,                 &["--file={target}"], false),
        tool!("pwntools",   "python3",    "CTF exploit development framework",
              "RE", TargetType::File,                 &["-c", "from pwn import *; context.log_level='debug'"], false),
    ]
}
