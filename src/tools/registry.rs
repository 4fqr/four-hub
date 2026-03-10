// ─── Four-Hub · tools/registry.rs ───────────────────────────────────────────
//! Discovers and loads all `ToolSpec` entries from TOML manifests.
//! Falls back to a comprehensive built-in set if no external directory exists.

use crate::{config::AppConfig, tools::spec::ToolSpec};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, warn};
use which::which;

pub struct ToolRegistry {
    /// Map from category name → list of tools in that category.
    categories: HashMap<String, Vec<ToolSpec>>,
}

impl ToolRegistry {
    pub async fn load(cfg: &AppConfig) -> Result<Self> {
        let mut categories: HashMap<String, Vec<ToolSpec>> = HashMap::new();

        // ── Load built-in manifest ────────────────────────────────────────────
        let builtin: Vec<ToolSpec> = builtin_tools();
        for spec in builtin {
            categories
                .entry(spec.category.clone())
                .or_default()
                .push(spec);
        }

        // ── Load from tools directory ─────────────────────────────────────────
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
                                    info!(tool = %spec.name, "loaded tool from {}", path.display());
                                    categories
                                        .entry(spec.category.clone())
                                        .or_default()
                                        .push(spec);
                                }
                            }
                            Err(e) => warn!(path = %path.display(), err = %e, "failed to parse tool manifest"),
                        },
                        Err(e) => warn!(path = %path.display(), err = %e, "failed to read tool manifest"),
                    }
                }
            }
        }

        // Sort by name within each category.
        for tools in categories.values_mut() {
            tools.sort_by(|a, b| a.name.cmp(&b.name));
        }

        info!(categories = categories.len(), "tool registry loaded");
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
        self.categories
            .values()
            .flat_map(|v| v.iter())
            .find(|t| t.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Check which tools are actually installed on this system.
    pub fn availability_check(&self) -> HashMap<String, bool> {
        self.categories
            .values()
            .flat_map(|v| v.iter())
            .map(|t| (t.name.clone(), which(&t.binary).is_ok()))
            .collect()
    }

    /// Return a clone of the entire category → tools map.
    /// Used to populate `AppState` before the registry is moved into the executor.
    pub fn export_all(&self) -> HashMap<String, Vec<ToolSpec>> {
        self.categories.clone()
    }

    /// Return a flat list of every registered tool across all categories.
    pub fn all_tools(&self) -> Vec<ToolSpec> {
        self.categories
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }
}

// ── Built-in tool definitions ─────────────────────────────────────────────────

fn builtin_tools() -> Vec<ToolSpec> {
    vec![
        // ── RECON ─────────────────────────────────────────────────────────────
        ToolSpec {
            name:        "nmap".into(),
            binary:      "nmap".into(),
            description: "Network mapper – port scanning & service detection".into(),
            category:    "Recon".into(),
            default_args: vec!["-sV".into(), "-sC".into(), "-oX".into(), "/tmp/fh_nmap_{target}.xml".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/nmap_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["scan".into(), "ports".into()],
        },
        ToolSpec {
            name:        "masscan".into(),
            binary:      "masscan".into(),
            description: "High-speed TCP port scanner".into(),
            category:    "Recon".into(),
            default_args: vec!["--rate=1000".into(), "-p1-65535".into(), "{target}".into()],
            wrapper:     None,
            needs_root:  true,
            proxychains: false,
            interactive: false,
            tags:        vec!["scan".into(), "fast".into()],
        },
        ToolSpec {
            name:        "theharvester".into(),
            binary:      "theHarvester".into(),
            description: "OSINT email/domain/IP harvesting".into(),
            category:    "Recon".into(),
            default_args: vec!["-d".into(), "{target}".into(), "-b".into(), "all".into()],
            wrapper:     Some("python/wrappers/theharvester_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["osint".into(), "email".into()],
        },
        ToolSpec {
            name:        "dnsenum".into(),
            binary:      "dnsenum".into(),
            description: "DNS enumeration – zone transfers, brute-force subdomains".into(),
            category:    "Recon".into(),
            default_args: vec!["--noreverse".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/dnsenum_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["dns".into(), "enum".into()],
        },
        ToolSpec {
            name:        "eyewitness".into(),
            binary:      "eyewitness".into(),
            description: "Web-app screenshot and header fingerprinting".into(),
            category:    "Recon".into(),
            default_args: vec!["--single".into(), "{target}".into(), "--no-prompt".into()],
            wrapper:     Some("python/wrappers/eyewitness_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["web".into(), "screenshot".into()],
        },
        // ── WEB ───────────────────────────────────────────────────────────────
        ToolSpec {
            name:        "nikto".into(),
            binary:      "nikto".into(),
            description: "Web server vulnerability scanner".into(),
            category:    "Web".into(),
            default_args: vec!["-h".into(), "{target}".into(), "-Format".into(), "json".into(), "-output".into(), "/tmp/fh_nikto_{target}.json".into()],
            wrapper:     Some("python/wrappers/nikto_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["web".into(), "vuln".into()],
        },
        ToolSpec {
            name:        "gobuster".into(),
            binary:      "gobuster".into(),
            description: "Directory / DNS / vhost brute-forcer".into(),
            category:    "Web".into(),
            default_args: vec!["dir".into(), "-u".into(), "{target}".into(), "-w".into(), "/usr/share/wordlists/dirb/common.txt".into(), "-o".into(), "/tmp/fh_gobuster_{target}.txt".into()],
            wrapper:     Some("python/wrappers/gobuster_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["web".into(), "fuzz".into()],
        },
        ToolSpec {
            name:        "ffuf".into(),
            binary:      "ffuf".into(),
            description: "Fast web fuzzer (dir, param, header, vhost)".into(),
            category:    "Web".into(),
            default_args: vec!["-u".into(), "{target}/FUZZ".into(), "-w".into(), "/usr/share/seclists/Discovery/Web-Content/common.txt".into(), "-json".into(), "-o".into(), "/tmp/fh_ffuf_{target}.json".into()],
            wrapper:     Some("python/wrappers/ffuf_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["web".into(), "fuzz".into()],
        },
        ToolSpec {
            name:        "sqlmap".into(),
            binary:      "sqlmap".into(),
            description: "Automatic SQL injection detection and exploitation".into(),
            category:    "Web".into(),
            default_args: vec!["-u".into(), "{target}".into(), "--batch".into(), "--json-errors".into(), "--output-dir".into(), "/tmp/fh_sqlmap/".into()],
            wrapper:     Some("python/wrappers/sqlmap_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["sqli".into(), "web".into()],
        },
        ToolSpec {
            name:        "wpscan".into(),
            binary:      "wpscan".into(),
            description: "WordPress vulnerability scanner".into(),
            category:    "Web".into(),
            default_args: vec!["--url".into(), "{target}".into(), "--format".into(), "json".into(), "--output".into(), "/tmp/fh_wpscan_{target}.json".into()],
            wrapper:     Some("python/wrappers/wpscan_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["wordpress".into(), "web".into()],
        },
        ToolSpec {
            name:        "nuclei".into(),
            binary:      "nuclei".into(),
            description: "Fast vulnerability scanner using community templates".into(),
            category:    "Web".into(),
            default_args: vec!["-u".into(), "{target}".into(), "-json".into(), "-o".into(), "/tmp/fh_nuclei_{target}.json".into()],
            wrapper:     Some("python/wrappers/nuclei_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["vuln".into(), "templates".into()],
        },
        // ── EXPLOITATION ──────────────────────────────────────────────────────
        ToolSpec {
            name:        "metasploit".into(),
            binary:      "msfconsole".into(),
            description: "Metasploit Framework interactive console".into(),
            category:    "Exploitation".into(),
            default_args: vec!["-q".into()],
            wrapper:     Some("python/wrappers/metasploit_wrapper.py".into()),
            needs_root:  false,
            proxychains: false,
            interactive: true,
            tags:        vec!["exploit".into(), "post".into()],
        },
        ToolSpec {
            name:        "msfvenom".into(),
            binary:      "msfvenom".into(),
            description: "Payload generator for Metasploit".into(),
            category:    "Exploitation".into(),
            default_args: vec!["-p".into(), "linux/x64/shell_reverse_tcp".into(), "LHOST={target}".into(), "LPORT=4444".into(), "-f".into(), "elf".into()],
            wrapper:     None,
            needs_root:  false,
            proxychains: false,
            interactive: false,
            tags:        vec!["payload".into(), "shellcode".into()],
        },
        // ── NETWORK ───────────────────────────────────────────────────────────
        ToolSpec {
            name:        "hydra".into(),
            binary:      "hydra".into(),
            description: "Online password / login brute-forcer".into(),
            category:    "Network".into(),
            default_args: vec!["-L".into(), "/usr/share/wordlists/metasploit/unix_users.txt".into(), "-P".into(), "/usr/share/wordlists/rockyou.txt".into(), "{target}".into(), "ssh".into()],
            wrapper:     Some("python/wrappers/hydra_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["brute".into(), "login".into()],
        },
        ToolSpec {
            name:        "crackmapexec".into(),
            binary:      "crackmapexec".into(),
            description: "SMB / WinRM / LDAP credential validation & lateral movement".into(),
            category:    "Network".into(),
            default_args: vec!["smb".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/crackmapexec_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["smb".into(), "ad".into()],
        },
        ToolSpec {
            name:        "enum4linux".into(),
            binary:      "enum4linux".into(),
            description: "SMB/CIFS enumeration for Windows & Samba targets".into(),
            category:    "Network".into(),
            default_args: vec!["-a".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/enum4linux_wrapper.py".into()),
            needs_root:  false,
            proxychains: true,
            interactive: false,
            tags:        vec!["smb".into(), "enum".into()],
        },
        // ── PASSWORD ──────────────────────────────────────────────────────────
        ToolSpec {
            name:        "john".into(),
            binary:      "john".into(),
            description: "John the Ripper – offline password cracking".into(),
            category:    "Password".into(),
            default_args: vec!["--wordlist=/usr/share/wordlists/rockyou.txt".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/john_wrapper.py".into()),
            needs_root:  false,
            proxychains: false,
            interactive: false,
            tags:        vec!["crack".into(), "hash".into()],
        },
        ToolSpec {
            name:        "hashcat".into(),
            binary:      "hashcat".into(),
            description: "GPU-accelerated hash cracker".into(),
            category:    "Password".into(),
            default_args: vec!["-m".into(), "0".into(), "-a".into(), "0".into(), "{target}".into(), "/usr/share/wordlists/rockyou.txt".into()],
            wrapper:     Some("python/wrappers/hashcat_wrapper.py".into()),
            needs_root:  false,
            proxychains: false,
            interactive: false,
            tags:        vec!["crack".into(), "gpu".into()],
        },
        // ── WIRELESS ──────────────────────────────────────────────────────────
        ToolSpec {
            name:        "aircrack-ng".into(),
            binary:      "aircrack-ng".into(),
            description: "WPA/WEP wireless network cracker".into(),
            category:    "Wireless".into(),
            default_args: vec!["-w".into(), "/usr/share/wordlists/rockyou.txt".into(), "{target}".into()],
            wrapper:     Some("python/wrappers/aircrack_wrapper.py".into()),
            needs_root:  true,
            proxychains: false,
            interactive: false,
            tags:        vec!["wifi".into(), "wpa".into()],
        },
        ToolSpec {
            name:        "wifite".into(),
            binary:      "wifite".into(),
            description: "Automated wireless network auditor".into(),
            category:    "Wireless".into(),
            default_args: vec!["--kill".into(), "--dict".into(), "/usr/share/wordlists/rockyou.txt".into()],
            wrapper:     Some("python/wrappers/wifite_wrapper.py".into()),
            needs_root:  true,
            proxychains: false,
            interactive: true,
            tags:        vec!["wifi".into(), "auto".into()],
        },
        // ── FORENSICS / NETWORK ANALYSIS ──────────────────────────────────────
        ToolSpec {
            name:        "packet-capture".into(),
            binary:      "four-hub-pcap".into(),
            description: "Built-in raw packet capture (C extension)".into(),
            category:    "Network".into(),
            default_args: vec!["-i".into(), "{target}".into(), "-c".into(), "1000".into()],
            wrapper:     None,
            needs_root:  true,
            proxychains: false,
            interactive: false,
            tags:        vec!["pcap".into(), "raw".into()],
        },

        // ── RECON (extended) ─────────────────────────────────────────────────
        ToolSpec {
            name: "amass".into(), binary: "amass".into(),
            description: "In-depth attack surface mapping and subdomain enumeration".into(),
            category: "Recon".into(),
            default_args: vec!["enum".into(), "-d".into(), "{target}".into(), "-o".into(), "/tmp/fh_amass_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["subdomain".into(), "osint".into()],
        },
        ToolSpec {
            name: "subfinder".into(), binary: "subfinder".into(),
            description: "Fast passive subdomain discovery".into(),
            category: "Recon".into(),
            default_args: vec!["-d".into(), "{target}".into(), "-o".into(), "/tmp/fh_subfinder_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["subdomain".into()],
        },
        ToolSpec {
            name: "sublist3r".into(), binary: "sublist3r".into(),
            description: "Enumerate subdomains using multiple search engines".into(),
            category: "Recon".into(),
            default_args: vec!["-d".into(), "{target}".into(), "-o".into(), "/tmp/fh_sublist3r_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["subdomain".into()],
        },
        ToolSpec {
            name: "dnsrecon".into(), binary: "dnsrecon".into(),
            description: "DNS enumeration and zone transfer detection".into(),
            category: "Recon".into(),
            default_args: vec!["-d".into(), "{target}".into(), "-j".into(), "/tmp/fh_dnsrecon_{target}.json".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["dns".into(), "recon".into()],
        },
        ToolSpec {
            name: "fierce".into(), binary: "fierce".into(),
            description: "DNS reconnaissance tool".into(),
            category: "Recon".into(),
            default_args: vec!["--domain".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["dns".into()],
        },
        ToolSpec {
            name: "whatweb".into(), binary: "whatweb".into(),
            description: "Web technology fingerprinting".into(),
            category: "Recon".into(),
            default_args: vec!["--color=never".into(), "-a".into(), "3".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["fingerprint".into(), "web".into()],
        },
        ToolSpec {
            name: "wafw00f".into(), binary: "wafw00f".into(),
            description: "Detect and fingerprint WAF".into(),
            category: "Recon".into(),
            default_args: vec!["-a".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["waf".into(), "web".into()],
        },
        ToolSpec {
            name: "assetfinder".into(), binary: "assetfinder".into(),
            description: "Find domains and subdomains from internet datasets".into(),
            category: "Recon".into(),
            default_args: vec!["--subs-only".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["subdomain".into(), "osint".into()],
        },
        ToolSpec {
            name: "netdiscover".into(), binary: "netdiscover".into(),
            description: "Active/passive ARP host discovery".into(),
            category: "Recon".into(),
            default_args: vec!["-r".into(), "{target}".into(), "-P".into()],
            wrapper: None, needs_root: true, proxychains: false, interactive: false,
            tags: vec!["arp".into(), "lan".into()],
        },

        // ── WEB (extended) ───────────────────────────────────────────────────
        ToolSpec {
            name: "dirsearch".into(), binary: "dirsearch".into(),
            description: "Web path scanner with multiple wordlists".into(),
            category: "Web".into(),
            default_args: vec!["-u".into(), "{target}".into(), "--format=plain".into(), "-o".into(), "/tmp/fh_dirsearch_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["fuzz".into(), "web".into()],
        },
        ToolSpec {
            name: "feroxbuster".into(), binary: "feroxbuster".into(),
            description: "Fast, recursive content discovery".into(),
            category: "Web".into(),
            default_args: vec!["-u".into(), "{target}".into(), "--no-recursion".into(), "-q".into(), "-o".into(), "/tmp/fh_feroxbuster_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["fuzz".into(), "web".into()],
        },
        ToolSpec {
            name: "dirb".into(), binary: "dirb".into(),
            description: "Web content scanner using wordlist".into(),
            category: "Web".into(),
            default_args: vec!["{target}".into(), "/usr/share/wordlists/dirb/common.txt".into(), "-o".into(), "/tmp/fh_dirb_{target}.txt".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["fuzz".into(), "web".into()],
        },
        ToolSpec {
            name: "arjun".into(), binary: "arjun".into(),
            description: "HTTP parameter discovery".into(),
            category: "Web".into(),
            default_args: vec!["-u".into(), "{target}".into(), "--stable".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["param".into(), "web".into()],
        },
        ToolSpec {
            name: "dalfox".into(), binary: "dalfox".into(),
            description: "XSS parameter analysis and exploitation tool".into(),
            category: "Web".into(),
            default_args: vec!["url".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["xss".into(), "web".into()],
        },
        ToolSpec {
            name: "commix".into(), binary: "commix".into(),
            description: "Command injection exploiter".into(),
            category: "Web".into(),
            default_args: vec!["--url".into(), "{target}".into(), "--batch".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["rce".into(), "web".into()],
        },

        // ── EXPLOITATION (extended) ──────────────────────────────────────────
        ToolSpec {
            name: "searchsploit".into(), binary: "searchsploit".into(),
            description: "Exploit-DB local search".into(),
            category: "Exploitation".into(),
            default_args: vec!["--colour".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["exploit".into(), "exploitdb".into()],
        },
        ToolSpec {
            name: "evil-winrm".into(), binary: "evil-winrm".into(),
            description: "WinRM shell for pentesting".into(),
            category: "Exploitation".into(),
            default_args: vec!["-i".into(), "{target}".into(), "-u".into(), "Administrator".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: true,
            tags: vec!["winrm".into(), "windows".into()],
        },
        ToolSpec {
            name: "impacket-psexec".into(), binary: "impacket-psexec".into(),
            description: "Impacket PsExec – Windows lateral movement".into(),
            category: "Exploitation".into(),
            default_args: vec!["Administrator@{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: true,
            tags: vec!["lateral".into(), "windows".into()],
        },
        ToolSpec {
            name: "impacket-secretsdump".into(), binary: "impacket-secretsdump".into(),
            description: "Dump SAM / LSA / NTDS hashes remotely".into(),
            category: "Exploitation".into(),
            default_args: vec!["Administrator@{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["hashes".into(), "windows".into()],
        },
        ToolSpec {
            name: "impacket-getuserspns".into(), binary: "impacket-GetUserSPNs".into(),
            description: "Kerberoasting – list/request service tickets".into(),
            category: "Exploitation".into(),
            default_args: vec!["{target}/".into(), "-request".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["kerberos".into(), "ad".into()],
        },
        ToolSpec {
            name: "responder".into(), binary: "responder".into(),
            description: "LLMNR/NBT-NS/MDNS poisoner – hash capture".into(),
            category: "Exploitation".into(),
            default_args: vec!["-I".into(), "{target}".into(), "-rdwv".into()],
            wrapper: None, needs_root: true, proxychains: false, interactive: false,
            tags: vec!["mitm".into(), "hash".into()],
        },
        ToolSpec {
            name: "bettercap".into(), binary: "bettercap".into(),
            description: "Swiss army knife for network attacks and monitoring".into(),
            category: "Exploitation".into(),
            default_args: vec!["-iface".into(), "{target}".into()],
            wrapper: None, needs_root: true, proxychains: false, interactive: true,
            tags: vec!["mitm".into(), "arp".into()],
        },
        ToolSpec {
            name: "beef-xss".into(), binary: "beef-xss".into(),
            description: "Browser Exploitation Framework".into(),
            category: "Exploitation".into(),
            default_args: vec![],
            wrapper: None, needs_root: false, proxychains: false, interactive: true,
            tags: vec!["xss".into(), "browser".into()],
        },

        // ── NETWORK (extended) ───────────────────────────────────────────────
        ToolSpec {
            name: "ncrack".into(), binary: "ncrack".into(),
            description: "High-speed network authentication cracker".into(),
            category: "Network".into(),
            default_args: vec!["-U".into(), "/usr/share/wordlists/metasploit/unix_users.txt".into(), "-P".into(), "/usr/share/wordlists/rockyou.txt".into(), "ssh://{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["brute".into(), "login".into()],
        },
        ToolSpec {
            name: "netexec".into(), binary: "netexec".into(),
            description: "Network execution tool (successor to CrackMapExec)".into(),
            category: "Network".into(),
            default_args: vec!["smb".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["smb".into(), "ad".into()],
        },
        ToolSpec {
            name: "smbclient".into(), binary: "smbclient".into(),
            description: "SMB shares enumeration and file access".into(),
            category: "Network".into(),
            default_args: vec!["-L".into(), "\\\\{target}".into(), "-N".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["smb".into(), "enum".into()],
        },
        ToolSpec {
            name: "rpcclient".into(), binary: "rpcclient".into(),
            description: "MS-RPC client for domain enumeration".into(),
            category: "Network".into(),
            default_args: vec!["-U".into(), "\"\"".into(), "-N".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: true,
            tags: vec!["rpc".into(), "ad".into()],
        },
        ToolSpec {
            name: "ldapsearch".into(), binary: "ldapsearch".into(),
            description: "LDAP enumeration – users, groups, policies".into(),
            category: "Network".into(),
            default_args: vec!["-x".into(), "-H".into(), "ldap://{target}".into(), "-b".into(), "DC=domain,DC=local".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["ldap".into(), "ad".into()],
        },
        ToolSpec {
            name: "snmpwalk".into(), binary: "snmpwalk".into(),
            description: "SNMP enumeration".into(),
            category: "Network".into(),
            default_args: vec!["-c".into(), "public".into(), "-v2c".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["snmp".into()],
        },
        ToolSpec {
            name: "onesixtyone".into(), binary: "onesixtyone".into(),
            description: "Fast SNMP community string brute-forcer".into(),
            category: "Network".into(),
            default_args: vec!["-c".into(), "/usr/share/seclists/Discovery/SNMP/snmp.txt".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["snmp".into()],
        },
        ToolSpec {
            name: "enum4linux-ng".into(), binary: "enum4linux-ng".into(),
            description: "Next-gen SMB enumeration (Python rewrite)".into(),
            category: "Network".into(),
            default_args: vec!["-A".into(), "-C".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["smb".into(), "enum".into()],
        },
        ToolSpec {
            name: "socat".into(), binary: "socat".into(),
            description: "Multipurpose relay — tunnels and reverse shells".into(),
            category: "Network".into(),
            default_args: vec!["TCP-LISTEN:4444,reuseaddr,fork".into(), "EXEC:/bin/bash,pty,stderr,setsid,sigint,sane".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["tunnel".into(), "shell".into()],
        },
        ToolSpec {
            name: "chisel".into(), binary: "chisel".into(),
            description: "Fast TCP/UDP tunnelling over HTTP".into(),
            category: "Network".into(),
            default_args: vec!["server".into(), "-p".into(), "8080".into(), "--reverse".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["tunnel".into(), "pivot".into()],
        },

        // ── PASSWORD (extended) ──────────────────────────────────────────────
        ToolSpec {
            name: "keepass2john".into(), binary: "keepass2john".into(),
            description: "Extract hash from KeePass databases".into(),
            category: "Password".into(),
            default_args: vec!["{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["hash".into(), "keepass".into()],
        },
        ToolSpec {
            name: "zip2john".into(), binary: "zip2john".into(),
            description: "Extract hash from encrypted ZIP files".into(),
            category: "Password".into(),
            default_args: vec!["{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["hash".into(), "zip".into()],
        },
        ToolSpec {
            name: "pdf2john".into(), binary: "pdf2john".into(),
            description: "Extract hash from password-protected PDFs".into(),
            category: "Password".into(),
            default_args: vec!["{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["hash".into(), "pdf".into()],
        },
        ToolSpec {
            name: "office2john".into(), binary: "office2john".into(),
            description: "Extract hash from MS Office documents".into(),
            category: "Password".into(),
            default_args: vec!["{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["hash".into(), "office".into()],
        },
        ToolSpec {
            name: "fcrackzip".into(), binary: "fcrackzip".into(),
            description: "ZIP password cracker".into(),
            category: "Password".into(),
            default_args: vec!["-u".into(), "-D".into(), "-p".into(), "/usr/share/wordlists/rockyou.txt".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["crack".into(), "zip".into()],
        },
        ToolSpec {
            name: "cewl".into(), binary: "cewl".into(),
            description: "Custom wordlist generator from target website".into(),
            category: "Password".into(),
            default_args: vec!["-d".into(), "2".into(), "-m".into(), "5".into(), "-w".into(), "/tmp/fh_cewl_{target}.txt".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: true, interactive: false,
            tags: vec!["wordlist".into()],
        },
        ToolSpec {
            name: "crunch".into(), binary: "crunch".into(),
            description: "Wordlist generator with pattern-based rules".into(),
            category: "Password".into(),
            default_args: vec!["6".into(), "8".into(), "abcdefghijklmnopqrstuvwxyz0123456789".into(), "-o".into(), "/tmp/fh_crunch.txt".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["wordlist".into()],
        },

        // ── FORENSICS ────────────────────────────────────────────────────────
        ToolSpec {
            name: "volatility3".into(), binary: "vol".into(),
            description: "Memory forensics framework".into(),
            category: "Forensics".into(),
            default_args: vec!["-f".into(), "{target}".into(), "windows.info".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["memory".into(), "forensics".into()],
        },
        ToolSpec {
            name: "binwalk".into(), binary: "binwalk".into(),
            description: "Firmware analysis and extraction".into(),
            category: "Forensics".into(),
            default_args: vec!["-e".into(), "--run-as=root".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["firmware".into(), "forensics".into()],
        },
        ToolSpec {
            name: "foremost".into(), binary: "foremost".into(),
            description: "File carving from raw images".into(),
            category: "Forensics".into(),
            default_args: vec!["-t".into(), "all".into(), "-i".into(), "{target}".into(), "-o".into(), "/tmp/fh_foremost/".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["carving".into(), "forensics".into()],
        },
        ToolSpec {
            name: "exiftool".into(), binary: "exiftool".into(),
            description: "Read/write metadata from files".into(),
            category: "Forensics".into(),
            default_args: vec!["-json".into(), "{target}".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["metadata".into(), "osint".into()],
        },
        ToolSpec {
            name: "steghide".into(), binary: "steghide".into(),
            description: "Steganography tool – hide/extract data from images".into(),
            category: "Forensics".into(),
            default_args: vec!["extract".into(), "-sf".into(), "{target}".into(), "-p".into(), "\"\"".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["steganography".into()],
        },
        ToolSpec {
            name: "stegseek".into(), binary: "stegseek".into(),
            description: "Ultra-fast steghide password cracker".into(),
            category: "Forensics".into(),
            default_args: vec!["{target}".into(), "/usr/share/wordlists/rockyou.txt".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["steganography".into(), "crack".into()],
        },

        // ── PRIVILEGE ESCALATION ─────────────────────────────────────────────
        ToolSpec {
            name: "linpeas".into(), binary: "linpeas.sh".into(),
            description: "Linux Privilege Escalation (PEASS-ng)".into(),
            category: "PrivEsc".into(),
            default_args: vec![],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["privesc".into(), "linux".into()],
        },
        ToolSpec {
            name: "winpeas".into(), binary: "winPEAS.exe".into(),
            description: "Windows Privilege Escalation (PEASS-ng)".into(),
            category: "PrivEsc".into(),
            default_args: vec![],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["privesc".into(), "windows".into()],
        },
        ToolSpec {
            name: "linux-exploit-suggester".into(), binary: "linux-exploit-suggester.sh".into(),
            description: "Suggest kernel exploits for Linux privesc".into(),
            category: "PrivEsc".into(),
            default_args: vec![],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["privesc".into(), "kernel".into()],
        },
        ToolSpec {
            name: "pspy".into(), binary: "pspy64".into(),
            description: "Unprivileged Linux process snooping".into(),
            category: "PrivEsc".into(),
            default_args: vec!["-pf".into(), "-i".into(), "1000".into()],
            wrapper: None, needs_root: false, proxychains: false, interactive: false,
            tags: vec!["privesc".into(), "cron".into()],
        },
    ]
}
