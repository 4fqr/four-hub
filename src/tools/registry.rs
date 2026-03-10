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
    ]
}
