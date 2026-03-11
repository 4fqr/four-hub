# Four-Hub

A terminal-based offensive security platform built in Rust.  
Full Kali Linux tool suite, encrypted session storage, 10-layer stealth engine, and a polished TUI.

---

## Features

### 10-Layer Stealth Engine
All layers activate automatically at startup via `StealthEngine::engage_all()`:

| Layer | Technique |
|-------|-----------|
| 1 | `mlockall(MCL_CURRENT \| MCL_FUTURE)` — entire process memory locked against swap |
| 2 | `prctl(PR_SET_NAME, "[kworker/0:2]")` — process name spoofed in `ps`/`top` |
| 3 | Strip `LD_PRELOAD`, `LD_AUDIT`, `PYTHONPATH`, `RUBYOPT`, `NODE_OPTIONS` env vars + set `HISTFILE=/dev/null` |
| 4 | `umask(0o077)` — no world-readable temp files created |
| 5 | Write `[kworker/0:2]` to `/proc/self/comm` |
| 6 | Random timing jitter 50–350 ms between sensitive operations |
| 7 | `setrlimit(RLIMIT_CORE, 0)` — disable core dumps |
| 8 | Tor routing verification via `https://check.torproject.org/api/ip` |
| 9 | DNS-over-HTTPS (Cloudflare) — no plaintext DNS leaks |
| 10 | `PR_SET_DUMPABLE=0` + `PR_SET_NO_NEW_PRIVS=1` |

Additional helpers:
- `StealthEngine::randomise_mac(iface)` — randomise NIC MAC address
- `StealthEngine::wipe_artefacts()` — overwrite /tmp leftovers
- `StealthEngine::lock_sensitive<T>(val)` — mlock a value's memory page
- `StealthEngine::spoof_dns_via_doh(domain)` — DoH DNS resolution
- `apply_timing_jitter()` — sleep random 50–350 ms

---

### Full Kali Suite (160+ tools, 11 categories)

| Category | Representative Tools |
|----------|----------------------|
| **Recon** | nmap (5 profiles), masscan, amass, subfinder, dnsrecon, fierce, dnsx, theHarvester, shodan-cli, whois, spiderfoot, sublist3r, dnsenum, recon-ng, maltego |
| **Web** | nikto, sqlmap (3 profiles), gobuster (dir+dns), ffuf, feroxbuster, dirb, dirsearch, wpscan, joomscan, nuclei (full+cves), wafw00f, whatweb, httpx, arjun, dalfox, commix, xsstrike |
| **Exploitation** | msfconsole, msfvenom, searchsploit, evil-winrm, impacket-psexec/wmiexec/smbexec/secretsdump, crackmapexec (smb+winrm), mimikatz, responder, beef-xss, SET |
| **Network** | wireshark, tcpdump, tshark, ettercap, bettercap, arpspoof, netcat, socat, chisel, proxychains, mitmproxy, sslscan, testssl, snmpwalk, onesixtyone, dnschef |
| **Password** | hydra (ssh+http), medusa, ncrack, john (crack+show), hashcat (md5+ntlm), crunch, cewl, cupp |
| **Wireless** | aircrack-ng, airodump-ng, aireplay-ng, airmon-ng, reaver, bully, wifite, kismet, fern-wifi, hcxdumptool, hcxtools |
| **Forensics** | volatility3 (win+mac), binwalk, foremost, scalpel, exiftool, steghide, stegseek, bulk-extractor, strings, pspy |
| **PrivEsc** | linpeas, winpeas, les, les2, wesng, sudo-killer, BeRoot, GTFOBins-check |
| **SMB/AD** | enum4linux, enum4linux-ng, smbclient, smbmap, rpcclient, ldapsearch, bloodhound-python, kerbrute, GetNPUsers, GetUserSPNs |
| **Database** | sqlmap-dump, mssqlclient, mysql/mongodb/redis enum |
| **RE** | ghidra, radare2, gdb, objdump, strace, ltrace, file, ldd, checksec, pwntools |

Every tool entry carries a `TargetType` enum (`IpOrCidr`, `Domain`, `Url`, `File`, `Interface`, `IpPort`, `Custom`, …) shown as a hint in the launcher detail panel and target-input popup.

---

### Encrypted Storage
- AES-256-GCM encrypted SQLite via `rusqlite` + `aes-gcm`
- Per-session vault key derived with Argon2id
- All scan results, findings, and notes stored encrypted at rest

---

### TUI Views (F1–F5)

| Key | View | Description |
|-----|------|-------------|
| F1 | Dashboard | Live job status, findings summary, recent activity |
| F2 | Launcher | Category tree → tool list → detail panel with target type hint |
| F3 | Workspace | Host map → port table → findings panel (Tab cycles focus) |
| F4 | Inspector | Scrollable raw output for selected job |
| F5 | Terminal | Interactive pseudo-terminal inside the TUI |

Global keys: `r` run, `t` set target, `x` kill job, `S` stealth menu, `w` workflow menu, `^e` export, `F1`–`F5` switch view, `q` quit.

---

## Build

```bash
git clone https://github.com/foufqr/Four-Hub
cd Four-Hub
cargo build --release
sudo ./target/release/four-hub
```

Install Kali tools:
```bash
chmod +x hubinstall.sh && sudo ./hubinstall.sh
```

---

## Architecture

```
src/
├── main.rs              — entry point, StealthEngine boot, runtime wiring
├── app.rs               — Application struct, event loop
├── config.rs            — TOML configuration
├── crypto/              — AES-GCM vault, key derivation
├── db/                  — encrypted SQLite session storage
├── tools/
│   ├── spec.rs          — ToolSpec + TargetType enum + effective_hint()
│   ├── registry.rs      — 160+ built-in tool definitions across 11 categories
│   ├── executor.rs      — async job runner, proxychains wrapping
│   └── parser.rs        — structured output parsers (nmap, nikto, hydra, sqlmap …)
├── stealth/
│   ├── ops.rs           — StealthEngine (10-layer)
│   ├── anti_forensics.rs
│   ├── identity.rs
│   ├── memory.rs
│   └── network.rs
├── tui/
│   ├── app_state.rs     — AppState, events, popup kinds
│   ├── renderer.rs      — Terminal setup, frame renderer
│   ├── theme.rs         — Color palette and styles
│   ├── layout.rs        — Responsive layout computation
│   └── widgets/         — dashboard, launcher, workspace, inspector, terminal
├── plugins/             — PyO3 Python plugin runtime
├── reporting/           — JSON / Markdown report exporter
└── pcap_ffi.rs          — libpcap bindings for live capture
```

---

## Configuration

`~/.config/four-hub/config.toml`:

```toml
[paths]
tools_dir = "~/.config/four-hub/tools"
db_path   = "~/.local/share/four-hub/sessions.db"

[crypto]
kdf        = "argon2id"
memory_kib = 65536
iterations = 3

[proxy]
socks5 = "127.0.0.1:9050"
```

---

## Custom Tools

Drop a TOML file into `~/.config/four-hub/tools/`:

```toml
[[tools]]
name         = "my-scanner"
binary       = "my-scanner"
description  = "Custom internal scanner"
category     = "Recon"
target_type  = "IpOrCidr"
default_args = ["--rate=500", "{target}"]
needs_root   = false
proxychains  = true
```

---

## License

MIT — use responsibly, on systems you own or have explicit written permission to test.
