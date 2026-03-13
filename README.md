
# 🪐 Four-Hub: The Architect's Offensive Command Centre

[![Rust](https://img.shields.io/badge/language-rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stealth](https://img.shields.io/badge/stealth-10--layer-green.svg)](#10-layer-stealth-engine)
[![Powerhouse](https://img.shields.io/badge/tools-160+-purple.svg)](#elite-pentesting-suite)

Four-Hub is a high-performance, terminal-based orchestration platform for elite penetration testing. Engineered for speed, opsec, and deep asset intelligence, it unifies the industrial-standard Kali suite with proprietary **Null-Suite** tools—optimized in Rust for maximum performance and stealth.

---

## 💎 Elite Features

### 🦾 Architect-Level Intelligence
*   **Live Tactical Map**: Real-time visualization of discovered infrastructure.
*   **Intelligence Correlation**: Automatically maps port banners to known CVEs and suggests the most effective pivot tools.
*   **Encrypted Storage**: Every session, finding, and packet log is encrypted at rest using **AES-256-GCM** with Argon2id key derivation.

### 🌑 10-Layer Stealth Engine
Shadow Mode (`S` menu) engages redundant layers of anti-forensics and network concealment:
1.  **Memory Lock**: `mlockall` prevents any sensitive data from ever touching the swap disk.
2.  **PID Spoofing**: Polymorphic process renaming (appears as `[kworker/0:2]`).
3.  **Environment Sanitization**: Strips traces of `LD_PRELOAD`, `PYTHONPATH`, and history files.
4.  **MAC Shuffling**: Automatic NIC identifier randomization for every operation.
5.  **DNS-over-HTTPS**: All reconnaissance occurs via encrypted Cloudflare/Google DNS.
6.  **Timing Jitter**: 50–450ms random delay between network operations to defeat traffic analysis.
7.  **Resource Masking**: Disables core dumps and wipes `/proc/self/comm`.
8.  **Anti-Debugging**: Internal checks for PTRACE and sandboxing.
9.  **Automated Forensics Wipe**: Securely overwrites temporary files on exit.
10. **Tor Routing Verification**: Optional SOCKS5 proxy enforcement via `proxychains`.

---

## ⚡ Proprietary Null-Suite
*   **`4nmap` (Elite)**: Parallel SYN scanning with OS fingerprinting and automated CVE lookup.
*   **`4gobuster` (Architect)**: HTTP/2 supported recursive fuzzing with smart wildcard detection.
*   **`4subfinder` (Passive)**: Blends high-speed DNS resolution with passive OSINT scraping.
*   **`4hydra` (Force)**: Multi-threaded brute-forcing for SSH and HTTP-Basic with credential intelligence.
*   **`4nikto` (Deep)**: Targeted vulnerability scanning for high-impact leaks (.env, .git, etc.).

---

## 🚀 Deployment

### Prerequisites
*   Kali Linux (Highly recommended)
*   `libssh2-1-dev`, `libpcap-dev`, `libsqlite3-dev`

### One-Click Installation
```bash
git clone https://github.com/foufqr/Four-Hub
cd Four-Hub
chmod +x hubinstall.sh
sudo ./hubinstall.sh
```

### Manual Build
```bash
cargo build --release
sudo ./target/release/four-hub
```

---

## 🛠️ Architecture Detail

```
src/
├── app.rs           — High-performance event loop & state management
├── crypto/          — AES-GCM vault & Argon2id implementation
├── db/              — Encrypted SQLite orchestration
├── stealth/         — The 10-Layer Stealth Engine
├── tools/
│   ├── null/        — Proprietary Rust-native elite tools
│   ├── workflow.rs  — Multi-stage automation engine
│   └── executor.rs  — Async process runner & IO multiplexer
└── tui/             — Custom Ratatui interface with Glassmorphism styles
```

---

## ⚖️ License & Ethical Use
Four-Hub is released under the **MIT License**. This tool is intended only for professional penetration testers and security researchers. **Unauthorized access to computer systems is illegal.** Use responsibly.

---

Created with ⚡ by **NullSector**
