# Four-Hub: Offensive Command Center

Four-Hub is a high-performance terminal orchestration platform designed for professional penetration testing. It integrates industry-standard tools with a proprietary suite of Rust-native reconnaissance and exploitation modules, optimized for operational security and high-speed execution.

---

## Technical Specifications

### Strategic Intelligence
*   **Infrastructure Mapping**: Real-time correlation of network assets and discovered infrastructure.
*   **Vulnerability Correlation**: Automated matching of service banners to CVE databases and recommended exploit vectors.
*   **Cryptographic Security**: Session data and findings are encrypted at rest using AES-256-GCM with Argon2id key derivation.

### Multi-Layer Stealth Engine
The Stealth Mode (accessible via the `S` menu) implements comprehensive operational security layers:
1.  **Memory Protection**: Utilizes `mlockall` to prevent sensitive tactical data from being written to swap space.
2.  **Process Masking**: Polymorphic process renaming to mimic standard system kernels.
3.  **Environment Sanitization**: Automated removal of trace variables and execution history.
4.  **Network Identity Shuffling**: NIC hardware identifier randomization for every active operation.
5.  **Encrypted DNS Resolution**: Forced DNS-over-HTTPS (DoH) utilizing secure providers.
6.  **Traffic Jitter**: Randomized micro-delays between operations to defeat automated traffic analysis systems.
7.  **Resource Hardening**: Prevention of core dumps and masking of process communications.
8.  **Anti-Debugging Mechanisms**: Internal monitoring for PTRACE and sandbox detection.

---

## Integrated Null-Suite Modules
The Null-Suite provides high-concurrency alternatives to traditional tools, re-engineered for precise control:
*   **4nmap**: High-speed SYN scanning with OS fingerprinting and automated CVE lookup.
*   **4gobuster**: Recursive HTTP fuzzing with support for HTTP/2 and intelligent wildcard detection.
*   **4subfinder**: Hybrid passive OSINT scraping and active DNS resolution.
*   **4hydra**: Multi-threaded credential auditing for SSH and HTTP-Basic services.
*   **4nikto**: Targeted vulnerability assessment for configuration leaks and sensitive file exposure.

---

## Deployment and Installation

### Prerequisites
*   OS: Kali Linux or a Debian-based distribution.
*   Dependencies: `libssh2-1-dev`, `libpcap-dev`, `libsqlite3-dev`, `build-essential`.

### Automated Installation
```bash
git clone https://github.com/4fqr/four-hub.git
cd four-hub
chmod +x hubinstall.sh
sudo ./hubinstall.sh
```

### Manual Compilation
```bash
cargo build --release
sudo ./target/release/four-hub
```

---

## Directory Architecture
```
src/
├── app.rs           - Main event loop and application state orchestration.
├── crypto/          - Vault security and cryptographic primitives.
├── db/              - Encrypted persistence layer.
├── stealth/         - Multi-layer operational security engine.
├── tools/
│   ├── null/        - Proprietary high-performance offensive modules.
│   ├── workflow.rs  - Multi-stage automation and pipeline engine.
│   └── executor.rs  - Asynchronous process management and IO multiplexing.
└── tui/             - Terminal User Interface implementation.
```

---

## Legal and Ethical Use
Four-Hub is released under the **MIT License**. This software is intended for use by authorized security professionals only. Unauthorized access to computer systems is prohibited by law. The developers assume no liability for misuse of this tool.

---

NullSector Security Frameworks
