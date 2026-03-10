# Four-Hub

> **The ultimate penetration-testing unified command centre** — a production-ready,
> mouse-navigable TUI built in Rust, wrapping 20+ Kali Linux tools with an
> AES-256-GCM encrypted database, real-time finding extraction, stealth primitives,
> and a Python plugin API.

---

## Feature Highlights

| Category | Detail |
|---|---|
| **TUI** | ratatui 0.26 + crossterm 0.27; neon-cyberpunk theme; full mouse support; 5 views |
| **Crypto** | AES-256-GCM + Argon2id KDF; all DB columns encrypted at rest |
| **Database** | Encrypted SQLite (rusqlite bundled); hosts, ports, findings, jobs, notes |
| **Tools** | 20+ built-in wrappers: nmap, masscan, nikto, gobuster, ffuf, hydra, sqlmap, crackmapexec, enum4linux, metasploit, msfvenom, hydra, aircrack-ng, wifite, john, hashcat, nuclei, wpscan, dnsenum, eyewitness, theharvester |
| **Stealth** | `prctl(PR_SET_NAME)` process spoofing; mlock secret memory; anti-forensics wipe on exit; MAC randomisation |
| **Plugins** | Python plugin API via PyO3; drop `.py` files into plugins dir; `on_new_finding` / `on_tool_finished` hooks |
| **Packet capture** | C extension wrapping libpcap; safe Rust FFI via `CaptureSession` |
| **REST API** | Optional axum-based JSON API on `127.0.0.1:7878` for scripted access |
| **Reporting** | Self-contained HTML + JSON reports; severity-coloured; per-engagement |
| **Workflows** | Pre-defined multi-tool chains (Full Recon, Web Audit, Network Spray, Credential Hunt) |

---

## Prerequisites

```
rustup update stable          # Rust ≥ 1.77
sudo apt install libpcap-dev  # for C packet-capture extension
sudo apt install python3-dev  # for PyO3
```

The following Kali tools need to be installed and on `$PATH` for their wrappers
to activate. Four-Hub runs with whatever subset is present — missing tools are
marked unavailable in the launcher rather than causing any crash.

```
nmap masscan nikto gobuster ffuf sqlmap hydra crackmapexec enum4linux
metasploit-framework aircrack-ng wifite john hashcat nuclei wpscan
dnsenum theharvester eyewitness dirb smbclient
```

---

## Build

```bash
git clone https://github.com/your-org/four-hub
cd four-hub

# Debug build (fast compile, extra logging)
cargo build

# Release build — LTO, strip symbols, panic=abort
cargo build --release

# Run tests
cargo test

# Launch (debug)
cargo run
```

The compiled binary is at `target/release/four-hub`.

---

## First Run

```
four-hub
```

1. You are prompted for a **vault passphrase**. Choose a strong one — it
   protects all stored data with AES-256-GCM.
2. The database is created at `~/.local/share/four-hub/four-hub.db`.
3. The TUI opens in full-screen mode.

To avoid the passphrase prompt in automated pipelines:

```bash
export FH_PASS="my-strong-passphrase"
four-hub --passphrase-env FH_PASS
```

---

## Configuration

Copy `config.toml` (project root) to `~/.config/four-hub/config.toml` and
edit as needed. All settings are commented inline.

```bash
mkdir -p ~/.config/four-hub
cp config.toml ~/.config/four-hub/
```

To add custom tools, drop entries into `tools.toml` (see the bundled example).

---

## TUI Key Map

| Key | Action |
|---|---|
| `1`–`5` | Switch views (Dashboard / Launcher / Workspace / Inspector / Terminal) |
| `Tab` / `Shift-Tab` | Cycle views |
| `↑` / `↓` | Navigate lists |
| `Enter` | Launch tool / inspect finding |
| `q` / `Ctrl-C` | Quit (anti-forensics wipe runs) |
| `Esc` | Close popup |
| `/` (Launcher) | Search tools |
| `e` (Inspector) | Export finding to report |

---

## Plugin API

```python
# ~/.local/share/four-hub/plugins/my_plugin.py

def on_new_finding(finding: dict) -> None:
    if finding["severity"] == "critical":
        # send a Slack alert, write to external DB, fire a webhook…
        pass

def on_tool_finished(job_id: str, exit_code: int) -> None:
    pass
```

See `python/plugins/example_plugin.py` for a fully-annotated template.

---

## Reporting

Reports are written to `~/four-hub-reports/` by default.

- `<project>_<timestamp>.html` — self-contained single-file HTML with embedded CSS
- `<project>_<timestamp>.json` — structured JSON with metadata

Press `e` on any selected finding in the Inspector view to generate a report for
the current workspace.

---

## Architecture

```
src/
  main.rs            CLI args · logging · vault init · TUI launch
  app.rs             Application struct · async event loop
  config.rs          TOML config structs
  crypto/
    vault.rs         VaultKey (Argon2id KDF + AES-256-GCM)
  db/
    schema.rs        SQLite DDL
    mod.rs           Database · Host · Port · Finding · ScanJob
  tui/
    app_state.rs     Central UI state
    renderer.rs      Terminal init + per-frame render orchestration
    theme.rs         Neon-cyberpunk colour palette
    layout.rs        Responsive layout computation
    events.rs        AppEvent enum + crossterm EventStream bridge
    widgets/         dashboard · launcher · workspace · inspector · terminal
  tools/
    spec.rs          ToolSpec (TOML-deserializable tool descriptor)
    registry.rs      20+ built-in tools + custom loader
    executor.rs      Async process spawner + stdout/stderr streaming
    parser.rs        Real-time regex parsers (nmap, nikto, hydra, …)
    workflow.rs      Multi-tool workflow chains
  stealth/
    identity.rs      Process-name spoofing via prctl
    anti_forensics.rs History & artefact wipe
    memory.rs        mlock / munlock wrappers
    network.rs       MAC randomisation
  plugins/
    runtime.rs       PyO3 plugin host
  reporting/
    html.rs          Self-contained HTML report
    json.rs          JSON report
  pcap_ffi.rs        Safe Rust wrapper for C libpcap extension
c/
  packet_capture.{h,c}  libpcap C extension with mlock
python/
  plugin_api.py      ToolWrapper ABC + Finding dataclass
  wrappers/          20 Python tool wrappers (nmap, nikto, …)
  plugins/           Drop-in .py plugin directory
tests/
  test_crypto.rs     Vault encrypt/decrypt integration tests
  test_db.rs         Database layer integration tests
  test_tools.rs      Registry, spec, parser integration tests
```

---

## Security Notes

- The vault passphrase is read via `rpassword` and never stored. It is dropped
  from memory immediately after the VaultKey is derived.
- All `Finding.description`, `Finding.evidence`, `Host.notes`, `Port.banner`
  values are AES-256-GCM encrypted before being written to SQLite.
- Sensitive heap regions (VaultKey internal bytes) are `mlock`ed on Linux to
  prevent them from being swapped to disk.
- On clean exit, `stealth::anti_forensics::wipe_on_exit()` overwrites and
  removes bash/zsh history and any `/tmp/fh_*` artefacts.

---

## License

MIT — see [LICENSE](LICENSE).
