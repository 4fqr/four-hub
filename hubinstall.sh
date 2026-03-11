#!/usr/bin/env bash
# four-hub · hubinstall.sh
# Full setup for Kali Linux.  Run once as root:  sudo bash hubinstall.sh
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash hubinstall.sh"

# ── 1. APT packages ──────────────────────────────────────────────────────────
ok "Updating apt…"
apt-get update -qq

ok "Installing apt packages…"
apt-get install -y \
    build-essential libpcap-dev libsqlite3-dev \
    python3 python3-pip python3-dev pkg-config \
    curl git tor proxychains4 \
    nmap masscan nikto hydra sqlmap \
    gobuster dirb feroxbuster ffuf wpscan \
    enum4linux crackmapexec netdiscover dnsrecon \
    fierce whatweb wafw00f \
    john hashcat wordlists smbclient \
    aircrack-ng reaver bully \
    metasploit-framework beef-xss \
    evil-winrm responder impacket-scripts \
    ncrack snmp onesixtyone \
    binwalk steghide foremost libimage-exiftool-perl \
    chisel socat netcat-traditional \
    macchanger arp-scan \
    2>/dev/null || warn "Some apt packages failed — continuing"

# ── 2. amass / subfinder / nuclei — from Go or package ───────────────────────
ok "Installing Go-based tools (amass, subfinder, nuclei)…"
if command -v go &>/dev/null; then
    go install github.com/owasp-amass/amass/v4/...@latest      2>/dev/null || true
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       2>/dev/null || true
else
    apt-get install -y amass             2>/dev/null || warn "amass not available via apt — install manually"
    pip3 install --break-system-packages nuclei 2>/dev/null || true
fi

# ── 3. volatility3 — pip install, not apt ────────────────────────────────────
ok "Installing volatility3 via pip…"
pip3 install --break-system-packages volatility3 2>/dev/null \
    || pip3 install volatility3 2>/dev/null \
    || warn "volatility3 install failed — try: pip3 install volatility3"

# ── 4. linpeas — direct download ─────────────────────────────────────────────
ok "Downloading linpeas…"
mkdir -p /opt/privesc
curl -fsSL \
    https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
    -o /opt/privesc/linpeas.sh \
    && chmod +x /opt/privesc/linpeas.sh \
    && ln -sf /opt/privesc/linpeas.sh /usr/local/bin/linpeas \
    && ok "linpeas → /usr/local/bin/linpeas" \
    || warn "linpeas download failed — check internet access"

# ── 5. pspy — download static binary ─────────────────────────────────────────
ok "Downloading pspy64…"
curl -fsSL \
    https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
    -o /usr/local/bin/pspy64 \
    && chmod +x /usr/local/bin/pspy64 \
    && ok "pspy64 → /usr/local/bin/pspy64" \
    || warn "pspy64 download failed"

# ── 6. wash — part of reaver on Kali (already in PATH after apt) ──────────────
# On older Kali 'wash' ships inside the reaver package.
# If still missing, build from source.
if ! command -v wash &>/dev/null; then
    warn "'wash' not found — building from source…"
    apt-get install -y libpcap-dev libssl-dev 2>/dev/null
    TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/t6x/reaver-wps-fork-t6x "$TMP/reaver" 2>/dev/null \
        && cd "$TMP/reaver/src" \
        && ./configure --prefix=/usr/local && make -j"$(nproc)" && make install \
        && ok "wash built and installed" \
        || warn "wash build failed — WPS scanning unavailable"
    cd - >/dev/null
    rm -rf "$TMP"
fi

# ── 7. Python helpers ─────────────────────────────────────────────────────────
ok "Installing Python packages…"
pip3 install --break-system-packages \
    python-nmap requests beautifulsoup4 impacket 2>/dev/null \
    || pip3 install python-nmap requests beautifulsoup4 impacket

# ── 8. Rust + four-hub ───────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    ok "Installing Rust toolchain…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    source "$HOME/.cargo/env"
fi

ok "Building + installing four-hub…"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
cargo install --path . 2>&1 | tail -5

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
ok "Installation complete."
echo -e "   ${GREEN}four-hub${NC}          — main TUI (needs root for raw packets)"
echo -e "   ${GREEN}linpeas${NC}           — /usr/local/bin/linpeas"
echo -e "   ${GREEN}pspy64${NC}            — /usr/local/bin/pspy64"
echo ""
echo -e "   Run:  ${YELLOW}sudo four-hub${NC}"
