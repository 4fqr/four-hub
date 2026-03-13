#!/usr/bin/env bash

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Root privileges required: sudo bash hubinstall.sh"

log "Synchronizing system package repositories..."
apt-get update -qq

log "Installing system dependencies..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential libpcap-dev libsqlite3-dev libssh2-1-dev \
    python3 python3-pip python3-dev pkg-config \
    curl git tor proxychains4 \
    nmap masscan nikto hydra sqlmap \
    gobuster dirb feroxbuster ffuf wpscan \
    enum4linux netdiscover dnsrecon \
    fierce whatweb wafw00f \
    john hashcat wordlists smbclient \
    aircrack-ng reaver bully \
    metasploit-framework beef-xss \
    evil-winrm responder \
    ncrack snmp onesixtyone \
    binwalk steghide foremost libimage-exiftool-perl \
    chisel socat netcat-traditional \
    macchanger arp-scan \
    2>/dev/null || warn "Apt package installation incomplete."

log "Configuring Go-based tooling..."
if command -v go &>/dev/null; then
    go install github.com/owasp-amass/amass/v4/...@latest      2>/dev/null || true
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       2>/dev/null || true
else
    apt-get install -y amass 2>/dev/null || true
fi

log "Installing Volatility3 via Python package manager..."
pip3 install --break-system-packages volatility3 2>/dev/null || true

log "Deploying LinPEAS for privilege escalation auditing..."
mkdir -p /opt/privesc
curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/privesc/linpeas.sh 2>/dev/null \
    && chmod +x /opt/privesc/linpeas.sh \
    && ln -sf /opt/privesc/linpeas.sh /usr/local/bin/linpeas \
    || warn "LinPEAS deployment failed."

log "Deploying pspy64 process monitor..."
curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy64 2>/dev/null \
    && chmod +x /usr/local/bin/pspy64 \
    || warn "pspy64 deployment failed."

if ! command -v wash &>/dev/null; then
    log "Wash binary not detected. Compiling Reaver from source..."
    TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/t6x/reaver-wps-fork-t6x "$TMP/reaver" 2>/dev/null \
        && cd "$TMP/reaver/src" \
        && ./configure --prefix=/usr/local >/dev/null \
        && make -j"$(nproc)" >/dev/null \
        && make install >/dev/null \
        && log "Reaver/Wash successfully compiled." \
        || warn "Reaver/Wash compilation failed."
    rm -rf "$TMP"
fi

log "Installing required Python modules..."
pip3 install --break-system-packages python-nmap requests beautifulsoup4 impacket 2>/dev/null || true

if ! command -v cargo &>/dev/null; then
    log "Rust toolchain not detected. Initiating installation..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path >/dev/null
fi

export PATH="$HOME/.cargo/bin:$PATH"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

log "Building Four-Hub binary..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
cargo install --path . --force

if [ -f "$HOME/.cargo/bin/four-hub" ]; then
    ln -sf "$HOME/.cargo/bin/four-hub" /usr/local/bin/four-hub
    log "Binary symlinked to /usr/local/bin/four-hub"
fi

echo ""
log "Installation sequence concluded."
echo -e "   Execution Command: ${YELLOW}sudo four-hub${NC}"
echo ""
