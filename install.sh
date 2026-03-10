#!/usr/bin/env bash
# ── Four-Hub installer ────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════╗"
echo "║      Four-Hub  installer         ║"
echo "╚══════════════════════════════════╝"
echo ""

# Make sure Rust toolchain is available.
if ! command -v cargo &>/dev/null; then
    echo "[!] Rust/cargo not found."
    echo "    Install Rust: https://rustup.rs"
    exit 1
fi

echo "[1/3] Building release binary …"
cargo build --release 2>&1

echo "[2/3] Installing to ~/.cargo/bin/four-hub …"
cargo install --path . --force 2>&1

echo "[3/3] Verifying install …"
if command -v four-hub &>/dev/null; then
    echo ""
    echo "✓ four-hub installed successfully!"
    echo ""
    echo "  Usage:"
    echo "    four-hub                   # launch TUI"
    echo "    four-hub --help            # show CLI options"
    echo ""
else
    echo ""
    echo "⚠  Binary built but 'four-hub' not in PATH."
    echo "   Add this to your shell profile:"
    echo "       export PATH=\"\$HOME/.cargo/bin:\$PATH\""
    echo ""
fi
