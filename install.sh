#!/bin/sh
set -eu

echo "silo — syscall interception on loopback"
echo "https://github.com/silo-rs/silo"
echo ""

if ! command -v curl > /dev/null; then
    echo "error: curl is required but not installed."
    exit 1
fi

# --- 1. Install binary ---

echo "Installing silo binary..."

curl --proto '=https' --tlsv1.2 -LsSf https://github.com/silo-rs/silo/releases/latest/download/silo-cli-installer.sh | sh

# --- 2. Sudoers ---
# Passwordless sudo for loopback aliases is configured automatically
# on first `silo run`. This ensures proper path security checks and
# uses the controlled _hosts helper instead of raw tee.

echo ""
echo "Setup complete! Try it out:"
echo ""
echo "  cd <your-repo>"
echo "  silo npm run dev"
echo ""
echo "On first run, silo will configure passwordless sudo for loopback aliases."
echo ""
