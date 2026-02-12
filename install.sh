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

curl --proto '=https' --tlsv1.2 -LsSf https://github.com/silo-rs/silo/releases/latest/download/silo-installer.sh | sh

# --- 2. Configure passwordless sudo for loopback aliases ---

configure_sudoers() {
    if [ "$(uname)" = "Darwin" ]; then
        SUDOERS_RULE='%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 alias 127.* netmask 255.0.0.0
%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 -alias 127.*
%admin ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts'
    else
        SUDOERS_RULE='%sudo ALL=(root) NOPASSWD: /sbin/ip addr add 127.*/8 dev lo
%sudo ALL=(root) NOPASSWD: /sbin/ip addr del 127.*/8 dev lo
%sudo ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts'
    fi

    if [ ! -f /etc/sudoers.d/silo ]; then
        echo ""
        echo "Configuring passwordless sudo for loopback IP aliases..."
        echo "(required so silo can manage network aliases without prompting for a password)"
        echo ""
        echo "$SUDOERS_RULE" | sudo tee /etc/sudoers.d/silo > /dev/null
        sudo chmod 0440 /etc/sudoers.d/silo
        echo "Done."
    else
        echo "sudoers rule already configured."
    fi
}

configure_sudoers

echo ""
echo "Setup complete! Try it out:"
echo ""
echo "  cd <your-repo>"
echo "  silo run npm run dev"
echo ""
