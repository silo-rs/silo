#!/bin/sh
set -eu

echo "silo — development environment isolation via loopback IP aliasing"
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
        SUDOERS_RULE='%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 alias 127.0.* netmask 255.0.0.0
%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 -alias 127.0.*
%admin ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts'
    else
        SUDOERS_RULE='%sudo ALL=(root) NOPASSWD: /sbin/ip addr add 127.0.*/8 dev lo
%sudo ALL=(root) NOPASSWD: /sbin/ip addr del 127.0.*/8 dev lo
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

# --- 3. Shell integration ---

add_shell_init() {
    SHELL_INIT='eval "$(silo shell-init)"'

    # zsh
    ZSHRC="${ZDOTDIR:-$HOME}/.zshrc"
    if [ -f "$ZSHRC" ] || [ -n "${ZSH_VERSION:-}" ]; then
        if ! grep -q "silo shell-init" "$ZSHRC" 2>/dev/null; then
            printf '\n%s\n' "$SHELL_INIT" >> "$ZSHRC"
            echo "Added silo init to $ZSHRC"
        else
            echo "$ZSHRC already configured."
        fi
    fi

    # bash
    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q "silo shell-init" "$HOME/.bashrc" 2>/dev/null; then
            printf '\n%s\n' "$SHELL_INIT" >> "$HOME/.bashrc"
            echo "Added silo init to ~/.bashrc"
        else
            echo "~/.bashrc already configured."
        fi
    fi

    # fish
    FISH_CONFIG="$HOME/.config/fish/config.fish"
    if [ -f "$FISH_CONFIG" ]; then
        if ! grep -q "silo shell-init" "$FISH_CONFIG" 2>/dev/null; then
            printf '\nsilo shell-init | source\nsilo activate 2>/dev/null\n' >> "$FISH_CONFIG"
            echo "Added silo init to $FISH_CONFIG"
        else
            echo "$FISH_CONFIG already configured."
        fi
    fi
}

echo ""
echo "Setting up shell integration..."
add_shell_init

echo ""
echo "Setup complete! Restart your shell, then:"
echo ""
echo "  cd <your-repo>"
echo "  silo init"
echo "  silo add <name>"
echo ""
