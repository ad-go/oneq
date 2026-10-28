#!/bin/bash
# Removes the oneq client from macOS. Keeps the configuration and the node key unless --purge is given.
set -uo pipefail
PLIST="$HOME/Library/LaunchAgents/ro.example.oneq.menubar.plist"
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null
rm -f "$PLIST"
rm -rf "$HOME/Applications/oneq.app"
if [ -x /usr/local/libexec/oneq/oneqclient ]; then
    sudo /usr/local/libexec/oneq/oneqclient service uninstall 2>/dev/null
    sudo /usr/local/libexec/oneq/oneqclient relay uninstall 2>/dev/null
fi
# per-user installation (./install.sh --user)
UB="$HOME/Library/Application Support/oneq/bin"
if [ -x "$UB/oneqclient" ]; then
    "$UB/oneqclient" relay uninstall --user 2>/dev/null
    rm -rf "$UB"; rm -f "$HOME/.local/bin/oneqclient"
fi
if [ -d /usr/local/libexec/oneq ] || [ -e /usr/local/bin/oneqclient ]; then   # a system-wide installation (asks for the administrator password)
    sudo rm -rf /usr/local/libexec/oneq
    sudo rm -f /usr/local/bin/oneqclient
fi
if [ "${1:-}" = "--purge" ]; then
    [ -d "/Library/Application Support/oneq" ] && sudo rm -rf "/Library/Application Support/oneq"
    rm -rf "$HOME/.config/oneq"
    echo "configuration and keys removed"
else
    echo "kept: /Library/Application Support/oneq and ~/.config/oneq (use --purge to delete them)"
fi
echo "oneq removed"
