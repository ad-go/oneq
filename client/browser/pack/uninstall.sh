#!/bin/sh
# Removes what install.sh put on this computer (the login service, the copied extension; --purge also the saved password and the node key).
# Remove the extension itself in the browser: extensions page -> Remove.
set -eu
OS=$(uname -s)
if [ "$OS" = Darwin ]; then DEST="$HOME/Library/Application Support/oneq/browser"; else DEST="${XDG_DATA_HOME:-$HOME/.local/share}/oneq/browser"; fi
PURGE=0
while [ $# -gt 0 ]; do case "$1" in --dest) DEST=$2; shift 2;; --purge) PURGE=1; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; done
if [ "$OS" = Darwin ]; then
  PLIST="$HOME/Library/LaunchAgents/ro.1q.oneq.proxy.plist"
  if [ -f "$PLIST" ]; then launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true; rm -f "$PLIST"; echo "LaunchAgent removed"; fi
else
  UNIT="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/oneq-proxy.service"
  if [ -f "$UNIT" ]; then
    systemctl --user disable --now oneq-proxy.service 2>/dev/null || true
    rm -f "$UNIT"; systemctl --user daemon-reload 2>/dev/null || true; echo "systemd user service removed"
  fi
fi
if [ -d "$DEST" ]; then
  if [ "$PURGE" = 1 ]; then rm -rf "$DEST"; echo "removed $DEST (including the saved password)"
  else rm -rf "$DEST/extension" "$DEST/proxy-command.txt"; echo "removed the extension copy in $DEST (kept proxy.pass; --purge deletes it)"; fi
fi
if [ "$PURGE" = 1 ]; then
  for k in "${XDG_CONFIG_HOME:-$HOME/.config}/oneq/proxy.key" "$HOME/Library/Application Support/oneq/proxy.key"; do [ -f "$k" ] && rm -f "$k" && echo "removed the proxy node key"; done
fi
echo 'Now remove "oneq mesh" from the browser: extensions page -> Remove.'
