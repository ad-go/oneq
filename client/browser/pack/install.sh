#!/bin/sh
# Installs the oneq browser extension on macOS or Linux and, with --relay/--community/--user, starts `oneqclient proxy` at every login
# (macOS: a LaunchAgent; Linux: a systemd user service). The browser loads an unpacked extension only from its own extensions page: the last step is yours.
#
#   ./install.sh                                                  only the extension
#   ./install.sh --relay https://relay.example.org:8443 --community lan --user alice [--cafile ca.pem] [--name laptop] [--password-file F]
#   options: --dest DIR   --client PATH   --no-startup   --no-start-now
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OS=$(uname -s)
RELAY="" COMMUNITY="" USER_="" CAFILE="" NAME="" PWFILE="" CLIENT="" STARTUP=1 STARTNOW=1
if [ "$OS" = Darwin ]; then DEST="$HOME/Library/Application Support/oneq/browser"; else DEST="${XDG_DATA_HOME:-$HOME/.local/share}/oneq/browser"; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --relay) RELAY=$2; shift 2;; --community) COMMUNITY=$2; shift 2;; --user) USER_=$2; shift 2;; --cafile) CAFILE=$2; shift 2;;
    --name) NAME=$2; shift 2;; --password-file) PWFILE=$2; shift 2;; --dest) DEST=$2; shift 2;; --client) CLIENT=$2; shift 2;;
    --no-startup) STARTUP=0; shift;; --no-start-now) STARTNOW=0; shift;;
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ -f "$HERE/extension/manifest.json" ] || { echo "the extension folder is missing next to this script" >&2; exit 1; }

mkdir -p "$DEST"
rm -rf "$DEST/extension"
cp -R "$HERE/extension" "$DEST/extension"
echo "extension copied to $DEST/extension"

# the connection manager: the extension asks this native host (oneqclient native-host) to run the proxy, so the settings can be typed in the extension
if [ -z "$CLIENT" ]; then
  for c in "$HERE/oneqclient" /usr/local/bin/oneqclient /usr/local/libexec/oneq/oneqclient "$HOME/.local/bin/oneqclient"; do [ -x "$c" ] && CLIENT=$c && break; done
  [ -n "$CLIENT" ] || CLIENT=$(command -v oneqclient || true)
fi
if [ -n "$CLIENT" ] && [ -x "$CLIENT" ]; then
  "$CLIENT" native-host install || echo "native-host install failed (the extension can still use a proxy you start yourself)"
else
  echo "oneqclient not found: the extension cannot start the connection by itself (install the oneq client, then run: oneqclient native-host install)"
fi

if [ -n "$RELAY" ] && [ -n "$COMMUNITY" ] && [ -n "$USER_" ] && [ "$STARTUP" = 1 ]; then
  if [ -z "$CLIENT" ]; then
    for c in "$HERE/oneqclient" /usr/local/bin/oneqclient /usr/local/libexec/oneq/oneqclient "$HOME/.local/bin/oneqclient"; do [ -x "$c" ] && CLIENT=$c && break; done
    [ -n "$CLIENT" ] || CLIENT=$(command -v oneqclient || true)
  fi
  [ -n "$CLIENT" ] && [ -x "$CLIENT" ] || { echo "oneqclient not found: install the oneq client first or pass --client PATH" >&2; exit 1; }
  if [ -z "$PWFILE" ]; then
    PWFILE="$DEST/proxy.pass"
    printf "Password of %s in community %s: " "$USER_" "$COMMUNITY" >&2
    stty -echo 2>/dev/null || true; read -r PW; stty echo 2>/dev/null || true; echo >&2
    (umask 077; printf '%s' "$PW" > "$PWFILE"); PW=""
  fi
  CMD="$CLIENT proxy --relay $RELAY --community $COMMUNITY --user $USER_ --password-file $PWFILE"
  [ -n "$CAFILE" ] && CMD="$CMD --cafile $(cd "$(dirname "$CAFILE")" && pwd)/$(basename "$CAFILE")"
  [ -n "$NAME" ] && CMD="$CMD --name $NAME"
  echo "$CMD" > "$DEST/proxy-command.txt"
  if [ "$OS" = Darwin ]; then
    PLIST="$HOME/Library/LaunchAgents/ro.1q.oneq.proxy.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    {
      echo '<?xml version="1.0" encoding="UTF-8"?>'
      echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
      echo '<plist version="1.0"><dict><key>Label</key><string>ro.1q.oneq.proxy</string><key>ProgramArguments</key><array>'
      for a in $CMD; do echo "<string>$a</string>"; done
      echo "</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>30</integer>"
      echo "<key>StandardOutPath</key><string>$DEST/proxy.log</string><key>StandardErrorPath</key><string>$DEST/proxy.log</string></dict></plist>"
    } > "$PLIST"
    echo "LaunchAgent written: $PLIST"
    if [ "$STARTNOW" = 1 ]; then launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true; launchctl bootstrap "gui/$(id -u)" "$PLIST" && echo "proxy started"; fi
  else
    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$UNIT_DIR"
    printf '[Unit]\nDescription=oneq mesh SOCKS5 proxy for the browser extension\nAfter=network-online.target\n\n[Service]\nExecStart=%s\nRestart=on-failure\nRestartSec=15\n\n[Install]\nWantedBy=default.target\n' "$CMD" > "$UNIT_DIR/oneq-proxy.service"
    echo "systemd user service written: $UNIT_DIR/oneq-proxy.service"
    if command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null; then
      systemctl --user enable oneq-proxy.service 2>/dev/null || true
      [ "$STARTNOW" = 1 ] && systemctl --user restart oneq-proxy.service && echo "proxy started"
    else
      echo "(no systemd user session here: start it with: $CMD)"
    fi
  fi
else
  echo "no proxy at login set up: start it yourself (oneqclient proxy --relay ... --community ... --user ... --password-file ...)"
fi

cat <<EOF

Last step, in the browser (it cannot be done for you):
  1. open the extensions page (brave://extensions, chrome://extensions or edge://extensions)
  2. turn on "Developer mode" (top right)
  3. press "Load unpacked" and choose this folder:
       $DEST/extension
EOF
