#!/bin/bash
# Installs the oneq client on macOS WITHOUT Xcode, Command Line Tools or an Apple developer account (a prebuilt `oneqclient` next to this script;
# otherwise Rust is needed to build it).
#   ./install.sh              install (asks for the administrator password once, for the root-owned binary)
#   ./install.sh --user       install for this user only, WITHOUT administrator rights: no root-owned files, no daemon (the TUN node needs root;
#                             `oneqclient proxy`, the relay as a LaunchAgent and the browser extension do not)
# What it does:
#   1. oneqclient -> /usr/local/libexec/oneq (root-owned: it runs as root in the launchd service), ad-hoc signed
#   2. ~/Applications/oneq.app (+ an alias on the desktop) and the menu-bar icon (`oneqclient menubar`, same icons as the app)
#   3. starts the icon at login (LaunchAgent)
#   4. the relay (oneqrelay with its own Python 3.13 / OpenSSL 3.5) is unpacked into /usr/local/libexec/oneq/relay when the bundle
#      oneqrelay-bundle-<arm64|x64>.tar.gz is next to this script (or in dist/); set it up afterwards with `sudo oneqclient relay init ...`
# The node itself is installed from that page (button Connect) or with `sudo oneqclient service install ...`.
set -euo pipefail
cd "$(dirname "$0")"
HERE=$PWD
USERMODE=0
[ "${1:-}" = "--user" ] && USERMODE=1

[ "$(uname)" = Darwin ] || { echo "this installer is for macOS" >&2; exit 1; }
command -v codesign >/dev/null || { echo "codesign is missing" >&2; exit 1; }
if [ "$USERMODE" = 1 ]; then
    LIBEXEC="$HOME/Library/Application Support/oneq/bin"; LINKDIR="$HOME/.local/bin"
    as_root() { "$@"; }
else
    LIBEXEC=/usr/local/libexec/oneq; LINKDIR=/usr/local/bin
    as_root() { sudo "$@"; }
fi

# 1. oneqclient: a prebuilt binary next to this script, or build it here
CLIENT=""
for c in "$HERE/oneqclient" "$HERE/oneqclient-$(uname -m)" "$HERE/dist/oneqclient-$(uname -m)"; do [ -x "$c" ] && CLIENT=$c && break; done
if [ -z "$CLIENT" ]; then
    command -v cargo >/dev/null || { echo "No prebuilt oneqclient here and Rust is not installed (https://rustup.rs)." >&2; exit 1; }
    echo "== building oneqclient (a few minutes)"
    (cd "$HERE/.." && cargo build --release -p oneq-core --bin oneqclient)
    CLIENT="$HERE/../target/release/oneqclient"
fi
file "$CLIENT" | grep -q "Mach-O" || { echo "$CLIENT is not a macOS binary" >&2; exit 1; }

echo "== installing oneqclient ($([ "$USERMODE" = 1 ] && echo "for this user" || echo "root-owned"), ad-hoc signed)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cp "$CLIENT" "$TMP/oneqclient"
xattr -cr "$TMP/oneqclient" 2>/dev/null || true
codesign --force --sign - "$TMP/oneqclient"
as_root mkdir -p "$LIBEXEC" "$LINKDIR"
if [ "$USERMODE" = 1 ]; then install -m 755 "$TMP/oneqclient" "$LIBEXEC/oneqclient"; else sudo install -m 755 -o root -g wheel "$TMP/oneqclient" "$LIBEXEC/oneqclient"; fi
as_root ln -sf "$LIBEXEC/oneqclient" "$LINKDIR/oneqclient"

# 1b. the relay bundle (optional): python-build-standalone + dependencies + the relay's files, built by client/relay/build-bundle.py
case "$(uname -m)" in arm64) RARCH=arm64;; *) RARCH=x64;; esac
RELAY_BUNDLE=""
for c in "$HERE/oneqrelay-bundle-macos-$RARCH.tar.gz" "$HERE/dist/oneqrelay-bundle-macos-$RARCH.tar.gz" "$HERE/../relay/dist/macos-$RARCH/oneqrelay-bundle-macos-$RARCH.tar.gz"; do
    [ -f "$c" ] && RELAY_BUNDLE=$c && break
done
if [ -n "$RELAY_BUNDLE" ]; then
    echo "== installing the relay bundle ($RELAY_BUNDLE)"
    as_root rm -rf "$LIBEXEC/relay"
    as_root mkdir -p "$LIBEXEC/relay"
    as_root tar -xzf "$RELAY_BUNDLE" -C "$LIBEXEC/relay"
    [ "$USERMODE" = 1 ] || sudo chown -R root:wheel "$LIBEXEC/relay"
    as_root chmod -R go-w "$LIBEXEC/relay"
    as_root xattr -cr "$LIBEXEC/relay" 2>/dev/null || true
    "$LIBEXEC/relay/python/bin/python3" -s -c "import ssl; print('relay Python:', ssl.OPENSSL_VERSION)" || echo "WARNING: the bundled Python does not start"
else
    echo "(no relay bundle next to this script: only the node is installed)"
fi

# the menu-bar icon is `oneqclient menubar` (same icons as the Windows/macOS app; no Swift or Command Line Tools needed)
echo "== menu-bar icon and the oneq app"
ONEQ="$LIBEXEC/oneqclient"
APP="$HOME/Applications/oneq.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
printf '%s\n' '#!/bin/bash' "exec \"$ONEQ\" menubar --open" > "$APP/Contents/MacOS/oneq"
chmod +x "$APP/Contents/MacOS/oneq"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>ro.1q.oneq.menubar</string>
  <key>CFBundleName</key><string>oneq</string>
  <key>CFBundleExecutable</key><string>oneq</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
xattr -cr "$APP" 2>/dev/null || true
codesign --force --sign - "$APP" >/dev/null 2>&1 || true
# an alias on the desktop (best effort)
rm -f "$HOME/Desktop/oneq"
osascript -e "tell application \"Finder\" to make new alias file to POSIX file \"$APP\" at desktop with properties {name:\"oneq\"}" >/dev/null 2>&1 || true

echo "== starting the icon at login"
PLIST="$HOME/Library/LaunchAgents/ro.1q.oneq.menubar.plist"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ro.1q.oneq.menubar</string>
  <key>ProgramArguments</key><array><string>$ONEQ</string><string>menubar</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo
echo "Done. The oneq icon is in the menu bar (and a oneq alias on the desktop); click the icon and choose \"Open oneq…\" to set up the connection."
[ "$USERMODE" = 1 ] && echo "(installed for this user: make sure $LINKDIR is in your PATH)"
if [ -n "$RELAY_BUNDLE" ]; then
    echo
    if [ "$USERMODE" = 1 ]; then
        echo "Relay (no administrator rights; runs while you are logged in): set it up once, then register it:"
        echo "  oneqclient relay init --user --name YOUR.HOST.NAME [--ip PUBLIC.IP]"
        echo "  oneqclient relay install --user"
        echo "Open TCP 8443 and UDP 8443-8445 on your router for it; clients import ~/.config/oneq/relay/ca.crt."
    else
        echo "Relay: set it up once, then register it as a service (asks for the administrator password):"
        echo "  sudo oneqclient relay init --name YOUR.HOST.NAME [--ip PUBLIC.IP]"
        echo "  sudo oneqclient relay install"
        echo "Open TCP 8443 and UDP 8443-8445 on your router for it; clients import /Library/Application Support/oneq/relay/ca.crt."
    fi
fi
echo "Remove everything with ./uninstall.sh"
