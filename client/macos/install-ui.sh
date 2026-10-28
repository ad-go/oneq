#!/bin/bash
# Builds and installs the oneq UI window app on macOS.
# No Apple Developer account required — ad-hoc signing only.
# Requirements: macOS 10.13+, Command Line Tools (clang/swiftc).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Applications/oneq-ui.app"
BIN="$APP/Contents/MacOS"
BIN_NAME="onequi"

echo "Compiling oneq UI..."
swiftc -framework Cocoa \
    "$SCRIPT_DIR/$BIN_NAME.swift" \
    -o "$SCRIPT_DIR/$BIN_NAME" \
    || { echo "Compilation failed"; exit 1; }

echo "Creating app bundle at $APP ..."
rm -rf "$APP"
mkdir -p "$BIN"
cp "$SCRIPT_DIR/$BIN_NAME" "$BIN/"
cp "$SCRIPT_DIR/Info.plist" "$APP/Contents/"

echo "Signing ad-hoc (no Apple account needed)..."
codesign --deep --force --sign - "$APP"

echo "Removing Gatekeeper quarantine flag..."
xattr -cr "$APP"

echo ""
echo "Installed: $APP"
echo "Launch with:  open '$APP'"
open "$APP"
