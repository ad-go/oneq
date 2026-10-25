#!/bin/bash
# Gathers the installers that were already built into build/<system>/ and writes build/SHA256SUMS. It builds nothing (see README.md for the build commands)
# and copies only what exists; a missing artifact is reported, not an error.
set -u
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)
VERSION=${VERSION:-0.0.1}
put() { # SOURCE DESTINATION-DIR
    if [ -f "$1" ]; then cp -f "$1" "$2/" && echo "ok       $2/$(basename "$1")"; else echo "MISSING  $1"; fi
}

put "$ROOT/client/dist-packages/oneq-node-windows-x64.msi"   windows
put "$ROOT/client/dist-packages/oneq-server-windows-x64.msi" windows

for pair in "arm64:arm64" "x64:x86_64"; do
    tag=${pair%%:*}; arch=${pair##*:}; bin="$ROOT/client/macos/dist/oneqclient-$arch"
    if [ -f "$bin" ]; then
        t=$(mktemp -d); mkdir "$t/oneq-macos"
        cp "$bin" "$ROOT/client/macos/install.sh" "$ROOT/client/macos/uninstall.sh" "$t/oneq-macos/"
        chmod 755 "$t/oneq-macos/"*
        tar --mode=755 -C "$t" -czf "macos/oneq-node-macos-$tag.tar.gz" oneq-macos && echo "ok       macos/oneq-node-macos-$tag.tar.gz"
        rm -rf "$t"
    else echo "MISSING  $bin"; fi
done

for f in oneqnode_${VERSION}_amd64.deb oneqrelay_${VERSION}_amd64.deb oneq-server_${VERSION}_all.deb; do put "$ROOT/dist/$f" debian; done
put "$ROOT/client/app/build/app/outputs/flutter-apk/app-release.apk" android

PY=python3; "$PY" -c 1 2>/dev/null || PY=python
"$PY" "$ROOT/client/browser/build-store.py" --out browser >/dev/null && echo "ok       browser/ (chromium + firefox zips)" || echo "FAILED   browser"

find . -type f ! -name SHA256SUMS ! -name .gitkeep ! -name .gitignore ! -name README.md ! -name collect.sh ! -path './browser/store-listing/*' | sort | xargs sha256sum > SHA256SUMS
echo; cat SHA256SUMS
