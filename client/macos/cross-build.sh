#!/bin/bash
# Cross-compiles oneqclient for macOS (Apple Silicon and Intel) from Windows or Linux, with Zig as the C compiler and
# linker: no Mac, Xcode or Apple account needed. The result is unsigned: install.sh signs it ad-hoc on the Mac.
#   pip install ziglang && cargo install cargo-zigbuild && rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   ./cross-build.sh                 -> macos/dist/oneqclient-arm64, macos/dist/oneqclient-x86_64
# (The cdylib output of the core crate is switched off for this build: zig's linker mishandles
# -exported_symbols_list on Windows. The dylib is only needed by the Flutter app.)
set -euo pipefail
cd "$(dirname "$0")/.."
Z=$(python -c "import ziglang,os;print(os.path.dirname(ziglang.__file__))" 2>/dev/null || true)
[ -z "$Z" ] || export PATH="$(cygpath -u "$Z" 2>/dev/null || echo "$Z"):$PATH"
command -v zig >/dev/null || { echo "zig not found (pip install ziglang)" >&2; exit 1; }

cp core/Cargo.toml core/Cargo.toml.orig
trap 'mv -f core/Cargo.toml.orig core/Cargo.toml' EXIT
sed -i 's/^crate-type = .*/crate-type = ["rlib"]/' core/Cargo.toml

mkdir -p macos/dist
for t in aarch64-apple-darwin:arm64 x86_64-apple-darwin:x86_64; do
    triple=${t%%:*}; name=${t##*:}
    cargo zigbuild --release --target "$triple" -p oneq-core --bin oneqclient
    cp "target/$triple/release/oneqclient" "macos/dist/oneqclient-$name"
done
ls -la macos/dist
