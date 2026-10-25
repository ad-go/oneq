# build: the installers, one folder per system

`collect.sh` copies the **already compiled** installers here and writes `SHA256SUMS`. The files are committed to git together with `SHA256SUMS`; rebuild and run `collect.sh` before committing a new version.

| Folder | Contents | Built with |
|---|---|---|
| `windows/` | `oneq-node-windows-x64.msi` (and `oneq-server-...` when built) | `cargo build --release -p oneq-core --bin oneqclient` and `--lib`; `cd client/app && flutter build windows --release`; copy `client/target/release/oneq_core.dll` into `client/app/build/windows/x64/runner/Release/`; `python client/windows/build-msi.py --edition node --appdir <Release folder> --out client/dist-packages/oneq-node-windows-x64.msi` |
| `macos/` | `oneq-node-macos-arm64.tar.gz`, `oneq-node-macos-x64.tar.gz` (`oneq-macos/`: `install.sh`, `uninstall.sh`, `oneqclient-ARCH`) | `client/macos/cross-build.sh` (do not run `cargo` or commit meanwhile) |
| `debian/` | `oneqnode`, `oneqrelay`, `oneq-server` `.deb` (Debian 13, amd64) | in a Debian 13 chroot: `VERSION=0.0.1 PIP=<venv>/bin/pip OUT=<dir> bash packaging/build-debs.sh`; copy the result to `dist/` |
| `android/` | `app-release.apk` (arm64, signed with the debug key) | `cargo ndk -t arm64-v8a build --release -p oneq-core --lib`, copy `liboneq_core.so` to `client/app/android/app/src/main/jniLibs/arm64-v8a/`, `cd client/app && flutter build apk --release` |
| `browser/` | `oneq-mesh-chromium-VERSION.zip`, `oneq-mesh-firefox-VERSION.zip`, `store-listing/` | `client/browser/build-store.py` (run by `collect.sh`) |

    bash build/collect.sh            # VERSION=0.0.1 by default
    sha256sum -c build/SHA256SUMS    # from the build/ folder

Details of each build: [client/README.md](../client/README.md). The installers are not code-signed; the extension zips are not signed or uploaded (see `client/browser/store/PUBLISHING.md`).
