"""Assembles the desktop packages of the oneq client: for every platform one package with the node only and one with the node and the relay (the server).
Run after: cargo build --release, flutter build windows, macos/cross-build.sh and relay/build-bundle.py for the three platforms. Output: client/dist-packages/
  oneq-node-windows-x64.msi      installer: app + oneqclient.exe (node) + wintun.dll           (built by windows/build-msi.py, needs WiX)
  oneq-server-windows-x64.msi    installer: the same + the relay (Python 3.13 / OpenSSL 3.5, relay code)
  oneq-node-macos-arm64.tar.gz   install.sh, uninstall.sh, oneqclient-arm64 (with `menubar`): node only
  oneq-server-macos-arm64.tar.gz the same + oneqrelay-bundle-macos-arm64.tar.gz (install.sh then also installs the relay)
  oneq-node-macos-x64.tar.gz / oneq-server-macos-x64.tar.gz   the same for Intel
  oneq-browser-extension-windows.zip  install.ps1 / uninstall.ps1 + the Chrome/Brave/Edge/Firefox extension
  oneq-browser-extension-unix.tar.gz  install.sh / uninstall.sh + the extension
Debian: packaging/build-debs.sh builds oneqnode (node only), oneqrelay (relay only) and oneq-server (node + relay).
"""
import os
import shutil
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "dist-packages")
os.makedirs(OUT, exist_ok=True)

import subprocess
import sys

old = os.path.join(OUT, "oneq-windows-x64.zip")
if os.path.exists(old):
    os.remove(old)                                  # replaced by the two installers
r = subprocess.run([sys.executable, os.path.join(HERE, "windows", "build-msi.py"), "--out", OUT])
if r.returncode != 0:
    raise SystemExit("the Windows installers were not built (see above; WiX 5 is needed: dotnet tool install --global wix --version 5.0.2)")

ext = os.path.join(HERE, "browser", "extension")
pack = os.path.join(HERE, "browser", "pack")


def ext_files():
    for d, _, names in os.walk(ext):
        for n in sorted(names):
            p = os.path.join(d, n)
            yield p, "extension/" + os.path.relpath(p, ext).replace(os.sep, "/")


zx = os.path.join(OUT, "oneq-browser-extension-windows.zip")
with zipfile.ZipFile(zx, "w", zipfile.ZIP_DEFLATED) as zf:
    for n in ("install.ps1", "uninstall.ps1", "set-password.ps1", "README.txt"):
        zf.write(os.path.join(pack, n), "oneq-browser-extension/" + n)
    for p, arc in ext_files():
        zf.write(p, "oneq-browser-extension/" + arc)
print(zx, os.path.getsize(zx) // 1024, "KB")

tx = os.path.join(OUT, "oneq-browser-extension-unix.tar.gz")
with tarfile.open(tx, "w:gz") as t:
    for n, mode in (("install.sh", 0o755), ("uninstall.sh", 0o755), ("README.txt", 0o644)):
        ti = t.gettarinfo(os.path.join(pack, n), arcname="oneq-browser-extension/" + n)
        ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = mode, 0, 0, "root", "root"
        with open(os.path.join(pack, n), "rb") as f:
            data = f.read().replace(bytes([13, 10]), bytes([10]))
        ti.size = len(data)
        import io as _io
        t.addfile(ti, _io.BytesIO(data))
    for p, arc in ext_files():
        ti = t.gettarinfo(p, arcname="oneq-browser-extension/" + arc)
        ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = 0o644, 0, 0, "root", "root"
        with open(p, "rb") as f:
            t.addfile(ti, f)
print(tx, os.path.getsize(tx) // 1024, "KB")

for arch, tag in (("arm64", "arm64"), ("x86_64", "x64")):
    for edition in ("node", "server"):
        out = os.path.join(OUT, f"oneq-{edition}-macos-{tag}.tar.gz")
        files = {
            "install.sh": (os.path.join(HERE, "macos", "install.sh"), 0o755),
            "uninstall.sh": (os.path.join(HERE, "macos", "uninstall.sh"), 0o755),
            f"oneqclient-{arch}": (os.path.join(HERE, "macos", "dist", f"oneqclient-{arch}"), 0o755),
        }
        if edition == "server":      # install.sh installs the relay when its bundle is next to it
            files[f"oneqrelay-bundle-macos-{tag}.tar.gz"] = (os.path.join(HERE, "relay", "dist", f"macos-{tag}", f"oneqrelay-bundle-macos-{tag}.tar.gz"), 0o644)
        with tarfile.open(out, "w:gz") as t:
            for name, (src, mode) in files.items():
                ti = t.gettarinfo(src, arcname=f"oneq-macos/{name}")
                ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = mode, 0, 0, "root", "root"
                with open(src, "rb") as f:
                    t.addfile(ti, f)
        print(out, os.path.getsize(out) // 1048576, "MB")
    old = os.path.join(OUT, f"oneq-macos-{tag}.tar.gz")
    if os.path.exists(old):
        os.remove(old)
