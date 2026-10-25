#!/usr/bin/env python3
"""Builds the Windows installers (MSI, WiX 5) from the Flutter release folder:
  python build-msi.py [--edition node|server|both] [--version X.Y.Z] [--appdir DIR] [--out DIR]

  oneq-node-windows-x64.msi     the app, oneqclient.exe (node), wintun.dll
  oneq-server-windows-x64.msi   the same plus the relay (bundled Python 3.13 / OpenSSL 3.5): registry, accounts, relay, STUN, admin page

Needs `dotnet tool install --global wix --version 5.0.2` and the folder `app/build/windows/x64/runner/Release` (flutter build windows + the release
oneqclient.exe + relay/ from relay/build-bundle.py; see package-desktop.py). The two editions share an UpgradeCode: installing one over the other switches
edition; settings and data are never removed."""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def project_version():
    m = re.search(r'^VERSION = "([0-9.]+)"', open(os.path.join(ROOT, "oneqrelay.py"), encoding="utf-8").read(), re.M)
    return m.group(1) if m else "0.0.0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edition", default="both", choices=["node", "server", "both"])
    ap.add_argument("--version", default=project_version())
    ap.add_argument("--appdir", default=os.path.join(HERE, "..", "app", "build", "windows", "x64", "runner", "Release"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "dist-packages"))
    a = ap.parse_args()
    appdir = os.path.abspath(a.appdir)
    out = os.path.abspath(a.out)
    for need in ("oneq_app.exe", "oneqclient.exe", "wintun.dll"):
        if not os.path.exists(os.path.join(appdir, need)):
            raise SystemExit(f"missing {need} in {appdir}")
    editions = ["node", "server"] if a.edition == "both" else [a.edition]
    if "server" in editions and not os.path.exists(os.path.join(appdir, "relay", "relay", "oneqrelay.py")):
        raise SystemExit(f"missing relay/relay/oneqrelay.py in {appdir}")
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, PATH=os.environ["PATH"] + os.pathsep + os.path.expanduser("~/.dotnet/tools"))
    for ed in editions:
        msi = os.path.join(out, f"oneq-{ed}-windows-x64.msi")
        name = "oneq node" if ed == "node" else "oneq node and relay"
        cmd = ["wix", "build", "-arch", "x64", os.path.join(HERE, "oneq.wxs"), "-d", f"AppDir={appdir}", "-d", f"Relay={'yes' if ed == 'server' else 'no'}",
               "-d", f"Version={a.version}", "-d", f"ProductName={name}", "-pdbtype", "none", "-o", msi]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:])
            raise SystemExit(f"wix build failed for {ed}")
        print(msi, os.path.getsize(msi) // 1048576, "MB")


if __name__ == "__main__":
    sys.exit(main())
