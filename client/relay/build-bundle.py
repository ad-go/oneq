"""Builds the relay bundle that ships next to oneqclient on Windows and macOS: python-build-standalone (Python 3.13 with OpenSSL >= 3.5,
which the post-quantum TLS of the relay needs), the relay's dependencies as wheels for the target platform, and the relay's own files.

    python build-bundle.py --platform windows-x64|macos-arm64|macos-x64 --out DIR      -> DIR/python, DIR/site-packages, DIR/relay

Every download is checked against the SHA256SUMS of the pinned python-build-standalone release. Run it with any Python 3.9+ that has pip
(on any OS: the wheels are fetched for the target platform). Nothing is executed from the downloaded archive here.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

PBS_TAG = "20261013"
PBS_PY = "3.13.16"
TARGETS = {
    "windows-x64": ("x86_64-pc-windows-msvc", ["win_amd64"]),
    "macos-arm64": ("aarch64-apple-darwin", ["macosx_11_0_arm64", "macosx_10_13_universal2", "macosx_10_9_universal2"]),
    "macos-x64": ("x86_64-apple-darwin", ["macosx_10_13_x86_64", "macosx_10_12_x86_64", "macosx_10_9_x86_64", "macosx_11_0_x86_64", "macosx_10_13_universal2", "macosx_10_9_universal2"]),
}
# the relay itself needs only aiohttp; cryptography is used by `oneqrelay init` (certificates). cryptography 50 has no wheel for Intel Macs.
REQUIREMENTS = ["aiohttp==3.14.5", "cryptography>=50.0.2", "segno==1.6.1"]
REQUIREMENTS_OVERRIDE = {"macos-x64": ["aiohttp==3.14.5", "cryptography>=46,<49", "segno==1.6.1"]}
RELAY_FILES = ["oneqrelay.py", "oneqadmin.py", "oneqadmin.html", "oneqtotp.py", "oneqinit.py", "oneqnat.py", "oneqpop.py", "meshdb.py", "rendezvous_server.py",
               "pqtls.py", "oneqconf.py", "pq_openssl.cnf", os.path.join("packaging", "relay-selftest.py")]
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _root_owned(ti):
    """Files made on Windows come out rw-rw-rw-: the daemon runs this code as root, so nobody else may write it."""
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    ti.mode = 0o755 if ti.isdir() or ti.name.endswith((".so", ".dylib")) else 0o644
    return ti


def fetch(url: str, dest: str):
    with urllib.request.urlopen(url, timeout=300) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, choices=sorted(TARGETS))
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default=os.path.join(tempfile.gettempdir(), "oneq-relay-bundle-cache"))
    a = ap.parse_args()
    triple, wheel_plat = TARGETS[a.platform]
    os.makedirs(a.cache, exist_ok=True)
    base = f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/"
    name = f"cpython-{PBS_PY}+{PBS_TAG}-{triple}-install_only.tar.gz"
    arch = os.path.join(a.cache, name)
    sums = os.path.join(a.cache, f"SHA256SUMS-{PBS_TAG}")
    if not os.path.exists(sums):
        fetch(base + "SHA256SUMS", sums)
    want = next((l.split()[0] for l in open(sums) if l.strip().endswith(name)), None)
    if not want:
        sys.exit(f"{name} is not in SHA256SUMS of release {PBS_TAG}")
    if not os.path.exists(arch):
        fetch(base + urllib.parse.quote(name), arch)
    got = hashlib.sha256(open(arch, "rb").read()).hexdigest()
    if got != want:
        os.remove(arch)
        sys.exit(f"checksum mismatch for {name}: {got} != {want}")
    print(f"python-build-standalone {PBS_PY} ({triple}) verified: {got}")

    out = os.path.abspath(a.out)
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)
    mac = a.platform.startswith("macos")
    # macOS: the interpreter's symlinks (python3 -> python3.13, ...) must survive, and Windows cannot create them: the result is a tar.gz
    # that is unpacked on the Mac; the Windows bundle is a plain directory.
    stage = tempfile.mkdtemp(prefix="oneq-bundle-") if mac else out
    if not mac:
        with tarfile.open(arch) as t:
            t.extractall(stage, filter="data")          # -> out/python
    sp = os.path.join(stage, "site-packages")
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--target", sp, "--only-binary=:all:",
                    ] + [x for p in wheel_plat for x in ("--platform", p)] + ["--python-version", "3.13", "--implementation", "cp", "--abi", "cp313"]
                   + REQUIREMENTS_OVERRIDE.get(a.platform, REQUIREMENTS), check=True)
    shutil.rmtree(os.path.join(sp, "bin"), ignore_errors=True)
    rel = os.path.join(stage, "relay")
    os.makedirs(rel)
    for f in RELAY_FILES:
        shutil.copy2(os.path.join(REPO, f), os.path.join(rel, os.path.basename(f)))
    with open(os.path.join(stage, "VERSION"), "w") as f:
        f.write(f"python-build-standalone {PBS_TAG} (CPython {PBS_PY}), {a.platform}" + chr(10) + f"requirements: {' '.join(REQUIREMENTS_OVERRIDE.get(a.platform, REQUIREMENTS))}" + chr(10))
    if mac:
        target = os.path.join(out, f"oneqrelay-bundle-{a.platform}.tar.gz")
        with tarfile.open(arch) as src, tarfile.open(target, "w:gz") as dst:
            for m in src:                                # python/... exactly as in the verified archive (symlinks and modes kept)
                dst.addfile(m, src.extractfile(m) if m.isreg() else None)
            for n in ("site-packages", "relay", "VERSION"):
                dst.add(os.path.join(stage, n), arcname=n, filter=_root_owned)
        shutil.rmtree(stage)
        print(f"bundle ready: {target} ({os.path.getsize(target) // 1048576} MB); unpack it into <install dir>/relay on the Mac")
        return
    size = sum(os.path.getsize(os.path.join(d, n)) for d, _, ns in os.walk(out) for n in ns)
    print(f"bundle ready: {out} ({size // 1048576} MB)")


if __name__ == "__main__":
    main()
