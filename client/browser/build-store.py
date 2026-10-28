#!/usr/bin/env python3
"""Builds the store packages of the browser extension from client/browser/extension:

  python build-store.py [--out DIR]          (default DIR: client/dist-store)

  oneq-mesh-chromium-VERSION.zip   Chrome Web Store, Microsoft Edge Add-ons (Brave installs from the Chrome Web Store): the manifest as it is (service worker)
  oneq-mesh-firefox-VERSION.zip    addons.mozilla.org: the same code with a Firefox manifest (event page, gecko id, data-collection declaration)
  store-listing/                  texts for the store forms (description, single purpose, permission justifications, privacy policy)
  SHA256SUMS

Reproducible: files in sorted order, fixed timestamps, no extra metadata. Nothing here signs or uploads anything: signing and publishing need the
publisher's own store accounts (see store-listing/PUBLISHING.md).
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "extension")
LISTING = os.path.join(HERE, "store")
GECKO_ID = "k@example.com"          # cannot be changed after the first submission to addons.mozilla.org
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def read_manifest():
    with open(os.path.join(SRC, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)


def store_manifest(m):
    """The development `key` fixes the extension id of unpacked builds (the native host names that id); a store assigns its own id, so the key is left out."""
    m = json.loads(json.dumps(m))
    m.pop("key", None)
    return m


def firefox_manifest(m):
    m = store_manifest(m)
    m.pop("minimum_chrome_version", None)
    m["background"] = {"scripts": ["pac.js", "update.js", "background.js"]}        # Firefox: event page; no service_worker key
    # proxy.onRequest can only see requests of hosts the extension has permission for; the mesh addresses are not known in advance
    m["host_permissions"] = sorted(set(m.get("host_permissions", []) + ["<all_urls>"]))
    m["browser_specific_settings"] = {"gecko": {"id": GECKO_ID, "strict_min_version": "140.0",
                                                "data_collection_permissions": {"required": ["none"]}}}
    return m


def write_zip(path, files):
    """files: list of (arcname, bytes)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(files):
            zi = zipfile.ZipInfo(name, FIXED_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)


def tree(root):
    out = []
    for d, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            out.append((os.path.relpath(p, root).replace(os.sep, "/"), open(p, "rb").read()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "..", "dist-store"))
    out = os.path.abspath(ap.parse_args().out)
    m = read_manifest()
    v = m["version"]
    files = [f for f in tree(SRC) if f[0] != "manifest.json"]
    os.makedirs(out, exist_ok=True)

    chromium = os.path.join(out, f"oneq-mesh-chromium-{v}.zip")
    write_zip(chromium, files + [("manifest.json", (json.dumps(store_manifest(m), indent=2) + chr(10)).encode())])
    firefox = os.path.join(out, f"oneq-mesh-firefox-{v}.zip")
    write_zip(firefox, files + [("manifest.json", (json.dumps(firefox_manifest(m), indent=2) + "\n").encode())])

    dst = os.path.join(out, "store-listing")
    shutil.rmtree(dst, ignore_errors=True)
    if os.path.isdir(LISTING):
        shutil.copytree(LISTING, dst)
    sums = []
    for p in (chromium, firefox):
        sums.append(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {os.path.basename(p)}")
    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sums) + "\n")
    for s in sums:
        print(s)
    print("written to", out)


if __name__ == "__main__":
    sys.exit(main())
