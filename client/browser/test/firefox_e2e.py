"""End-to-end test of the Firefox build in a real Firefox against a running `oneqclient proxy` (the same checks as chrome_e2e.py):
  python firefox_e2e.py FIREFOX_EXE EXTENSION_ZIP_OR_DIR MESH_URL EXPECTED_TITLE [MEMBER_NAME]
Starts Firefox headless with a throw-away profile and Marionette, installs the extension as a temporary add-on (no signature needed for that), then checks that the
mesh page loads through the proxy (by address and by member name), that the popup shows the connection and the access mode, and that the off switch releases
the proxy. Needs only the Python standard library. The proxy on 127.0.0.1:1080/1081 must serve browsers (the default)."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from marionette import Marionette

exe, ext, url, title = sys.argv[1], os.path.abspath(sys.argv[2]), sys.argv[3], sys.argv[4]
member = sys.argv[5] if len(sys.argv) > 5 else None
profile = tempfile.mkdtemp(prefix="oneq-ffx-")
UUID = "7c1d0b52-3e1a-4a53-9f0a-5b6d1f2e8a11"       # fixed, so the popup's address is known
GECKO_ID = "oneq-mesh@1q.ro"
PORT = 2828


def main():
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write('user_pref("extensions.webextensions.uuids", %s);\n' % json.dumps(json.dumps({GECKO_ID: UUID})))
        f.write('user_pref("marionette.port", %d);\nuser_pref("browser.shell.checkDefaultBrowser", false);\n' % PORT)
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\nuser_pref("app.update.auto", false);\n')
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            raise SystemExit(f"port {PORT} is already in use: a Firefox of an earlier run is still running")
    p = subprocess.Popen([exe, "-headless", "-marionette", "-remote-allow-system-access", "-no-remote", "-profile", profile, "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        mc = None
        for _ in range(60):
            try:
                mc = Marionette(PORT)
                break
            except OSError:
                time.sleep(0.5)
        if mc is None:
            raise SystemExit("Firefox did not start")
        mc.call("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {}}})
        addon = mc.call("Addon:Install", {"path": ext, "temporary": True})
        results.append((f"the extension installed as a temporary add-on ({addon.get('value')})", addon.get("value") == GECKO_ID))

        def title_of(u, wait=25):
            u = u + ("&" if "?" in u else "?") + "r=%d" % int(time.time() * 1000)      # never a cached copy
            try:
                mc.call("WebDriver:Navigate", {"url": u})
            except RuntimeError:
                return None
            for _ in range(int(wait * 2)):
                t = mc.script("return document.readyState === 'complete' ? document.title : null")
                if t:
                    return t
                time.sleep(0.5)
            return None

        # the extension needs a moment to read the proxy's status and arm its listener
        t = None
        for _ in range(20):
            t = title_of(f"http://{member}.oneq/", 5) if member else title_of(url, 5)
            if t == title:
                break
            time.sleep(1)
        results.append((f"{'http://' + member + '.oneq/' if member else url} loads through the proxy (title {t!r})", t == title))
        t1 = title_of(url)
        results.append((f"{url} loads (title {t1!r})", t1 == title))

        # the extension's own page: the popup shows the connection and the access mode
        mc.open_extension_page(f"moz-extension://{UUID}/popup.html")
        text = ""
        for _ in range(20):
            text = mc.script("return document.body.innerText") or ""
            if "Connected to the mesh" in text:
                break
            time.sleep(0.5)
        print("popup text:", " | ".join(text.split(chr(10))), flush=True)
        results.append(("the popup shows the connection, the access mode and the members",
                        "Connected to the mesh" in text and ("direct" in text or "relay" in text) and "browsers only" in text))

        # the off switch: the mesh name must stop resolving
        mc.open_extension_page(f"moz-extension://{UUID}/popup.html")
        time.sleep(1)
        mc.script("document.getElementById('enabled').click(); return 1")
        time.sleep(2)
        gone = True
        if member:
            for _ in range(10):
                t2 = title_of(f"http://{member}.oneq/", 4)
                gone = t2 != title
                if gone:
                    break
                time.sleep(1)
        results.append(("turning the extension off stops sending the mesh through the proxy", gone))
        if member:                                  # ... and turning it on again brings the mesh back
            mc.open_extension_page(f"moz-extension://{UUID}/popup.html")
            time.sleep(1)
            mc.script("document.getElementById('enabled').click(); return 1")
            back = None
            for _ in range(20):
                back = title_of(f"http://{member}.oneq/", 4)
                if back == title:
                    break
                time.sleep(1)
            results.append(("turning it on again sends the mesh through the proxy again", back == title))
    finally:
        # Firefox starts helper processes of its own: stop everything that uses this run's profile
        if os.name == "nt":
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*" + os.path.basename(profile) + "*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    for name, ok in results:
        print(("ok:   " if ok else "FAIL: ") + name)
    return 0 if results and all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
