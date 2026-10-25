"""End-to-end test of the connection manager in a real Firefox: the extension ALONE sets up and runs the connection (same checks as chrome_native_e2e.py).
  python firefox_native_e2e.py FIREFOX_EXE EXTENSION_ZIP RELAY_URL CA_FILE COMMUNITY USER PASSWORD_FILE MESH_TITLE MEMBER_NAME
Needs `oneqclient native-host install` (the host registration for Firefox), the relay and the member reachable, no proxy on 1080/1081. Windows (PowerShell for the
process checks). The extension is installed as a temporary add-on (no signature needed for that)."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from marionette import Marionette

exe, ext, relay, cafile, community, user, pwfile, title, member = sys.argv[1:10]
ext = os.path.abspath(ext)
password = open(pwfile, encoding="utf-8").read().strip()
ca_pem = open(cafile, encoding="utf-8").read()
profile = tempfile.mkdtemp(prefix="oneq-ffx-")
UUID = "7c1d0b52-3e1a-4a53-9f0a-5b6d1f2e8a11"
GECKO_ID = "k@1q.ro"
PORT = 2828
results = []


def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True).stdout.strip()


def proxy_procs():
    out = ps("Get-CimInstance Win32_Process -Filter \"Name='oneqclient.exe'\" | Where-Object { $_.CommandLine -match ' proxy ' } | ForEach-Object { '' + $_.ProcessId + '|' + $_.CommandLine }")
    return [l for l in out.splitlines() if "|" in l]


def port_open(p):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", p)) == 0


def main():
    for p in (1080, 1081, PORT):
        if port_open(p):
            raise SystemExit(f"port {p} is already in use (a proxy or a Firefox of an earlier run)")
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write('user_pref("extensions.webextensions.uuids", %s);\n' % json.dumps(json.dumps({GECKO_ID: UUID})))
        f.write('user_pref("marionette.port", %d);\nuser_pref("browser.shell.checkDefaultBrowser", false);\n' % PORT)
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\nuser_pref("app.update.auto", false);\n')
    subprocess.Popen([exe, "-headless", "-marionette", "-remote-allow-system-access", "-no-remote", "-profile", profile, "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    def title_of(u, wait=8):
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

    # the form of the options page (Firefox does not let automation go to an extension page straight from about:blank: visit an ordinary page first)
    # (the test mesh's web node is reachable directly here, which is all this needs; a real page is required, an error page does not count)
    webip = open(os.path.join(os.path.dirname(pwfile), "webip"), encoding="ascii").read().strip()
    title_of(f"http://{webip}/", 8)
    mc.open_extension_page(f"moz-extension://{UUID}/options.html")
    time.sleep(2)
    note = mc.script("return document.getElementById('hostnote').hidden ? '' : document.getElementById('hostnote').textContent")
    results.append((f"the extension finds the connection manager (no 'not installed' notice: {note!r})", note == ""))
    fill = ("const v = (id, x) => { document.getElementById(id).value = x; };"
            " v('relays', @RELAY@); v('community', @COMM@); v('user', @USER@); v('password', @PW@); v('name', 'e2e-firefox'); v('ca', @CA@);"
            " document.getElementById('connect').click(); return 1;")
    for k, val in (("@RELAY@", relay), ("@COMM@", community), ("@USER@", user), ("@PW@", password), ("@CA@", ca_pem)):
        fill = fill.replace(k, json.dumps(val))
    mc.script(fill)
    msg = ""
    for _ in range(40):
        msg = mc.script("return document.getElementById('connmsg').textContent") or ""
        if msg.startswith("Saved") or "not" in msg.lower() or "error" in msg.lower():
            break
        time.sleep(0.5)
    results.append((f"the options form saved the connection ({msg!r})", msg.startswith("Saved")))
    results.append(("the password field is emptied after saving", mc.script("return document.getElementById('password').value") == ""))

    t = None
    for _ in range(20):
        t = title_of(f"http://{member}.oneq/", 6)
        if t == title:
            break
        time.sleep(2)
    results.append((f"http://{member}.oneq/ opens through the proxy the extension started (title {t!r})", t == title))

    procs = proxy_procs()
    results.append((f"the proxy runs once, with --exit-with-pid and without the password on its command line ({len(procs)} process)",
                    len(procs) == 1 and "--exit-with-pid" in procs[0] and password not in procs[0] and "--password-file" in procs[0]))
    try:
        urllib.request.urlopen("http://127.0.0.1:1081/status", timeout=5)
        refused = False
    except Exception:
        refused = True
    results.append(("a program that is not a browser is refused by the proxy", refused))

    # the popup's button disconnects and connects again
    mc.open_extension_page(f"moz-extension://{UUID}/popup.html")
    def button():
        for _ in range(30):
            t = mc.script("const b = document.getElementById('connbtn'); return !b || b.hidden ? '' : b.textContent;") or ""
            if t:
                return t
            time.sleep(0.5)
        return ""
    b1 = button()
    mc.script("document.getElementById('connbtn').click(); return 1;")
    gone = False
    for _ in range(30):
        if not port_open(1080):
            gone = True
            break
        time.sleep(0.5)
    results.append((f"the popup button ({b1!r}) disconnects: the SOCKS port closes", b1 == "Disconnect" and gone))
    b2 = ""
    for _ in range(30):
        b2 = button()
        if b2 == "Connect":
            break
        time.sleep(0.5)
    mc.script("document.getElementById('connbtn').click(); return 1;")
    t = None
    for _ in range(20):
        t = title_of(f"http://{member}.oneq/", 6)
        if t == title:
            break
        time.sleep(2)
    results.append((f"the button ({b2!r}) connects again and the mesh opens (title {t!r})", b2 == "Connect" and t == title))


try:
    main()
except BaseException as e:
    results.append((f"aborted: {type(e).__name__}: {str(e)[:160]}", False))
finally:
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*" + os.path.basename(profile) + "*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ended = False
for _ in range(40):
    if not proxy_procs() and not port_open(1080) and not port_open(1081):
        ended = True
        break
    time.sleep(0.5)
results.append(("the proxy and its ports are gone when the browser is (the SOCKS5 port lives only as long as the browser session)", ended))
for name, ok in results:
    print(("ok:   " if ok else "FAIL: ") + name)
sys.exit(0 if all(ok for _, ok in results) else 1)
