"""End-to-end test of the connection manager in a real Chromium browser (Chrome, Brave): the extension ALONE sets up and runs the connection.
  python chrome_native_e2e.py BROWSER_EXE RELAY_URL CA_FILE COMMUNITY USER PASSWORD_FILE MESH_TITLE MEMBER_NAME
Needs: `oneqclient native-host install` done for this browser (the host registration), the relay and the member reachable, no proxy running on 1080/1081.
Starts the browser with a throw-away profile, loads the extension, fills the form of its options page and presses "Save and connect"; then checks that the
mesh page opens by member name, that no secret is in the extension's storage or on a command line, that other programs are refused, that the popup's button
disconnects and reconnects, and that the proxy is gone once the browser is. Needs aiohttp (any Python with it). Windows (process checks use PowerShell)."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import aiohttp

exe, relay, cafile, community, user, pwfile, title, member = sys.argv[1:9]
password = open(pwfile, encoding="utf-8").read().strip()
ca_pem = open(cafile, encoding="utf-8").read()
ext = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "extension"))
EXT_ID = "bgmdbjhjoieanbojmbkjpcdmkmofikoo"
profile = tempfile.mkdtemp(prefix="oneq-chrome-")
PORT = 9339


def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True).stdout.strip()


def proxy_procs():
    out = ps("Get-CimInstance Win32_Process -Filter \"Name='oneqclient.exe'\" | Where-Object { $_.CommandLine -match ' proxy ' } | ForEach-Object { '' + $_.ProcessId + '|' + $_.CommandLine }")
    return [l for l in out.splitlines() if "|" in l]


def port_open(p):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", p)) == 0


async def cdp(ws, method, params=None, _id=[0]):
    _id[0] += 1
    await ws.send_json({"id": _id[0], "method": method, "params": params or {}})
    while True:
        m = await ws.receive_json()
        if m.get("id") == _id[0]:
            if "error" in m:
                raise RuntimeError(f"{method}: {m['error']}")
            return m.get("result", {})


async def evaluate(ws, expr, await_promise=True):
    r = await cdp(ws, "Runtime.evaluate", {"expression": expr, "awaitPromise": await_promise, "returnByValue": True})
    if "exceptionDetails" in r:
        raise RuntimeError(r["exceptionDetails"].get("text", "") + str(r["exceptionDetails"].get("exception", {}).get("description", "")))
    return r["result"].get("value")


results = []


async def main():
    for p in (1080, 1081):
        if port_open(p):
            raise SystemExit(f"port {p} is already in use: stop the running proxy first (the test must start it through the extension)")
        if port_open(PORT):
            raise SystemExit(f"port {PORT} is already in use: a browser of an earlier run is still running")
    p = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
                          "--enable-unsafe-extension-debugging", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        async with aiohttp.ClientSession() as http:
            for _ in range(60):
                try:
                    async with http.get(f"http://127.0.0.1:{PORT}/json/version") as r:
                        if r.status == 200:
                            browser_ws = (await r.json())["webSocketDebuggerUrl"]
                            break
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.5)
            else:
                raise SystemExit("the browser did not start")
            async with http.ws_connect(browser_ws) as bws:
                r = await asyncio.wait_for(cdp(bws, "Extensions.loadUnpacked", {"path": ext}), 15)
            results.append((f"the extension loaded with the fixed id ({r.get('id')})", r.get("id") == EXT_ID))
            sw = None
            for _ in range(40):
                async with http.get(f"http://127.0.0.1:{PORT}/json/list") as r:
                    for t in await r.json():
                        if t["type"] == "service_worker" and t["url"].endswith("/background.js"):
                            sw = t
                if sw:
                    break
                await asyncio.sleep(0.5)
            if not sw:
                raise SystemExit("the extension's service worker did not start")

            async def page(u):
                async with http.put(f"http://127.0.0.1:{PORT}/json/new?{u}") as r:
                    tgt = await r.json()
                return tgt

            async def page_title(u, wait=25):
                tgt = await page(u)
                async with http.ws_connect(tgt["webSocketDebuggerUrl"]) as pws:
                    for _ in range(int(wait * 2)):
                        try:
                            t = await evaluate(pws, "document.readyState === 'complete' ? document.title : null", False)
                        except RuntimeError:
                            t = None
                        if t:
                            return t
                        await asyncio.sleep(0.5)
                return None

            async with http.ws_connect(sw["webSocketDebuggerUrl"]) as ws:
                # 1. the connection manager is found, nothing is set up yet
                s0 = json.loads(await evaluate(ws, "state().then(s => JSON.stringify({native: s.native, running: s.running}))"))
                results.append(("the extension finds the connection manager (native host)", s0["native"]["available"] is True and s0["native"]["data"] is not None))
                results.append(("nothing is running before the setup", not s0["running"] and not port_open(1080)))

                # 2. the form of the options page: this is what a user does
                tgt = await page(f"chrome-extension://{EXT_ID}/options.html")
                async with http.ws_connect(tgt["webSocketDebuggerUrl"]) as ows:
                    await asyncio.sleep(1.5)
                    fill = ("(() => { const v = (id, x) => { document.getElementById(id).value = x; };"
                            " v('relays', @RELAY@); v('community', @COMM@); v('user', @USER@); v('password', @PW@);"
                            " v('name', 'e2e-browser'); v('ca', @CA@); document.getElementById('connect').click(); return 1; })()")
                    for k, val in (("@RELAY@", relay), ("@COMM@", community), ("@USER@", user), ("@PW@", password), ("@CA@", ca_pem)):
                        fill = fill.replace(k, json.dumps(val))
                    await evaluate(ows, fill, False)
                    msg = ""
                    for _ in range(20):
                        msg = await evaluate(ows, "document.getElementById('connmsg').textContent", False)
                        if msg.startswith("Saved") or "not" in msg.lower() or "error" in msg.lower():
                            break
                        await asyncio.sleep(0.5)
                    results.append((f"the options form saved the connection ({msg!r})", msg.startswith("Saved")))
                    pwleft = await evaluate(ows, "document.getElementById('password').value", False)
                    results.append(("the password field is emptied after saving", pwleft == ""))

                # 3. the proxy comes up and joins the mesh
                up = None
                for _ in range(80):
                    st = json.loads(await evaluate(ws, "state().then(s => JSON.stringify({running: s.running, control: s.control, snap: s.status && s.status.snapshot && s.status.snapshot.state, pac: s.pacSig, nrun: s.native.data && s.native.data.running}))"))
                    if st["running"] and st["snap"] == "connected" and st["pac"]:
                        up = st
                        break
                    await asyncio.sleep(0.5)
                results.append((f"the proxy started by the connection manager joined the mesh and the PAC script is set ({up})", up is not None))

                t = None
                for _ in range(10):          # the session with the member may still be coming up: reload, as a user would
                    t = await page_title(f"http://{member}.oneq/", 6)
                    if t == title:
                        break
                    await asyncio.sleep(2)
                results.append((f"http://{member}.oneq/ opens through the proxy the extension started (title {t!r})", t == title))

                # 4. secrets
                store = json.dumps(json.loads(await evaluate(ws, "chrome.storage.local.get(null).then(v => JSON.stringify(v))")))
                results.append(("the password is not in the extension's storage", password not in store and ca_pem not in store))
                procs = proxy_procs()
                results.append((f"the proxy runs once, with --exit-with-pid and without the password on its command line ({len(procs)} process)",
                                len(procs) == 1 and "--exit-with-pid" in procs[0] and password not in procs[0] and "--password-file" in procs[0]))
                try:
                    urllib.request.urlopen("http://127.0.0.1:1081/status", timeout=5)
                    refused = False
                except Exception:
                    refused = True
                results.append(("a program that is not a browser is refused by the proxy", refused))

                # 5. the popup's button disconnects and connects again
                tgt = await page(f"chrome-extension://{EXT_ID}/popup.html")
                async with http.ws_connect(tgt["webSocketDebuggerUrl"]) as pws:
                    async def button():
                        for _ in range(30):
                            try:
                                t = await evaluate(pws, "(() => { const b = document.getElementById('connbtn'); return !b || b.hidden ? '' : b.textContent; })()", False)
                            except RuntimeError:
                                t = ""
                            if t:
                                return t
                            await asyncio.sleep(0.5)
                        return ""
                    b1 = await button()
                    await evaluate(pws, "document.getElementById('connbtn').click(); 1", False)
                    gone = False
                    for _ in range(30):
                        if not port_open(1080):
                            gone = True
                            break
                        await asyncio.sleep(0.5)
                    results.append((f"the popup button ({b1!r}) disconnects: the SOCKS port closes", b1 == "Disconnect" and gone))
                    b2 = ""
                    for _ in range(30):
                        b2 = await button()
                        if b2 == "Connect":
                            break
                        await asyncio.sleep(0.5)
                    await evaluate(pws, "document.getElementById('connbtn').click(); 1", False)
                    back = None
                    for _ in range(80):
                        st = json.loads(await evaluate(ws, "state().then(s => JSON.stringify({running: s.running, snap: s.status && s.status.snapshot && s.status.snapshot.state}))"))
                        if st["running"] and st["snap"] == "connected":
                            back = st
                            break
                        await asyncio.sleep(0.5)
                    results.append((f"the button ({b2!r}) connects again", b2 == "Connect" and back is not None))
                t = None
                for _ in range(10):          # the session with the member comes up again after a reconnect: reload, as a user would
                    t = await page_title(f"http://{member}.oneq/", 6)
                    if t == title:
                        break
                    await asyncio.sleep(2)
                results.append((f"the mesh opens again after reconnecting (title {t!r})", t == title))
    finally:
        # the browser goes away: stop every process of this run's profile
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
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    except BaseException as e:
        for name, ok in results:
            print(("ok:   " if ok else "FAIL: ") + name)
        print("ABORTED:", type(e).__name__, str(e)[:200])
        code = 1
    sys.exit(code)
