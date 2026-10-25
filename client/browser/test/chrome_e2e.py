"""End-to-end test of the extension in a real Chromium browser (Chrome or Brave) against a running `oneqclient proxy`:
  python chrome_e2e.py BROWSER_EXE MESH_URL EXPECTED_TITLE [MEMBER_NAME]
Starts the browser with a throw-away profile and the unpacked extension, waits until the extension has set the PAC script, loads the mesh page
(title must match), loads it by name (http://MEMBER_NAME.oneq/), renders the popup, then turns the extension off and checks the proxy is released.
Needs aiohttp (any Python with it). Needs the proxy on 127.0.0.1:1080/1081 and no other route to the mesh addresses to prove the path."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

import aiohttp

exe, url, title = sys.argv[1], sys.argv[2], sys.argv[3]
member = sys.argv[4] if len(sys.argv) > 4 else None
ext = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "extension"))
profile = tempfile.mkdtemp(prefix="oneq-chrome-")
PORT = 9339


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


async def main():
    import socket
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            raise SystemExit(f"port {PORT} is already in use: a browser of an earlier run is still running (it would be tested instead of this one)")
    p = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
                          f"--load-extension={ext}", "--disable-features=DisableLoadExtensionCommandLineSwitch", "--enable-unsafe-extension-debugging", "about:blank"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        async with aiohttp.ClientSession() as http:
            for _ in range(60):
                try:
                    async with http.get(f"http://127.0.0.1:{PORT}/json/version") as r:
                        if r.status == 200:
                            break
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.5)
            else:
                raise SystemExit("the browser did not start")
            # recent Chrome builds ignore --load-extension: load it through the DevTools protocol (needs --enable-unsafe-extension-debugging)
            async with http.get(f"http://127.0.0.1:{PORT}/json/version") as r:
                browser_ws = (await r.json())["webSocketDebuggerUrl"]
            async with http.ws_connect(browser_ws) as bws:
                try:
                    await asyncio.wait_for(cdp(bws, "Extensions.loadUnpacked", {"path": ext}), 10)
                except (RuntimeError, asyncio.TimeoutError) as e:
                    print("Extensions.loadUnpacked:", e or "no answer (the browser uses --load-extension instead)", flush=True)
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
                raise SystemExit("the extension's service worker did not start (extension not loaded?)")
            ext_id = sw["url"].split("/")[2]
            results.append(("the extension loaded (service worker running)", True))
            async with http.ws_connect(sw["webSocketDebuggerUrl"]) as ws:
                set_ok = False
                for _ in range(40):
                    v = await evaluate(ws, "new Promise(r => chrome.proxy.settings.get({}, d => r(JSON.stringify(d))))")
                    d = json.loads(v)
                    if d.get("value", {}).get("mode") == "pac_script" and d["levelOfControl"] == "controlled_by_this_extension":
                        set_ok = True
                        pac = d["value"]["pacScript"]["data"]
                        break
                    await asyncio.sleep(0.5)
                results.append(("the extension set the PAC script from the running proxy's status", set_ok))
                if set_ok:
                    # the proxy serves browsers only: the subnet is read by the browser (the extension's worker), not by this script
                    net = (await evaluate(ws, "fetch('http://127.0.0.1:1081/status').then(r => r.json()).then(j => j.proxy.subnet)")).split("/")[0]
                    results.append((f"the PAC script names the mesh subnet ({net})", net in pac and "SOCKS5 127.0.0.1:1080" in pac))
                    import urllib.request
                    try:
                        urllib.request.urlopen("http://127.0.0.1:1081/status", timeout=5)
                        refused = False
                    except Exception:
                        refused = True
                    results.append(("a program that is not a browser (this script) is refused by the status page", refused))

                async def page_title(u, wait=25):
                    async with http.put(f"http://127.0.0.1:{PORT}/json/new?{u}") as r:
                        tgt = await r.json()
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
                t = await page_title(url)
                results.append((f"{url} loads through the proxy (title {t!r})", t == title))
                if member:
                    t2 = await page_title(f"http://{member}.oneq/")
                    results.append((f"http://{member}.oneq/ resolves by member name (title {t2!r})", t2 == title))
                # popup
                async with http.put(f"http://127.0.0.1:{PORT}/json/new?chrome-extension://{ext_id}/popup.html") as r:
                    tgt = await r.json()
                async with http.ws_connect(tgt["webSocketDebuggerUrl"]) as pws:
                    text = ""
                    for _ in range(20):
                        text = await evaluate(pws, "document.body.innerText", False) or ""
                        if "Connected to the mesh" in text:
                            break
                        await asyncio.sleep(0.5)
                    print("popup text:", " | ".join(text.split(chr(10))), flush=True)
                    results.append(("the popup shows the connection, the access mode and the members", "Connected to the mesh" in text and ("direct" in text or "relay" in text) and "browsers only" in text))
                # off switch releases the proxy
                await evaluate(ws, "chrome.storage.local.set({enabled:false}).then(() => 1)")   # what the popup's switch does
                released = False
                for _ in range(20):
                    v = json.loads(await evaluate(ws, "new Promise(r => chrome.proxy.settings.get({}, d => r(JSON.stringify(d))))"))
                    if v.get("levelOfControl") != "controlled_by_this_extension":
                        released = True
                        break
                    await asyncio.sleep(0.5)
                results.append(("turning the extension off gives the proxy settings back", released))
    finally:
        if os.name == "nt":
            # Chromium re-launches itself, so the process we started is not the browser, and the helpers (and the debugging port) outlive it:
            # stop every process that was started with this run's throw-away profile
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
    return all(ok for _, ok in results)


sys.exit(0 if asyncio.run(main()) else 1)
