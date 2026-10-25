"""Minimal Marionette client (Firefox's automation protocol: `NNN:` + JSON over TCP), standard library only."""
import json
import socket


class Marionette:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), 10)
        self.s.settimeout(60)
        self.id = 0
        self._read()                                                    # the greeting

    def _read(self):
        head = b""
        while not head.endswith(b":"):
            c = self.s.recv(1)
            if not c:
                raise ConnectionError("Marionette closed")
            head += c
        n = int(head[:-1])
        data = b""
        while len(data) < n:
            data += self.s.recv(n - len(data))
        return json.loads(data)

    def call(self, name, params=None):
        self.id += 1
        body = json.dumps([0, self.id, name, params or {}]).encode()
        self.s.sendall(str(len(body)).encode() + b":" + body)
        while True:
            m = self._read()
            if isinstance(m, list) and m[0] == 1 and m[1] == self.id:
                if m[2]:
                    raise RuntimeError(f"{name}: {m[2].get('error')}: {str(m[2].get('message'))[:160]}")
                return m[3]

    def script(self, js):
        r = self.call("WebDriver:ExecuteScript", {"script": js, "args": []})
        return r.get("value") if isinstance(r, dict) else r

    def open_extension_page(self, url):
        """Recent Firefox builds refuse WebDriver:Navigate to moz-extension: pages. Load the page the way the browser's own UI does: in the chrome context,
        with the system principal."""
        try:
            self.call("WebDriver:Navigate", {"url": url})
            return
        except RuntimeError:
            pass
        self.call("Marionette:SetContext", {"value": "chrome"})
        try:
            self.call("WebDriver:ExecuteScript", {"script": "const u = arguments[0]; gBrowser.selectedBrowser.fixupAndLoadURIString(u, "
                      "{ triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() }); return 1;", "args": [url]})
        finally:
            self.call("Marionette:SetContext", {"value": "content"})
