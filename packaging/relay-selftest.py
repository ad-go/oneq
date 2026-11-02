"""Checks a running relay that was set up with `oneqrelay init` (Windows/macOS bundles, or any directory), from the same machine:
TLS 1.3 X25519MLKEM768 with the generated CA, /v1/health, the STUN service on its three UDP ports, and the admin page login with the
operator password plus a code computed from the TOTP secret. Prints results only, never the secrets.
usage: python relay-selftest.py RELAY_DIR [HOST] [PORT]    (run with the bundled Python, next to the relay modules)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqtls  # noqa: E402,F401  (before ssl)

import json  # noqa: E402
import socket  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

import oneqnat  # noqa: E402
import oneqtotp  # noqa: E402

d = sys.argv[1]
host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443
base = f"https://{host}:{port}"
ctx = pqtls.client_context(os.path.join(d, "ca.crt"))
results = []


def call(method, path, body=None, tok=None):
    req = urllib.request.Request(base + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {})}, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:80]


st, h = call("GET", "/v1/health")
results.append(("TLS 1.3 PQ handshake with the generated CA, /v1/health", st == 200))
for off in (0, 1, 2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(oneqnat.binding_request()[0], (host, port + off))
        m = oneqnat.parse(s.recvfrom(2048)[0])
        ok = oneqnat.mapped_of(m) is not None
    except OSError:
        ok = False
    results.append((f"STUN answers on UDP {port + off}", ok))
if os.path.exists(os.path.join(d, "admin.pw")):
    pw = open(os.path.join(d, "admin.pw")).read().strip()
    secret = json.load(open(os.path.join(d, "admin.totp")))["secret"]
    st, i = call("GET", "/admin/api/info")
    results.append(("admin page asks for the second factor", st == 200 and i == {"two_factor": True}))
    st, _ = call("POST", "/admin/api/login", {"password": pw})
    results.append(("password alone refused", st == 401))
    st, t = call("POST", "/admin/api/login", {"password": pw, "code": oneqtotp.totp_now(secret)})
    results.append(("password + authenticator code accepted", st == 200 and "token" in t))
    st, o = call("GET", "/admin/api/overview", tok=t.get("token") if isinstance(t, dict) else None)
    results.append(("overview with the token", st == 200))
for name, ok in results:
    print(("ok:   " if ok else "FAIL: ") + name)
sys.exit(0 if all(ok for _, ok in results) else 1)
