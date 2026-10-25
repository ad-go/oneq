"""Test of the native messaging host on macOS/Linux (standard library only; no browser needed):
  python3 native_host_unix_test.py ONEQCLIENT RELAY_URL CA_FILE COMMUNITY USER PASSWORD_FILE
Runs `oneqclient native-host` on stdin/stdout with a throw-away HOME, like a browser would: hello, get, set, start; checks the proxy it starts (own process, the
password on no command line, ends with --exit-with-pid), that closing stdin stops it, that killing the host abruptly still ends it, and the registration of the host
manifests for browsers found in a fake home. Needs a reachable relay with the given account and ports 1080/1081 free."""
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

client, relay, cafile, community, user, pwfile = sys.argv[1:7]
password = open(pwfile, encoding="utf-8").read().strip()
ca_pem = open(cafile, encoding="utf-8").read()
home = tempfile.mkdtemp(prefix="oneq-nh-home-")
env = dict(os.environ, HOME=home)
env.pop("XDG_CONFIG_HOME", None)
results = []


def ok(name, cond):
    results.append((name, bool(cond)))


def port_open(p):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", p)) == 0


def proxies():
    out = subprocess.run(["ps", "-axo", "pid=,args="], capture_output=True, text=True).stdout
    return [l.strip() for l in out.splitlines() if " proxy " in l and "--exit-with-pid" in l and home in l]


class Host:
    def __init__(self):
        self.p = subprocess.Popen([client, "native-host"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.n = 0

    def call(self, cmd, **kw):
        self.n += 1
        body = json.dumps(dict(id=self.n, cmd=cmd, **kw)).encode()
        self.p.stdin.write(struct.pack("<I", len(body)) + body)
        self.p.stdin.flush()
        n = struct.unpack("<I", self.p.stdout.read(4))[0]
        r = json.loads(self.p.stdout.read(n))
        assert r["id"] == self.n
        return r


def main():
    for p in (1080, 1081):
        if port_open(p):
            raise SystemExit(f"port {p} is in use")
    h = Host()
    r = h.call("hello")
    ok(f"hello ({r.get('host')} {r.get('version')} on {r.get('os')})", r["ok"] and r["host"] == "ro.1q.oneq")
    r = h.call("get")
    ok("a new host has nothing configured", r["ok"] and not r["complete"] and not r["has_password"])
    r = h.call("start")
    ok("start without settings is refused with a message", not r["ok"] and "not set up" in r["error"])
    r = h.call("set", config={"relays": [relay], "community": community, "user": user, "name": "unix-test", "ca_pem": ca_pem}, password=password)
    ok("set stores the settings and the password, never returns it", r["ok"] and r["complete"] and password not in json.dumps(r))
    pw_file = os.path.join(home, ".config", "oneq", "browser.pass")
    ok("the password file is readable by this user only (0600)", os.path.exists(pw_file) and (os.stat(pw_file).st_mode & 0o077) == 0)
    r = h.call("start")
    ok("start runs the proxy", r["ok"] and r["running"])
    up = False
    for _ in range(60):
        if port_open(1080) and port_open(1081):
            up = True
            break
        time.sleep(0.5)
    ok("the SOCKS5 and status ports are open", up)
    ps = proxies()
    ok(f"one proxy process, with --exit-with-pid and without the password on its command line ({len(ps)})",
       len(ps) == 1 and password not in ps[0] and "--password-file" in ps[0] and f"--exit-with-pid {h.p.pid}" in ps[0])
    # closing the pipe is what a browser does when it exits: the proxy must go with it
    h.p.stdin.close()
    h.p.wait(10)
    gone = False
    for _ in range(40):
        if not proxies() and not port_open(1080):
            gone = True
            break
        time.sleep(0.5)
    ok("closing the host's stdin (the browser exits) stops the proxy and frees the ports", gone)

    # the host is killed abruptly: the proxy notices by itself
    h2 = Host()
    h2.call("start")
    for _ in range(40):
        if port_open(1080):
            break
        time.sleep(0.5)
    pid = h2.p.pid
    os.kill(pid, signal.SIGKILL)
    h2.p.wait(10)
    gone = False
    for _ in range(40):
        if not proxies() and not port_open(1080):
            gone = True
            break
        time.sleep(0.5)
    ok("killing the host abruptly still ends the proxy (--exit-with-pid)", gone)

    # registration of the manifests in a fake home
    fake = tempfile.mkdtemp(prefix="oneq-nh-fake-")
    base = os.path.join(fake, "Library/Application Support") if sys.platform == "darwin" else fake
    dirs = {"brave": "BraveSoftware/Brave-Browser", "chrome": "Google/Chrome", "firefox": "Mozilla"} if sys.platform == "darwin" else \
           {"brave": ".config/BraveSoftware/Brave-Browser", "chrome": ".config/google-chrome", "firefox": ".mozilla"}
    for d in dirs.values():
        os.makedirs(os.path.join(base if sys.platform == "darwin" else fake, d))
    fenv = dict(env, HOME=fake)
    out = subprocess.run([client, "native-host", "install", "--extension-id", "a" * 32], capture_output=True, text=True, env=fenv).stdout
    nm = lambda b, name: os.path.join(base if sys.platform == "darwin" else fake, dirs[b], "NativeMessagingHosts" if name != "firefox" or sys.platform == "darwin" else "native-messaging-hosts", "ro.1q.oneq.json")
    chrome_m = json.load(open(nm("chrome", "chrome")))
    ff_m = json.load(open(nm("firefox", "firefox")))
    ok("install writes the Chromium manifest with the dev id and the given id", chrome_m["allowed_origins"] == ["chrome-extension://" + "a" * 32 + "/"] and chrome_m["type"] == "stdio"
       and os.path.samefile(chrome_m["path"], client))
    ok("install writes the Firefox manifest with the add-on id", ff_m["allowed_extensions"] == ["oneq-mesh@1q.ro"])
    ok("install skips the browsers that are not there", "edge: not installed" in out and os.path.exists(nm("brave", "brave")))
    subprocess.run([client, "native-host", "uninstall"], capture_output=True, text=True, env=fenv)
    ok("uninstall removes the registrations", not os.path.exists(nm("chrome", "chrome")) and not os.path.exists(nm("firefox", "firefox")))
    shutil.rmtree(fake, ignore_errors=True)


try:
    main()
except BaseException as e:
    results.append((f"aborted: {type(e).__name__}: {str(e)[:160]}", False))
finally:
    for l in proxies():
        try:
            os.kill(int(l.split()[0]), signal.SIGKILL)
        except Exception:
            pass
    shutil.rmtree(home, ignore_errors=True)
for name, good in results:
    print(("ok:   " if good else "FAIL: ") + name)
sys.exit(0 if all(g for _, g in results) else 1)
