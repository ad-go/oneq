#!/usr/bin/env python3
"""End-to-end test with real TUN devices in separate network namespaces. Needs root + Linux.

    sudo /opt/oneq-src/venv/bin/python test_e2e.py

Topology (everything lives in private namespaces; the host network is not touched):

    pqA --vAS--[10.77.1.0/24]--vSA-- pqS (rendezvous server 8443) --vSB--[10.77.2.0/24]--vBS-- pqB
    pqA --vAB--[10.77.3.0/24]--vBA-- pqB                      (optional direct link, can be set down)

The nodes only know each other's public key and the rendezvous URL. TCP traffic runs over the
tunnel (10.99.0.1 <-> 10.99.0.2). A raw-socket sniffer on node A's physical interfaces proves
the payload never appears in clear text and shows which path was used.
Uses `nsenter --net` instead of `ip netns exec` (which needs a sysfs remount, unavailable in containers).
"""
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
NS = {"A": "pqA", "B": "pqB", "S": "pqS"}
CERT_IPS = ["10.77.1.254", "10.77.2.254"]
MARKER = b"TOP-SECRET-ONEQ-MARKER-" + os.urandom(8).hex().encode()


def sh(*cmd, ns=None, check=True, **kw):
    if ns:
        cmd = ("nsenter", f"--net=/run/netns/{NS[ns]}") + cmd
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


def popen(*cmd, ns=None, log=None):
    if ns:
        cmd = ("nsenter", f"--net=/run/netns/{NS[ns]}") + cmd
    f = open(log, "wb") if log else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid)


def make_cert(d, ips):
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rv.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(i)) for i in ips]), False)
            .sign(key, hashes.SHA256()))
    c, k = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    with open(c, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(k, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return c, k


# ---------------------------------------------------------------- sniffer (runs inside a namespace)

def sniff_main(iface, out):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, 3))      # ETH_P_ALL; protocol 0 would not re-attach when the interface comes back up
    f = open(out, "wb", buffering=0)
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        d = s.recv(65535)
        f.write(struct.pack(">I", len(d)) + d)


def read_frames(path):
    data = open(path, "rb").read()
    o, frames = 0, []
    while o + 4 <= len(data):
        n = struct.unpack(">I", data[o:o + 4])[0]
        frames.append(data[o + 4:o + 4 + n])
        o += 4 + n
    return frames


def summarize(frames):
    """-> dict(udp51820=..., udp_data=..., tcp8443=..., total=...)"""
    r = {"total": len(frames), "udp51820": 0, "udp_data": 0, "udp_frag": 0, "tcp8443": 0}
    for fr in frames:
        if len(fr) < 34 or fr[12:14] != b"\x08\x00":
            continue
        ihl = (fr[14] & 0x0F) * 4
        proto, l4 = fr[23], fr[14 + ihl:]
        if proto == 17 and len(l4) >= 9:
            sp, dp = struct.unpack(">HH", l4[:4])
            if 51820 in (sp, dp):
                r["udp51820"] += 1
                r["udp_data"] += l4[8] == 0x13
                r["udp_frag"] += l4[8] == 0x15
        elif proto == 6 and len(l4) >= 4 and 8443 in struct.unpack(">HH", l4[:4]):
            r["tcp8443"] += 1
    return r


# ---------------------------------------------------------------- tunnel traffic helpers

ECHO_SERVER = """
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.99.0.2", 5001)); s.listen(4)
while True:
    c, _ = s.accept()
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
"""

ECHO_CLIENT = """
import socket, sys, hashlib
marker = sys.argv[1].encode()
payload = (marker + b" ") * (262144 // (len(marker) + 1))
c = socket.create_connection(("10.99.0.2", 5001), timeout=15)
c.settimeout(15)
import threading
def tx(): c.sendall(payload); c.shutdown(socket.SHUT_WR)
threading.Thread(target=tx, daemon=True).start()
got = b""
while True:
    d = c.recv(65536)
    if not d: break
    got += d
print("OK" if got == payload else "MISMATCH %d/%d" % (len(got), len(payload)))
"""


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "needs Linux + root")
class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="pqe2e")
        os.chmod(cls.d, 0o755)
        cls.procs = []
        cls.cleanup_ns()
        for n in NS.values():
            sh("ip", "netns", "add", n)
            sh("ip", "link", "set", "lo", "up", ns=[k for k, v in NS.items() if v == n][0])
        for a, b, ia, ib in (("A", "S", "10.77.1.1/24", "10.77.1.254/24"),
                             ("B", "S", "10.77.2.1/24", "10.77.2.254/24"),
                             ("A", "B", "10.77.3.1/24", "10.77.3.2/24")):
            va, vb = f"v{a}{b}", f"v{b}{a}"
            sh("ip", "link", "add", va, "type", "veth", "peer", "name", vb)
            sh("ip", "link", "set", va, "netns", NS[a])
            sh("ip", "link", "set", vb, "netns", NS[b])
            sh("ip", "addr", "add", ia, "dev", va, ns=a)
            sh("ip", "addr", "add", ib, "dev", vb, ns=b)
            sh("ip", "link", "set", va, "up", ns=a)
            sh("ip", "link", "set", vb, "up", ns=b)
        cls.cert, cls.key = make_cert(cls.d, CERT_IPS)
        sys.path.insert(0, HERE)
        import rendezvous_server as rs
        cls.tokfile = os.path.join(cls.d, "token")
        with open(cls.tokfile, "w") as f:
            f.write("e2e-network-token\n")
        os.chmod(cls.tokfile, 0o600)
        cls.hashfile = os.path.join(cls.d, "tokens.sha256")
        with open(cls.hashfile, "w") as f:
            f.write(rs.token_hash("e2e-network-token") + "\n")
        for n in "AB":
            subprocess.run([PY, os.path.join(HERE, "oneqtunel.py"), "genkey", "--key",
                            os.path.join(cls.d, f"{n}.key")], check=True, capture_output=True)
        cls.server = popen(PY, os.path.join(HERE, "rendezvous_server.py"), "run", "--listen", "0.0.0.0:8443",
                           "--cert", cls.cert, "--key", cls.key, "--tokens-file", cls.hashfile,
                           ns="S", log=os.path.join(cls.d, "server.log"))
        cls.procs.append(cls.server)
        time.sleep(1.5)
        if cls.server.poll() is not None:
            raise RuntimeError("server died: " + open(os.path.join(cls.d, "server.log")).read())

    @classmethod
    def cleanup_ns(cls):
        for n in NS.values():
            subprocess.run(["ip", "netns", "del", n], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.stop_all()
        cls.cleanup_ns()
        print(f"\nlogs kept in {cls.d}")

    @classmethod
    def stop_all(cls):
        for p in cls.procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for p in cls.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
        cls.procs = []

    # ---- scenario plumbing
    def direct_link(self, up):
        """The A-B link stays administratively up (so the sniffers keep working); it is 'cut' by
        removing the addresses, which makes 10.77.3.x unreachable for both nodes."""
        for ns, dev, addr in (("A", "vAB", "10.77.3.1/24"), ("B", "vBA", "10.77.3.2/24")):
            sh("ip", "addr", "flush", "dev", dev, ns=ns)
            if up:
                sh("ip", "addr", "add", addr, "dev", dev, ns=ns)

    def start_scenario(self, name, link_up, extra=()):
        self.__class__.stop_all()
        self.direct_link(link_up)
        self.name = name
        self.srv = popen(PY, os.path.join(HERE, "rendezvous_server.py"), "run", "--listen", "0.0.0.0:8443",
                         "--cert", self.cert, "--key", self.key, "--tokens-file", self.hashfile,
                         ns="S", log=os.path.join(self.d, f"{name}.server.log"))
        self.procs.append(self.srv)
        self.sniff = {}
        for iface in ("vAS", "vAB"):
            out = os.path.join(self.d, f"{name}.{iface}.cap")
            self.sniff[iface] = out
            self.procs.append(popen(PY, os.path.abspath(__file__), "--sniff", iface, out, ns="A"))
        pub = {}
        for n in "AB":
            pub[n] = subprocess.run([PY, os.path.join(HERE, "oneqtunel.py"), "pubkey", "--key",
                                     os.path.join(self.d, f"{n}.key")], capture_output=True, text=True,
                                    check=True).stdout.strip()
        self.logs = {}
        time.sleep(1.5)
        for n, other, addr, rv, adv in (("A", "B", "10.99.0.1/24", "10.77.1.254", "10.77.3.1:51820"),
                                        ("B", "A", "10.99.0.2/24", "10.77.2.254", "10.77.3.2:51820")):
            self.logs[n] = os.path.join(self.d, f"{name}.{n}.log")
            peerfile = os.path.join(self.d, f"{name}.{other}.pub")
            with open(peerfile, "w") as f:
                f.write(pub[other] + "\n")
            self.procs.append(popen(PY, os.path.join(HERE, "oneqtunel.py"), "run", "--key",
                                    os.path.join(self.d, f"{n}.key"), "--peer", peerfile, "--ifname", "pq0",
                                    "--addr", addr, "--listen", "0.0.0.0:51820", "--advertise", adv,
                                    "--rendezvous", f"https://{rv}:8443", "--token-file", self.tokfile,
                                    "--cafile", self.cert, *extra, ns=n, log=self.logs[n]))
        end = time.time() + 15
        while time.time() < end and "10.99.0.2" not in sh("ip", "-br", "addr", "show", "pq0", ns="B", check=False).stdout:
            time.sleep(0.2)
        self.echo = popen("python3", "-c", ECHO_SERVER, ns="B", log=os.path.join(self.d, f"{name}.echo.log"))
        self.procs.append(self.echo)

    def log(self, n):
        return open(self.logs[n], errors="replace").read()

    def wait_log(self, needle, timeout, nodes="AB"):
        end = time.time() + timeout
        while time.time() < end:
            if any(needle in self.log(n) for n in nodes):
                return True
            time.sleep(0.5)
        return False

    def wait_tunnel(self, timeout=45):
        end = time.time() + timeout
        last = ""
        while time.time() < end:
            r = sh("python3", "-c", ECHO_CLIENT, MARKER.decode(), ns="A", check=False, timeout=40)
            last = r.stdout.strip() + r.stderr.strip()[-200:]
            if r.stdout.strip() == "OK":
                return True
            time.sleep(1)
        self.fail(f"tunnel did not carry TCP traffic: {last}\nA:\n{self.log('A')}\nB:\n{self.log('B')}")

    def captures(self):
        time.sleep(1)
        return {i: read_frames(p) for i, p in self.sniff.items()}

    def assert_no_plaintext(self, caps):
        total = sum(len(f) for fr in caps.values() for f in fr)
        self.assertGreater(total, 100000, "sniffer captured too little to be meaningful")
        for iface, frames in caps.items():
            for fr in frames:
                self.assertNotIn(MARKER, fr, f"plaintext marker visible on {iface}")
                self.assertNotIn(MARKER[:16], fr, f"plaintext marker prefix visible on {iface}")

    def sniffer_control(self):
        """The sniffer must be able to see plaintext: send the marker in clear on the A-B link."""
        sh("python3", "-c",
           f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
           f"s.sendto({MARKER!r},('10.77.3.2',9999))", ns="A")
        time.sleep(1)
        frames = read_frames(self.sniff["vAB"])
        self.assertTrue(any(MARKER in f for f in frames), "sniffer failed to see a clear-text control packet")

    # ---- scenarios
    def test_1_direct_path(self):
        self.start_scenario("direct", link_up=True)
        self.wait_tunnel()
        self.assertIn("path=direct", self.log("A") + self.log("B"))
        self.assertNotIn("relay connected", self.log("A") + self.log("B"), "relay must not be used")
        caps = self.captures()
        self.assert_no_plaintext(caps)
        sA, sAB = summarize(caps["vAS"]), summarize(caps["vAB"])
        self.assertGreater(sAB["udp_data"], 50, sAB)           # data flows on the direct link
        self.assertGreater(sAB["udp_frag"], 0, sAB)            # handshake travelled as fragments
        self.assertEqual(sA["udp51820"], 0, sA)                 # nothing VPN-related towards the server
        for fr in caps["vAB"]:
            if len(fr) > 42 and fr[14 + 9] == 17 and 51820 in struct.unpack(">HH", fr[34:38]) and fr[42] == 0x15:
                self.assertLessEqual(len(fr) - 42, 1200)
        self.sniffer_control()

    def test_2_forced_relay(self):
        self.start_scenario("forced", link_up=True, extra=("--force-relay",))
        self.wait_tunnel()
        self.assertIn("relay connected", self.log("A"))
        self.assertIn("path=relay", self.log("A") + self.log("B"))
        caps = self.captures()
        self.assert_no_plaintext(caps)
        sA, sAB = summarize(caps["vAS"]), summarize(caps["vAB"])
        self.assertEqual(sAB["udp51820"], 0, sAB)               # direct link unused
        self.assertEqual(sA["udp51820"], 0, sA)
        self.assertGreater(sA["tcp8443"], 50, sA)               # everything rides the wss connection

    def test_3_fallback_to_relay_then_back_to_direct(self):
        t0 = time.time()
        self.start_scenario("fallback", link_up=False)
        self.wait_tunnel(60)
        self.assertGreaterEqual(time.time() - t0, 9, "relay fallback must wait ~10 s for the direct path")
        self.assertIn("enabling relay", self.log("A") + self.log("B"))
        self.assertIn("path=relay", self.log("A") + self.log("B"))
        mid = self.captures()
        self.assertEqual(summarize(mid["vAB"])["udp_data"], 0)
        # the direct link comes up: the tunnel must return to it by itself
        self.direct_link(True)
        self.assertTrue(self.wait_log("back on direct path", 60), "no return to the direct path\n" + self.log("A"))
        self.wait_tunnel()
        time.sleep(1)
        caps = self.captures()
        self.assert_no_plaintext(caps)
        self.assertGreater(summarize(caps["vAB"])["udp_data"], 50)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--sniff":
        sniff_main(sys.argv[2], sys.argv[3])
    else:
        unittest.main(verbosity=2)
