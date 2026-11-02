#!/usr/bin/env python3
"""End-to-end mesh test: real TAP devices, two federated oneqrelays and three oneqnodes, each in its own
network namespace. Needs root + Linux:   sudo /opt/oneq-src/venv/bin/python test_e2e_mesh.py

    R1 ===== R2        oneqrelays (federation over TLS 1.3 X25519MLKEM768, replicated registry)
    |  \\   /  |
    A   B     C        oneqnodes; every node has a link to both oneqrelays and to the other nodes
    (A,C use R1 first, B uses R2 first; the node-to-node links can be cut)

Everything is configured through the real CLIs (admin user-add, oneqnode run). Addresses are allocated
automatically; TCP runs between all pairs over the L2 mesh (so ARP crosses the tunnels); a raw-socket
sniffer on node A's physical interfaces proves nothing readable leaves the host and shows the path used.
Uses `nsenter --net` instead of `ip netns exec` (needs a sysfs remount, unavailable in containers).
"""
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from test_e2e import make_cert, read_frames, sniff_main

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
NODES, RELAYS = ("A", "B", "C"), ("R1", "R2")
NS = {n: f"pq{n}" for n in NODES + RELAYS}
MARKER = b"MESH-SECRET-MARKER-" + os.urandom(8).hex().encode()
PW = {"alice": "alice-password-1", "bob": "bob-password-22"}


def sh(*cmd, ns=None, check=True, **kw):
    if ns:
        cmd = ("nsenter", f"--net=/run/netns/{NS[ns]}") + cmd
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


def popen(*cmd, ns=None, log=None):
    if ns:
        cmd = ("nsenter", f"--net=/run/netns/{NS[ns]}") + cmd
    f = open(log, "ab") if log else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid)


def kill(p):
    if p is None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(8)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


ECHO_SERVER = """
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 5001)); s.listen(8)
while True:
    c, _ = s.accept()
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
"""

ECHO_CLIENT = """
import socket, sys, threading
marker = sys.argv[2].encode()
payload = (marker + b" ") * (65536 // (len(marker) + 1))
c = socket.create_connection((sys.argv[1], 5001), timeout=20); c.settimeout(20)
threading.Thread(target=lambda: (c.sendall(payload), c.shutdown(socket.SHUT_WR)), daemon=True).start()
got = b""
while True:
    d = c.recv(65536)
    if not d: break
    got += d
print("OK" if got == payload else "MISMATCH %d/%d" % (len(got), len(payload)))
"""

LOGIN = """
import asyncio, sys, aiohttp
async def go():
    async with aiohttp.ClientSession() as s:
        r = await s.post(sys.argv[1] + "/v1/login", ssl=False, json={"community": "lan", "user": sys.argv[2], "password": sys.argv[3]})
        print(r.status)
asyncio.run(go())
"""


def summarize(frames):
    r = {"total": len(frames), "udp_data": 0, "udp_frag": 0, "udp51820": 0, "tcp8443": 0, "tcp8443_bytes": 0}
    for fr in frames:
        if len(fr) < 34 or fr[12:14] != b"\x08\x00":
            continue
        ihl = (fr[14] & 0x0F) * 4
        proto, l4 = fr[23], fr[14 + ihl:]
        if proto == 17 and len(l4) >= 9 and 51820 in struct.unpack(">HH", l4[:4]):
            r["udp51820"] += 1
            r["udp_data"] += l4[8] == 0x23
            r["udp_frag"] += l4[8] == 0x15
        elif proto == 6 and len(l4) >= 4 and 8443 in struct.unpack(">HH", l4[:4]):
            r["tcp8443"] += 1
            r["tcp8443_bytes"] += len(fr)
    return r


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "needs Linux + root")
class TestMeshE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="oneqe2e")
        os.chmod(cls.d, 0o755)
        cls.procs, cls.links, cls.addr = [], {}, {}      # addr[(x, y)] = x's own address on the x-y link
        for n in NS:
            subprocess.run(["ip", "netns", "del", NS[n]], capture_output=True)
        for n in NS:
            sh("ip", "netns", "add", NS[n])
            sh("ip", "link", "set", "lo", "up", ns=n)
        pairs = [("R1", "R2")] + [(n, r) for n in NODES for r in RELAYS] + [("A", "B"), ("A", "C"), ("B", "C")]
        for k, (x, y) in enumerate(pairs, start=1):
            vx, vy = f"v{x}{y}", f"v{y}{x}"
            sh("ip", "link", "add", vx, "type", "veth", "peer", "name", vy)
            sh("ip", "link", "set", vx, "netns", NS[x])
            sh("ip", "link", "set", vy, "netns", NS[y])
            cls.addr[(x, y)], cls.addr[(y, x)] = f"10.88.{k}.1", f"10.88.{k}.2"
            cls.links[(x, y)] = (vx, vy)
            sh("ip", "addr", "add", f"10.88.{k}.1/24", "dev", vx, ns=x)
            sh("ip", "addr", "add", f"10.88.{k}.2/24", "dev", vy, ns=y)
            sh("ip", "link", "set", vx, "up", ns=x)
            sh("ip", "link", "set", vy, "up", ns=y)
        cls.cert, cls.key = make_cert(cls.d, sorted({cls.addr[(r, o)] for r in RELAYS for o in NS if (r, o) in cls.addr}))
        cls.secret = os.path.join(cls.d, "fed.secret")
        with open(cls.secret, "w") as f:
            f.write(subprocess.run([PY, os.path.join(HERE, "oneqrelay.py"), "gen-secret"], capture_output=True,
                                   text=True, check=True).stdout)
        os.chmod(cls.secret, 0o600)
        cls.pwfile = {}
        for u, pw in PW.items():
            cls.pwfile[u] = os.path.join(cls.d, f"{u}.pw")
            with open(cls.pwfile[u], "w") as f:
                f.write(pw + "\n")
            os.chmod(cls.pwfile[u], 0o600)
        for n in NODES:
            subprocess.run([PY, os.path.join(HERE, "oneqnode.py"), "genkey", "--key", os.path.join(cls.d, f"{n}.key")],
                           check=True, capture_output=True)
        cls.admin("community-add", "lan", "10.50.0.0/24", db="R1")
        cls.admin("user-add", "lan", "alice", "--role", "admin", "--password-file", cls.pwfile["alice"], db="R1")
        cls.admin("user-add", "lan", "bob", "--password-file", cls.pwfile["bob"], db="R1")
        cls.start_relay("R1")
        cls.start_relay("R2")

    @classmethod
    def admin(cls, *args, db):
        subprocess.run([PY, os.path.join(HERE, "oneqrelay.py"), "admin", "--db", os.path.join(cls.d, f"{db}.db"),
                        "--id", db.lower(), "--secret-file", cls.secret, *args], check=True, capture_output=True)

    @classmethod
    def start_relay(cls, r):
        other = "R2" if r == "R1" else "R1"
        cls.rp = getattr(cls, "rp", {})
        cls.rp[r] = popen(PY, os.path.join(HERE, "oneqrelay.py"), "run", "--id", r.lower(), "--db",
                          os.path.join(cls.d, f"{r}.db"), "--secret-file", cls.secret, "--listen", "0.0.0.0:8443",
                          "--cert", cls.cert, "--key", cls.key, "--cafile", cls.cert, "--fed-peer",
                          f"https://{cls.addr[(other, r)]}:8443", ns=r, log=os.path.join(cls.d, f"{r}.log"))
        cls.procs.append(cls.rp[r])
        time.sleep(1.5)

    @classmethod
    def tearDownClass(cls):
        cls.stop_nodes()
        for p in getattr(cls, "rp", {}).values():
            kill(p)
        for n in NS.values():
            subprocess.run(["ip", "netns", "del", n], capture_output=True)
        print(f"\nlogs kept in {cls.d}")

    @classmethod
    def stop_nodes(cls):
        for p in getattr(cls, "np", {}).values():
            kill(p)
        for p in getattr(cls, "aux", []):
            kill(p)
        cls.np, cls.aux = {}, []

    # ------------------------------------------------------------ scenario helpers
    def direct_links(self, up):
        for (x, y), (vx, vy) in self.links.items():
            if x in NODES and y in NODES:
                for ns, dev, a in ((x, vx, self.addr[(x, y)]), (y, vy, self.addr[(y, x)])):
                    sh("ip", "addr", "flush", "dev", dev, ns=ns)
                    if up:
                        sh("ip", "addr", "add", f"{a}/24", "dev", dev, ns=ns)

    def start_scenario(self, name, direct_up, extra=(), users=None, order=None):
        self.stop_nodes()
        self.name = name
        self.direct_links(direct_up)
        self.sniff = {}
        for dev in (self.links[("A", "R1")][0], self.links[("A", "R2")][0], self.links[("A", "B")][0],
                    self.links[("A", "C")][0]):
            out = os.path.join(self.d, f"{name}.{dev}.cap")
            self.sniff[dev] = out
            self.aux.append(popen(PY, os.path.join(HERE, "test_e2e.py"), "--sniff", dev, out, ns="A"))
        time.sleep(1.5)
        self.logs = {}
        order = order or {"A": ("R1", "R2"), "B": ("R2", "R1"), "C": ("R1", "R2")}
        for n in NODES:
            user = (users or {}).get(n, "alice")
            self.logs[n] = os.path.join(self.d, f"{name}.{n}.log")
            args = [PY, os.path.join(HERE, "oneqnode.py"), "run", "--key", os.path.join(self.d, f"{n}.key"),
                    "--community", "lan", "--user", user, "--password-file", self.pwfile[user], "--name", n,
                    "--ifname", "oneq0", "--listen", "0.0.0.0:51820", "--cafile", self.cert, *extra]
            if os.environ.get("ONEQ_E2E_VERBOSE"):
                args.append("-v")
            for r in order[n]:
                args += ["--relay", f"https://{self.addr[(r, n)]}:8443"]
            for other in NS:
                if (n, other) in self.addr:
                    args += ["--advertise", f"{self.addr[(n, other)]}:51820"]
            self.node_args = getattr(self, "node_args", {})
            self.node_args[n] = args
            self.np[n] = popen(*args, ns=n, log=self.logs[n])

    def restart_node(self, n):
        """Kill the node process and start it again with the same key (a crash, or an upgrade)."""
        kill(self.np[n])
        end = time.time() + 10
        while time.time() < end and sh("ip", "link", "show", "oneq0", ns=n, check=False).returncode == 0:
            time.sleep(0.2)
        self.np[n] = popen(*self.node_args[n], ns=n, log=self.logs[n])

    def log(self, n):
        return open(self.logs[n], errors="replace").read()

    def node_ip(self, n):
        out = sh("ip", "-4", "-br", "addr", "show", "oneq0", ns=n, check=False).stdout
        m = re.search(r"(10\.50\.0\.\d+)/24", out)
        return m.group(1) if m else None

    def wait_ips(self, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            ips = {n: self.node_ip(n) for n in NODES}
            if all(ips.values()):
                return ips
            time.sleep(0.5)
        self.fail("nodes did not get addresses: " + "\n".join(f"{n}:\n{self.log(n)}" for n in NODES))

    def wait_log(self, needle, timeout, nodes=NODES):
        end = time.time() + timeout
        while time.time() < end:
            if any(needle in self.log(n) for n in nodes):
                return True
            time.sleep(0.5)
        return False

    def start_echo(self, ips):
        for n in NODES:
            end = time.time() + 10
            while time.time() < end and ips[n] not in sh("ip", "-br", "addr", "show", "oneq0", ns=n, check=False).stdout:
                time.sleep(0.2)
            self.aux.append(popen("python3", "-c", ECHO_SERVER, ips[n], ns=n, log=os.path.join(self.d, f"{self.name}.echo{n}.log")))
        time.sleep(0.5)

    def tcp_all_pairs(self, ips, timeout=60):
        """Every ordered pair talks TCP over the mesh (ARP is flooded through the tunnels first)."""
        for x in NODES:
            for y in NODES:
                if x == y:
                    continue
                end, last = time.time() + timeout, ""
                while time.time() < end:
                    r = sh("python3", "-c", ECHO_CLIENT, ips[y], MARKER.decode(), ns=x, check=False, timeout=60)
                    last = (r.stdout + r.stderr).strip()[-200:]
                    if r.stdout.strip() == "OK":
                        break
                    time.sleep(1)
                else:
                    self.fail(f"TCP {x}->{y} failed: {last}\n{self.name} logs:\n" +
                              "\n".join(f"-- {n}\n{self.log(n)[-1500:]}" for n in NODES))

    def captures(self):
        time.sleep(1)
        return {d: read_frames(p) for d, p in self.sniff.items()}

    def assert_no_plaintext(self, caps):
        total = sum(len(f) for fr in caps.values() for f in fr)
        self.assertGreater(total, 100000, "sniffer saw too little to be meaningful")
        for dev, frames in caps.items():
            for fr in frames:
                self.assertNotIn(MARKER, fr, f"plaintext on {dev}")
                self.assertNotIn(MARKER[:14], fr, f"plaintext prefix on {dev}")

    # ------------------------------------------------------------ scenarios
    def test_1_direct_mesh_with_automatic_addresses(self):
        self.start_scenario("direct", True)
        ips = self.wait_ips()
        self.assertEqual(len(set(ips.values())), 3, ips)
        macs = {n: re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", sh("ip", "-br", "link", "show", "oneq0", ns=n).stdout).group(1)
                for n in NODES}
        self.assertTrue(all(re.match(r"^02(:[0-9a-f]{2}){5}$", m) for m in macs.values()), macs)
        self.assertEqual(len(set(macs.values())), 3)
        self.start_echo(ips)
        self.tcp_all_pairs(ips)
        neigh = sh("ip", "neigh", "show", "dev", "oneq0", ns="A").stdout
        for n in ("B", "C"):                                  # ARP crossed the tunnels and learned the allocated MACs
            self.assertIn(macs[n], neigh)
        caps = self.captures()
        self.assert_no_plaintext(caps)
        s = {d: summarize(f) for d, f in caps.items()}
        direct = [s[self.links[("A", "B")][0]], s[self.links[("A", "C")][0]]]
        self.assertGreater(sum(x["udp_data"] for x in direct), 100, s)
        self.assertGreater(sum(x["udp_frag"] for x in direct), 0, s)
        for r in RELAYS:
            self.assertEqual(s[self.links[("A", r)][0]]["udp51820"], 0, s)
        logs = self.log("A") + self.log("B") + self.log("C")
        self.assertNotIn("path=relay", logs)
        self.assertNotIn("enabling relay", logs, "no handshake needed the relay")
        # nodes stay attached to a relay, but the payload must not travel through it: A took part in ~512 KiB of
        # transfers, the registry traffic of a 20 s run is a few tens of KB
        relayed = sum(s[self.links[("A", r)][0]]["tcp8443_bytes"] for r in RELAYS)
        self.assertLess(relayed, 200_000, f"{relayed} bytes went to the relays")

    def test_2_forced_relay_across_federated_oneqrelays(self):
        self.start_scenario("forced", True, extra=("--force-relay",))
        ips = self.wait_ips()
        self.start_echo(ips)
        self.tcp_all_pairs(ips)                                # A,C attach to R1 and B to R2: frames cross the federation
        caps = self.captures()
        self.assert_no_plaintext(caps)
        s = {d: summarize(f) for d, f in caps.items()}
        for p in (("A", "B"), ("A", "C")):
            self.assertEqual(s[self.links[p][0]]["udp51820"], 0, s)
        self.assertGreater(s[self.links[("A", "R1")][0]]["tcp8443"], 100, s)

    def test_3_fallback_failover_and_recovery(self):
        t0 = time.time()
        self.start_scenario("failover", False)                 # no node-to-node connectivity at all
        ips = self.wait_ips()
        self.start_echo(ips)
        self.tcp_all_pairs(ips, timeout=60)
        self.assertGreaterEqual(time.time() - t0, 9, "relay fallback waits ~10 s for a direct path")
        self.assertIn("enabling relay", self.log("A"))
        # a relay dies: nodes fail over to the other one and the tunnels keep working
        kill(self.rp["R1"])
        self.assertTrue(self.wait_log("switching to oneqrelay", 30, nodes=("A", "C")), self.log("A"))
        self.tcp_all_pairs(ips, timeout=90)
        self.assertEqual(sh(PY, "-c", LOGIN, f"https://{self.addr[('R2', 'A')]}:8443", "alice", "wrong",
                            ns="A").stdout.strip(), "401")
        # the relay comes back and catches up through federation; direct links return and are preferred again
        self.__class__.start_relay("R1")
        self.direct_links(True)
        self.assertTrue(self.wait_log("back on direct path", 90), self.log("A"))
        self.tcp_all_pairs(ips, timeout=60)
        caps = self.captures()
        self.assert_no_plaintext(caps)
        self.assertGreater(sum(summarize(caps[self.links[p][0]])["udp_data"] for p in (("A", "B"), ("A", "C"))), 50)

    def test_5_a_restarted_node_is_reachable_again_within_seconds(self):
        # Measured on real hosts before the fix: a node that never initiates (its key sorts last) stayed unreachable for
        # ~100 s after a restart, until the others' rekey timer. Restart the worst case and the best case.
        import base64
        pubs = {n: base64.b64decode(open(os.path.join(self.d, f"{n}.key.pub")).read().strip()) for n in NODES}
        last, first = max(NODES, key=lambda n: pubs[n]), min(NODES, key=lambda n: pubs[n])
        self.start_scenario("restart", True)
        ips = self.wait_ips()
        self.start_echo(ips)
        self.tcp_all_pairs(ips)
        time.sleep(4)                                            # sessions must be a few seconds old
        for n, what in ((last, "responder to everyone"), (first, "initiator to everyone")):
            t0 = time.time()
            self.restart_node(n)
            end = time.time() + 30
            while time.time() < end and self.node_ip(n) != ips[n]:
                time.sleep(0.5)
            self.assertEqual(self.node_ip(n), ips[n], f"{n} did not get its address back")
            self.aux.append(popen("python3", "-c", ECHO_SERVER, ips[n], ns=n))     # its old listener died with the TAP
            time.sleep(0.5)
            others = [x for x in NODES if x != n]
            for o in others:                                      # every other node must reach it again, fast
                end2, ok = time.time() + 25, False
                while time.time() < end2 and not ok:
                    r = sh("python3", "-c", ECHO_CLIENT, ips[n], MARKER.decode(), ns=o, check=False, timeout=40)
                    ok = r.stdout.strip() == "OK"
                    if not ok:
                        time.sleep(1)
                self.assertTrue(ok, f"{o} cannot reach restarted {n} ({what}) after {time.time() - t0:.0f}s\n" + self.log(o)[-1200:])
            self.assertLess(time.time() - t0, 60, f"recovery of {n} ({what}) took {time.time() - t0:.0f}s")
        self.tcp_all_pairs(ips, timeout=40)

    def test_4_accounts_are_enforced_and_replicated(self):
        self.start_scenario("accounts", True, users={"B": "bob"})
        # B's key is already registered to alice (earlier scenarios): a different user cannot take that node over
        self.assertTrue(self.wait_log("node id belongs to another user", 20, nodes=("B",)), self.log("B"))
        self.assertIsNone(self.node_ip("B"))
        import oneqtunel
        bid = oneqtunel.node_id(oneqtunel.load_public(os.path.join(self.d, "B.key.pub"))).hex()
        self.admin("node-del", "lan", bid, db="R1")                 # an admin frees the stale registration
        ips = self.wait_ips(60)
        # a user created on R2 while everything runs becomes valid on R1 through federation
        self.admin("user-add", "lan", "carol", "--password-file", self.pwfile["bob"], db="R2")
        end, code = time.time() + 20, None
        while time.time() < end:
            code = sh(PY, "-c", LOGIN, f"https://{self.addr[('R1', 'A')]}:8443", "carol", PW["bob"],
                      ns="A").stdout.strip()
            if code == "200":
                break
            time.sleep(1)
        self.assertEqual(code, "200")
        # wrong password never gets an address
        self.stop_nodes()
        bad = os.path.join(self.d, "bad.pw")
        with open(bad, "w") as f:
            f.write("definitely-wrong\n")
        os.chmod(bad, 0o600)
        self.pwfile["alice_bad"] = bad
        self.start_scenario("badpw", True, users={"A": "alice_bad"})
        time.sleep(8)
        self.assertIsNone(self.node_ip("A"))
        self.assertIn("login refused", self.log("A"))
        self.assertIsNotNone(self.node_ip("B"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
