#!/usr/bin/env python3
"""NAT simulation with real Linux NATs (network namespaces + nftables): needs root, ip, nft and /dev/net/tun.

  internet:  bridge brnat 192.0.2.1/24 in the root namespace, with a real oneqrelay (HTTP + STUN) on it
  per NAT:   a router namespace (natK: 192.0.2.(10+K) outside, 10.100.K.1 inside) and a host namespace (lanK: 10.100.K.2)

  port-restricted  nft masquerade                       (Linux default: the port is kept, replies only from the contacted ip:port)
  symmetric        nft masquerade random                (a new public port for every destination)
  cone             static SNAT/DNAT of one port         (same public port for every destination, anybody may send to it)
  open             a host directly on the bridge
  blocked          a router that drops all UDP (TCP is translated and passes)

Part 1: `oneqnode nat-check` run behind each of them must report the right type.
Part 2: real oneqnode processes (TAP devices) behind pairs of NATs: which pairs end up on a direct UDP path and which stay on the relay."""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
RELAY_PORT = 18443
RELAY_URL = f"http://192.0.2.1:{RELAY_PORT}"
KINDS = ["port-restricted", "symmetric", "cone", "blocked", "port-restricted2", "blocked2"]
CONE_LOCAL, CONE_PUBLIC = 4000, 40000
LATENCY_MS = int(os.environ.get("ONEQ_SIM_LATENCY_MS", "15"))   # 0 where the kernel has no netem (WSL): the hard pairs may then fail by lab artifact
# every host/router uplink: one-way delay between two NATs is then ~30 ms, like a real network.
                           # Without it two packets that cross in the lab (0.1 ms) poison each other's connection tracking.

RS = os.path.join(HERE, "oneqclient-linux")        # the Rust client cross-built for Linux (client/macos-style: cargo zigbuild)
ANSI = re.compile(r"\x1b\[[0-9;]*m")

NEED = os.geteuid() == 0 and shutil.which("nft") and shutil.which("ip") and os.path.exists("/dev/net/tun")


def sh(cmd, check=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{cmd}: {r.stderr.strip() or r.stdout.strip()}")
    return r


def ns(name, *cmd, check=True, **kw):
    return sh(["nsenter", f"--net=/run/netns/{name}", *cmd], check=check, **kw)


def nft(name, ruleset):
    sh(["nsenter", f"--net=/run/netns/{name}", "nft", "-f", "-"], input=ruleset)


@unittest.skipUnless(NEED, "needs root, ip, nft and /dev/net/tun (run with sudo on a Linux host)")
class NatSim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="natsim")
        cls.procs, cls.namespaces = [], []
        cls.addClassCleanup(cls.tearDownClass)            # also when the set-up itself fails halfway
        sh(["pkill", "-f", "oneqrelay.py run --db /tmp/natsim"], check=False)      # leftovers of an aborted run
        cls.cleanup_net()
        sh("ip link add brnat type bridge && ip addr add 192.0.2.1/24 dev brnat && ip link set brnat up")
        env = dict(os.environ, TUNMESH_PASSWORD="nat-sim-password")
        secret = os.path.join(cls.tmp, "secret")
        with open(secret, "w") as f:
            f.write(subprocess.check_output([PY, f"{HERE}/oneqrelay.py", "gen-secret"], text=True))
        os.chmod(secret, 0o600)
        base = [PY, f"{HERE}/oneqrelay.py", "admin", "--db", f"{cls.tmp}/r.db", "--id", "nat", "--secret-file", secret]
        cls.admin_base = base
        subprocess.check_call(base + ["community-add", "lan", "10.50.0.0/24"])
        subprocess.check_call(base + ["user-add", "lan", "alice", "--max-nodes", "500"], env=env)
        cls.relay_log = open(f"{cls.tmp}/relay.log", "w")
        cls.procs.append(subprocess.Popen([PY, f"{HERE}/oneqrelay.py", "run", "--db", f"{cls.tmp}/r.db", "--id", "nat", "--secret-file", secret,
                                           "--listen", f"192.0.2.1:{RELAY_PORT}", "--insecure-http"], stdout=cls.relay_log, stderr=cls.relay_log))
        for _ in range(50):
            if sh(f"curl -fs {RELAY_URL}/v1/health", check=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("relay did not start: " + open(f"{cls.tmp}/relay.log").read())
        with open(f"{cls.tmp}/pw", "w") as f:
            f.write("nat-sim-password\n")
        os.chmod(f"{cls.tmp}/pw", 0o600)
        cls.build("open", None)
        for i, kind in enumerate(KINDS):
            cls.build(kind, i + 1)

    @classmethod
    def cleanup_net(cls):
        for n in sh("ip netns list", check=False).stdout.split():
            n = n.split()[0]
            if n.startswith(("lan", "nat")):
                sh(["ip", "netns", "del", n], check=False)
        sh("ip link del brnat", check=False)
        for p in sh("ip -o link", check=False).stdout.splitlines():
            name = p.split(":")[1].strip().split("@")[0]
            if name.startswith("vpn") or name.startswith("vp"):
                sh(["ip", "link", "del", name], check=False)

    @classmethod
    def build(cls, kind, k):
        """Host namespace `lan<kind>`; behind a router namespace `nat<kind>` unless the kind is open."""
        tag = kind.replace("-", "")
        host = f"lan{tag}"
        sh(["ip", "netns", "add", host])
        cls.namespaces.append(host)
        ns(host, "ip", "link", "set", "lo", "up")
        if kind == "open":
            sh("ip link add vpopen type veth peer name vnopen")
            sh(f"ip link set vnopen netns {host}")
            sh("ip link set vpopen master brnat up")
            ns(host, "ip", "addr", "add", "192.0.2.30/24", "dev", "vnopen")
            ns(host, "ip", "link", "set", "vnopen", "up")
            if LATENCY_MS:
                ns(host, "tc", "qdisc", "add", "dev", "vnopen", "root", "netem", "delay", f"{LATENCY_MS}ms")
            return
        router, wan_ip, lan = f"nat{tag}", f"192.0.2.{10 + k}", f"10.100.{k}"
        sh(["ip", "netns", "add", router])
        cls.namespaces.append(router)
        sh(f"ip link add vp{k} type veth peer name vw{k}")
        sh(f"ip link set vw{k} netns {router}")
        sh(f"ip link set vp{k} master brnat up")
        sh(f"ip link add vl{k} type veth peer name vn{k}")
        sh(f"ip link set vl{k} netns {router}")
        sh(f"ip link set vn{k} netns {host}")
        for cmd in (["ip", "link", "set", "lo", "up"], ["ip", "addr", "add", f"{wan_ip}/24", "dev", f"vw{k}"], ["ip", "link", "set", f"vw{k}", "up"],
                    ["ip", "addr", "add", f"{lan}.1/24", "dev", f"vl{k}"], ["ip", "link", "set", f"vl{k}", "up"],
                    ["sysctl", "-qw", "net.ipv4.ip_forward=1"]):
            ns(router, *cmd)
        if LATENCY_MS:
            ns(router, "tc", "qdisc", "add", "dev", f"vw{k}", "root", "netem", "delay", f"{LATENCY_MS}ms")
        ns(host, "ip", "addr", "add", f"{lan}.2/24", "dev", f"vn{k}")
        ns(host, "ip", "link", "set", f"vn{k}", "up")
        ns(host, "ip", "route", "add", "default", "via", f"{lan}.1")
        wan = f"vw{k}"
        if kind.startswith("port-restricted"):
            nft(router, f"""table ip nat {{
  chain post {{
    type nat hook postrouting priority srcnat;
    oifname "{wan}" masquerade
  }}
}}
""")
        elif kind == "symmetric":
            nft(router, f"""table ip nat {{
  chain post {{
    type nat hook postrouting priority srcnat;
    oifname "{wan}" masquerade random
  }}
}}
""")
        elif kind == "cone":
            nft(router, f"""table ip nat {{
  chain pre {{
    type nat hook prerouting priority dstnat;
    iifname "{wan}" udp dport {CONE_PUBLIC} dnat to {lan}.2:{CONE_LOCAL}
  }}
  chain post {{
    type nat hook postrouting priority srcnat;
    oifname "{wan}" ip saddr {lan}.2 udp sport {CONE_LOCAL} snat to {wan_ip}:{CONE_PUBLIC}
    oifname "{wan}" masquerade
  }}
}}
""")
        elif kind.startswith("blocked"):
            # TCP is translated and passes (the relay's HTTP/WebSocket connection), UDP is dropped
            nft(router, f"""table ip f {{
  chain fw {{
    type filter hook forward priority 0;
    ip protocol udp drop
  }}
}}
table ip nat {{
  chain post {{
    type nat hook postrouting priority srcnat;
    oifname "{wan}" masquerade
  }}
}}
""")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.send_signal(signal.SIGTERM)
        for p in cls.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        cls.cleanup_net()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, kind):
        tag = kind.replace("-", "")
        args = [PY, f"{HERE}/oneqnode.py", "nat-check", f"192.0.2.1:{RELAY_PORT}", "--json"]
        if kind == "cone":
            args += ["--local-port", str(CONE_LOCAL)]
        r = ns(f"lan{tag}", *args, check=False)
        self.assertIn(r.returncode, (0, 2), r.stderr)
        return json.loads(r.stdout)

    # ------------------------------------------------------------------ part 2: real nodes behind pairs of NATs
    def start_node(self, kind, name, impl="py", extra=()):
        """impl: "py" = oneqnode.py (TAP), "rs" = the Rust client (TUN)."""
        tag = kind.replace("-", "")
        NatSim.counter = getattr(NatSim, "counter", 0) + 1
        key = f"{self.tmp}/{name}-{NatSim.counter}.key"
        log = f"{self.tmp}/{name}-{NatSim.counter}.log"
        if impl == "rs":
            args = [RS, "up", "--relay", RELAY_URL, "--community", "lan", "--user", "alice", "--password-file", f"{self.tmp}/pw",
                    "--key-file", key, "--name", name, "--ifname", f"r{name}", "--relay-after", "12"]
        else:
            sh([PY, f"{HERE}/oneqnode.py", "genkey", "--key", key])
            args = [PY, f"{HERE}/oneqnode.py", "run", "--key", key, "--relay", RELAY_URL, "--community", "lan", "--user", "alice",
                    "--password-file", f"{self.tmp}/pw", "--ifname", f"n{name}", "--name", name, "--relay-after", "12"]
        args += ["--listen", f"0.0.0.0:{CONE_LOCAL}"] if kind == "cone" else []
        args += list(extra)
        f = open(log, "w")
        p = subprocess.Popen(["nsenter", f"--net=/run/netns/lan{tag}", *args], stdout=f, stderr=f)
        self.__class__.procs.append(p)
        return p, log

    def wait_log(self, log, needle, timeout):
        end = time.time() + timeout
        while time.time() < end:
            text = open(log).read()
            if needle in text:
                return text
            time.sleep(0.5)
        raise AssertionError(f"{needle!r} not in {log} after {timeout}s:\n" + open(log).read()[-1500:])

    @staticmethod
    def lines(log):
        return ANSI.sub("", open(log).read()).splitlines()

    @staticmethod
    def own_ip(log):
        for l in NatSim.lines(log):
            if " address " in l:
                return l.split("address ")[1].split("/")[0]
        return None

    @staticmethod
    def final_path(log, peer_ip):
        """Last known path to peer_ip according to the node log (session line, then 'path to ...: a -> b' lines)."""
        path = None
        for l in NatSim.lines(log):
            if f"session with {peer_ip} " in l and "path=" in l:
                path = l.split("path=")[1].strip()
            elif f"path to {peer_ip}:" in l:                                  # oneqnode.py
                path = l.split("->")[1].split()[0]
            elif f"back on direct path to {peer_ip} " in l:                   # Rust client
                path = "direct"
            elif f"direct path to {peer_ip} is stale" in l:
                path = "relay"
        return path

    def until(self, fn, timeout, what):
        end = time.time() + timeout
        while time.time() < end:
            if fn():
                return
            time.sleep(0.5)
        raise AssertionError(f"timeout waiting for: {what}")

    def pair(self, kind_a, kind_b, expect_direct, settle=45, impl_a="py", impl_b="py"):
        a, b = f"{kind_a[:3]}{impl_a[0]}A", f"{kind_b[:3]}{impl_b[0]}B"
        pa, la = self.start_node(kind_a, a, impl_a)
        pb, lb = self.start_node(kind_b, b, impl_b)
        try:
            self.wait_log(la, "session with", 45)
            self.wait_log(lb, "session with", 45)
            ip_a, ip_b = self.own_ip(la), self.own_ip(lb)
            if expect_direct:
                try:
                    self.until(lambda: self.final_path(la, ip_b) == "direct" and self.final_path(lb, ip_a) == "direct", settle, "direct path")
                except AssertionError:
                    nl = chr(10)
                    raise AssertionError(f"no direct path {kind_a} <-> {kind_b}: {self.final_path(la, ip_b)}/{self.final_path(lb, ip_a)}" + nl
                                         + f"--- A ({ip_a}):" + nl + open(la).read()[-2500:] + nl
                                         + f"--- B ({ip_b}):" + nl + open(lb).read()[-2500:])
            else:
                time.sleep(settle / 2)
                self.assertEqual((self.final_path(la, ip_b), self.final_path(lb, ip_a)), ("relay", "relay"))
            r = ns(f"lan{kind_a.replace('-', '')}", PY, f"{HERE}/oneqping.py", ip_b, "3", check=False)      # works on either path
            self.assertIn("3/3 ok", r.stdout, r.stdout + r.stderr + open(la).read()[-800:])
            return (self.nat_type(la), self.nat_type(lb))
        finally:
            for p in (pa, pb):
                p.send_signal(signal.SIGTERM)
            for p in (pa, pb):
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def nat_type(self, log):
        for l in self.lines(log):
            if "NAT: " in l:
                return l.split("NAT: ")[1].split(",")[0]
        return None

    def test_port_restricted_with_port_restricted_punches_a_direct_path(self):
        self.assertEqual(self.pair("port-restricted", "port-restricted2", True), ("port-restricted", "port-restricted"))

    def test_port_restricted_with_cone_goes_direct(self):
        self.pair("port-restricted", "cone", True)

    def test_symmetric_with_cone_goes_direct(self):
        self.pair("symmetric", "cone", True)

    def test_open_with_symmetric_goes_direct(self):
        self.pair("open", "symmetric", True)

    # ---- the Rust client (cross-built for Linux) against the Python node and against itself
    @unittest.skipUnless(os.path.exists(RS), "build oneqclient-linux first: cargo zigbuild --target x86_64-unknown-linux-gnu.2.31 (see client/README.md)")
    def test_rust_port_restricted_with_python_port_restricted_punches_a_direct_path(self):
        self.assertEqual(self.pair("port-restricted", "port-restricted2", True, impl_a="rs", impl_b="py"), ("port-restricted", "port-restricted"))

    @unittest.skipUnless(os.path.exists(RS), "oneqclient-linux missing")
    def test_python_port_restricted_with_rust_port_restricted_punches_a_direct_path(self):
        self.pair("port-restricted", "port-restricted2", True, impl_a="py", impl_b="rs")

    @unittest.skipUnless(os.path.exists(RS), "oneqclient-linux missing")
    def test_rust_with_rust_between_two_port_restricted_nats_punches_a_direct_path(self):
        self.pair("port-restricted", "port-restricted2", True, impl_a="rs", impl_b="rs")

    @unittest.skipUnless(os.path.exists(RS), "oneqclient-linux missing")
    def test_rust_symmetric_with_python_cone_goes_direct(self):
        self.pair("symmetric", "cone", True, impl_a="rs", impl_b="py")

    @unittest.skipUnless(os.path.exists(RS), "oneqclient-linux missing")
    def test_rust_open_with_python_symmetric_goes_direct(self):
        self.pair("open", "symmetric", True, impl_a="rs", impl_b="py")

    @unittest.skipUnless(os.path.exists(RS), "oneqclient-linux missing")
    def test_rust_symmetric_with_python_port_restricted_uses_the_relay_at_once(self):
        a, la = self.start_node("symmetric", "rsymA", "rs")
        b, lb = self.start_node("port-restricted", "prsB", "py")
        try:
            t0 = time.time()
            self.wait_log(la, "direct UDP cannot be punched, using the relay", 30)
            self.assertLess(time.time() - t0, 12, "must not wait for relay_after (12 s)")
            self.wait_log(lb, "session with", 40)
            ip_a, ip_b = self.own_ip(la), self.own_ip(lb)
            time.sleep(15)
            self.assertEqual((self.final_path(la, ip_b), self.final_path(lb, ip_a)), ("relay", "relay"))
            r = ns("lansymmetric", PY, f"{HERE}/oneqping.py", ip_b, "3", check=False)
            self.assertIn("3/3 ok", r.stdout, r.stdout + r.stderr)
        finally:
            for p in (a, b):
                p.send_signal(signal.SIGTERM)
            for p in (a, b):
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def test_symmetric_with_port_restricted_uses_the_relay_at_once_and_still_works(self):
        a, la = self.start_node("symmetric", "symA")
        b, lb = self.start_node("port-restricted", "prsB")
        try:
            t0 = time.time()
            self.wait_log(la, "direct UDP cannot be punched, using the relay", 30)
            self.assertLess(time.time() - t0, 12, "must not wait for relay_after (12 s)")
            self.wait_log(lb, "session with", 40)
            ip_a, ip_b = self.own_ip(la), self.own_ip(lb)
            time.sleep(15)
            self.assertEqual((self.final_path(la, ip_b), self.final_path(lb, ip_a)), ("relay", "relay"))
            r = ns("lansymmetric", PY, f"{HERE}/oneqping.py", ip_b, "3", check=False)
            self.assertIn("3/3 ok", r.stdout, r.stdout + r.stderr)
        finally:
            for p in (a, b):
                p.send_signal(signal.SIGTERM)
            for p in (a, b):
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def test_a_node_behind_a_router_that_drops_udp_works_through_the_relay_websocket(self):
        # no UDP at all (STUN, handshake, data): everything must go over the relay's TCP connection
        self.assertEqual(self.pair("blocked", "open", False, settle=20)[0], "blocked")

    def test_two_nodes_that_both_have_no_udp_reach_each_other_through_the_relay(self):
        self.assertEqual(self.pair("blocked", "blocked2", False, settle=20), ("blocked", "blocked"))

    # ------------------------------------------------------------------ delegated relay nodes
    def admin(self, *args):
        return subprocess.run(self.admin_base + list(args), capture_output=True, text=True)

    def node_id_of(self, name):
        for l in self.admin("list").stdout.splitlines():
            parts = l.split()
            if len(parts) > 3 and parts[0] == "node" and name in l:
                return parts[1]
        raise AssertionError("node " + name + " not in the registry")

    def delegate_open_host(self, impl):
        """An open host offers to relay; the administrator delegates it. Returns (process, log)."""
        name = f"relayR{impl}{getattr(NatSim, 'counter', 0) + 1}"            # unique: earlier tests left their nodes in the registry
        proc, log = self.start_node("open", name, impl, extra=["--relay-offer"])
        self.until(lambda: "offers relay" in self.admin("list").stdout and name in self.admin("list").stdout, 40, "the open host offered to relay")
        self.until(lambda: self.admin("relay-grant", "lan", self.node_id_of(name), "--max-kbps", "50000").returncode == 0, 40,
                   "the open host was measured as reachable and delegated")
        self.wait_log(log, "now a delegated relay node", 30)
        return proc, log

    def run_pair_through_delegate(self, impl_relay, impl_a="py", impl_b="py"):
        r, lr = self.delegate_open_host(impl_relay)
        a, la = self.start_node("symmetric", "dgsymA", impl_a)
        b, lb = self.start_node("port-restricted", "dgprsB", impl_b)
        try:
            self.wait_log(la, "session with", 60)
            self.wait_log(lb, "session with", 60)
            ip_a, ip_b = self.own_ip(la), self.own_ip(lb)
            self.until(lambda: "forwarding datagrams for the members" in ANSI.sub("", open(lr).read()), 40, "the delegated node forwarded datagrams")
            self.assertEqual((self.final_path(la, ip_b), self.final_path(lb, ip_a)), ("relay", "relay"))
            # the members learn from the registry which delegated nodes each of them holds a session with; traffic keeps flowing until
            # both directions run through the delegated node
            def through_the_node():
                rr = ns("lansymmetric", PY, f"{HERE}/oneqping.py", ip_b, "3", check=False)
                assert "3/3 ok" in rr.stdout, rr.stdout + rr.stderr
                return impl_a != "py" or any("goes through the relay node" in l for l in self.lines(la))
            self.until(through_the_node, 90, "traffic from A to B through the delegated node")
            rr = ns("lansymmetric", PY, f"{HERE}/oneqping.py", ip_b, "5", check=False)
            self.assertIn("5/5 ok", rr.stdout, rr.stdout + rr.stderr + open(la).read()[-1500:])
            return la, lb, lr
        finally:
            for p in (a, b, r):
                p.send_signal(signal.SIGTERM)
            for p in (a, b, r):
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def test_a_delegated_python_node_carries_a_symmetric_and_a_port_restricted_node(self):
        la, lb, lr = self.run_pair_through_delegate("py")
        nl = chr(10)
        self.assertTrue(any("goes through the relay node" in l for l in self.lines(la)),
                        "A:" + nl + nl.join(self.lines(la)[-25:]) + nl + "B:" + nl + nl.join(self.lines(lb)[-25:]) + nl + "R:" + nl + nl.join(self.lines(lr)[-25:]))

    @unittest.skipUnless(os.path.exists(RS), "needs the Rust client cross-built for Linux (oneqclient-linux next to this file)")
    def test_a_delegated_rust_node_carries_a_symmetric_and_a_port_restricted_node(self):
        self.run_pair_through_delegate("rs")

    @unittest.skipUnless(os.path.exists(RS), "needs the Rust client cross-built for Linux (oneqclient-linux next to this file)")
    def test_rust_members_use_a_delegated_python_node(self):
        self.run_pair_through_delegate("py", "rs", "rs")

    # ------------------------------------------------------------------ part 1
    def test_open_host(self):
        d = self.check("open")
        self.assertEqual((d["type"], d["public"]), ("open", d["local"]))
        self.assertEqual(d["public"].split(":")[0], "192.0.2.30")

    def test_port_restricted_nat(self):
        d = self.check("port-restricted")
        self.assertEqual((d["type"], d["mapping"], d["filtering"]), ("port-restricted", "independent", "restricted"))
        self.assertTrue(d["public"].startswith("192.0.2.11:"))

    def test_symmetric_nat(self):
        d = self.check("symmetric")
        self.assertEqual((d["type"], d["mapping"], d["public"]), ("symmetric", "dependent", None))
        self.assertTrue(d["mapped"].startswith("192.0.2.12:"))

    def test_cone_nat(self):
        d = self.check("cone")
        self.assertEqual((d["type"], d["mapping"], d["filtering"], d["public"]), ("cone", "independent", "open", f"192.0.2.13:{CONE_PUBLIC}"))

    def test_udp_blocked(self):
        self.assertEqual(self.check("blocked")["type"], "blocked")

    def test_the_relay_counted_the_requests(self):
        self.check("open")
        self.assertIn("200", sh(f"curl -s -o /dev/null -w %{{http_code}} {RELAY_URL}/v1/health").stdout)


if __name__ == "__main__":
    unittest.main()
