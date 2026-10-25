#!/usr/bin/env python3
"""NAT discovery: STUN codec and server (real UDP on loopback), NAT classification against modelled NAT behaviours,
hole-punching rules, the relay API (nat field, reachability test) and a node measuring a relay's STUN service."""
import pqtls  # noqa: F401

import asyncio
import base64
import socket
import struct
import time
import unittest

import aiohttp
from aiohttp import web

import meshdb
import meshproto as mp
import oneqnat as nn
import oneqnode
import oneqrelay as sn
import oneqtunel as t
from test_oneqrelay import SECRET, eventually, free_port, free_udp_port

LOCAL = ("192.168.1.10", 4000)


class Udp:
    """A UDP socket in the test: collects (data, addr)."""

    def __init__(self):
        self.got, self.tr = [], None

    async def open(self, port=0, auto_answer=False):
        outer = self

        class P(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                outer.got.append((data, addr))
                if auto_answer:
                    m = nn.parse(data)
                    if m and m[0] == nn.BINDING_REQUEST:
                        outer.tr.sendto(nn.binding_response(m[1], addr), addr)
        self.tr, _ = await asyncio.get_running_loop().create_datagram_endpoint(P, local_addr=("127.0.0.1", port))
        return self

    @property
    def addr(self):
        return self.tr.get_extra_info("sockname")

    async def wait(self, n=1, timeout=1.0):
        end = time.monotonic() + timeout
        while len(self.got) < n and time.monotonic() < end:
            await asyncio.sleep(0.01)
        return list(self.got)

    def close(self):
        self.tr.close()


class TestCodec(unittest.TestCase):
    def test_binding_roundtrip_ipv4_and_ipv6(self):
        req, tx = nn.binding_request(nn.CHANGE_PORT)
        m = nn.parse(req)
        self.assertEqual((m[0], m[1], struct.unpack(">I", m[2][nn.A_CHANGE_REQUEST])[0]), (nn.BINDING_REQUEST, tx, nn.CHANGE_PORT))
        for addr in (("203.0.113.9", 40001), ("2001:db8::7", 65535)):
            r = nn.parse(nn.binding_response(tx, addr))
            self.assertEqual(nn.mapped_of(r), addr)

    def test_known_xor_mapped_address_vector(self):
        # RFC 5769 section 2.2: IPv4 response, address 192.0.2.1 port 32853
        tx = bytes.fromhex("b7e7a701bc34d686fa87dfae")
        self.assertEqual(nn.xor_address(("192.0.2.1", 32853), tx), bytes.fromhex("0001a147e112a643"))
        self.assertEqual(nn.unxor_address(bytes.fromhex("0001a147e112a643"), tx), ("192.0.2.1", 32853))

    def test_malformed_messages_are_rejected_not_crashed_on(self):
        good, tx = nn.binding_request()
        for bad in (b"", b"\x00" * 19, good[:-1], good + b"x", b"\x05" + good[1:], good[:4] + b"\0\0\0\0" + good[8:],
                    nn.build(nn.BINDING_REQUEST, tx) + b"\x00\x20\xff\xff", b"\x00\x01\x00\x08" + good[4:20] + b"\x80\x2c\x00\x40" + b"x" * 4):
            self.assertIsNone(nn.parse(bad), bad[:12])
        self.assertIsNone(nn.unxor_address(b"\x00\x09\x00\x00abcd", tx))
        self.assertIsNone(nn.unxor_address(b"", tx))
        self.assertIsNone(nn.mapped_of(nn.parse(nn.build(nn.BINDING_SUCCESS, tx))))          # no address attribute
        self.assertFalse(nn.is_stun(b"\x23" + b"\0" * 30))                                  # a mesh DATA packet is not STUN


class TestClassification(unittest.IsolatedAsyncioTestCase):
    """The decision logic against models of the usual NAT behaviours."""
    MAIN, ALT = ("198.51.100.1", 3478), ("198.51.100.1", 3479)

    def model(self, kind):
        calls = []

        async def transact(dst, change):
            calls.append((dst, change))
            if kind == "blocked":
                return None
            if kind == "open":
                return LOCAL
            pub = ("203.0.113.5", 40000)
            if kind == "symmetric":
                return ("203.0.113.5", 40000 + dst[1] % 997)                # a new port per destination
            if change & nn.CHANGE_PORT:
                return pub if kind == "cone" else None                       # port-restricted drops the new source port
            return pub
        return transact, calls

    async def test_every_kind(self):
        for kind, want_type, endpoint in (("open", "open", f"{LOCAL[0]}:{LOCAL[1]}"), ("cone", "cone", "203.0.113.5:40000"),
                                          ("port-restricted", "port-restricted", "203.0.113.5:40000"),
                                          ("symmetric", "symmetric", None), ("blocked", "blocked", None)):
            tr, calls = self.model(kind)
            info = await nn.classify(tr, self.MAIN, self.ALT, LOCAL)
            self.assertEqual(info.type, want_type, kind)
            self.assertEqual(info.public_endpoint(), endpoint, kind)
            self.assertLessEqual(len(calls), 3)
            if kind == "symmetric":
                self.assertEqual((info.mapping, info.filtering), ("dependent", "unknown"))   # filtering is not meaningful then
            if kind in ("cone", "port-restricted", "open"):
                # the filtering test is last: the mapping test must not be disturbed by its unsolicited packet
                self.assertEqual(calls[-1], (self.MAIN, nn.CHANGE_PORT))

    def sequential(self, step=2, start=40000):
        """A symmetric NAT that hands out consecutive ports (every `step`) as the node contacts new destinations."""
        seen, calls = {}, []

        async def transact(dst, change):
            calls.append((dst, change))
            if dst not in seen:
                seen[dst] = start + step * len(seen)
            return ("203.0.113.5", seen[dst])
        return transact, calls

    THIRD = ("198.51.100.1", 3480)

    async def test_sequential_symmetric_nat_is_predictable(self):
        for step in (1, 2, 4):
            tr, calls = self.sequential(step)
            info = await nn.classify(tr, self.MAIN, self.ALT, LOCAL, self.THIRD)
            self.assertEqual((info.type, info.delta), ("symmetric", step))
            self.assertEqual(info.mapped, ("203.0.113.5", 40000 + 2 * step), "the newest mapping is the base of the prediction")
            self.assertEqual(len(calls), 3)

    async def test_random_symmetric_nat_has_no_delta(self):
        import random
        rnd = random.Random(7)
        async def transact(dst, change):
            return ("203.0.113.5", rnd.randrange(1024, 65535))
        info = await nn.classify(transact, self.MAIN, self.ALT, LOCAL, self.THIRD)
        self.assertEqual((info.type, info.delta), ("symmetric", None))

    async def test_the_third_destination_is_not_used_when_it_could_disturb_the_filtering_test(self):
        for kind in ("cone", "port-restricted", "open"):
            tr, calls = self.model(kind)
            info = await nn.classify(tr, self.MAIN, self.ALT, LOCAL, self.THIRD)
            self.assertNotIn(self.THIRD, [c[0] for c in calls], kind)
            self.assertIsNone(info.delta)
        tr, calls = self.model("symmetric")
        await nn.classify(tr, self.MAIN, self.ALT, LOCAL)            # without a third destination nothing extra is sent
        self.assertEqual(len(calls), 2)

    def test_predict_delta_rules(self):
        self.assertEqual(nn.predict_delta([100, 101, 102]), 1)
        self.assertEqual(nn.predict_delta([100, 102, 104]), 2)
        self.assertEqual(nn.predict_delta([100, 102, 105]), 3, "another flow used a port in between: small positive steps still count")
        self.assertIsNone(nn.predict_delta([100, 100, 100]))
        self.assertIsNone(nn.predict_delta([100, 5000, 9000]))
        self.assertIsNone(nn.predict_delta([100, 99, 101]))
        self.assertIsNone(nn.predict_delta([100, 101]))
        self.assertEqual(nn.predict_delta([100, 99, 98]), -1)

    async def test_partial_answers_give_unknown_not_a_wrong_claim(self):
        async def only_main(dst, change):
            return ("203.0.113.5", 40000) if dst == self.MAIN and not change else None
        info = await nn.classify(only_main, self.MAIN, self.ALT, LOCAL)
        self.assertEqual(info.type, "port-restricted" if info.mapping == "independent" else "unknown")
        self.assertEqual(info.mapping, "unknown")                              # the alt socket never answered
        self.assertEqual(info.type, "unknown")

    def test_hole_punching_rules(self):
        types = ("open", "cone", "port-restricted", "symmetric")
        impossible = {("symmetric", "symmetric"), ("symmetric", "port-restricted"), ("port-restricted", "symmetric")}
        for a in types:
            for b in types:
                self.assertEqual(nn.can_punch(a, b), (a, b) not in impossible, (a, b))
        self.assertTrue(nn.can_punch("unknown", "symmetric"))                  # unknown is tried
        self.assertTrue(nn.can_punch("blocked", "symmetric"))

    def test_predictable_symmetric_nats_rescue_the_hard_pairs(self):
        self.assertTrue(nn.can_punch("symmetric", "port-restricted", a_pred=True))
        self.assertTrue(nn.can_punch("port-restricted", "symmetric", b_pred=True))
        self.assertFalse(nn.can_punch("port-restricted", "symmetric", a_pred=True), "the prediction belongs to the symmetric side")
        self.assertFalse(nn.can_punch("symmetric", "symmetric", a_pred=True))
        self.assertTrue(nn.can_punch("symmetric", "symmetric", a_pred=True, b_pred=True))
        self.assertTrue(nn.can_punch("symmetric", "cone"))

    def test_a_second_nat_goes_to_the_relay_unless_the_other_side_is_open(self):
        for other in ("cone", "port-restricted", "symmetric", "unknown"):
            self.assertFalse(nn.can_punch("cone", other, a_cgnat=True), other)
            self.assertFalse(nn.can_punch(other, "cone", b_cgnat=True), other)
        self.assertTrue(nn.can_punch("port-restricted", "open", a_cgnat=True))
        self.assertTrue(nn.can_punch("open", "symmetric", b_cgnat=True, b_pred=True))
        self.assertFalse(nn.can_punch("open", "cone", a_cgnat=True, b_cgnat=True), "two second NATs")

    def test_punch_ports_only_for_a_predictable_symmetric_peer(self):
        ports = nn.punch_ports("symmetric", "203.0.113.5:40010", 2)
        self.assertEqual(ports[:3], [("203.0.113.5", 40012), ("203.0.113.5", 40014), ("203.0.113.5", 40016)])
        self.assertEqual(len(ports), 16)
        self.assertEqual(nn.punch_ports("cone", "203.0.113.5:40010", 2), [])
        self.assertEqual(nn.punch_ports("symmetric", "203.0.113.5:40010", None), [])
        self.assertEqual(nn.punch_ports("symmetric", None, 1), [])
        self.assertEqual(nn.punch_ports("symmetric", "203.0.113.5:notaport", 1), [])
        top = nn.punch_ports("symmetric", "203.0.113.5:65530", 1)
        self.assertTrue(all(p <= 65535 for _, p in top) and len(top) == 5, top)
        self.assertEqual([p for _, p in nn.punch_ports("symmetric", "203.0.113.5:1030", -1)][:3], [1029, 1028, 1027])
        self.assertTrue(all(p >= 1024 for _, p in nn.punch_ports("symmetric", "203.0.113.5:1030", -1)))

    def test_double_nat_detection(self):
        self.assertTrue(nn.double_nat("100.64.3.9", None), "mapped address in 100.64.0.0/10")
        self.assertTrue(nn.double_nat("100.127.255.254", "100.70.0.1"))
        self.assertTrue(nn.double_nat("203.0.113.5", "192.168.0.2"), "the router itself has a private WAN address")
        self.assertTrue(nn.double_nat("203.0.113.5", "198.51.100.8"), "the router and the relay disagree about the address")
        self.assertFalse(nn.double_nat("203.0.113.5", "203.0.113.5"))
        self.assertFalse(nn.double_nat("203.0.113.5", None), "nothing known: assume a single NAT")
        self.assertFalse(nn.double_nat("203.0.113.5", "0.0.0.0"))
        self.assertFalse(nn.double_nat("203.0.113.5", "not an address"))
        self.assertFalse(nn.double_nat("10.0.0.5", "10.0.0.5"), "a relay on the same LAN sees the router's own address")

    def test_reachability_test_targets(self):
        ok = nn.probe_target_ok
        self.assertEqual(ok("203.0.113.9:5000", "203.0.113.9"), ("203.0.113.9", 5000))
        self.assertIsNone(ok("203.0.113.10:5000", "203.0.113.9"))               # somebody else's address
        self.assertEqual(ok("198.51.100.2:5000", "203.0.113.9", is_admin=True), ("198.51.100.2", 5000))
        for bad in ("127.0.0.1:5000", "169.254.1.1:5000", "224.0.0.1:5000", "0.0.0.0:5000", "[::1]:5000", "203.0.113.9:0",
                    "203.0.113.9:70000", "host.example.org:5000", "203.0.113.9", ""):
            self.assertIsNone(ok(bad, "203.0.113.9", is_admin=True), bad)
        self.assertEqual(ok("127.0.0.1:5000", "127.0.0.1", allow_loopback=True), ("127.0.0.1", 5000))


class TestStunServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = nn.StunServer("127.0.0.1", free_udp_port(), free_udp_port(), free_udp_port(), rate=1000.0)
        await self.srv.start()
        self.c = await Udp().open()

    async def asyncTearDown(self):
        self.c.close()
        self.srv.close()

    async def test_binding_returns_the_source_address_from_the_socket_asked(self):
        req, tx = nn.binding_request()
        self.c.tr.sendto(req, ("127.0.0.1", self.srv.port))
        (data, src), = await self.c.wait()
        self.assertEqual((src[1], nn.mapped_of(nn.parse(data))), (self.srv.port, self.c.addr))
        self.assertLessEqual(len(data), 48)                                     # tiny: a poor amplifier
        self.c.got.clear()
        self.c.tr.sendto(req, ("127.0.0.1", self.srv.alt_port))
        (data, src), = await self.c.wait()
        self.assertEqual(src[1], self.srv.alt_port)

    async def test_change_port_answers_from_the_third_socket_and_change_ip_is_ignored(self):
        req, _ = nn.binding_request(nn.CHANGE_PORT)
        for port in (self.srv.port, self.srv.alt_port):
            self.c.got.clear()
            self.c.tr.sendto(req, ("127.0.0.1", port))
            (data, src), = await self.c.wait()
            self.assertEqual(src[1], self.srv.change_port)                    # a port nobody sends to
            self.assertEqual(nn.mapped_of(nn.parse(data)), self.c.addr)
        self.c.got.clear()
        self.c.tr.sendto(nn.binding_request(nn.CHANGE_IP)[0], ("127.0.0.1", self.srv.port))
        self.c.tr.sendto(nn.binding_request(nn.CHANGE_IP | nn.CHANGE_PORT)[0], ("127.0.0.1", self.srv.port))
        self.assertEqual(await self.c.wait(1, 0.3), [])

    async def test_garbage_and_non_requests_get_no_answer(self):
        tx = b"\x01" * 12
        for junk in (b"hello", b"\x00" * 40, nn.build(nn.BINDING_ERROR, tx), nn.binding_response(tx, ("1.2.3.4", 5)),
                     nn.build(0x0002, tx)):
            self.c.tr.sendto(junk, ("127.0.0.1", self.srv.port))
        self.assertEqual(await self.c.wait(1, 0.3), [])

    async def test_rate_limit_per_source(self):
        self.srv.buckets.clear()
        self.srv.rate = 5.0
        for _ in range(60):
            self.c.tr.sendto(nn.binding_request()[0], ("127.0.0.1", self.srv.port))
        await asyncio.sleep(0.4)
        self.assertLess(len(self.c.got), 25)
        self.assertGreater(self.srv.stats["rate_limited"], 30)

    async def test_probe_comes_from_the_alt_port_and_reports_unreachable_quietly(self):
        node = await Udp().open(auto_answer=True)
        try:
            rtt = await self.srv.probe(node.addr, timeout=1.0)
            self.assertIsNotNone(rtt)
            self.assertEqual(node.got[0][1][1], self.srv.change_port)           # a source port nobody ever sends to
        finally:
            node.close()
        dead = await Udp().open()
        addr = dead.addr
        dead.close()
        self.assertIsNone(await self.srv.probe(addr, timeout=0.4))
        self.assertEqual(self.srv.pending, {})


class TestProberAgainstTheServer(unittest.IsolatedAsyncioTestCase):
    async def test_classification_on_loopback_is_open_and_prober_ignores_forged_answers(self):
        srv = nn.StunServer("127.0.0.1", free_udp_port(), free_udp_port(), free_udp_port(), rate=1000.0)
        await srv.start()
        c = Udp()
        prober = nn.NatProber(lambda d, a: c.tr.sendto(d, a), timeout=0.3, tries=2)
        await c.open()
        c.tr._protocol.datagram_received = lambda data, addr: prober.feed(data, addr)       # route answers to the prober
        try:
            info = await nn.classify(prober.transact, ("127.0.0.1", srv.port), ("127.0.0.1", srv.alt_port), c.addr)
            self.assertEqual((info.type, info.mapped, info.mapping, info.filtering), ("open", c.addr, "independent", "open"))
            # an answer from the wrong IP, or for an unknown transaction, is not accepted
            req, tx = nn.binding_request()
            fut = asyncio.get_running_loop().create_future()
            prober.pending[tx] = (fut, "127.0.0.1")
            self.assertFalse(prober.feed(nn.binding_response(tx, ("6.6.6.6", 1)), ("10.9.9.9", 1)))
            self.assertFalse(prober.feed(nn.binding_response(b"\x07" * 12, ("6.6.6.6", 1)), ("127.0.0.1", 1)))
            self.assertFalse(fut.done())
        finally:
            c.close()
            srv.close()


class StunRelay(unittest.IsolatedAsyncioTestCase):
    """One relay with the STUN service; a second one without."""

    async def asyncSetUp(self):
        import os
        import tempfile
        self.tmp = tempfile.mkdtemp()
        meshdb.SCRYPT_N = 2 ** 10
        self.ports = [free_port(), free_port()]
        self.stun = nn.StunServer("127.0.0.1", free_udp_port(), free_udp_port(), free_udp_port(), rate=1000.0)
        self.relays, self.runners = [], []
        for i, stun in enumerate((self.stun, None)):
            r = sn.OneqRelay(meshdb.Store(os.path.join(self.tmp, f"r{i}.db"), f"r{i + 1}"), SECRET, [], stun=stun)
            r.nat_test_loopback = True
            runner = web.AppRunner(r.make_app(), access_log=None)
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", self.ports[i], shutdown_timeout=1).start()
            self.relays.append(r)
            self.runners.append(runner)
        self.urls = [f"http://127.0.0.1:{p}" for p in self.ports]
        for r in self.relays:
            r.reg.create_community("lan", "10.50.0.0/24")
            r.reg.add_user("lan", "alice", "alice-password", "user", max_nodes=10)
            r.reg.add_user("lan", "bob", "bob-password!", "user", max_nodes=10)
        self.http = aiohttp.ClientSession()

    async def asyncTearDown(self):
        await self.http.close()
        for r in self.runners:
            await r.cleanup()

    async def tok(self, i, user="alice", pw="alice-password"):
        r = await self.http.post(self.urls[i] + "/v1/login", json={"community": "lan", "user": user, "password": pw})
        return {"Authorization": "Bearer " + (await r.json())["token"]}

    async def join(self, i, ident, h, **extra):
        body = {"pub": __import__("base64").b64encode(ident.pub).decode(), "endpoints": ["10.0.0.1:5000"], "name": "n", **extra}
        return await self.http.put(f"{self.urls[i]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=h)


class TestRelayApi(StunRelay):
    async def test_join_tells_the_stun_ports_and_stores_the_nat_description(self):
        h, ident = await self.tok(0), t.Identity.generate()
        r = await self.join(0, ident, h, nat={"type": "port-restricted", "mapped": "203.0.113.5:40000", "inbound": False})
        d = await r.json()
        self.assertEqual((r.status, d["stun"]), (200, {"port": self.stun.port, "alt_port": self.stun.alt_port, "change_port": self.stun.change_port}))
        m = await (await self.http.get(self.urls[0] + "/v1/c/lan/nodes", headers=h)).json()
        self.assertEqual(m["nodes"][0]["nat"], {"type": "port-restricted", "mapped": "203.0.113.5:40000", "inbound": False})
        self.assertEqual((await (await self.http.get(self.urls[0] + "/v1/health")).json())["stun"]["port"], self.stun.port)
        # a relay without the service says nothing about stun
        h1 = await self.tok(1)
        d1 = await (await self.join(1, ident, h1)).json()
        self.assertNotIn("stun", d1)

    async def test_bad_nat_descriptions_are_refused(self):
        h = await self.tok(0)
        for bad in ({"type": "wormhole"}, {"type": "cone", "mapped": "not-an-endpoint"}, "cone", [], {"mapped": "1.2.3.4:5"}, {"type": 7}):
            r = await self.join(0, t.Identity.generate(), h, nat=bad)
            self.assertEqual(r.status, 400, bad)
        self.assertEqual((await self.join(0, t.Identity.generate(), h)).status, 200)            # the field is optional

    async def test_reachability_test(self):
        h, ident = await self.tok(0), t.Identity.generate()
        await self.join(0, ident, h)
        url = f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}/nat-test"
        node = await Udp().open(auto_answer=True)
        try:
            ep = "%s:%d" % node.addr
            d = await (await self.http.post(url, json={"endpoint": ep}, headers=h)).json()
            self.assertEqual((d["reachable"], d["probe_from_port"]), (True, self.stun.change_port))
            self.assertEqual(node.got[0][1][1], self.stun.change_port)
            # nobody listening there
            dead = await Udp().open()
            dead_ep = "%s:%d" % dead.addr
            dead.close()
            self.relays[0].nat_test_rate.clear()
            r = await self.http.post(url, json={"endpoint": dead_ep}, headers=h)
            self.assertEqual((r.status, (await r.json())["reachable"]), (200, False))
            # somebody else's address / garbage / not your node / no service / rate limit
            self.relays[0].nat_test_rate.clear()
            self.assertEqual((await self.http.post(url, json={"endpoint": "198.51.100.7:5000"}, headers=h)).status, 400)
            self.assertEqual((await self.http.post(url, json={"endpoint": "junk"}, headers=h)).status, 400)
            self.assertEqual((await self.http.post(url, json={}, headers=h)).status, 400)
            hb = await self.tok(0, "bob", "bob-password!")
            self.assertEqual((await self.http.post(url, json={"endpoint": ep}, headers=hb)).status, 403)
            self.assertEqual((await self.http.post(url, json={"endpoint": ep})).status, 401)
            h1 = await self.tok(1)
            await self.join(1, ident, h1)
            self.assertEqual((await self.http.post(f"{self.urls[1]}/v1/c/lan/nodes/{ident.node_id.hex()}/nat-test",
                                                   json={"endpoint": ep}, headers=h1)).status, 503)
            self.relays[0].nat_test_rate.clear()
            codes = [(await self.http.post(url, json={"endpoint": ep}, headers=h)).status for _ in range(6)]
            self.assertEqual(codes[:3], [200, 200, 200])
            self.assertIn(429, codes)
        finally:
            node.close()

    async def test_nat_test_is_off_for_other_networks_than_the_callers_own(self):
        self.relays[0].nat_test_loopback = False
        h, ident = await self.tok(0), t.Identity.generate()
        await self.join(0, ident, h)
        r = await self.http.post(f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}/nat-test", json={"endpoint": "127.0.0.1:9"}, headers=h)
        self.assertEqual(r.status, 400)                                          # loopback can never be probed


class TestNodeMeasuresTheRelay(StunRelay):
    async def test_node_classifies_publishes_and_checks_inbound_access(self):
        class Tap:
            name = "t0"

            def fileno(self):
                return -1

            def write(self, f):
                pass
        cfg = oneqnode.NodeConfig(relays=[self.urls[0]], community="lan", user="alice", password="alice-password", no_config=True,
                                 register_every=0.5, refresh_fast=0.2, name="measured", nat_keepalive=0.3)
        node = oneqnode.OneqNode(t.Identity.generate(), cfg, Tap())
        loop = asyncio.get_running_loop()

        class P(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                node.on_udp(data, addr)
        node.udp, _ = await loop.create_datagram_endpoint(P, local_addr=("127.0.0.1", 0))
        node._guess_ip = lambda: "127.0.0.1"                                     # the relay is on loopback
        node.tasks = [asyncio.ensure_future(node._registry_loop()), asyncio.ensure_future(node._nat_loop())]
        try:
            bound = node.udp.get_extra_info("sockname")
            await eventually(lambda: node.nat.type == "open" and node.nat_inbound is not None, timeout=10)
            self.assertEqual(node.nat.mapped, bound)
            self.assertTrue(node.nat_inbound)                                    # the relay reached us from its alt port
            self.assertEqual(node.endpoints()[-1], "%s:%d" % bound)

            async def published():
                m = await node.control.members()
                return m and (m[0]["nat"] or {}).get("type") == "open" and m[0]["nat"].get("inbound") is True and m[0]
            m = await eventually(published, timeout=10)
            self.assertEqual(m["nat"]["mapped"], "%s:%d" % bound)
            self.assertIn("%s:%d" % bound, m["endpoints"])
            # a changed NAT mapping is noticed and measured again
            before = node.nat
            node.nat_raw = nn.NatInfo("cone", ("203.0.113.5", 1))
            await eventually(lambda: node.nat.type == "open", timeout=10)
        finally:
            for tk in node.tasks:
                tk.cancel()
            node.udp.close()
            await node.control.close()

    async def mapped_node(self, ext_ip):
        """A node behind a (modelled) port-restricted NAT whose router speaks PCP and maps our port to `ext_ip`."""
        from test_oneqportmap import pcp_gateway, udp_server
        import oneqportmap

        class Tap:
            name = "t0"

            def fileno(self):
                return -1
        cfg = oneqnode.NodeConfig(relays=[self.urls[0]], community="lan", user="alice", password="alice-password", no_config=True,
                                 register_every=0.5, refresh_fast=0.2, name="mapped")
        node = oneqnode.OneqNode(t.Identity.generate(), cfg, Tap())

        class P(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                node.on_udp(data, addr)
        node.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(P, local_addr=("127.0.0.1", 0))
        port = node.udp.get_extra_info("sockname")[1]
        handler, state = pcp_gateway(ext_port=port, ext_ip=ext_ip)
        gw = await udp_server(handler)
        node.portmapper = oneqportmap.PortMapper(gateway="127.0.0.1", methods=("pcp",), pcp_port=gw.port, local_ip="192.168.1.10")
        node.tasks = [asyncio.ensure_future(node._registry_loop())]
        await eventually(lambda: node.control.info is not None, timeout=10)
        return node, gw, state, port

    async def test_router_mapping_makes_the_node_open_once_the_relay_reaches_it(self):
        node, gw, state, port = await self.mapped_node("127.0.0.1")
        try:
            node.nat_raw = nn.NatInfo("port-restricted", ("127.0.0.1", port + 1), "independent", "restricted")
            await node._port_mapping(port)
            node._apply_nat()
            self.assertEqual(node.nat.type, "port-restricted", "a mapping nobody verified is not claimed")
            self.assertEqual(node.mapping.method, "pcp")
            await node._check_inbound()
            node._apply_nat()
            self.assertTrue(node.mapping_ok)
            self.assertEqual((node.nat.type, node.nat.via, node.nat.mapped), ("open", "pcp", ("127.0.0.1", port)))
            d = node.nat_description()
            self.assertEqual((d["type"], d["via"]), ("open", "pcp"))
            self.assertIn(f"127.0.0.1:{port}", node.endpoints())
            self.assertFalse(node.cgnat)
            await node.close()
            self.assertEqual(state["maps"][-1]["lifetime"], 0, "the mapping is released when the node stops")
        finally:
            for tk in node.tasks:
                tk.cancel()
            gw.tr.close()

    async def test_a_router_mapping_behind_a_second_nat_is_released_and_flagged(self):
        node, gw, state, port = await self.mapped_node("192.168.0.2")           # the router's WAN address is private
        try:
            node.nat_raw = nn.NatInfo("port-restricted", ("127.0.0.1", port + 1), "independent", "restricted")
            await node._port_mapping(port)
            node._apply_nat()
            self.assertTrue(node.cgnat)
            self.assertIsNone(node.mapping)
            self.assertEqual(state["maps"][-1]["lifetime"], 0, "released at once")
            self.assertEqual((node.nat.type, node.nat.cgnat), ("port-restricted", True))
            self.assertTrue(node.nat_description()["cgnat"])
        finally:
            for tk in node.tasks:
                tk.cancel()
            node.udp.close()
            await node.control.close()
            gw.tr.close()

    async def test_carrier_grade_mapped_address_is_flagged_without_any_router_protocol(self):
        node, gw, state, port = await self.mapped_node("127.0.0.1")
        try:
            node.portmapper = None
            node.nat_raw = nn.NatInfo("symmetric", ("100.72.1.9", 4000), "dependent")
            await node._port_mapping(port)
            self.assertTrue(node.cgnat)
            self.assertEqual(state["maps"], [])
        finally:
            for tk in node.tasks:
                tk.cancel()
            node.udp.close()
            await node.control.close()
            gw.tr.close()

    async def test_node_answers_binding_requests_with_the_address_it_sees(self):
        class Tap:
            name = "t0"

        cfg = oneqnode.NodeConfig(relays=[self.urls[0]], community="lan", user="alice", password="x", no_config=True)
        node = oneqnode.OneqNode(t.Identity.generate(), cfg, Tap())
        sent = []
        node.udp = type("S", (), {"sendto": lambda _s, d, a: sent.append((d, a)), "close": lambda _s: None})()
        req, tx = nn.binding_request()
        node.on_udp(req, ("198.51.100.4", 4444))
        self.assertEqual(nn.mapped_of(nn.parse(sent[0][0])), ("198.51.100.4", 4444))
        self.assertEqual(sent[0][1], ("198.51.100.4", 4444))
        for _ in range(100):                                                     # at most 20 answers per second
            node.on_udp(req, ("198.51.100.4", 4444))
        self.assertLessEqual(len(sent), 21)
        await node.control.close()


class TestPunchingRules(StunRelay):
    """Decisions of the node: when it may send unsolicited packets, which source addresses it trusts, the shared clock."""

    def node(self, my_nat="port-restricted"):
        class Tap:
            name = "t0"
        cfg = oneqnode.NodeConfig(relays=[self.urls[0]], community="lan", user="alice", password="alice-password", no_config=True)
        n = oneqnode.OneqNode(t.Identity.generate(), cfg, Tap())
        n.sent = []
        n.udp = type("S", (), {"sendto": lambda _s, d, a: n.sent.append((d, a)), "close": lambda _s: None})()
        n.nat = nn.NatInfo(my_nat, ("198.51.100.1", 4000))
        n.control.clock_offset = 0.0                          # the relay clock is known: punch rounds are available
        return n

    def peer(self, n, nat="port-restricted", cands=(("203.0.113.9", 5000),), mapped=None, initiator=True):
        ident = t.Identity.generate()
        p = oneqnode.Peer(ident.node_id, ident.pub, "10.50.0.9", "02:00:00:00:00:09")
        p.nat, p.nat_mapped, p.candidates, p.initiator = nat, mapped, list(cands), initiator
        n.peers[p.id] = p
        return p

    async def test_careful_only_when_both_sides_filter(self):
        n = self.node("port-restricted")
        for peer_nat, want in (("port-restricted", True), ("symmetric", True), ("cone", False), ("open", False), (None, False)):
            self.assertEqual(n._careful(self.peer(n, peer_nat)), want, peer_nat)
        n = self.node("cone")
        self.assertFalse(n._careful(self.peer(n, "symmetric")))
        n = self.node("unknown")
        self.assertFalse(n._careful(self.peer(n, "port-restricted")))
        await n.control.close()

    async def test_a_predictable_symmetric_peer_is_punched_at_the_predicted_ports(self):
        n = self.node("port-restricted")
        now = time.monotonic()
        hard = self.peer(n, "symmetric", cands=(), mapped="203.0.113.9:5000")
        self.assertNotIn(hard, n._punch_peers(now), "symmetric with random ports: hopeless for a port-restricted node")
        hard.nat_delta = 2
        hard.predicted = nn.punch_ports(hard.nat, hard.nat_mapped, hard.nat_delta)
        self.assertIn(hard, n._punch_peers(now))
        self.assertEqual(hard.predicted[0], ("203.0.113.9", 5002))
        # the sender accepts holes at the IP the symmetric peer published, whatever port the NAT picked
        self.assertTrue(n._open_hole(hard, ("203.0.113.9", 5006)))
        # we are symmetric too: both sides must be predictable
        n2 = self.node("symmetric")
        both = self.peer(n2, "symmetric", cands=(), mapped="203.0.113.9:5000")
        both.nat_delta, both.predicted = 2, nn.punch_ports("symmetric", both.nat_mapped, 2)
        self.assertNotIn(both, n2._punch_peers(now))
        n2.nat.delta = 1
        self.assertIn(both, n2._punch_peers(now))
        await n.control.close()
        await n2.control.close()

    async def test_a_second_nat_sends_the_traffic_to_the_relay_at_once(self):
        for mine, theirs, cgnat_side in (("cone", "cone", "me"), ("cone", "cone", "peer"), ("port-restricted", "cone", "me")):
            n = self.node(mine)
            if cgnat_side == "me":
                n.nat.cgnat = True
            p = self.peer(n, theirs)
            p.nat_cgnat = cgnat_side == "peer"
            n.relay = type("R", (), {"enabled": asyncio.Event(), "connected": False, "send": lambda *_a: None})()
            n._tick_peer(p, time.monotonic())
            self.assertTrue(p.relay_hs and n.relay.enabled.is_set(), (mine, theirs, cgnat_side))
            await n.control.close()
        # a peer that accepts unsolicited packets is still worth a direct attempt
        n = self.node("cone")
        n.nat.cgnat = True
        n.relay = type("R", (), {"enabled": asyncio.Event(), "connected": False, "send": lambda *_a: None})()
        p = self.peer(n, "open")
        n._tick_peer(p, time.monotonic())
        self.assertFalse(p.relay_hs)
        await n.control.close()

    async def test_two_hosts_with_global_ipv6_always_try_direct(self):
        n = self.node("symmetric")
        n.dual_stack, n.v6_endpoint = True, "[2001:db8::1]:5000"
        n.nat.cgnat = True
        p = self.peer(n, "symmetric", cands=(("2001:db8::2", 6000), ("203.0.113.9", 5000)))
        self.assertTrue(n._punchable(p))
        n.relay = type("R", (), {"enabled": asyncio.Event(), "connected": False, "send": lambda *_a: None})()
        n._tick_peer(p, time.monotonic())
        self.assertFalse(p.relay_hs, "direct IPv6 is possible: no early relay")
        v4only = self.peer(n, "symmetric", cands=(("203.0.113.10", 5000),))
        self.assertFalse(n._punchable(v4only))
        await n.control.close()

    async def test_members_with_ipv6_endpoints_and_the_new_nat_fields(self):
        n = self.node("cone")
        ident = t.Identity.generate()
        member = {"id": ident.node_id.hex(), "pub": base64.b64encode(ident.pub).decode(), "ip": "10.50.0.7", "mac": "02:00:00:00:00:07",
                  "endpoints": ["203.0.113.7:5000", "[2001:DB8:0:0::7]:5001", "[2001:db8::8]", "nonsense", "[::1]:x"],
                  "nat": {"type": "symmetric", "mapped": "203.0.113.7:5002", "delta": 2, "cgnat": True, "via": "upnp"}}
        n.apply_members([member])
        p = n.peers[ident.node_id]
        self.assertEqual(p.candidates, [("203.0.113.7", 5000)], "no IPv6 socket: IPv6 candidates are skipped")
        self.assertEqual((p.nat_delta, p.nat_cgnat), (2, True))
        self.assertEqual(p.predicted[0], ("203.0.113.7", 5004))
        n.dual_stack = True
        n.apply_members([member])
        self.assertEqual(n.peers[ident.node_id].candidates, [("203.0.113.7", 5000), ("2001:db8::7", 5001)])
        member["nat"] = {"type": "symmetric", "delta": "2", "cgnat": "yes"}
        n.apply_members([member])
        q = n.peers[ident.node_id]
        self.assertEqual((q.nat_delta, q.nat_cgnat, q.predicted), (None, False, []), "wrong types are ignored")
        await n.control.close()

    async def test_a_real_dual_stack_socket_exchanges_datagrams_with_ipv4_peers(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6 on this host")
        n = self.node()
        got = []

        class P(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                got.append((data, oneqnode.normalize_addr(addr)))
        tr = await n._bind_dual_stack(asyncio.get_running_loop(), P, 0)
        if tr is None:
            self.skipTest("this host cannot bind a dual-stack socket")
        n.udp = tr
        port = tr.get_extra_info("sockname")[1]
        peer = await Udp().open()
        peer.tr.sendto(b"hello", ("127.0.0.1", port))
        for _ in range(100):
            if got:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(got, [(b"hello", peer.addr)], "an IPv4 peer shows up as a plain IPv4 address")
        n._udp_send(b"back", peer.addr)
        self.assertEqual([d for d, _ in await peer.wait(1)], [b"back"])
        self.assertTrue(n.dual_stack)
        self.assertEqual(n.parse_endpoint("[2001:db8::1]:5"), ("2001:db8::1", 5))
        peer.close()
        tr.close()
        await n.control.close()

    async def test_address_normalisation_of_a_dual_stack_socket(self):
        f = oneqnode.normalize_addr
        self.assertEqual(f(("::ffff:203.0.113.9", 5000, 0, 0)), ("203.0.113.9", 5000))
        self.assertEqual(f(("::FFFF:203.0.113.9", 5000, 0, 0)), ("203.0.113.9", 5000))
        self.assertEqual(f(("2001:db8::7", 5001, 0, 0)), ("2001:db8::7", 5001))
        self.assertEqual(f(("fe80::1%eth0", 5001, 0, 2)), ("fe80::1", 5001))
        self.assertEqual(f(("203.0.113.9", 5000)), ("203.0.113.9", 5000))
        n = self.node()
        n.dual_stack = True
        n._udp_send(b"x", ("203.0.113.9", 5000))
        n._udp_send(b"y", ("2001:db8::7", 5001))
        self.assertEqual(n.sent, [(b"x", ("::ffff:203.0.113.9", 5000)), (b"y", ("2001:db8::7", 5001))])
        await n.control.close()

    async def test_without_the_relay_clock_the_plain_behaviour_stays(self):
        n = self.node("port-restricted")
        p = self.peer(n, "port-restricted")
        self.assertTrue(n._careful(p))
        n.control.clock_offset = None
        self.assertFalse(n._careful(p))
        self.assertEqual(n._direct_targets(p, time.monotonic()), p.candidates)
        await n.control.close()

    async def test_unsolicited_sends_only_after_the_peer_opened_a_hole(self):
        n = self.node()
        p = self.peer(n)
        now = time.monotonic()
        self.assertEqual(n._direct_targets(p, now), [])                       # nothing outside punch rounds
        self.assertTrue(n._open_hole(p, ("203.0.113.9", 5000)))
        self.assertEqual(n._direct_targets(p, now), [("203.0.113.9", 5000)])
        self.assertFalse(n._open_hole(p, ("203.0.113.9", 5000)))              # already open
        self.assertEqual(n._direct_targets(p, now + oneqnode.HOLE_TTL + 1), [])  # closes again
        easy = self.peer(n, "cone", cands=(("198.51.100.77", 6000),))
        self.assertEqual(n._direct_targets(easy, now), [("198.51.100.77", 6000)])   # no filtering on the other side: plain behaviour
        await n.control.close()

    async def test_forged_source_addresses_do_not_open_holes(self):
        n = self.node()
        p = self.peer(n, cands=(("203.0.113.9", 5000), ("10.100.1.2", 5000)), mapped="192.0.2.12:50001")
        self.assertFalse(n._open_hole(p, ("6.6.6.6", 5000)))                  # a stranger
        self.assertTrue(n._open_hole(p, ("203.0.113.9", 61000)))              # same IP, the NAT chose another port
        p.hole_until = 0
        self.assertTrue(n._open_hole(p, ("192.0.2.12", 33333)))               # the IP a symmetric NAT published
        before = len(n.sent)
        n._punch_from(p.id, ("6.6.6.6", 1))
        n._punch_from(b"\x00" * 16, ("203.0.113.9", 5000))                    # unknown node id
        self.assertEqual(len(n.sent), before)
        await n.control.close()

    async def test_a_punch_from_the_peer_is_answered_and_starts_the_handshake_at_that_address_only(self):
        n = self.node()
        p = self.peer(n, initiator=True)
        n._punch_from(p.id, ("203.0.113.9", 5000))
        kinds = [(d[0], a) for d, a in n.sent]
        self.assertIn((mp.T_PUNCH, ("203.0.113.9", 5000)), kinds)              # reply, so the peer's NAT has its entry too
        frags = [a for k, a in kinds if k == mp.T_FRAG]
        self.assertTrue(frags and set(frags) == {("203.0.113.9", 5000)})        # INIT fragments go there and nowhere else
        n.sent.clear()
        n._punch_from(p.id, ("203.0.113.9", 5000))                             # rate limited: no second INIT right away
        self.assertEqual([k for k, _ in [(d[0], a) for d, a in n.sent] if k == mp.T_FRAG], [])
        # a responder only answers
        r = self.peer(n, initiator=False, cands=(("203.0.113.10", 5000),))
        n.sent.clear()
        n._punch_from(r.id, ("203.0.113.10", 5000))
        self.assertEqual({d[0] for d, _ in n.sent}, {mp.T_PUNCH})
        await n.control.close()

    async def test_tick_sends_nothing_unsolicited_between_two_filtering_nats(self):
        n = self.node()
        careful, easy = self.peer(n), self.peer(n, "cone", cands=(("198.51.100.77", 6000),))
        n.relay = None
        n._tick_peer(careful, time.monotonic() + 5)
        self.assertEqual(n.sent, [])
        n._tick_peer(easy, time.monotonic() + 5)
        self.assertTrue(n.sent and all(a == ("198.51.100.77", 6000) for _, a in n.sent))
        await n.control.close()

    def test_punch_rounds_are_a_pattern_of_the_shared_clock(self):
        rounds = [i for i in range(40) if oneqnode.OneqNode.punch_attempt_round(i)]
        self.assertEqual(rounds, [0, 1, 2, 10, 11, 12, 20, 21, 22, 30, 31, 32])
        gap = (oneqnode.PUNCH_CYCLE - oneqnode.PUNCH_ATTEMPTS + 1) * oneqnode.PUNCH_PERIOD - oneqnode.PUNCH_OFFSETS[-1]
        self.assertGreater(gap, 30.0)                  # conntrack keeps an unanswered UDP entry for 30 s

    async def test_clock_offset_is_measured_against_the_relay(self):
        n = self.node()
        n.control.clock_offset = None
        self.assertIsNone(n.relay_time())
        await n.control.join(n.me.node_id.hex(), n.me.pub, [], "clock")
        self.assertLess(abs(n.control.clock_offset), 0.5)
        self.assertLess(abs(n.relay_time() - time.time()), 0.5)
        self.assertLess(n.control.clock_rtt, 1.0)
        await n.control.close()


if __name__ == "__main__":
    unittest.main()
