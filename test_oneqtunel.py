#!/usr/bin/env python3
"""Unit + integration tests (no root needed). Run: python3 test_oneqtunel.py

Covers: key sizes, hybrid handshake, data plane/anti-replay/expiry, fragmentation and
reassembly (missing, duplicate, memory exhaustion), STUN parsing, node state machine over
an in-memory network, rendezvous REST API, WebSocket relay, and TLS group enforcement
(X25519MLKEM768 accepted; classic groups refused, no fallback).
The root-only end-to-end test with real TUN devices is test_e2e.py.
"""
import pqtls  # noqa: F401  (first: OPENSSL_CONF)

import asyncio
import base64
import datetime
import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import rendezvous_server as rs
import oneqtunel as t

HERE = os.path.dirname(os.path.abspath(__file__))
OPENSSL = shutil.which("openssl")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def pair():
    a, b = t.Identity.generate(), t.Identity.generate()
    return (a, b) if a.pub < b.pub else (b, a)      # (initiator, responder)


# ------------------------------------------------------------------ keys and handshake

class TestKeys(unittest.TestCase):
    def test_sizes_and_roundtrip(self):
        a = t.Identity.generate()
        self.assertEqual(len(a.pub), 1216)
        self.assertEqual(len(a.to_bytes()), 96)
        b = t.Identity.from_bytes(a.to_bytes())
        self.assertEqual(a.pub, b.pub)
        self.assertEqual(len(a.node_id), 16)

    @unittest.skipUnless(os.name == "posix", "posix permissions")
    def test_key_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k")
            t.save_identity(p, t.Identity.generate(), p + ".pub")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            t.load_identity(p)
            os.chmod(p, 0o644)
            with self.assertRaises(PermissionError):
                t.load_identity(p)
            self.assertEqual(len(t.load_public(p + ".pub")), 1216)


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.i, self.r = pair()

    def run_hs(self):
        msg, st = t.init_create(self.i, self.r.pub)
        ts, ck, h, E, ek = t.init_consume(self.r, self.i.pub, msg)
        resp, rsk, rrk = t.resp_create(self.r, self.i.pub, ck, h, E, ek)
        isk, irk = t.resp_consume(self.i, st, resp)
        return msg, resp, (isk, irk), (rsk, rrk)

    def test_sizes_match_spec(self):
        msg, resp, _, _ = self.run_hs()
        self.assertEqual((len(msg), msg[0]), (2329, 0x11))
        self.assertEqual((len(resp), resp[0]), (2225, 0x12))

    def test_session_keys_agree_and_are_directional(self):
        _, _, (isk, irk), (rsk, rrk) = self.run_hs()
        self.assertEqual(isk, rrk)
        self.assertEqual(irk, rsk)
        self.assertNotEqual(isk, irk)

    def test_each_handshake_is_fresh(self):
        _, _, a, _ = self.run_hs()
        _, _, b, _ = self.run_hs()
        self.assertNotEqual(a, b)

    def test_tampered_init_rejected(self):
        msg, _ = t.init_create(self.i, self.r.pub)
        for pos in (5, 40, 1300, 2300, 2328):          # E_i, ek_e, ct_sr, AEAD
            bad = bytearray(msg)
            bad[pos] ^= 1
            with self.assertRaises(t.HandshakeError):
                t.init_consume(self.r, self.i.pub, bytes(bad))

    def test_init_from_unknown_static_key_rejected(self):
        stranger = t.Identity.generate()
        msg, _ = t.init_create(stranger, self.r.pub)
        with self.assertRaises(t.HandshakeError):
            t.init_consume(self.r, self.i.pub, msg)

    def test_init_for_other_responder_rejected(self):
        other = t.Identity.generate()
        msg, _ = t.init_create(self.i, other.pub)
        with self.assertRaises(t.HandshakeError):
            t.init_consume(self.r, self.i.pub, msg)

    def test_tampered_or_foreign_resp_rejected(self):
        msg, st = t.init_create(self.i, self.r.pub)
        _, ck, h, E, ek = t.init_consume(self.r, self.i.pub, msg)
        resp, _, _ = t.resp_create(self.r, self.i.pub, ck, h, E, ek)
        for pos in (5, 100, 1200, 2224):
            bad = bytearray(resp)
            bad[pos] ^= 1
            with self.assertRaises(t.HandshakeError):
                t.resp_consume(self.i, st, bytes(bad))
        _, st2 = t.init_create(self.i, self.r.pub)      # RESP belongs to another INIT
        with self.assertRaises(t.HandshakeError):
            t.resp_consume(self.i, st2, resp)

    def test_resp_cannot_be_forged_without_responder_key(self):
        msg, st = t.init_create(self.i, self.r.pub)
        impostor = t.Identity.generate()
        _, ck, h, E, ek = t.init_consume(self.r, self.i.pub, msg)
        # impostor lacks the real k_sr/dh secrets: derives its own chain from a different INIT
        msg2, _ = t.init_create(self.i, impostor.pub)
        _, ck2, h2, E2, ek2 = t.init_consume(impostor, self.i.pub, msg2)
        fake, _, _ = t.resp_create(impostor, self.i.pub, ck2, h2, E, ek)
        with self.assertRaises(t.HandshakeError):
            t.resp_consume(self.i, st, fake)


# ------------------------------------------------------------------ data plane

class TestData(unittest.TestCase):
    def mk(self, clock=time.monotonic):
        k1, k2 = os.urandom(32), os.urandom(32)
        return t.Session(k1, k2, True, clock), t.Session(k2, k1, False, clock)

    def test_roundtrip_and_header_is_aad(self):
        a, b = self.mk()
        p = a.encrypt(b"hello")
        self.assertEqual(p[0], 0x13)
        self.assertEqual(b.decrypt(p), b"hello")
        a2, b2 = self.mk()
        q = bytearray(a2.encrypt(b"x"))
        q[3] ^= 1                                       # counter is authenticated
        self.assertIsNone(b2.decrypt(bytes(q)))
        q = bytearray(a2.encrypt(b"x"))
        q[-1] ^= 1
        self.assertIsNone(b2.decrypt(bytes(q)))

    def test_replay_rejected(self):
        a, b = self.mk()
        p = a.encrypt(b"x")
        self.assertEqual(b.decrypt(p), b"x")
        self.assertIsNone(b.decrypt(p))

    def test_window_1024(self):
        a, b = self.mk()
        pk = [a.encrypt(b"%d" % i) for i in range(1100)]
        self.assertIsNotNone(b.decrypt(pk[1099]))
        self.assertIsNone(b.decrypt(pk[10]))            # older than 1024 behind the top
        self.assertIsNotNone(b.decrypt(pk[1099 - 1023]))   # last slot of the window
        self.assertIsNotNone(b.decrypt(pk[500]))        # out of order but inside the window
        self.assertIsNone(b.decrypt(pk[500]))

    def test_counter_never_repeats(self):
        a, _ = self.mk()
        self.assertEqual(len({a.encrypt(b"") for _ in range(100)}), 100)

    def test_reject_after_180s(self):
        now = [1000.0]
        a, b = self.mk(lambda: now[0])
        p = a.encrypt(b"x")
        now[0] += 179
        self.assertEqual(b.decrypt(p), b"x")
        self.assertTrue(a.usable())
        now[0] += 2
        self.assertFalse(a.usable())
        with self.assertRaises(t.HandshakeError):
            a.encrypt(b"y")
        self.assertIsNone(b.decrypt(a._send.encrypt(b"\0" * 12, b"", b"")))   # garbage also rejected
        self.assertIsNone(b.decrypt(p[:9] + b"\0" * 20))


# ------------------------------------------------------------------ fragmentation

class TestFragmentation(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.r = t.Reassembler(clock=lambda: self.now[0])

    def frags(self, size=2329, mid=7):
        msg = os.urandom(size)
        return msg, t.fragment(msg, mid)

    def test_split_limits(self):
        for size in (1, 1193, 1194, 2329, 2225, 4772):
            msg, fr = self.frags(size)
            self.assertTrue(all(len(f) <= 1200 for f in fr), size)
            self.assertEqual(self.r.feed("a", fr[0]) if len(fr) == 1 else None, msg if len(fr) == 1 else None)
        with self.assertRaises(ValueError):
            t.fragment(os.urandom(4773))

    def test_reassembly_in_any_order(self):
        msg, fr = self.frags()
        self.assertEqual(len(fr), 2)
        self.assertIsNone(self.r.feed("a", fr[1]))
        self.assertEqual(self.r.feed("a", fr[0]), msg)
        self.assertEqual(self.r.bytes, 0)

    def test_missing_fragment_never_completes_and_expires(self):
        msg, fr = self.frags(4000)
        self.assertEqual(len(fr), 4)
        for f in fr[:3]:
            self.assertIsNone(self.r.feed("a", f))
        self.now[0] += 6                                # ttl 5 s
        self.assertIsNone(self.r.feed("a", fr[3]))      # starts a fresh entry, old one is gone
        self.assertEqual(len(self.r.entries), 1)

    def test_duplicates_do_not_corrupt_or_grow(self):
        msg, fr = self.frags()
        self.assertIsNone(self.r.feed("a", fr[0]))
        before = self.r.bytes
        for _ in range(50):
            self.assertIsNone(self.r.feed("a", fr[0]))
        self.assertEqual(self.r.bytes, before)
        self.assertEqual(self.r.feed("a", fr[1]), msg)

    def test_inconsistent_total_drops_entry(self):
        _, fr = self.frags(2329, 9)
        self.r.feed("a", fr[0])
        bad = t.FRAG_HDR.pack(t.T_FRAG, 9, 1, 3) + b"x" * t.FRAG_PAYLOAD
        self.assertIsNone(self.r.feed("a", bad))
        self.assertEqual(len(self.r.entries), 0)

    def test_malformed_dropped(self):
        h = t.FRAG_HDR
        full = b"x" * t.FRAG_PAYLOAD
        for d in (b"", b"\x15", h.pack(0x15, 1, 0, 0) + full, h.pack(0x15, 1, 2, 2) + full,
                  h.pack(0x15, 1, 0, 5) + full, h.pack(0x15, 1, 0, 2) + b"short",
                  h.pack(0x15, 1, 0, 2) + b"x" * 1300):
            self.assertIsNone(self.r.feed("a", d))
        self.assertEqual(len(self.r.entries), 0)

    def test_memory_exhaustion_per_source(self):
        for mid in range(100):
            self.r.feed("attacker", t.FRAG_HDR.pack(0x15, mid, 0, 2) + b"x" * t.FRAG_PAYLOAD)
        self.assertEqual(len(self.r.entries), 4)        # max_per_src
        self.assertLessEqual(self.r.bytes, 4 * t.FRAG_PAYLOAD)

    def test_memory_exhaustion_many_sources(self):
        for i in range(500):
            self.r.feed(("10.0.0.%d" % (i % 250), i), t.FRAG_HDR.pack(0x15, i, 0, 4) + b"x" * t.FRAG_PAYLOAD)
        self.assertLessEqual(len(self.r.entries), 16)
        self.assertLessEqual(self.r.bytes, 64 * 1024)

    def test_legit_traffic_works_after_flood_expires(self):
        for i in range(500):
            self.r.feed(("a", i), t.FRAG_HDR.pack(0x15, i, 0, 4) + b"x" * t.FRAG_PAYLOAD)
        self.now[0] += 6
        msg, fr = self.frags()
        self.r.feed("good", fr[0])
        self.assertEqual(self.r.feed("good", fr[1]), msg)


# ------------------------------------------------------------------ STUN

class TestStun(unittest.TestCase):
    def test_parse_xor_mapped_address(self):
        req, tx = t.stun_request()
        ip, port = "203.0.113.9", 40001
        xp = port ^ (t.STUN_COOKIE >> 16)
        xi = struct.unpack(">I", socket.inet_aton(ip))[0] ^ t.STUN_COOKIE
        attr = struct.pack(">HHBBHI", 0x0020, 8, 0, 1, xp, xi)
        resp = struct.pack(">HHI", 0x0101, len(attr), t.STUN_COOKIE) + tx + attr
        self.assertTrue(t.is_stun(resp))
        self.assertEqual(t.stun_parse(resp, tx), (ip, port))
        self.assertIsNone(t.stun_parse(resp, os.urandom(12)))
        self.assertFalse(t.is_stun(b"\x13" + b"\0" * 40))


# ------------------------------------------------------------------ node over an in-memory network

class FakeTun:
    def __init__(self):
        self.out = []

    def fileno(self):
        return -1

    def write(self, p):
        self.out.append(p)


class FakeNet:
    def __init__(self):
        self.nodes = {}
        self.sizes = []
        self.raw_hs = 0
        self.drop = lambda d, s, a: False

    def add(self, node, addr):
        node.udp = self.Sock(self, addr)
        self.nodes[addr] = node

    class Sock:
        def __init__(self, net, addr):
            self.net, self.addr = net, addr

        def sendto(self, data, dst):
            self.net.sizes.append(len(data))
            if data[0] in (t.T_INIT, t.T_RESP):
                self.net.raw_hs += 1
            if self.net.drop(data, self.addr, dst):
                return
            n = self.net.nodes.get(dst)
            if n:
                asyncio.get_running_loop().call_soon(n.on_udp, data, self.addr)

        def close(self):
            pass


class TestNode(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.i, self.r = pair()
        self.net = FakeNet()
        ca = t.Config(peer_endpoints=["10.0.0.2:1"])
        cb = t.Config(peer_endpoints=["10.0.0.1:1"])
        self.a = t.Node(self.i, self.r.pub, ca, FakeTun())     # initiator
        self.b = t.Node(self.r, self.i.pub, cb, FakeTun())
        self.net.add(self.a, ("10.0.0.1", 1))
        self.net.add(self.b, ("10.0.0.2", 1))

    async def pump(self, n=8):
        for _ in range(n):
            await asyncio.sleep(0)

    async def test_session_and_traffic(self):
        self.a._tick()
        await self.pump()
        self.assertIsNotNone(self.a.cur)
        self.assertIsNotNone(self.b.cur)
        self.assertEqual(self.net.raw_hs, 0, "handshake must only travel as fragments")
        self.assertTrue(all(s <= 1200 for s in self.net.sizes if s < 1400))
        hs_sizes = [s for s in self.net.sizes]
        self.assertTrue(max(hs_sizes) <= 1200, hs_sizes)
        self.a.send_payload(b"\x45" + b"A" * 100)
        self.b.send_payload(b"\x45" + b"B" * 50)
        await self.pump()
        self.assertEqual(self.b.tun.out, [b"\x45" + b"A" * 100])
        self.assertEqual(self.a.tun.out, [b"\x45" + b"B" * 50])

    async def test_handshake_survives_lost_fragment(self):
        lost = {"n": 0}

        def drop(d, src, dst):
            if d[0] == t.T_FRAG and src == ("10.0.0.1", 1) and lost["n"] < 1:
                lost["n"] += 1
                return True
            return False
        self.net.drop = drop
        self.a._tick()
        await self.pump()
        self.assertIsNone(self.b.cur)
        self.a.last_init -= 3                            # retry timer
        self.a._tick()
        await self.pump()
        self.assertIsNotNone(self.b.cur)
        self.assertIsNotNone(self.a.cur)

    async def test_replayed_init_rejected(self):
        captured = []
        self.net.drop = lambda d, s, a: captured.append((d, s, a)) and False
        self.a._tick()
        await self.pump()
        first_session = self.b.cur
        self.assertIsNotNone(first_session)
        init_frags = [c for c in captured if c[1] == ("10.0.0.1", 1) and c[0][0] == t.T_FRAG]
        for d, s, a in init_frags:                       # attacker replays the captured INIT
            self.b.on_udp(d, s)
        await self.pump()
        self.assertIs(self.b.cur, first_session)

    async def test_stale_timestamp_rejected(self):
        old = (time.time_ns() // 1000) - 400 * 1_000_000
        msg, _ = t.init_create(self.i, self.r.pub, now_us=old)
        for f in t.fragment(msg):
            self.b.on_udp(f, ("10.0.0.1", 1))
        await self.pump()
        self.assertIsNone(self.b.cur)

    async def test_garbage_ignored(self):
        for junk in (b"\x13" * 5, b"\x11" + os.urandom(2328), b"\x12" + os.urandom(2224), os.urandom(100),
                     b"\x15" + os.urandom(1199)):
            self.b.on_udp(junk, ("6.6.6.6", 6))
        self.assertIsNone(self.b.cur)

    async def test_unauthenticated_packet_does_not_move_peer_address(self):
        self.a._tick()
        await self.pump()
        before = self.b.peer_addr
        self.b.on_udp(bytes([t.T_DATA]) + os.urandom(60), ("6.6.6.6", 6))
        self.assertEqual(self.b.peer_addr, before)

    async def test_rekey_keeps_old_session_for_inflight_packets(self):
        self.a._tick()
        await self.pump()
        old_pkt = self.a.cur.encrypt(b"\x45old")
        self.a.cur.created -= 130                        # force rekey
        self.a.last_init -= 3
        self.a._tick()
        await self.pump()
        self.assertGreater(self.a.cur.age() + 1, 0)
        self.assertLess(self.a.cur.age(), 5)
        self.b.on_udp(old_pkt, ("10.0.0.1", 1))          # packet encrypted with the previous key
        self.assertIn(b"\x45old", self.b.tun.out)


# ------------------------------------------------------------------ rendezvous API + relay (plain HTTP, in-process)

class ServerCase(unittest.IsolatedAsyncioTestCase):
    allowed = None
    open_ = True

    async def asyncSetUp(self):
        self.state = rs.State(allowed=self.allowed, open_=self.open_)
        self.runner = web.AppRunner(rs.make_app(self.state))
        await self.runner.setup()
        self.port = free_port()
        await web.TCPSite(self.runner, "127.0.0.1", self.port).start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.http = aiohttp.ClientSession()

    async def asyncTearDown(self):
        await self.http.close()
        await self.runner.cleanup()

    def hdr(self, tok="netA"):
        return {"Authorization": "Bearer " + tok}


class TestRendezvousApi(ServerCase):
    async def put(self, ident, eps=("127.0.0.1:5000",), tok="netA", pub=None):
        body = {"pub": base64.b64encode(pub or ident.pub).decode(), "endpoints": list(eps)}
        return await self.http.put(f"{self.base}/v1/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(tok))

    async def test_health_needs_no_auth(self):
        r = await self.http.get(self.base + "/v1/health")
        self.assertEqual((r.status, (await r.json())["status"]), (200, "ok"))

    async def test_register_and_lookup(self):
        a = t.Identity.generate()
        self.assertEqual((await self.put(a)).status, 200)
        r = await self.http.get(f"{self.base}/v1/nodes/{a.node_id.hex()}", headers=self.hdr())
        j = await r.json()
        self.assertEqual(base64.b64decode(j["pub"]), a.pub)
        self.assertEqual(j["endpoints"], ["127.0.0.1:5000"])

    async def test_networks_are_isolated_by_token(self):
        a = t.Identity.generate()
        await self.put(a, tok="netA")
        r = await self.http.get(f"{self.base}/v1/nodes/{a.node_id.hex()}", headers=self.hdr("netB"))
        self.assertEqual(r.status, 404)

    async def test_id_must_match_public_key(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        body = {"pub": base64.b64encode(b.pub).decode(), "endpoints": []}
        r = await self.http.put(f"{self.base}/v1/nodes/{a.node_id.hex()}", json=body, headers=self.hdr())
        self.assertEqual(r.status, 400)

    async def test_validation(self):
        a = t.Identity.generate()
        for eps in (["nonsense"], ["1.2.3.4:99999"], ["1.2.3.4:1"] * 20, "x", [5]):
            self.assertEqual((await self.put(a, eps=eps)).status, 400, eps)
        r = await self.http.put(f"{self.base}/v1/nodes/zz", data=b"{}", headers=self.hdr())
        self.assertEqual(r.status, 400)
        r = await self.http.put(f"{self.base}/v1/nodes/{a.node_id.hex()}", data=b"x" * 20000, headers=self.hdr())
        self.assertIn(r.status, (400, 413))

    async def test_missing_token_rejected(self):
        a = t.Identity.generate()
        r = await self.http.get(f"{self.base}/v1/nodes/{a.node_id.hex()}")
        self.assertEqual(r.status, 401)

    async def test_records_expire(self):
        a = t.Identity.generate()
        await self.put(a)
        for net in self.state.nets.values():
            for rec in net.nodes.values():
                rec["expires"] = time.time() - 1
        r = await self.http.get(f"{self.base}/v1/nodes/{a.node_id.hex()}", headers=self.hdr())
        self.assertEqual(r.status, 404)

    async def test_rate_limit(self):
        codes = [(await self.http.get(self.base + "/v1/nodes/" + "0" * 32, headers=self.hdr())).status
                 for _ in range(90)]
        self.assertIn(429, codes)

    async def test_stores_only_token_hash(self):
        a = t.Identity.generate()
        await self.put(a, tok="super-secret-token")
        self.assertNotIn("super-secret-token", repr(self.state.nets.keys()))
        self.assertIn(rs.token_hash("super-secret-token"), self.state.nets)


class TestRendezvousAllowlist(ServerCase):
    allowed = {rs.token_hash("good")}
    open_ = False

    async def test_only_allowed_tokens(self):
        a = t.Identity.generate()
        body = {"pub": base64.b64encode(a.pub).decode(), "endpoints": []}
        url = f"{self.base}/v1/nodes/{a.node_id.hex()}"
        self.assertEqual((await self.http.put(url, json=body, headers=self.hdr("bad"))).status, 401)
        self.assertEqual((await self.http.put(url, json=body, headers=self.hdr("good"))).status, 200)


class TestRelay(ServerCase):
    async def ws(self, ident, tok="netA"):
        return await self.http.ws_connect(f"{self.base}/v1/relay?node={ident.node_id.hex()}", headers=self.hdr(tok))

    async def test_forwards_opaque_datagrams_between_two_nodes(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        wa, wb = await self.ws(a), await self.ws(b)
        await wa.send_bytes(b.node_id + b"opaque-bytes")
        m = await asyncio.wait_for(wb.receive(), 3)
        self.assertEqual(m.data, a.node_id + b"opaque-bytes")
        await wb.send_bytes(a.node_id + b"back")
        m = await asyncio.wait_for(wa.receive(), 3)
        self.assertEqual(m.data, b.node_id + b"back")

    async def test_cross_network_isolation(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        wa, wb = await self.ws(a, "netA"), await self.ws(b, "netB")
        await wa.send_bytes(b.node_id + b"x")
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(wb.receive(), 0.5)

    async def test_oversize_message_closes_connection(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        wa, _ = await self.ws(a), await self.ws(b)
        await wa.send_bytes(b.node_id + b"x" * 3000)
        m = await asyncio.wait_for(wa.receive(), 3)
        self.assertIn(m.type, (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED))

    async def test_rate_limit_drops_excess(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        wa, wb = await self.ws(a), await self.ws(b)
        n = 6000
        for _ in range(n):
            await wa.send_bytes(b.node_id + b"y" * 100)
        got = 0
        try:
            while True:
                await asyncio.wait_for(wb.receive(), 1.0)
                got += 1
        except asyncio.TimeoutError:
            pass
        self.assertGreater(got, 0)
        self.assertLess(got, n)

    async def test_unauthorized_and_bad_id(self):
        a = t.Identity.generate()
        with self.assertRaises(aiohttp.WSServerHandshakeError):
            await self.http.ws_connect(f"{self.base}/v1/relay?node={a.node_id.hex()}")
        with self.assertRaises(aiohttp.WSServerHandshakeError):
            await self.http.ws_connect(f"{self.base}/v1/relay?node=nothex", headers=self.hdr())

    async def test_reconnect_replaces_old_connection(self):
        a = t.Identity.generate()
        w1 = await self.ws(a)
        w2 = await self.ws(a)
        m = await asyncio.wait_for(w1.receive(), 3)
        self.assertIn(m.type, (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED))
        self.assertFalse(w2.closed)


# ------------------------------------------------------------------ TLS: post-quantum only

def make_cert(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    c, k = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    with open(c, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(k, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return c, k


def openssl_has_mlkem():
    if not OPENSSL:
        return False
    r = subprocess.run([OPENSSL, "list", "-tls1_3", "-tls-groups"], capture_output=True, text=True)
    return "X25519MLKEM768" in (r.stdout + r.stderr)


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


@unittest.skipUnless(openssl_has_mlkem(), "needs `openssl` >= 3.5 (X25519MLKEM768)")
class TestTlsPostQuantum(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.cert, cls.key = make_cert(cls.d)
        cls.port = free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "rendezvous_server.py"), "run", "--listen",
             f"127.0.0.1:{cls.port}", "--cert", cls.cert, "--key", cls.key, "--open"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_port(cls.port), "server did not start"

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(5)
        shutil.rmtree(cls.d, ignore_errors=True)

    def s_client(self, groups, port=None, extra=()):
        env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}   # plain openssl, no PQ-only config
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port or self.port}", "-groups", groups,
                            "-CAfile", self.cert, "-tls1_3", "-brief", *extra],
                           input=b"", capture_output=True, env=env, timeout=20)
        return r.returncode, (r.stdout + r.stderr).decode(errors="replace")

    def test_server_negotiates_x25519mlkem768(self):
        rc, out = self.s_client("X25519MLKEM768")
        self.assertEqual(rc, 0, out)
        self.assertIn("TLSv1.3", out)
        self.assertIn("X25519MLKEM768", out)

    def test_server_refuses_classic_groups(self):
        for g in ("X25519", "secp256r1", "secp384r1", "X448"):
            rc, out = self.s_client(g)
            self.assertNotEqual(rc, 0, (g, out))
            self.assertNotIn("Negotiated TLS1.3 group", out, g)

    def test_server_refuses_hybrid_it_does_not_list(self):
        rc, out = self.s_client("SecP256r1MLKEM768")
        self.assertNotEqual(rc, 0, out)

    def test_server_refuses_tls12(self):
        env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{self.port}", "-tls1_2", "-CAfile",
                            self.cert, "-brief"], input=b"", capture_output=True, env=env, timeout=20)
        self.assertNotEqual(r.returncode, 0)

    def test_python_client_works_against_pq_server(self):
        async def go():
            rv = t.Rendezvous(f"https://127.0.0.1:{self.port}", "tok", self.cert, os.urandom(1216))
            try:
                return await rv.register(["127.0.0.1:1"])
            finally:
                await rv.close()
        ident = t.Identity.generate()

        async def real():
            rv = t.Rendezvous(f"https://127.0.0.1:{self.port}", "tok", self.cert, ident.pub)
            try:
                return await rv.register(["127.0.0.1:1"])
            finally:
                await rv.close()
        self.assertEqual((asyncio.run(real()))["node_id"], ident.node_id.hex())

    def test_python_client_refuses_classic_only_server(self):
        port = free_port()
        srv = subprocess.Popen([OPENSSL, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", self.cert,
                                "-key", self.key, "-www", "-groups", "X25519", "-tls1_3"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env={k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"})
        try:
            self.assertTrue(wait_port(port))
            ident = t.Identity.generate()

            async def go():
                rv = t.Rendezvous(f"https://127.0.0.1:{port}", "tok", self.cert, ident.pub)
                try:
                    await rv.register([])
                finally:
                    await rv.close()
            with self.assertRaises(aiohttp.ClientConnectorSSLError) as cm:
                asyncio.run(go())
            self.assertIn("HANDSHAKE_FAILURE", str(cm.exception).upper())
            # sanity: the classic-only server itself is reachable with a classic client
            rc, out = self.s_client("X25519", port=port)
            self.assertEqual(rc, 0, out)
        finally:
            srv.terminate()
            srv.wait(5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
