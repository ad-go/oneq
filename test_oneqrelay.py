#!/usr/bin/env python3
"""Federated oneqrelay tests: three oneqrelays in one process, replicated state, login/lock-out,
node registration with automatic addresses, relay (local and across oneqrelays), federation auth."""
import pqtls  # noqa: F401

import asyncio
import base64
import json
import logging
import os
import socket
import tempfile
import time
import unittest
from unittest import mock

import aiohttp
from aiohttp import web

import meshdb
import oneqrelay as sn
import oneqtunel as t

meshdb.SCRYPT_N = 2 ** 10
logging.getLogger("oneqrelay").setLevel(logging.CRITICAL)      # peers going away during teardown is expected
SECRET = b"federation-secret-for-tests-0123456789"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def eventually(fn, timeout=8.0, step=0.1):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = await fn() if asyncio.iscoroutinefunction(fn) else fn()
            if last:
                return last
        except Exception as e:      # noqa: BLE001
            last = e
        await asyncio.sleep(step)
    raise AssertionError(f"condition not reached; last={last!r}")


class Fed(unittest.IsolatedAsyncioTestCase):
    N = 3
    SYNC = 0.3

    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ports = [free_port() for _ in range(self.N)]
        self.urls = [f"http://127.0.0.1:{p}" for p in self.ports]
        self.nodes, self.runners = [], []
        for i in range(self.N):
            await self.start(i)
        self.http = aiohttp.ClientSession()
        r = self.nodes[0].reg
        r.create_community("lan", "10.50.0.0/24")
        r.add_user("lan", "alice", "alice-password", "admin", max_nodes=100)
        r.add_user("lan", "bob", "bob-password!", "user", max_nodes=2)
        r.create_community("other", "10.60.0.0/24")
        r.add_user("other", "eve", "eve-password!", "user")
        self.nodes[0].poke_peers()

    async def start(self, i, fresh=False):
        db = os.path.join(self.tmp, f"s{i}{'b' if fresh else ''}.db")
        store = meshdb.Store(db, f"s{i + 1}")
        peers = [u for j, u in enumerate(self.urls) if j != i]
        node = sn.OneqRelay(store, SECRET, peers, sync_interval=self.SYNC)
        node.insecure_fed = True
        runner = web.AppRunner(node.make_app(), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.ports[i], shutdown_timeout=1).start()
        if i < len(self.nodes):
            self.nodes[i], self.runners[i] = node, runner
        else:
            self.nodes.append(node)
            self.runners.append(runner)
        return node

    async def asyncTearDown(self):
        await self.http.close()
        for r in self.runners:
            await r.cleanup()

    # ---- client helpers
    async def login(self, i, user="alice", pw="alice-password", comm="lan"):
        r = await self.http.post(self.urls[i] + "/v1/login", json={"community": comm, "user": user, "password": pw})
        return r.status, (await r.json() if r.status == 200 else await r.text())

    async def token(self, i, user="alice", pw="alice-password", comm="lan"):
        st, body = await self.login(i, user, pw, comm)
        self.assertEqual(st, 200, body)
        return body["token"]

    def hdr(self, tok):
        return {"Authorization": "Bearer " + tok}

    def ident(self):
        return t.Identity.generate()

    async def join(self, i, tok, ident, comm="lan", eps=("10.0.0.1:5000",), name="n"):
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": list(eps), "name": name}
        return await self.http.put(f"{self.urls[i]}/v1/c/{comm}/nodes/{ident.node_id.hex()}", json=body,
                                   headers=self.hdr(tok))


class TestReplicationAndAuth(Fed):
    async def test_accounts_replicate_and_tokens_work_everywhere(self):
        async def ok():
            return (await self.login(1, "bob", "bob-password!"))[0] == 200
        await eventually(ok)
        tok = await self.token(0)
        async def on_s3():
            r = await self.http.get(self.urls[2] + "/v1/c/lan", headers=self.hdr(tok))
            return r.status == 200 and (await r.json())["subnet"] == "10.50.0.0/24"
        await eventually(on_s3)

    async def test_bad_logins(self):
        await eventually(lambda: self.nodes[1].reg.community("lan"))
        for body in ({"community": "lan", "user": "alice", "password": "wrong-password"},
                     {"community": "lan", "user": "ghost", "password": "alice-password"},
                     {"community": "nope", "user": "alice", "password": "alice-password"},
                     {"community": "lan"}, {"community": 1, "user": 2, "password": 3}):
            r = await self.http.post(self.urls[1] + "/v1/login", json=body)
            self.assertIn(r.status, (400, 401), body)
        r = await self.http.post(self.urls[1] + "/v1/login", data=b"not json")
        self.assertEqual(r.status, 400)

    async def test_lockout_after_repeated_failures_even_with_correct_password(self):
        guard = self.nodes[0].guard
        for _ in range(sn.LOGIN_MAX_FAILS):
            self.assertEqual((await self.login(0, "alice", "wrong-password"))[0], 401)
        st, body = await self.login(0, "alice", "alice-password")
        self.assertEqual(st, 429, body)
        guard.state.clear()
        self.assertEqual((await self.login(0))[0], 200)

    async def test_guard_backoff_doubles(self):
        now = [0.0]
        g = sn.LoginGuard(clock=lambda: now[0])
        for _ in range(5):
            g.failure("k")
        self.assertAlmostEqual(g.blocked("k"), 60, delta=1)
        now[0] += 61
        self.assertEqual(g.blocked("k"), 0)
        for _ in range(5):
            g.failure("k")
        self.assertAlmostEqual(g.blocked("k"), 120, delta=1)
        g.success("k")
        self.assertEqual(g.blocked("k"), 0)

    async def test_token_only_valid_for_its_community(self):
        await eventually(lambda: self.nodes[0].reg.community("other"))
        tok = await self.token(0)
        r = await self.http.get(self.urls[0] + "/v1/c/other", headers=self.hdr(tok))
        self.assertEqual(r.status, 403)
        r = await self.http.get(self.urls[0] + "/v1/c/lan")
        self.assertEqual(r.status, 401)
        r = await self.http.get(self.urls[0] + "/v1/c/lan", headers=self.hdr(tok[:-3] + "AAA"))
        self.assertEqual(r.status, 401)

    async def test_password_change_revokes_tokens_across_the_federation(self):
        async def on1():
            return (await self.login(1, "bob", "bob-password!"))[0] == 200
        await eventually(on1)
        tok = await self.token(1, "bob", "bob-password!")
        self.nodes[0].reg.set_password("lan", "bob", "new-bob-password")
        async def revoked():
            r = await self.http.get(self.urls[1] + "/v1/c/lan", headers=self.hdr(tok))
            return r.status == 401
        await eventually(revoked)
        self.assertEqual((await self.login(1, "bob", "bob-password!"))[0], 401)
        async def new_ok():
            return (await self.login(2, "bob", "new-bob-password"))[0] == 200
        await eventually(new_ok)

    async def test_wiped_oneqrelay_resyncs_and_publishes_new_data(self):
        async def on1():
            return self.nodes[1].reg.community("lan") is not None
        await eventually(on1)
        await self.runners[1].cleanup()
        self.nodes[1] = await self.start(1, fresh=True)                      # empty database, new epoch
        await eventually(lambda: self.nodes[1].reg.community("lan"))         # pulled everything back
        self.nodes[1].reg.add_user("lan", "carol", "carol-password", "user")
        async def seen():
            return self.nodes[0].reg.s.get("user", "lan/carol") is not None
        await eventually(seen)                                               # s1's cursor was reset by the epoch change

    async def test_federation_endpoints_require_signature(self):
        body = json.dumps({"cursor": 0, "epoch": "x"}).encode()
        r = await self.http.post(self.urls[0] + "/fed/v1/sync", data=body)
        self.assertEqual(r.status, 401)
        h = sn.fed_headers(b"another-secret-entirely-xxxxxxxxxxxx", "evil", "POST", "/fed/v1/sync", body)
        r = await self.http.post(self.urls[0] + "/fed/v1/sync", data=body, headers=h)
        self.assertEqual(r.status, 401)
        h = sn.fed_headers(SECRET, "s9", "POST", "/fed/v1/sync", body)
        r = await self.http.post(self.urls[0] + "/fed/v1/sync", data=body, headers=h)
        self.assertEqual(r.status, 200)
        h["X-Fed-Ts"] = str(int(time.time()) - 600)                          # stale (replay) timestamp
        r = await self.http.post(self.urls[0] + "/fed/v1/sync", data=body, headers=h)
        self.assertEqual(r.status, 401)
        h = sn.fed_headers(SECRET, "s9", "POST", "/fed/v1/sync", body)
        r = await self.http.post(self.urls[0] + "/fed/v1/sync", data=body + b" ", headers=h)   # body is signed
        self.assertEqual(r.status, 401)
        r = await self.http.post(self.urls[0] + "/fed/v1/poke", data=b"")
        self.assertEqual(r.status, 401)

    async def test_health(self):
        r = await self.http.get(self.urls[0] + "/v1/health")
        j = await r.json()
        self.assertEqual((j["status"], j["origin"]), ("ok", "s1"))


class TestNodes(Fed):
    async def test_join_assigns_address_and_is_visible_on_every_oneqrelay(self):
        tok = await self.token(0)
        a = self.ident()
        r = await self.join(0, tok, a, eps=("203.0.113.5:51820",), name="laptop")
        self.assertEqual(r.status, 200)
        j = await r.json()
        self.assertTrue(j["ip"].startswith("10.50.0."))
        self.assertRegex(j["mac"], r"^02(:[0-9a-f]{2}){5}$")
        self.assertEqual((j["prefix"], j["mtu"]), (24, 1380))
        async def listed():
            tok2 = await self.token(2)
            r = await self.http.get(self.urls[2] + "/v1/c/lan/nodes", headers=self.hdr(tok2))
            nodes = (await r.json())["nodes"]
            return nodes if nodes and nodes[0]["online"] else None
        nodes = await eventually(listed)
        self.assertEqual((nodes[0]["id"], nodes[0]["ip"], nodes[0]["endpoints"], nodes[0]["name"]),
                         (a.node_id.hex(), j["ip"], ["203.0.113.5:51820"], "laptop"))
        again = await (await self.join(0, tok, a)).json()
        self.assertEqual(again["ip"], j["ip"])

    async def test_validation_and_ownership(self):
        tok = await self.token(0, "alice", "alice-password")
        a = self.ident()
        self.assertEqual((await self.join(0, tok, a)).status, 200)
        async def bob():
            return (await self.login(0, "bob", "bob-password!"))[0] == 200
        await eventually(bob)
        b_tok = await self.token(0, "bob", "bob-password!")
        self.assertEqual((await self.join(0, b_tok, a)).status, 403)       # a regular user cannot take over alice's node
        c = self.ident()
        self.assertEqual((await self.join(0, b_tok, c)).status, 200)
        r = await self.http.put(f"{self.urls[0]}/v1/c/lan/nodes/{c.node_id.hex()}", headers=self.hdr(tok),
                                json={"pub": base64.b64encode(self.ident().pub).decode(), "endpoints": []})
        self.assertEqual(r.status, 400)                                    # id does not match the key
        # bad requests
        for path, body in ((f"/v1/c/lan/nodes/nothex", {}), (f"/v1/c/lan/nodes/{'0' * 32}", {"pub": "AAAA"}),
                           (f"/v1/c/lan/nodes/{a.node_id.hex()}", {"pub": base64.b64encode(a.pub).decode(),
                                                                   "endpoints": ["bad"]}),
                           (f"/v1/c/lan/nodes/{a.node_id.hex()}", {"pub": base64.b64encode(a.pub).decode(),
                                                                   "endpoints": ["1.2.3.4:1"] * 20})):
            r = await self.http.put(self.urls[0] + path, json=body, headers=self.hdr(tok))
            self.assertEqual(r.status, 400, (path, body))

    async def test_user_quota_and_cross_user_takeover_blocked(self):
        async def bob():
            return (await self.login(1, "bob", "bob-password!"))[0] == 200
        await eventually(bob)
        tok = await self.token(1, "bob", "bob-password!")
        ids = [self.ident() for _ in range(3)]
        self.assertEqual((await self.join(1, tok, ids[0])).status, 200)
        self.assertEqual((await self.join(1, tok, ids[1])).status, 200)
        self.assertEqual((await self.join(1, tok, ids[2])).status, 403)    # quota 2
        self.nodes[0].reg.add_user("lan", "mallory", "mallory-password", "user")
        async def mal():
            return (await self.login(0, "mallory", "mallory-password"))[0] == 200
        await eventually(mal)
        mtok = await self.token(0, "mallory", "mallory-password")
        async def visible():
            return self.nodes[0].reg.s.get("node", f"lan/{ids[0].node_id.hex()}") is not None
        await eventually(visible)
        self.assertEqual((await self.join(0, mtok, ids[0])).status, 403)

    async def test_delete_node(self):
        tok = await self.token(0)
        a = self.ident()
        await self.join(0, tok, a)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/nodes/{a.node_id.hex()}", headers=self.hdr(tok))
        self.assertEqual(r.status, 200)
        async def gone():
            return self.nodes[2].reg.members("lan") == []
        await eventually(gone)

    async def test_addresses_stay_unique_when_joins_hit_different_oneqrelays_at_once(self):
        toks = [await self.token(i) for i in range(3)]
        idents = [self.ident() for _ in range(45)]
        rs = await asyncio.gather(*[self.join(i % 3, toks[i % 3], idents[i]) for i in range(45)])
        self.assertTrue(all(r.status == 200 for r in rs))
        async def converged():
            views = [{m["id"]: m["ip"] for m in n.reg.members("lan")} for n in self.nodes]
            for n in self.nodes:
                n.reg.fix_ip_conflicts("lan", grace_s=0)
            ok = all(len(v) == 45 and len(set(v.values())) == 45 for v in views) and views[0] == views[1] == views[2]
            return ok
        await eventually(converged, timeout=15)


class TestRelay(Fed):
    async def attach(self, i, tok, ident, comm="lan"):
        return await self.http.ws_connect(f"{self.urls[i]}/v1/relay?comm={comm}&node={ident.node_id.hex()}",
                                          headers=self.hdr(tok))

    async def test_relay_same_oneqrelay_and_across_the_federation(self):
        tok = await self.token(0)
        a, b, c = self.ident(), self.ident(), self.ident()
        for i, x in ((0, a), (1, b), (0, c)):
            self.assertEqual((await self.join(i if i == 0 else 0, tok, x)).status, 200)
        tok1 = await self.token(1)
        async def ready():
            return all(self.nodes[1].reg.s.get("node", f"lan/{x.node_id.hex()}") for x in (a, b, c)) \
                and "s1" in self.nodes[1].fed_links and "s2" in self.nodes[0].fed_links
        await eventually(ready)
        wa, wc = await self.attach(0, tok, a), await self.attach(0, tok, c)
        wb = await self.attach(1, tok1, b)
        # same oneqrelay
        await wa.send_bytes(c.node_id + b"local")
        self.assertEqual((await asyncio.wait_for(wc.receive(), 3)).data, a.node_id + b"local")
        # across oneqrelays, both directions (needs the attachment record to replicate)
        async def delivered():
            await wa.send_bytes(b.node_id + b"to-b")
            try:
                m = await asyncio.wait_for(wb.receive(), 0.5)
                return m.data == a.node_id + b"to-b"
            except asyncio.TimeoutError:
                return False
        await eventually(delivered, timeout=10, step=0.2)
        async def back():
            await wb.send_bytes(a.node_id + b"to-a")
            try:
                m = await asyncio.wait_for(wa.receive(), 0.5)
                return m.data == b.node_id + b"to-a"
            except asyncio.TimeoutError:
                return False
        await eventually(back, timeout=10, step=0.2)

    async def test_cannot_attach_someone_elses_node_or_other_community(self):
        async def bob():
            return (await self.login(0, "bob", "bob-password!"))[0] == 200
        await eventually(bob)
        tok_b = await self.token(0, "bob", "bob-password!")
        tok_a = await self.token(0)
        a = self.ident()
        await self.join(0, tok_a, a)
        with self.assertRaises(aiohttp.WSServerHandshakeError) as e:
            await self.attach(0, tok_b, a)
        self.assertEqual(e.exception.status, 403)
        with self.assertRaises(aiohttp.WSServerHandshakeError) as e:
            await self.attach(0, tok_a, a, comm="other")
        self.assertEqual(e.exception.status, 403)
        with self.assertRaises(aiohttp.WSServerHandshakeError) as e:
            await self.http.ws_connect(f"{self.urls[0]}/v1/relay?comm=lan&node={a.node_id.hex()}")
        self.assertEqual(e.exception.status, 401)

    async def test_oversize_and_rate_limit(self):
        tok = await self.token(0)
        a, b = self.ident(), self.ident()
        await self.join(0, tok, a)
        await self.join(0, tok, b)
        with mock.patch.object(sn, "RELAY_PPS", 200.0):                 # the limiter is built per connection
            wa, wb = await self.attach(0, tok, a), await self.attach(0, tok, b)
        n = 3000
        for _ in range(n):
            await wa.send_bytes(b.node_id + b"y" * 100)
        got = 0
        try:
            while True:
                await asyncio.wait_for(wb.receive(), 1.0)
                got += 1
        except asyncio.TimeoutError:
            pass
        self.assertTrue(0 < got < n, got)
        await wb.send_bytes(a.node_id + b"x" * 4000)
        m = await asyncio.wait_for(wb.receive(), 3)
        self.assertIn(m.type, (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED))

    async def test_attachment_is_published_and_withdrawn(self):
        tok = await self.token(0)
        a = self.ident()
        await self.join(0, tok, a)
        wa = await self.attach(0, tok, a)
        async def published():
            return self.nodes[2].reg.relay_at("lan", a.node_id.hex()) == "s1"
        await eventually(published)
        await wa.close()
        async def withdrawn():
            return self.nodes[2].reg.relay_at("lan", a.node_id.hex()) is None
        await eventually(withdrawn)


class ClientIp(unittest.TestCase):
    """Behind a reverse proxy the address comes from X-Forwarded-For, but only the entry the proxy appended."""

    class Req:
        def __init__(self, remote, xff=None):
            self.remote, self.headers = remote, ({"X-Forwarded-For": xff} if xff is not None else {})

    @staticmethod
    def ip(trust, remote, xff=None):
        stub = type("S", (), {"trust_proxy": trust})()
        return sn.OneqRelay.client_ip(stub, ClientIp.Req(remote, xff))

    def test_the_header_is_ignored_without_trust_proxy(self):
        self.assertEqual(self.ip(False, "172.172.0.1", "8.8.8.8"), "172.172.0.1")

    def test_the_entry_added_by_the_proxy_is_used_and_what_the_client_sent_is_not(self):
        self.assertEqual(self.ip(True, "172.172.0.1", "203.0.113.9"), "203.0.113.9")
        self.assertEqual(self.ip(True, "172.172.0.1", "1.2.3.4, 203.0.113.9"), "203.0.113.9", "a forged first entry")
        self.assertEqual(self.ip(True, "127.0.0.1", "1.1.1.1,2.2.2.2 , 203.0.113.9"), "203.0.113.9")
        self.assertEqual(self.ip(True, "::1", "2001:db8::7"), "2001:db8::7")

    def test_garbage_or_a_public_sender_falls_back_to_the_connection(self):
        self.assertEqual(self.ip(True, "172.172.0.1", "not an ip"), "172.172.0.1")
        self.assertEqual(self.ip(True, "172.172.0.1", "1.2.3.4,"), "172.172.0.1")
        self.assertEqual(self.ip(True, "172.172.0.1"), "172.172.0.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
