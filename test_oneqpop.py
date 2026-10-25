#!/usr/bin/env python3
"""Proof of possession of the node key: the codec (oneqpop), the relay endpoints (challenge, registration, downgrade protection,
require_pop, federation) and a node registering with and without it."""
import pqtls  # noqa: F401

import asyncio
import base64
import copy
import time
import unittest

import oneqpop as pop
import oneqtunel as t
from test_oneqrelay import Fed, eventually

SKEY = pop.server_key(b"federation-secret-for-tests-0123456789")


def b64(b):
    return base64.b64encode(b).decode()


class TestCodec(unittest.TestCase):
    def test_the_key_holder_proves_and_the_server_verifies_statelessly(self):
        a = t.Identity.generate()
        ch = pop.make_challenge(SKEY, a.pub)
        ans = pop.answer(a, ch)
        self.assertTrue(pop.verify(SKEY, a.node_id.hex(), ans))
        self.assertTrue(pop.verify(pop.server_key(b"federation-secret-for-tests-0123456789"), a.node_id.hex(), ans), "any relay of the federation")

    def test_nobody_else_can_answer(self):
        a, mallory = t.Identity.generate(), t.Identity.generate()
        ch = pop.make_challenge(SKEY, a.pub)
        with self.assertRaises(ValueError):
            pop.answer(mallory, ch)                                           # the challenge is sealed to a's keys
        # a forged proof without the challenge
        forged = {"nonce": ch["nonce"], "exp": ch["exp"], "proof": b64(b"\0" * 32)}
        self.assertFalse(pop.verify(SKEY, a.node_id.hex(), forged))
        # a valid proof of mallory for his own id is no proof for a's id
        own = pop.answer(mallory, pop.make_challenge(SKEY, mallory.pub))
        self.assertTrue(pop.verify(SKEY, mallory.node_id.hex(), own))
        self.assertFalse(pop.verify(SKEY, a.node_id.hex(), own))

    def test_other_servers_keys_expiry_and_garbage(self):
        a = t.Identity.generate()
        ans = pop.answer(a, pop.make_challenge(SKEY, a.pub))
        self.assertFalse(pop.verify(pop.server_key(b"another secret"), a.node_id.hex(), ans))
        now = time.time()
        self.assertTrue(pop.verify(SKEY, a.node_id.hex(), ans, now + 30))
        self.assertFalse(pop.verify(SKEY, a.node_id.hex(), ans, now + pop.LIFETIME + 30), "expired")
        self.assertFalse(pop.verify(SKEY, a.node_id.hex(), ans, now - 1000), "from the future")
        moved = dict(ans, exp=ans["exp"] + 1000)
        self.assertFalse(pop.verify(SKEY, a.node_id.hex(), moved), "the expiry is part of the proof")
        for bad in (None, {}, {"nonce": "x"}, {"nonce": b64(b"1" * 16), "exp": "1", "proof": b64(b"1" * 32)},
                    dict(ans, proof="!!!"), dict(ans, nonce=b64(b"short")), dict(ans, exp=True), "text", 5):
            self.assertFalse(pop.verify(SKEY, a.node_id.hex(), bad), bad)
        self.assertFalse(pop.verify(SKEY, "zz", ans))
        for bad_ch in ({}, {"e": "x"}, dict(pop.make_challenge(SKEY, a.pub), exp="1"), dict(pop.make_challenge(SKEY, a.pub), ct=b64(b"\0" * 5))):
            with self.assertRaises(ValueError):
                pop.answer(a, bad_ch)
        with self.assertRaises(ValueError):
            pop.make_challenge(SKEY, b"short")

    def test_a_tampered_challenge_is_not_answered(self):
        a = t.Identity.generate()
        ch = pop.make_challenge(SKEY, a.pub)
        for field in ("nonce", "enc", "ct"):
            bad = copy.deepcopy(ch)
            raw = bytearray(base64.b64decode(bad[field]))
            raw[0] ^= 1
            bad[field] = b64(bytes(raw))
            with self.assertRaises(ValueError, msg=field):
                pop.answer(a, bad)
        with self.assertRaises(ValueError):
            pop.answer(a, dict(ch, exp=ch["exp"] + 1))

    def test_prover_cache(self):
        a = t.Identity.generate()
        pr = pop.Prover(a)
        self.assertIsNone(pr.fresh())
        first = pr.store(pop.make_challenge(SKEY, a.pub))
        self.assertIs(pr.fresh(), first)
        self.assertIsNone(pr.fresh(margin=pop.LIFETIME + 1), "too close to the expiry")
        pr.drop()
        self.assertIsNone(pr.fresh())


class TestRelay(Fed):
    N = 2

    async def put(self, i, tok, ident, pop_=None, eps=("10.0.0.1:5000",), comm="lan"):
        body = {"pub": b64(ident.pub), "endpoints": list(eps), "name": "n"}
        if pop_ is not None:
            body["pop"] = pop_
        return await self.http.put(f"{self.urls[i]}/v1/c/{comm}/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(tok))

    async def challenge(self, i, tok, ident, pub=None):
        r = await self.http.post(f"{self.urls[i]}/v1/c/lan/nodes/{ident.node_id.hex()}/challenge",
                                 json={"pub": b64(pub or ident.pub)}, headers=self.hdr(tok))
        return r

    async def proof(self, i, tok, ident, via=None):
        r = await self.challenge(via if via is not None else i, tok, ident)
        self.assertEqual(r.status, 200, await r.text())
        return pop.answer(ident, await r.json())

    async def test_registration_with_a_proof_marks_the_node_and_blocks_downgrades(self):
        tok = await self.token(0)
        a = self.ident()
        p = await self.proof(0, tok, a)
        r = await self.put(0, tok, a, p)
        self.assertEqual(r.status, 200, await r.text())
        self.assertEqual((await r.json())["pop"], "optional")
        self.assertTrue(self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}")["pop"])
        # updating without a proof is refused now, with one it works
        r = await self.put(0, tok, a, None, eps=("203.0.113.5:1",))
        self.assertEqual(r.status, 403)
        self.assertIn("proof of possession", await r.text())
        self.assertEqual((await self.put(0, tok, a, p, eps=("203.0.113.5:1",))).status, 200)
        # the same on the other relay once replicated
        async def seen():
            return self.nodes[1].reg.s.get("node", f"lan/{a.node_id.hex()}") is not None
        await eventually(seen)
        self.assertEqual((await self.put(1, await self.token(1), a, None)).status, 403)
        self.assertEqual((await self.put(1, await self.token(1), a, await self.proof(1, await self.token(1), a))).status, 200)

    async def test_a_proof_for_another_node_or_a_forged_one_is_refused(self):
        tok = await self.token(0)
        a, b = self.ident(), self.ident()
        pb = await self.proof(0, tok, b)
        for bad in (pb, {"nonce": pb["nonce"], "exp": pb["exp"], "proof": b64(b"\0" * 32)}, "x", {}):
            r = await self.put(0, tok, a, bad)
            self.assertEqual(r.status, 403, bad)
            self.assertIn("proof of possession", await r.text())
        self.assertIsNone(self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}"), "nothing was registered")

    async def test_the_challenge_endpoint(self):
        tok = await self.token(0)
        a = self.ident()
        r = await self.challenge(0, tok, a)
        ch = await r.json()
        self.assertEqual(set(ch), {"e", "ct", "nonce", "exp", "enc"})
        self.assertEqual((await self.challenge(0, tok, a, pub=self.ident().pub)).status, 400, "key does not match the id")
        r = await self.http.post(f"{self.urls[0]}/v1/c/lan/nodes/{a.node_id.hex()}/challenge", json={"pub": "!!"}, headers=self.hdr(tok))
        self.assertEqual(r.status, 400)
        r = await self.http.post(f"{self.urls[0]}/v1/c/lan/nodes/{a.node_id.hex()}/challenge", json={"pub": b64(a.pub)})
        self.assertEqual(r.status, 401, "needs a login")
        # a challenge made by one relay is verified by the other
        p = pop.answer(a, await (await self.challenge(0, tok, a)).json())
        self.assertEqual((await self.put(1, await self.token(1), a, p)).status, 200)

    async def test_require_pop_refuses_registrations_without_a_proof(self):
        tok = await self.token(0)
        self.nodes[0].require_pop = True
        a = self.ident()
        r = await self.put(0, tok, a, None)
        self.assertEqual((r.status, "proof of possession required" in await r.text()), (403, True))
        self.assertEqual((await self.put(0, tok, a, await self.proof(0, tok, a))).status, 200)
        self.assertEqual((await (await self.put(0, tok, a, await self.proof(0, tok, a))).json())["pop"], "required")

    async def test_squatting_a_known_public_key_needs_the_private_key(self):
        """bob knows alice's node public key (the member list shows it) and registers it first, with his own endpoints."""
        async def bob():
            return (await self.login(0, "bob", "bob-password!"))[0] == 200
        await eventually(bob)
        btok, atok = await self.token(0, "bob", "bob-password!"), await self.token(0)
        a = self.ident()
        self.nodes[0].require_pop = True
        r = await self.put(0, btok, a, None, eps=("198.51.100.66:1",))
        self.assertEqual(r.status, 403)
        # he cannot get a challenge answered either: it is sealed to alice's key
        ch = await (await self.challenge(0, btok, a)).json()
        mallory = self.ident()
        with self.assertRaises(ValueError):
            pop.answer(mallory, ch)
        self.assertIsNone(self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}"))
        self.assertEqual((await self.put(0, atok, a, await self.proof(0, atok, a))).status, 200)

    async def test_an_old_node_without_proofs_still_registers_where_proofs_are_optional(self):
        tok = await self.token(0)
        a = self.ident()
        self.assertEqual((await self.put(0, tok, a, None)).status, 200)
        self.assertNotIn("pop", self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}"))
        self.assertEqual((await self.put(0, tok, a, None, eps=("203.0.113.9:2",))).status, 200)
        # upgrading to proofs later is allowed and then sticks
        self.assertEqual((await self.put(0, tok, a, await self.proof(0, tok, a))).status, 200)
        self.assertEqual((await self.put(0, tok, a, None)).status, 403)

    async def test_an_administrator_can_reset_a_protected_id_by_deleting_it(self):
        tok = await self.token(0)
        a = self.ident()
        self.assertEqual((await self.put(0, tok, a, await self.proof(0, tok, a))).status, 200)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/nodes/{a.node_id.hex()}", headers=self.hdr(tok))
        self.assertEqual(r.status, 200)
        self.assertEqual((await self.put(0, tok, a, None)).status, 200)


class TestNodeClient(Fed):
    N = 2

    def control(self, ident):
        import oneqnode
        c = oneqnode.Control([self.urls[0]], "lan", "alice", "alice-password")
        c.prover = pop.Prover(ident)
        return c

    async def test_the_node_registers_with_a_proof_and_reuses_it(self):
        a = self.ident()
        c = self.control(a)
        calls = []
        orig = c._call

        async def spy(method, path, **kw):
            calls.append((method, path.rsplit("/", 1)[-1]))
            return await orig(method, path, **kw)
        c._call = spy
        try:
            for _ in range(3):
                info = await c.join(a.node_id.hex(), a.pub, ["10.0.0.1:5000"], "n")
            self.assertEqual(info["pop"], "optional")
            self.assertEqual(calls.count(("POST", "challenge")), 1, "one challenge serves the refreshes until shortly before it expires")
            self.assertTrue(self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}")["pop"])
            # the cached proof is about to expire: a new challenge
            c.prover.cur = dict(c.prover.cur, exp=int(time.time()) + 5)
            await c.join(a.node_id.hex(), a.pub, ["10.0.0.1:5000"], "n")
            self.assertEqual(calls.count(("POST", "challenge")), 2)
        finally:
            await c.close()

    async def test_an_expired_proof_is_replaced_and_the_request_retried(self):
        a = self.ident()
        c = self.control(a)
        try:
            await c.join(a.node_id.hex(), a.pub, [], "n")
            old = dict(c.prover.cur)
            c.prover.cur = dict(old, exp=int(time.time()) - 100)      # the cache says expired but fresh() is bypassed below
            c.prover.fresh = lambda margin=15.0: c.prover.cur         # a stale proof is sent; the relay refuses it; the node retries
            r = await c.join(a.node_id.hex(), a.pub, [], "n")
            self.assertIn("ip", r)
            self.assertGreater(c.prover.cur["exp"], time.time())
        finally:
            await c.close()

    async def test_a_relay_that_does_not_know_the_feature_gets_a_plain_registration(self):
        a = self.ident()
        c = self.control(a)
        orig = c._call

        async def old_relay(method, path, **kw):
            if path.endswith("/challenge"):
                raise PermissionError("HTTP 404: Not Found")
            return await orig(method, path, **kw)
        c._call = old_relay
        try:
            info = await c.join(a.node_id.hex(), a.pub, [], "n")
            self.assertIn("ip", info)
            self.assertIn(c.base, c.pop_unsupported)
            self.assertNotIn("pop", self.nodes[0].reg.s.get("node", f"lan/{a.node_id.hex()}"))
        finally:
            await c.close()

    async def test_a_node_without_the_key_cannot_register_a_protected_id(self):
        a = self.ident()
        c = self.control(a)
        try:
            await c.join(a.node_id.hex(), a.pub, ["10.0.0.1:5000"], "n")
            imposter = self.control(self.ident())            # alice's account, a key that is not a's: it cannot open the challenge for a
            imposter.prover = pop.Prover(self.ident())
            with self.assertRaises(PermissionError):
                await imposter.join(a.node_id.hex(), a.pub, ["198.51.100.66:1"], "evil")
            m = self.nodes[0].reg.members("lan")[0]
            self.assertEqual(m["endpoints"], ["10.0.0.1:5000"])
            await imposter.close()
        finally:
            await c.close()


class TestRendezvousMode2(unittest.IsolatedAsyncioTestCase):
    """The point-to-point mode's rendezvous server: the token is shared by the nodes of a network, so any token holder could register
    (or take the relay slot of) any node id; with a proof only the key holder can."""

    async def asyncSetUp(self):
        import socket
        import rendezvous_server as rs
        from aiohttp import web
        self.rs = rs
        self.state = rs.State(open_=True)
        self.runner = web.AppRunner(rs.make_app(self.state), access_log=None)
        await self.runner.setup()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        await web.TCPSite(self.runner, "127.0.0.1", self.port).start()
        self.url = f"http://127.0.0.1:{self.port}"
        self.clients = []

    async def asyncTearDown(self):
        for c in self.clients:
            await c.close()
        await self.runner.cleanup()

    def rv(self, ident, with_key=True, token="tok"):
        c = t.Rendezvous(self.url, token, None, ident.pub, ident if with_key else None)
        self.clients.append(c)
        return c

    async def test_a_verified_registration_cannot_be_overwritten_without_the_key(self):
        a = t.Identity.generate()
        good = self.rv(a)
        await good.register(["10.0.0.1:5000"])
        self.assertTrue(self.state.nets[next(iter(self.state.nets))].nodes[a.node_id.hex()]["pop"])
        squatter = self.rv(a, with_key=False)                          # knows the public key and the token, not the private key
        with self.assertRaises(Exception) as cm:
            await squatter.register(["198.51.100.66:1"])
        self.assertIn("403", str(cm.exception))
        rec = await good.lookup(a.node_id.hex())
        self.assertEqual(rec["endpoints"], ["10.0.0.1:5000"])
        # the real node refreshes, and a forged proof is refused too
        await good.register(["10.0.0.1:5001"])
        self.assertEqual((await good.lookup(a.node_id.hex()))["endpoints"], ["10.0.0.1:5001"])
        mallory = t.Identity.generate()
        thief = self.rv(a)
        thief.ident = mallory                                         # answers with the wrong key: cannot even open the challenge
        with self.assertRaises(Exception):
            await thief.register(["198.51.100.66:1"])

    async def test_old_clients_and_servers_still_work(self):
        a = t.Identity.generate()
        legacy = self.rv(a, with_key=False)
        await legacy.register(["10.0.0.1:5000"])                       # no proof: accepted where proofs are optional
        await legacy.register(["10.0.0.1:5001"])
        self.assertFalse(self.state.nets[next(iter(self.state.nets))].nodes[a.node_id.hex()]["pop"])
        # a client with the key against a server that has no challenge endpoint falls back to a plain registration
        orig = self.rs.oneqpop
        self.rs.oneqpop = None
        try:
            b = t.Identity.generate()
            c = self.rv(b)
            await c.register(["10.0.0.2:5000"])
            self.assertTrue(c._pop_unsupported)
        finally:
            self.rs.oneqpop = orig

    async def test_require_pop(self):
        self.state.require_pop = True
        a = t.Identity.generate()
        with self.assertRaises(Exception) as cm:
            await self.rv(a, with_key=False).register([])
        self.assertIn("403", str(cm.exception))
        await self.rv(a).register([])

    async def test_the_relay_slot_of_a_verified_node_needs_the_proof(self):
        import json
        import aiohttp
        a = t.Identity.generate()
        good = self.rv(a)
        await good.register([])
        async with aiohttp.ClientSession() as s:
            url = f"{self.url}/v1/relay?node={a.node_id.hex()}"
            with self.assertRaises(aiohttp.WSServerHandshakeError) as cm:
                await s.ws_connect(url, headers={"Authorization": "Bearer tok"})
            self.assertEqual(cm.exception.status, 403)
            proof = await good.proof()
            hdr = {"Authorization": "Bearer tok", "X-Oneq-Pop": base64.b64encode(json.dumps(proof).encode()).decode()}
            ws = await s.ws_connect(url, headers=hdr)
            await ws.close()
            # a proof for another node is no good
            b = t.Identity.generate()
            other = self.rv(b)
            await other.register([])
            bad = {"Authorization": "Bearer tok", "X-Oneq-Pop": base64.b64encode(json.dumps(await other.proof()).encode()).decode()}
            with self.assertRaises(aiohttp.WSServerHandshakeError):
                await s.ws_connect(url, headers=bad)
            # an unregistered id is open as before (old nodes)
            ws = await s.ws_connect(f"{self.url}/v1/relay?node={'ab' * 16}", headers={"Authorization": "Bearer tok"})
            await ws.close()

    async def test_the_relay_client_sends_the_proof_by_itself(self):
        a, b = t.Identity.generate(), t.Identity.generate()
        ra, rb = self.rv(a), self.rv(b)
        await ra.register([])
        await rb.register([])
        got = []
        ca = t.RelayClient(self.url, "tok", None, a.node_id.hex(), lambda src, d: got.append((src, d)), proof=ra.proof)
        cb = t.RelayClient(self.url, "tok", None, b.node_id.hex(), lambda src, d: None, proof=rb.proof)
        for c in (ca, cb):
            c.enabled.set()
        tasks = [asyncio.ensure_future(c.run()) for c in (ca, cb)]
        try:
            for _ in range(100):
                if ca.connected and cb.connected:
                    break
                await asyncio.sleep(0.05)
            self.assertTrue(ca.connected and cb.connected)
            cb.send(a.node_id, b"hello")
            for _ in range(100):
                if got:
                    break
                await asyncio.sleep(0.05)
            self.assertEqual(got, [(b.node_id, b"hello")])
        finally:
            for tk in tasks:
                tk.cancel()


if __name__ == "__main__":
    unittest.main(verbosity=2)
