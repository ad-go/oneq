#!/usr/bin/env python3
"""Tests for the v2 wire protocol (meshproto) and the replicated registry (meshdb)."""
import pqtls  # noqa: F401

import base64
import hashlib
import ipaddress
import os
import random
import struct
import tempfile
import unittest

import meshdb
import meshproto as mp
import oneqtunel as t

meshdb.SCRYPT_N = 2 ** 10      # fast hashing in tests; production default is 2**15
SECRET = b"federation-secret-for-tests-0123456789"


def pair():
    a, b = t.Identity.generate(), t.Identity.generate()
    return (a, b) if a.pub < b.pub else (b, a)


# ------------------------------------------------------------------ protocol v2

class TestMeshHandshake(unittest.TestCase):
    def setUp(self):
        self.i, self.r = pair()

    def hs(self, ii=11, ri=22):
        msg, st = mp.init_create(self.i, self.r.pub, ii)
        ts, ck, h, E, ek, sidx = mp.init_consume(self.r, self.i.pub, msg)
        resp, rsk, rrk = mp.resp_create(self.r, self.i.pub, ck, h, E, ek, ri, sidx)
        isk, irk, pidx = mp.resp_consume(self.i, st, resp)
        return msg, resp, (isk, irk, pidx), (rsk, rrk, sidx)

    def test_sizes_and_indexes(self):
        msg, resp, (isk, irk, pidx), (rsk, rrk, sidx) = self.hs()
        self.assertEqual((len(msg), msg[0]), (2349, 0x21))
        self.assertEqual((len(resp), resp[0]), (2233, 0x22))
        self.assertEqual((isk, irk), (rrk, rsk))
        self.assertEqual((pidx, sidx), (22, 11))
        self.assertEqual(mp.init_peek(msg), (11, self.i.node_id))
        self.assertEqual(mp.resp_peek(resp), (22, 11))

    def test_label_is_v2_and_differs_from_v1(self):
        self.assertIn(b"v2", mp.LABEL)
        self.assertNotEqual(mp.LABEL, t.LABEL)

    def test_wrong_node_id_hint_rejected(self):
        msg, _ = mp.init_create(self.i, self.r.pub, 1)
        bad = bytearray(msg)
        bad[10] ^= 1                                    # node_id hint is part of the transcript too
        with self.assertRaises(t.HandshakeError):
            mp.init_consume(self.r, self.i.pub, bytes(bad))

    def test_header_fields_are_authenticated(self):
        msg, _ = mp.init_create(self.i, self.r.pub, 1)
        bad = bytearray(msg)
        bad[2] ^= 1                                     # sender index
        with self.assertRaises(t.HandshakeError):
            mp.init_consume(self.r, self.i.pub, bytes(bad))
        _, st = mp.init_create(self.i, self.r.pub, 5)
        m2, st2 = mp.init_create(self.i, self.r.pub, 5)
        _, ck, h, E, ek, s = mp.init_consume(self.r, self.i.pub, m2)
        resp, _, _ = mp.resp_create(self.r, self.i.pub, ck, h, E, ek, 7, s)
        tampered = bytearray(resp)
        tampered[4] ^= 1                                # responder's own index
        with self.assertRaises(t.HandshakeError):
            mp.resp_consume(self.i, st2, bytes(tampered))

    def test_resp_for_other_init_rejected(self):
        msg, st = mp.init_create(self.i, self.r.pub, 5)
        _, ck, h, E, ek, s = mp.init_consume(self.r, self.i.pub, msg)
        resp, _, _ = mp.resp_create(self.r, self.i.pub, ck, h, E, ek, 7, s)
        _, other = mp.init_create(self.i, self.r.pub, 6)          # different index
        with self.assertRaises(t.HandshakeError):
            mp.resp_consume(self.i, other, resp)
        _, same_idx = mp.init_create(self.i, self.r.pub, 5)       # same index, different ephemerals
        with self.assertRaises(t.HandshakeError):
            mp.resp_consume(self.i, same_idx, resp)

    def test_unknown_static_key_rejected(self):
        stranger = t.Identity.generate()
        msg, _ = mp.init_create(stranger, self.r.pub, 1)
        with self.assertRaises(t.HandshakeError):
            mp.init_consume(self.r, self.i.pub, msg)

    def test_fragments_fit(self):
        msg, _ = mp.init_create(self.i, self.r.pub, 1)
        fr = t.fragment(msg)
        self.assertTrue(all(len(f) <= 1200 for f in fr))
        r = t.Reassembler()
        out = None
        for f in fr:
            out = r.feed("x", f) or out
        self.assertEqual(out, msg)


class TestMeshSession(unittest.TestCase):
    def mk(self, clock=None):
        k1, k2 = os.urandom(32), os.urandom(32)
        kw = {"clock": clock} if clock else {}
        return mp.MSession(k1, k2, True, 100, 200, **kw), mp.MSession(k2, k1, False, 200, 100, **kw)

    def test_roundtrip_index_and_aad(self):
        a, b = self.mk()
        p = a.encrypt(b"\xaa" * 60)
        self.assertEqual(p[0], 0x23)
        self.assertEqual(mp.data_receiver_index(p), 200)       # addressed to the peer's index
        self.assertEqual(b.decrypt(p), b"\xaa" * 60)
        for pos in (1, 6, 12, 20, -1):                         # index, counter, ciphertext, tag
            a2, b2 = self.mk()
            q = bytearray(a2.encrypt(b"x" * 30))
            q[pos] ^= 1
            self.assertIsNone(b2.decrypt(bytes(q)), pos)

    def test_replay_and_window(self):
        a, b = self.mk()
        pk = [a.encrypt(b"%d" % i) for i in range(1100)]
        self.assertIsNotNone(b.decrypt(pk[1099]))
        self.assertIsNone(b.decrypt(pk[1099]))
        self.assertIsNone(b.decrypt(pk[10]))
        self.assertIsNotNone(b.decrypt(pk[1099 - 1023]))

    def test_expiry(self):
        now = [0.0]
        a, b = self.mk(lambda: now[0])
        p = a.encrypt(b"x")
        now[0] = 181
        self.assertFalse(a.usable())
        self.assertIsNone(b.decrypt(p))


# ------------------------------------------------------------------ LWW store

def mkstore(origin, clock=None):
    d = tempfile.mkdtemp()
    kw = {"clock": clock} if clock else {}
    return meshdb.Store(os.path.join(d, "s.db"), origin, **kw)


def pull(dst, src):
    """One anti-entropy round: dst pulls everything new from src."""
    ep, cur = dst.cursor(src.origin)
    if ep != src.epoch:
        cur = 0
    while True:
        recs, last, mx = src.changes_since(cur, 50)
        dst.merge(recs)
        cur = last
        if not recs:
            break
    dst.set_cursor(src.origin, src.epoch, cur)


class TestStore(unittest.TestCase):
    def test_put_get_delete(self):
        s = mkstore("s1")
        s.put("comm", "c", {"a": 1})
        self.assertEqual(s.get("comm", "c"), {"a": 1})
        s.delete("comm", "c")
        self.assertIsNone(s.get("comm", "c"))

    def test_expiry(self):
        now = [1000.0]
        s = mkstore("s1", lambda: now[0])
        s.put("pres", "c/n", {"endpoints": []}, ttl_ms=90_000)
        self.assertIsNotNone(s.get("pres", "c/n"))
        now[0] += 91
        self.assertIsNone(s.get("pres", "c/n"))
        self.assertEqual(s.list("pres"), [])

    def test_lww_and_tiebreak(self):
        s = mkstore("s1")
        rec = {"kind": "comm", "key": "k", "val": {"v": "new"}, "ts": 5000, "origin": "zz", "exp": 0, "deleted": False}
        self.assertEqual(s.merge([rec]), 1)
        old = dict(rec, val={"v": "old"}, ts=4000)
        self.assertEqual(s.merge([old]), 0)
        self.assertEqual(s.get("comm", "k"), {"v": "new"})
        tie_lo = dict(rec, val={"v": "lo"}, origin="aa")                     # same ts, smaller origin loses
        self.assertEqual(s.merge([tie_lo]), 0)
        tie_hi = dict(rec, val={"v": "hi"}, origin="zzz")
        self.assertEqual(s.merge([tie_hi]), 1)
        self.assertEqual(s.get("comm", "k"), {"v": "hi"})
        self.assertEqual(s.merge([tie_hi]), 0)                               # idempotent

    def test_tombstone_wins_only_if_newer(self):
        a, b = mkstore("a"), mkstore("b")
        a.put("comm", "k", {"v": 1})
        pull(b, a)
        b.delete("comm", "k")
        pull(a, b)
        self.assertIsNone(a.get("comm", "k"))
        a.put("comm", "k", {"v": 2})                                          # later write resurrects
        pull(b, a)
        self.assertEqual(b.get("comm", "k"), {"v": 2})

    def test_local_writes_survive_clock_skew(self):
        fast, slow = mkstore("fast", lambda: 9000.0), mkstore("slow", lambda: 1000.0)
        fast.put("comm", "k", {"v": "fast"})
        pull(slow, fast)
        slow.put("comm", "k", {"v": "slow-later"})                            # HLC: still newer than what it saw
        pull(fast, slow)
        self.assertEqual(fast.get("comm", "k"), {"v": "slow-later"})

    def test_rejects_malformed_remote_records(self):
        s = mkstore("s1")
        good = {"kind": "comm", "key": "k", "val": {}, "ts": 1, "origin": "o", "exp": 0, "deleted": False}
        bad = [dict(good, kind="evil"), dict(good, key=""), dict(good, val="x"), dict(good, ts="1"),
               dict(good, origin="bad origin!"), dict(good, val={"x": "y" * 9000}), {"kind": "comm"}]
        self.assertEqual(s.merge(bad), 0)
        self.assertEqual(s.merge([good]), 1)

    def test_convergence_random_ops_three_oneqrelays(self):
        rnd = random.Random(7)
        nodes = [mkstore(n) for n in ("s1", "s2", "s3")]
        keys = [f"k{i}" for i in range(12)]
        for step in range(300):
            n = rnd.choice(nodes)
            k = rnd.choice(keys)
            if rnd.random() < 0.25:
                n.delete("node", k)
            else:
                n.put("node", k, {"v": rnd.randrange(1000), "by": n.origin})
            if rnd.random() < 0.3:
                a, b = rnd.sample(nodes, 2)
                pull(a, b)
        for _ in range(3):                                                    # full mesh anti-entropy
            for a in nodes:
                for b in nodes:
                    if a is not b:
                        pull(a, b)
        snaps = [n.snapshot() for n in nodes]
        self.assertEqual(snaps[0], snaps[1])
        self.assertEqual(snaps[1], snaps[2])
        self.assertGreater(len(snaps[0]), 0)

    def test_multi_hop_and_no_echo_loop(self):
        a, b, c = mkstore("a"), mkstore("b"), mkstore("c")
        a.put("comm", "k", {"v": 1})
        pull(b, a)
        pull(c, b)                                                            # a -> b -> c, a and c never talk
        self.assertEqual(c.get("comm", "k"), {"v": 1})
        before = a.max_lseq()
        pull(a, b)                                                            # a gets its own record back: no change
        self.assertEqual(a.max_lseq(), before)

    def test_incremental_cursor_and_epoch(self):
        a, b = mkstore("a"), mkstore("b")
        for i in range(120):
            a.put("comm", f"k{i}", {"i": i})
        pull(b, a)
        self.assertEqual(len(b.list("comm")), 120)
        recs, _, _ = a.changes_since(b.cursor("a")[1])
        self.assertEqual(recs, [])
        a.put("comm", "new", {})
        recs, _, _ = a.changes_since(b.cursor("a")[1])
        self.assertEqual([r["key"] for r in recs], ["new"])
        a2 = mkstore("a")                                                    # a is wiped: new epoch
        self.assertNotEqual(a2.epoch, a.epoch)


# ------------------------------------------------------------------ registry: users, tokens, addresses

def nid_pub():
    i = t.Identity.generate()
    return i.node_id, base64.b64encode(i.pub).decode()


class TestAccounts(unittest.TestCase):
    def setUp(self):
        self.s = mkstore("s1")
        self.r = meshdb.Registry(self.s, SECRET)
        self.r.create_community("lan", "10.50.0.0/24")
        self.r.add_user("lan", "alice", "correct horse", "admin")
        self.r.add_user("lan", "bob", "battery staple", "user", max_nodes=2)

    def test_login_ok_and_failures(self):
        self.assertIsNotNone(self.r.login("lan", "alice", "correct horse"))
        self.assertIsNone(self.r.login("lan", "alice", "wrong password"))
        self.assertIsNone(self.r.login("lan", "nobody", "correct horse"))
        self.assertIsNone(self.r.login("other", "alice", "correct horse"))
        self.assertIsNone(self.r.login("lan", "alice", ""))
        self.assertIsNone(self.r.login("lan", "al ice!", "x"))

    def test_hash_is_salted_scrypt_not_plaintext(self):
        h1 = self.s.get("user", "lan/alice")["hash"]
        self.assertTrue(h1.startswith("scrypt$"))
        self.assertNotIn("correct horse", h1)
        self.r.add_user("lan", "carol", "correct horse")
        self.assertNotEqual(h1.split("$")[4], self.s.get("user", "lan/carol")["hash"].split("$")[4])

    def test_password_policy(self):
        with self.assertRaises(meshdb.RegistryError):
            self.r.add_user("lan", "dave", "short")
        with self.assertRaises(meshdb.RegistryError):
            self.r.add_user("nope", "dave", "long enough password")

    def test_token_roundtrip_tamper_expiry(self):
        tok = self.r.login("lan", "alice", "correct horse")
        self.assertEqual(self.r.authenticate(tok), {"c": "lan", "u": "alice", "r": "admin"})
        p, s = tok.rsplit(".", 1)
        for bad in (p + "." + s[:-2] + "AA", "v2.x.y", "", "garbage", tok.replace("v2.", "v1.")):
            self.assertIsNone(self.r.authenticate(bad), bad)
        forged = meshdb.make_token(b"another-secret-entirely-xxxxxxxxxxxx", "lan", "alice", "admin", 0)
        self.assertIsNone(self.r.authenticate(forged))
        old = meshdb.make_token(SECRET, "lan", "alice", "admin", 0, ttl=-5)
        self.assertIsNone(self.r.authenticate(old))

    def test_password_change_and_disable_revoke_tokens(self):
        tok = self.r.login("lan", "bob", "battery staple")
        self.assertIsNotNone(self.r.authenticate(tok))
        self.r.set_password("lan", "bob", "a brand new password")
        self.assertIsNone(self.r.authenticate(tok))
        self.assertIsNone(self.r.login("lan", "bob", "battery staple"))
        tok2 = self.r.login("lan", "bob", "a brand new password")
        self.assertIsNotNone(tok2)
        self.r.set_disabled("lan", "bob", True)
        self.assertIsNone(self.r.authenticate(tok2))
        self.assertIsNone(self.r.login("lan", "bob", "a brand new password"))
        self.r.set_disabled("lan", "bob", False)
        self.assertIsNotNone(self.r.login("lan", "bob", "a brand new password"))

    def test_token_role_comes_from_the_account_not_the_token(self):
        tok = self.r.login("lan", "bob", "battery staple")
        forged = meshdb.make_token(SECRET, "lan", "bob", "admin", self.s.get("user", "lan/bob")["tokgen"])
        self.assertEqual(self.r.authenticate(forged)["r"], "user")

    def test_account_replicates_and_token_works_on_another_oneqrelay(self):
        other = mkstore("s2")
        pull(other, self.s)
        r2 = meshdb.Registry(other, SECRET)
        tok = self.r.login("lan", "alice", "correct horse")
        self.assertIsNotNone(r2.authenticate(tok))
        self.assertIsNotNone(r2.login("lan", "alice", "correct horse"))
        self.r.set_password("lan", "alice", "rotated password!")
        pull(other, self.s)
        self.assertIsNone(r2.authenticate(tok))                              # revocation replicated


class TestNodesAndAddresses(unittest.TestCase):
    def setUp(self):
        self.s = mkstore("s1")
        self.r = meshdb.Registry(self.s, SECRET)
        self.r.create_community("lan", "10.50.0.0/24")
        self.r.add_user("lan", "alice", "correct horse", "admin", max_nodes=300)
        self.r.add_user("lan", "bob", "battery staple", "user", max_nodes=2)

    def test_unique_ips_inside_subnet_and_sticky(self):
        net = ipaddress.ip_network("10.50.0.0/24")
        seen, macs = {}, set()
        for _ in range(100):
            nid, pub = nid_pub()
            rec = self.r.join_node("lan", "alice", "admin", nid, pub)
            ip = ipaddress.ip_address(rec["ip"])
            self.assertIn(ip, net)
            self.assertNotIn(rec["ip"], seen)
            self.assertNotIn(ip, (net.network_address, net.broadcast_address))
            self.assertRegex(rec["mac"], r"^02(:[0-9a-f]{2}){5}$")
            seen[rec["ip"]] = nid
            macs.add(rec["mac"])
            self.assertEqual(self.r.join_node("lan", "alice", "admin", nid, pub)["ip"], rec["ip"])   # sticky
        self.assertEqual(len(macs), 100)

    def test_ownership_quota_and_key_pinning(self):
        n1, p1 = nid_pub()
        self.r.join_node("lan", "bob", "user", n1, p1)
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.join_node("lan", "alice2", "user", n1, p1)               # another user cannot take it over
        self.assertEqual(e.exception.status, 403)
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.join_node("lan", "bob", "user", n1, nid_pub()[1])        # same id, different key
        self.assertEqual(e.exception.status, 409)
        n2, p2 = nid_pub()
        self.r.join_node("lan", "bob", "user", n2, p2)
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.join_node("lan", "bob", "user", *nid_pub())              # quota 2
        self.assertEqual(e.exception.status, 403)
        self.r.join_node("lan", "alice", "admin", n1, p1)                   # admin may touch any node

    def test_delete_node_frees_the_address(self):
        n1, p1 = nid_pub()
        ip = self.r.join_node("lan", "bob", "user", n1, p1)["ip"]
        with self.assertRaises(meshdb.RegistryError):
            self.r.delete_node("lan", n1.hex(), "alice2", "user")
        self.r.delete_node("lan", n1.hex(), "bob", "user")
        self.assertEqual(self.r.members("lan"), [])
        self.assertEqual(self.r.join_node("lan", "bob", "user", n1, p1)["ip"], ip)    # same hash start

    def test_rename_user_keeps_password_role_and_nodes(self):
        self.r.add_user("lan", "carol", "password123", "user", max_nodes=7)
        n1, p1 = nid_pub()
        ip = self.r.join_node("lan", "carol", "user", n1, p1)["ip"]
        gen = self.r.s.get("user", "lan/carol")["tokgen"]
        self.assertEqual(self.r.rename_user("lan", "carol", "dave"), 1)
        self.assertIsNone(self.r.s.get("user", "lan/carol"))
        u = self.r.s.get("user", "lan/dave")
        self.assertEqual((u["role"], u["max_nodes"], u["tokgen"]), ("user", 7, gen + 1))
        self.assertTrue(meshdb.check_password(u["hash"], "password123"))
        self.assertEqual(self.r.join_node("lan", "dave", "user", n1, p1)["ip"], ip)       # the node follows the account
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.join_node("lan", "carol", "user", n1, p1)
        self.assertEqual(e.exception.status, 403)
        for args, status in ((("lan", "nobody", "x1"), 404), (("lan", "dave", "alice"), 409), (("lan", "dave", "bad name"), 400)):
            with self.assertRaises(meshdb.RegistryError, msg=str(args)) as e:
                self.r.rename_user(*args)
            self.assertEqual(e.exception.status, status, args)

    def test_a_node_can_get_a_fixed_address(self):
        (n1, p1), (n2, p2) = nid_pub(), nid_pub()
        self.r.join_node("lan", "alice", "admin", n1, p1)
        other = self.r.join_node("lan", "alice", "admin", n2, p2)
        sub = ipaddress.ip_network(self.r.community("lan")["subnet"])
        fixed = str(sub.network_address + 221)
        rec = self.r.set_node_ip("lan", n1.hex(), fixed)
        self.assertEqual(rec["ip"], fixed)
        self.assertEqual(self.r.join_node("lan", "alice", "admin", n1, p1)["ip"], fixed)     # a restart keeps it
        for ip, status in ((fixed, 409), (str(sub.network_address), 400), (str(sub.broadcast_address), 400), ("192.0.2.1", 400), ("x", 400)):
            with self.assertRaises(meshdb.RegistryError, msg=ip) as e:
                self.r.set_node_ip("lan", n2.hex(), ip)
            self.assertEqual(e.exception.status, status, ip)
        self.assertEqual(self.r.join_node("lan", "alice", "admin", n2, p2)["ip"], other["ip"])
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.set_node_ip("lan", "00" * 16, fixed)
        self.assertEqual(e.exception.status, 404)
        # a fresh node never takes a fixed address
        for _ in range(20):
            self.assertNotEqual(self.r.join_node("lan", "alice", "admin", *nid_pub())["ip"], fixed)

    def test_change_subnet_readdresses_every_node_and_keeps_macs(self):
        nodes = [nid_pub() for _ in range(5)]
        macs = {self.r.join_node("lan", "alice", "admin", n, p)["mac"] for n, p in nodes}
        self.assertEqual(self.r.change_subnet("lan", "10.10.10.0/24"), 5)
        self.assertEqual(self.r.community("lan")["subnet"], "10.10.10.0/24")
        members = self.r.members("lan")
        net = ipaddress.ip_network("10.10.10.0/24")
        self.assertEqual(len({m["ip"] for m in members}), 5)
        for m in members:
            self.assertIn(ipaddress.ip_address(m["ip"]), net)
        self.assertEqual({m["mac"] for m in members}, macs)
        again = self.r.join_node("lan", "alice", "admin", *nodes[0])          # registering again hands out the new address
        self.assertIn(ipaddress.ip_address(again["ip"]), net)
        newcomer = self.r.join_node("lan", "alice", "admin", *nid_pub())
        self.assertIn(ipaddress.ip_address(newcomer["ip"]), net)
        for bad in ("10.10.10.0/30", "10.0.0.0/8", "::1/64", "nonsense", "10.10.10.1/24"):
            with self.assertRaises(meshdb.RegistryError, msg=bad):
                self.r.change_subnet("lan", bad)
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.change_subnet("nope", "10.10.10.0/24")
        self.assertEqual(e.exception.status, 404)
        self.r.set_route("lan", "192.168.16.0/24", nodes[0][0].hex(), "t")
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.change_subnet("lan", "192.168.16.0/24")                      # would swallow the route
        self.assertEqual(e.exception.status, 409)
        self.assertEqual(self.r.community("lan")["subnet"], "10.10.10.0/24")
        self.r.create_community("tiny2", "10.61.0.0/28", max_nodes=100)
        self.r.add_user("tiny2", "u", "password123", "user", max_nodes=50)
        for _ in range(8):
            self.r.join_node("tiny2", "u", "user", *nid_pub())
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.change_subnet("tiny2", "10.62.0.0/29")                       # 6 hosts for 8 nodes
        self.assertEqual(e.exception.status, 507)

    def test_community_full(self):
        self.r.create_community("tiny", "10.60.0.0/29", max_nodes=100)       # 6 hosts
        self.r.add_user("tiny", "u", "password123", "user", max_nodes=50)
        for _ in range(6):
            self.r.join_node("tiny", "u", "user", *nid_pub())
        with self.assertRaises(meshdb.RegistryError) as e:
            self.r.join_node("tiny", "u", "user", *nid_pub())
        self.assertEqual(e.exception.status, 507)

    def test_members_include_presence(self):
        n1, p1 = nid_pub()
        self.r.join_node("lan", "bob", "user", n1, p1, "laptop")
        m = self.r.members("lan")[0]
        self.assertEqual((m["name"], m["online"], m["endpoints"]), ("laptop", False, []))
        self.r.set_presence("lan", n1.hex(), ["1.2.3.4:5"])
        m = self.r.members("lan")[0]
        self.assertEqual((m["online"], m["endpoints"]), (True, ["1.2.3.4:5"]))

    def test_concurrent_allocation_conflict_is_resolved_and_converges(self):
        # two oneqrelays, partitioned: they hand the same address to two different nodes
        self.r.create_community("small", "10.70.0.0/29")
        self.r.add_user("small", "u", "password123", "user", max_nodes=50)
        s2 = mkstore("s2")
        r2 = meshdb.Registry(s2, SECRET)
        pull(s2, self.s)
        n1 = n2 = None
        for _ in range(2000):                                                # find two ids with the same hash start
            a, b = nid_pub(), nid_pub()
            sa = int.from_bytes(hashlib.sha256(b"alloc" + a[0]).digest()[:8], "big") % 6
            sb = int.from_bytes(hashlib.sha256(b"alloc" + b[0]).digest()[:8], "big") % 6
            if sa == sb:
                n1, n2 = a, b
                break
        self.assertIsNotNone(n1)
        ra = self.r.join_node("small", "u", "user", *n1)
        rb = r2.join_node("small", "u", "user", *n2)
        self.assertEqual(ra["ip"], rb["ip"])                                 # the conflict
        pull(self.s, s2)
        pull(s2, self.s)
        for _ in range(3):
            self.r.fix_ip_conflicts("small", grace_s=0)
            r2.fix_ip_conflicts("small", grace_s=0)
            pull(self.s, s2)
            pull(s2, self.s)
        ips1 = {m["id"]: m["ip"] for m in self.r.members("small")}
        ips2 = {m["id"]: m["ip"] for m in r2.members("small")}
        self.assertEqual(ips1, ips2)
        self.assertEqual(len(set(ips1.values())), 2)
        winner = min((ra["alloc_ts"], n1[0].hex()), (rb["alloc_ts"], n2[0].hex()))[1]
        self.assertEqual(ips1[winner], ra["ip"])                             # the older allocation keeps the address


if __name__ == "__main__":
    unittest.main(verbosity=2)
