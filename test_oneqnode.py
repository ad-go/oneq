#!/usr/bin/env python3
"""oneqnode tests: real in-process oneqrelays (HTTP), nodes wired through an in-memory UDP network and
fake TAP devices. Covers registration, automatic addresses, full-mesh sessions, L2 switching
(unicast / broadcast / flood / learning / anti-spoofing), relay fallback and return to direct, and
failover between federated oneqrelays."""
import pqtls  # noqa: F401

import asyncio
import base64
import logging
import time
import unittest
from unittest import mock

import meshproto as mp
import oneqnode
import oneqtunel as t
from test_oneqrelay import Fed, eventually

logging.getLogger("oneqrelay").setLevel(logging.CRITICAL)
logging.getLogger("oneqnode").setLevel(logging.CRITICAL)


def eth(dst: bytes, src: bytes, payload: bytes = b"hello") -> bytes:
    return dst + src + b"\x08\x00" + payload.ljust(50, b"\0")


class FakeTap:
    name = "fake0"

    def __init__(self):
        self.out = []

    def fileno(self):
        return -1

    def write(self, f):
        self.out.append(f)


class FakeNet:
    """Datagram network between the nodes; `cut` partitions node-to-node traffic."""

    def __init__(self):
        self.nodes, self.sizes, self.raw_hs, self.cut = {}, [], 0, False
        self.block = set()           # (source address, destination address) pairs that are dropped, one way

    def sock(self, node, addr):
        net = self
        self.nodes[addr] = node

        class S:
            def sendto(_s, data, dst):
                net.sizes.append(len(data))
                if data[0] in (mp.M_INIT, mp.M_RESP):
                    net.raw_hs += 1
                n = net.nodes.get(dst)
                if n and not net.cut and (addr, dst) not in net.block:
                    asyncio.get_running_loop().call_soon(n.on_udp, data, addr)

            def close(_s):
                pass
        return S()


class MeshCase(Fed):
    N = 1
    SYNC = 0.3

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.net = FakeNet()
        self.mesh = []
        self.patches = [mock.patch.object(oneqnode, "PROBE_EVERY", 1.0)]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for n in self.mesh:
            await n.close()
        for p in self.patches:
            p.stop()
        await super().asyncTearDown()

    async def spawn(self, i, urls=None, user="alice", pw="alice-password", relay=True, ident=None, **kw):
        cfg = oneqnode.NodeConfig(relays=urls or self.urls[:1], community="lan", user=user, password=pw,
                                 no_config=True, advertise=[f"10.0.0.{i}:5000"], relay_after=kw.pop("relay_after", 1.0),
                                 refresh_fast=0.2, refresh_slow=kw.pop("refresh_slow", 0.5), register_every=1.0,
                                 name=f"n{i}", **kw)
        node = oneqnode.OneqNode(ident or t.Identity.generate(), cfg, FakeTap())
        node.test_index = i
        node.udp = self.net.sock(node, ("10.0.0.%d" % i, 5000))
        node.local_candidates = list(cfg.advertise)
        if relay:
            node.relay = oneqnode.RelayLink(node.control, node.me.node_id.hex(), node.on_relay)
            if node.cfg.relay_always:                                  # as in OneqNode.run(): stay attached
                node.relay.enabled.set()
            node.tasks.append(asyncio.ensure_future(node.relay.run()))
        node.tasks += [asyncio.ensure_future(node._registry_loop()), asyncio.ensure_future(node._maint())]
        self.mesh.append(node)
        return node

    async def full_mesh(self, nodes, timeout=15):
        def ready():
            return all(len(n.peers) == len(nodes) - 1 and all(p.cur is not None for p in n.peers.values())
                       for n in nodes)
        await eventually(ready, timeout=timeout, step=0.1)


class TestMesh(MeshCase):
    async def test_three_nodes_get_addresses_and_a_full_mesh_of_sessions(self):
        a, b, c = [await self.spawn(i) for i in (1, 2, 3)]
        await self.full_mesh([a, b, c])
        ips = {n.my_ip for n in (a, b, c)}
        macs = {n.my_mac for n in (a, b, c)}
        self.assertEqual((len(ips), len(macs)), (3, 3))
        self.assertTrue(all(ip.startswith("10.50.0.") for ip in ips))
        self.assertTrue(all(n.mtu == 1380 for n in (a, b, c)))
        self.assertEqual(self.net.raw_hs, 0, "handshake must only travel as fragments")
        self.assertLessEqual(max(s for s in self.net.sizes if s < 1300), 1200)
        for n in (a, b, c):
            for p in n.peers.values():
                self.assertEqual(p.ip, next(x for x in (a, b, c) if x.me.node_id == p.id).my_ip)

    async def test_switching_unicast_broadcast_and_flood(self):
        a, b, c = [await self.spawn(i) for i in (1, 2, 3)]
        await self.full_mesh([a, b, c])
        ma, mb, mc = (oneqnode.mac_bytes(n.my_mac) for n in (a, b, c))
        a.on_tap_frame(eth(mb, ma, b"A->B"))                       # known unicast: only B
        await eventually(lambda: len(b.tap.out) == 1)
        await asyncio.sleep(0.3)
        self.assertEqual((len(b.tap.out), len(c.tap.out)), (1, 0))
        self.assertTrue(b.tap.out[0].startswith(mb + ma))
        a.on_tap_frame(eth(oneqnode.BROADCAST, ma, b"bcast"))        # broadcast: both
        await eventually(lambda: len(b.tap.out) == 2 and len(c.tap.out) == 1)
        a.on_tap_frame(eth(b"\x01\x00\x5e\x00\x00\x01", ma, b"mcast"))   # multicast: both
        await eventually(lambda: len(b.tap.out) == 3 and len(c.tap.out) == 2)
        a.on_tap_frame(eth(b"\x02\xaa\xbb\xcc\xdd\xee", ma, b"unknown"))  # unknown unicast: flooded
        await eventually(lambda: len(b.tap.out) == 4 and len(c.tap.out) == 3)
        self.assertEqual(len(a.tap.out), 0)                          # nothing echoed back

    async def test_bridged_host_is_learned_then_unicast_goes_to_one_peer(self):
        a, b, c = [await self.spawn(i) for i in (1, 2, 3)]
        await self.full_mesh([a, b, c])
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        host = b"\x02\x77\x66\x55\x44\x33"                           # a machine bridged behind B
        b.on_tap_frame(eth(oneqnode.BROADCAST, host, b"I am behind B"))
        await eventually(lambda: len(a.tap.out) == 1 and len(c.tap.out) == 1)
        self.assertEqual(a.mac_table[host][0], b.me.node_id)
        a.on_tap_frame(eth(host, ma, b"to the bridged host"))
        await eventually(lambda: len(b.tap.out) == 1)
        await asyncio.sleep(0.3)
        self.assertEqual(len(c.tap.out), 1)                          # C did not get it

    async def test_member_cannot_spoof_another_members_mac_or_send_garbage(self):
        a, b, c = [await self.spawn(i) for i in (1, 2, 3)]
        await self.full_mesh([a, b, c])
        mc = oneqnode.mac_bytes(c.my_mac)
        mb = oneqnode.mac_bytes(b.my_mac)
        b.on_tap_frame(eth(oneqnode.BROADCAST, mc, b"I am really C"))   # B forges C's source MAC
        await asyncio.sleep(0.6)
        self.assertEqual((len(a.tap.out), len(c.tap.out)), (0, 0))
        a.on_tap_frame(b"short")                                       # runt frames are not forwarded
        a.on_tap_frame(eth(mb, oneqnode.mac_bytes(a.my_mac), b"x" * 5000))  # oversize
        await asyncio.sleep(0.4)
        self.assertEqual(len(b.tap.out), 0)

    async def test_registry_entry_with_wrong_key_binding_is_ignored(self):
        a = await self.spawn(1)
        good, evil = t.Identity.generate(), t.Identity.generate()
        a.apply_members([{"id": good.node_id.hex(), "pub": base64.b64encode(evil.pub).decode(), "name": "",
                          "ip": "10.50.0.9", "mac": "02:00:00:00:00:09", "endpoints": []},
                         {"id": "zz", "pub": "AAAA", "ip": "x", "mac": "bad", "endpoints": []}])
        self.assertEqual(a.peers, {})
        a.apply_members([{"id": good.node_id.hex(), "pub": base64.b64encode(good.pub).decode(), "name": "",
                          "ip": "10.50.0.9", "mac": "02:00:00:00:00:09", "endpoints": ["1.2.3.4:5"]}])
        self.assertEqual(len(a.peers), 1)

    async def test_wrong_password_is_refused_and_does_not_crash(self):
        n = await self.spawn(1, pw="not-the-password")
        await asyncio.sleep(1.0)
        self.assertIsNone(n.my_ip)
        self.assertTrue(all(not t_.done() for t_ in n.tasks))        # the node keeps running and retrying
        with self.assertRaises(PermissionError):
            await n.control.login()

    async def test_login_refused_by_an_unsynced_oneqrelay_falls_through_to_the_next(self):
        import os, tempfile
        import meshdb, oneqrelay
        from aiohttp import web
        fresh = oneqrelay.OneqRelay(meshdb.Store(os.path.join(tempfile.mkdtemp(), "e.db"), "s9"), b"x" * 32)
        runner = web.AppRunner(fresh.make_app(), access_log=None)
        await runner.setup()
        from test_oneqrelay import free_port
        port = free_port()
        await web.TCPSite(runner, "127.0.0.1", port, shutdown_timeout=1).start()
        try:
            urls = [f"http://127.0.0.1:{port}", self.urls[0]]       # the first knows no accounts (not replicated yet)
            n = await self.spawn(1, urls=urls)
            await eventually(lambda: n.my_ip, timeout=8)
            self.assertEqual(n.control.base, self.urls[0])
            bad = await self.spawn(2, urls=urls, pw="not-the-password")   # wrong everywhere: still refused
            await asyncio.sleep(1.5)
            self.assertIsNone(bad.my_ip)
        finally:
            await runner.cleanup()

    async def test_user_quota_applies_to_nodes(self):
        async def bob():
            return self.nodes[0].reg.s.get("user", "lan/bob") is not None
        await eventually(bob)
        nodes = [await self.spawn(i, user="bob", pw="bob-password!") for i in (1, 2, 3)]   # they race for the quota of 2
        await eventually(lambda: sum(1 for n in nodes if n.my_ip) == 2, timeout=8)
        await asyncio.sleep(1.5)
        self.assertEqual(sum(1 for n in nodes if n.my_ip), 2)          # the third is refused, however the race went


class TestDiscovery(MeshCase):
    async def test_new_member_is_found_quickly_even_when_everyone_else_is_connected(self):
        # Two nodes are fully connected and poll the registry only every 30 s. A newcomer must still be discovered
        # within a couple of seconds: its hole-punch packets (from an address nobody advertised) trigger a refresh.
        a, b = await self.spawn(1, refresh_slow=30.0), await self.spawn(2, refresh_slow=30.0)
        await self.full_mesh([a, b])
        await asyncio.sleep(1.0)                                     # let both settle into the slow interval
        c = await self.spawn(3, refresh_slow=30.0)
        await eventually(lambda: all(len(n.peers) == 2 for n in (a, b, c)), timeout=6, step=0.1)
        await self.full_mesh([a, b, c], timeout=8)
        ma, mc = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(c.my_mac)
        a.on_tap_frame(eth(mc, ma, b"hello newcomer"))
        await eventually(lambda: len(c.tap.out) == 1)

    async def test_punch_from_a_known_address_does_not_trigger_refreshes(self):
        a, b = await self.spawn(1, refresh_slow=30.0), await self.spawn(2, refresh_slow=30.0)
        await self.full_mesh([a, b])
        a.last_members = time.monotonic()
        a.on_udp(bytes([mp.T_PUNCH]) + b"12345678", ("10.0.0.2", 5000))   # b's advertised address
        self.assertGreater(a.last_members, 0.0)
        a.on_udp(bytes([mp.T_PUNCH]) + b"12345678", ("10.0.0.99", 5000))  # unknown address
        self.assertEqual(a.last_members, 0.0)


class TestRestart(MeshCase):
    N = 1

    async def test_a_restarted_responder_is_reached_again_within_seconds_not_minutes(self):
        # Measured on real hosts: a node that cannot initiate (its key sorts last) stayed unreachable for ~100 s
        # after a restart, until the initiators' rekey timer fired. Its PUNCH now makes them re-handshake at once.
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        init, resp = (a, b) if a.peers[b.me.node_id].initiator else (b, a)
        await asyncio.sleep(3.5)                                    # the stale session must be a few seconds old
        i = resp.test_index
        self.mesh.remove(resp)
        await resp.close()
        resp2 = await self.spawn(i, ident=resp.me)                  # same identity, no state: a restart
        mi, mr = oneqnode.mac_bytes(init.my_mac), oneqnode.mac_bytes(resp2.my_mac if resp2.my_mac else resp.my_mac)
        t0 = time.monotonic()

        async def reaches():
            init.on_tap_frame(eth(mr, mi, b"are you back?"))
            await asyncio.sleep(0.4)
            return len(resp2.tap.out) > 0
        await eventually(reaches, timeout=15, step=0.1)
        self.assertLess(time.monotonic() - t0, 15)                  # before: ~REKEY_AFTER (120 s)

    async def test_the_punch_that_triggers_a_new_handshake_is_rate_limited_and_only_for_initiators(self):
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        init, resp = (a, b) if a.peers[b.me.node_id].initiator else (b, a)
        await asyncio.sleep(3.5)
        init._on_punch(resp.me.node_id)
        first = init.peers[resp.me.node_id].last_rehs
        self.assertTrue(init.peers[resp.me.node_id].force_hs)
        init.peers[resp.me.node_id].force_hs = False
        init._on_punch(resp.me.node_id)                              # within 5 s: ignored
        self.assertEqual((init.peers[resp.me.node_id].last_rehs, init.peers[resp.me.node_id].force_hs), (first, False))
        resp._on_punch(init.me.node_id)                              # the responder cannot initiate: nothing to do
        self.assertFalse(resp.peers[init.me.node_id].force_hs)
        init._on_punch(b"\x00" * 16)                                # unknown node id: ignored
        # a young session is left alone: the peer may simply still be handshaking
        c = init.peers[resp.me.node_id]
        c.cur.created = time.monotonic()
        c.last_rehs = 0.0
        init._on_punch(resp.me.node_id)
        self.assertFalse(c.force_hs)


class TestHandshakeViaRelay(MeshCase):
    N = 2

    async def test_a_forced_rehandshake_with_a_peer_that_has_no_address_goes_through_the_relay(self):
        # Found with the Windows client behind NAT: it advertises no address and the initiator held a stale session,
        # so the forced INIT had neither candidates nor relay_hs and was never sent.
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        p = a.peers[b.me.node_id]
        p.relay_hs = False
        p.force_hs = False
        p.candidates = [("10.0.0.5", 1234)]
        self.assertFalse(a._hs_via_relay(p))                         # direct candidates and a healthy session: no relay
        p.force_hs = True
        self.assertTrue(a._hs_via_relay(p))
        p.force_hs = False
        p.candidates = []
        self.assertTrue(a._hs_via_relay(p))                          # nothing else can reach it


class TestRelayAttachment(MeshCase):
    N = 2

    async def test_every_node_is_attached_to_a_relay_even_when_all_paths_are_direct(self):
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        await eventually(lambda: a.relay.connected and b.relay.connected, timeout=8)
        self.assertTrue(all(p.path == "direct" for n in (a, b) for p in n.peers.values()))
        # the relay knows both of them, so either can be reached through it at any time
        await eventually(lambda: all(self.nodes[0].reg.relay_at("lan", n.me.node_id.hex()) for n in (a, b)), timeout=8)

    async def test_force_relay_on_one_node_reaches_peers_that_are_connected_directly(self):
        # Found on the real hosts: m forced everything through the relay, but x, y and n had direct sessions with it
        # and were never attached, so the relay could not deliver and every packet was lost.
        a, b, c = [await self.spawn(i) for i in (1, 2, 3)]
        await self.full_mesh([a, b, c])
        await eventually(lambda: all(n.relay.connected for n in (a, b, c)), timeout=8)
        a.cfg.force_relay = True                                       # only a changes; b and c still have direct sessions
        ma, mb, mc = (oneqnode.mac_bytes(n.my_mac) for n in (a, b, c))
        before = len(self.net.sizes)
        a.on_tap_frame(eth(mb, ma, b"a -> b through the relay"))
        a.on_tap_frame(eth(mc, ma, b"a -> c through the relay"))
        await eventually(lambda: len(b.tap.out) == 1 and len(c.tap.out) == 1, timeout=6)
        b.on_tap_frame(eth(ma, mb, b"b -> a direct"))
        await eventually(lambda: len(a.tap.out) == 1, timeout=6)

    async def test_a_stale_direct_path_falls_back_to_a_relay_the_peer_is_attached_to(self):
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        await eventually(lambda: a.relay.connected and b.relay.connected, timeout=8)
        self.net.cut = True                                            # the direct path silently dies
        for n in (a, b):
            for p in n.peers.values():
                p.last_direct_rx -= 200
        await eventually(lambda: all(p.path == "relay" for n in (a, b) for p in n.peers.values()), timeout=6)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"survives a dead direct path"))
        await eventually(lambda: len(b.tap.out) == 1, timeout=6)


class TestRelayAndRecovery(MeshCase):
    async def test_partition_falls_back_to_relay_then_returns_to_direct(self):
        self.net.cut = True                                          # no node-to-node UDP at all
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b], timeout=20)
        self.assertTrue(all(p.path == "relay" for n in (a, b) for p in n.peers.values()))
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"via relay"))
        await eventually(lambda: len(b.tap.out) == 1)
        self.net.cut = False                                         # network heals: probes switch back
        await eventually(lambda: all(p.path == "direct" for n in (a, b) for p in n.peers.values()), timeout=15)
        b.tap.out.clear()
        a.on_tap_frame(eth(mb, ma, b"direct again"))
        await eventually(lambda: len(b.tap.out) == 1)

    async def test_forced_relay_never_sends_node_to_node_udp(self):
        a, b = await self.spawn(1, force_relay=True), await self.spawn(2, force_relay=True)
        await self.full_mesh([a, b], timeout=20)
        before = len(self.net.sizes)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"relayed"))
        await eventually(lambda: len(b.tap.out) == 1)
        self.assertEqual(len(self.net.sizes), before)                # nothing went over the UDP network

    async def test_data_plane_survives_loss_of_every_oneqrelay(self):
        a, b = await self.spawn(1), await self.spawn(2)
        await self.full_mesh([a, b])
        for r in self.runners:
            await r.cleanup()
        await asyncio.sleep(0.5)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"no relay needed"))
        await eventually(lambda: len(b.tap.out) == 1)


class TestFederationFailover(MeshCase):
    N = 2

    async def test_nodes_switch_oneqrelay_and_keep_working(self):
        a = await self.spawn(1, urls=[self.urls[0], self.urls[1]])
        b = await self.spawn(2, urls=[self.urls[1], self.urls[0]])    # registered on different oneqrelays
        await self.full_mesh([a, b])
        self.assertEqual((a.control.base, b.control.base), (self.urls[0], self.urls[1]))
        await self.runners[0].cleanup()                               # a's oneqrelay dies
        async def a_failed_over():
            return a.control.base == self.urls[1] and a.control.token is not None
        await eventually(a_failed_over, timeout=15)
        c = await self.spawn(3, urls=[self.urls[1]])                 # a newcomer joins through the survivor
        await self.full_mesh([a, b, c], timeout=20)
        self.assertEqual(len({n.my_ip for n in (a, b, c)}), 3)
        mc, ma = oneqnode.mac_bytes(c.my_mac), oneqnode.mac_bytes(a.my_mac)
        c.on_tap_frame(eth(ma, mc, b"hi after failover"))
        await eventually(lambda: len(a.tap.out) >= 1)

    async def test_cross_oneqrelay_relay_path(self):
        self.net.cut = True
        a = await self.spawn(1, urls=[self.urls[0]])
        b = await self.spawn(2, urls=[self.urls[1]])
        await self.full_mesh([a, b], timeout=25)                      # sessions only possible via federated relay
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"across oneqrelays"))
        await eventually(lambda: len(b.tap.out) == 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
