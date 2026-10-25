"""Delegated relay nodes, data plane: a member that the administrator delegated forwards the (end-to-end encrypted) datagrams of two
members that cannot reach each other directly. Real oneqrelay (registry), nodes on an in-memory UDP network with fake TAP devices."""
import pqtls  # noqa: F401

import asyncio
import logging
from unittest import mock

import meshproto as mp
import oneqnode
from test_oneqnode import MeshCase, eth
from test_oneqrelay import eventually

logging.getLogger("oneqnode").setLevel(logging.CRITICAL)

NAT_OPEN = {"type": "open", "mapped": "10.0.0.3:5000"}


class Delegation(MeshCase):
    N = 1

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.patches.append(mock.patch.object(oneqnode, "RLY_PROBE_EVERY", 0.5))
        self.patches[-1].start()

    def addr(self, n):
        return ("10.0.0.%d" % n.test_index, 5000)

    def cut_between(self, a, b):
        self.net.block.add((self.addr(a), self.addr(b)))
        self.net.block.add((self.addr(b), self.addr(a)))

    async def trio(self, relay_for_ab=False, grant=True, max_kbps=20000):
        """a and b cannot reach each other; r (offers to relay) can be reached by both. The oneqrelay link of a and b is absent unless asked for."""
        r = await self.spawn(3, relay_offer=True)
        a = await self.spawn(1, relay=relay_for_ab)
        b = await self.spawn(2, relay=relay_for_ab)
        self.cut_between(a, b)
        # r must be known as reachable: it is delegated by the administrator (the registry checks the NAT it reported)
        await eventually(lambda: any(m["id"] == r.me.node_id.hex() and m["offer"] for m in self.nodes[0].reg.members("lan")))
        self.nodes[0].reg.s.put("pres", f"lan/{r.me.node_id.hex()}", {"endpoints": ["10.0.0.3:5000"], "at": "s1", "nat": NAT_OPEN}, ttl_ms=3_600_000)
        if grant:
            self.nodes[0].reg.grant_relay("lan", r.me.node_id.hex(), "test", max_kbps, 0)
        return a, b, r

    async def sessions(self, a, b, r, timeout=20):
        def ok():
            return (a.peers.get(b.me.node_id) and a.peers[b.me.node_id].cur is not None
                    and b.peers.get(a.me.node_id) and b.peers[a.me.node_id].cur is not None)
        await eventually(ok, timeout=timeout, step=0.1)

    async def test_two_members_that_cannot_connect_talk_through_the_delegated_node(self):
        a, b, r = await self.trio()
        await self.sessions(a, b, r)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"through r"))
        await eventually(lambda: any(f.endswith(b"through r".ljust(50, b"\0")) for f in b.tap.out))
        b.on_tap_frame(eth(ma, mb, b"and back"))
        await eventually(lambda: any(f.endswith(b"and back".ljust(50, b"\0")) for f in a.tap.out))
        self.assertGreater(r.rly_stats["packets"], 2)
        self.assertEqual(a.peers[b.me.node_id].rly_via, r.me.node_id)
        self.assertEqual(a.peers[b.me.node_id].path, "relay")
        self.assertIn(r.me.node_id, a.rly_nodes)
        self.assertEqual(r.rly_role["max_kbps"], 20000)

    async def test_a_node_that_is_not_delegated_does_not_forward(self):
        a, b, r = await self.trio(grant=False)
        await asyncio.sleep(4)
        self.assertIsNone(r.rly_role)
        self.assertEqual(a.rly_nodes, {})
        self.assertIsNone(a.peers[b.me.node_id].cur)                    # no path at all: no delegate, no oneqrelay link
        self.assertEqual(r.rly_stats["packets"], 0)

    async def test_the_delegated_node_cannot_read_what_it_forwards(self):
        a, b, r = await self.trio()
        await self.sessions(a, b, r)
        seen = []
        orig = r._rly_forward

        def spy(sender, body):
            seen.append(body)
            orig(sender, body)
        r._rly_forward = spy
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"SECRET-PAYLOAD-123"))
        await eventually(lambda: any(b"SECRET-PAYLOAD-123" in f for f in b.tap.out))
        self.assertTrue(seen)
        self.assertFalse(any(b"SECRET-PAYLOAD-123" in x for x in seen))

    async def test_revoking_the_delegation_moves_traffic_to_the_oneqrelay(self):
        a, b, r = await self.trio(relay_for_ab=True)
        await self.sessions(a, b, r)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        a.on_tap_frame(eth(mb, ma, b"first"))
        await eventually(lambda: any(f.endswith(b"first".ljust(50, b"\0")) for f in b.tap.out))
        await eventually(lambda: a.peers[b.me.node_id].rly_via == r.me.node_id)
        self.nodes[0].reg.revoke_relay("lan", r.me.node_id.hex())
        await eventually(lambda: not a.rly_nodes and r.rly_role is None, timeout=15)
        a.on_tap_frame(eth(mb, ma, b"second"))
        await eventually(lambda: any(f.endswith(b"second".ljust(50, b"\0")) for f in b.tap.out))
        self.assertIsNone(a.peers[b.me.node_id].rly_via)

    async def test_the_node_that_died_is_replaced_by_the_oneqrelay(self):
        with mock.patch.object(oneqnode, "RLY_ALIVE", 2.0):
            a, b, r = await self.trio(relay_for_ab=True)
            await self.sessions(a, b, r)
            ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
            a.on_tap_frame(eth(mb, ma, b"before"))
            await eventually(lambda: any(f.endswith(b"before".ljust(50, b"\0")) for f in b.tap.out))
            await eventually(lambda: a.peers[b.me.node_id].rly_via == r.me.node_id)
            await r.close()                                                      # r is gone
            self.net.block.update({(self.addr(r), self.addr(a)), (self.addr(r), self.addr(b)), (self.addr(a), self.addr(r)), (self.addr(b), self.addr(r))})
            await asyncio.sleep(3.5)
            a.on_tap_frame(eth(mb, ma, b"after"))
            await eventually(lambda: any(f.endswith(b"after".ljust(50, b"\0")) for f in b.tap.out), timeout=10)
            self.assertIsNone(a.peers[b.me.node_id].rly_via)

    async def test_the_bandwidth_cap_is_enforced(self):
        a, b, r = await self.trio(max_kbps=100)                                  # 100 kbit/s = 12.5 kB/s
        await self.sessions(a, b, r)
        ma, mb = oneqnode.mac_bytes(a.my_mac), oneqnode.mac_bytes(b.my_mac)
        for _ in range(400):                                                     # ~ 400 x 64 B of payload in a burst
            a.on_tap_frame(eth(mb, ma, b"x" * 1000))
        await asyncio.sleep(1.0)
        self.assertGreater(r.rly_stats["dropped"], 0)
        self.assertLess(r.rly_stats["bytes"], 120_000)

    async def test_nothing_is_forwarded_for_or_to_a_stranger_and_forged_deliveries_are_ignored(self):
        a, b, r = await self.trio()
        await self.sessions(a, b, r)
        c = await self.spawn(4)                                                  # an ordinary member, not delegated
        await eventually(lambda: a.peers.get(c.me.node_id) is not None and a.peers[c.me.node_id].cur is not None
                          and c.peers.get(a.me.node_id) is not None and c.peers[a.me.node_id].cur is not None, timeout=20)
        before = len(a.tap.out)
        packets = r.rly_stats["packets"]
        # c pretends to be a relay node: a DLV for a, "from" b
        pc = c.peers[a.me.node_id]
        c._send_rly(pc, mp.RLY_DLV, b.me.node_id + b"\x23" + b"\0" * 80)
        # a forward request for an unknown destination: the delegated node answers with a NACK
        pa = a.peers[r.me.node_id]
        a._send_rly(pa, mp.RLY_FWD, bytes(16) + b"x" * 40)
        await asyncio.sleep(0.5)
        self.assertEqual(len(a.tap.out), before)
        self.assertEqual(r.rly_stats["packets"], packets)                       # the request for nobody delivered nothing
        self.assertNotIn(c.me.node_id, a.rly_nodes)


if __name__ == "__main__":
    import unittest
    unittest.main()
