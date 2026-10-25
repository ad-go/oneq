"""Delegated relay nodes, control plane: offer, grant, revoke, expiry, replication, permissions and the members list."""
import base64
import unittest

import meshdb
from test_oneqrelay import Fed, eventually


class TestDelegation(Fed):
    N = 2

    async def put_node(self, i, tok, ident, offer=None, nat=None, relays=None, name="r"):
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.5:5000"], "name": name}
        if offer is not None:
            body["offer"] = offer
        if nat is not None:
            body["nat"] = nat
        if relays is not None:
            body["relays"] = relays
        return await self.http.put(f"{self.urls[i]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(tok))

    async def grant(self, i, tok, nid, **body):
        return await self.http.put(f"{self.urls[i]}/v1/c/lan/relays/{nid}", json=body, headers=self.hdr(tok))

    async def test_offer_grant_list_and_members(self):
        tok = await self.token(0)
        a, b = self.ident(), self.ident()
        r = await self.put_node(0, tok, a, offer=True, nat={"type": "open", "mapped": "203.0.113.5:5000"})
        self.assertEqual(r.status, 200)
        self.assertIsNone((await r.json())["relay_role"])                 # offered, not yet delegated
        await self.put_node(0, tok, b)                                      # an ordinary member
        members = {m["id"]: m for m in self.nodes[0].reg.members("lan")}
        self.assertTrue(members[a.node_id.hex()]["offer"])
        self.assertFalse(members[b.node_id.hex()]["offer"])
        self.assertIsNone(members[a.node_id.hex()]["relay_role"])

        r = await self.grant(0, tok, a.node_id.hex(), max_kbps=5000, days=1)
        self.assertEqual(r.status, 200, await r.text())
        rec = await r.json()
        self.assertEqual(rec["max_kbps"], 5000)
        self.assertGreater(rec["exp"], 0)
        members = {m["id"]: m for m in self.nodes[0].reg.members("lan")}
        self.assertEqual(members[a.node_id.hex()]["relay_role"]["max_kbps"], 5000)
        self.assertIsNone(members[b.node_id.hex()]["relay_role"])
        lst = await (await self.http.get(f"{self.urls[0]}/v1/c/lan/relays", headers=self.hdr(tok))).json()
        self.assertEqual([x["id"] for x in lst["relays"]], [a.node_id.hex()])
        # the node learns its role when it refreshes
        r = await self.put_node(0, tok, a, offer=True, nat={"type": "open", "mapped": "203.0.113.5:5000"})
        self.assertEqual((await r.json())["relay_role"]["max_kbps"], 5000)

        async def on_other():
            return bool(self.nodes[1].reg.relay_grants("lan").get(a.node_id.hex()))
        await eventually(on_other)                                           # replicated through the federation

    async def test_only_administrators_grant_and_revoke(self):
        await eventually(lambda: self.nodes[1].reg.community("lan"))
        admin = await self.token(0)
        bob = await self.token(1, "bob", "bob-password!")
        a = self.ident()
        await self.put_node(0, admin, a, offer=True, nat={"type": "cone", "mapped": "203.0.113.5:5000"})
        self.assertEqual((await self.grant(0, bob, a.node_id.hex())).status, 403)
        self.assertEqual((await self.grant(0, admin, a.node_id.hex())).status, 200)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/relays/{a.node_id.hex()}", headers=self.hdr(bob))
        self.assertEqual(r.status, 403)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/relays/{a.node_id.hex()}", headers=self.hdr(admin))
        self.assertEqual(r.status, 200)
        self.assertEqual((await self.http.delete(f"{self.urls[0]}/v1/c/lan/relays/{a.node_id.hex()}", headers=self.hdr(admin))).status, 404)
        self.assertEqual(self.nodes[0].reg.relay_grants("lan"), {})

    async def test_refusals(self):
        tok = await self.token(0)
        a, b, c = self.ident(), self.ident(), self.ident()
        await self.put_node(0, tok, a)                                                               # never offered
        self.assertEqual((await self.grant(0, tok, a.node_id.hex())).status, 409)
        await self.put_node(0, tok, b, offer=True, nat={"type": "symmetric", "mapped": "203.0.113.5:5000"})
        r = await self.grant(0, tok, b.node_id.hex())
        self.assertEqual(r.status, 409)
        self.assertIn("reachable", await r.text())
        self.assertEqual((await self.grant(0, tok, b.node_id.hex(), force=True)).status, 200)       # the administrator knows better
        self.assertEqual((await self.grant(0, tok, c.node_id.hex())).status, 404)                    # unknown node
        for bad in ({"max_kbps": 5}, {"max_kbps": "fast"}, {"days": -1}, {"days": 99999}, {"max_kbps": True}):
            await self.put_node(0, tok, a, offer=True, nat={"type": "open", "mapped": "203.0.113.5:5000"})
            self.assertEqual((await self.grant(0, tok, a.node_id.hex(), **bad)).status, 400, bad)
        r = await self.put_node(0, tok, a, offer="yes")
        self.assertEqual(r.status, 400)
        r = await self.put_node(0, tok, a, relays=["zz"] )
        self.assertEqual(r.status, 400)
        r = await self.put_node(0, tok, a, relays=["00" * 16] * 5)
        self.assertEqual(r.status, 400)

    async def test_withdrawn_offer_or_expiry_or_node_removal_ends_the_role(self):
        tok = await self.token(0)
        a = self.ident()
        nat = {"type": "open", "mapped": "203.0.113.5:5000"}
        await self.put_node(0, tok, a, offer=True, nat=nat)
        await self.grant(0, tok, a.node_id.hex())
        await self.put_node(0, tok, a, offer=False, nat=nat)                 # the node stops offering: not used any more
        m = [m for m in self.nodes[0].reg.members("lan") if m["id"] == a.node_id.hex()][0]
        self.assertIsNone(m["relay_role"])
        await self.put_node(0, tok, a, offer=True, nat=nat)
        self.assertIsNotNone([m for m in self.nodes[0].reg.members("lan") if m["id"] == a.node_id.hex()][0]["relay_role"])
        # expiry
        key = f"lan/{a.node_id.hex()}"
        rec = self.nodes[0].store.get("dlg", key)
        self.nodes[0].store.put("dlg", key, dict(rec, exp=1))
        self.assertEqual(self.nodes[0].reg.relay_grants("lan"), {})
        # removal of the node removes the delegation
        await self.grant(0, tok, a.node_id.hex())
        self.assertTrue(self.nodes[0].reg.relay_grants("lan"))
        self.nodes[0].reg.delete_node("lan", a.node_id.hex(), "alice", "admin")
        self.assertIsNone(self.nodes[0].store.get("dlg", key))

    async def test_cli_grant_and_revoke(self):
        import oneqrelay
        tok = await self.token(0)
        a = self.ident()
        await self.put_node(0, tok, a, offer=True, nat={"type": "open", "mapped": "203.0.113.5:5000"})
        reg = self.nodes[0].reg
        reg.grant_relay("lan", a.node_id.hex(), "cli", 1000, 0)
        self.assertEqual(reg.relay_grants("lan")[a.node_id.hex()]["max_kbps"], 1000)
        reg.revoke_relay("lan", a.node_id.hex())
        with self.assertRaises(meshdb.RegistryError):
            reg.revoke_relay("lan", a.node_id.hex())
        self.assertTrue(hasattr(oneqrelay, "main"))


if __name__ == "__main__":
    import unittest
    unittest.main()


class TestNodeConfiguration(unittest.TestCase):
    def test_relay_offer_and_use_delegates_come_from_the_configuration_file(self):
        import argparse
        import tempfile
        import os
        import oneqconf
        import oneqnode
        d = tempfile.mkdtemp()
        path = os.path.join(d, "node.conf")
        with open(path, "w") as f:
            f.write("[node]\nrelay_offer = yes\nuse_delegates = no\n")
        a = argparse.Namespace(relay_offer=None, no_delegates=False)
        oneqconf.fill(a, oneqconf.load(path, ["node"], oneqnode.NODE_KEYS), oneqnode.NODE_SPEC)
        self.assertTrue(a.relay_offer)
        self.assertTrue(a.no_delegates)
        b = argparse.Namespace(relay_offer=None, no_delegates=False)
        with open(path, "w") as f:
            f.write("[node]\nrelay_offer = no\n")
        oneqconf.fill(b, oneqconf.load(path, ["node"], oneqnode.NODE_KEYS), oneqnode.NODE_SPEC)
        self.assertFalse(b.relay_offer)
        self.assertFalse(b.no_delegates)
