"""Routes through a gateway node, control plane: set, list, replace, remove, validation, permissions, replication, cleanup and the CLI."""
import base64
import unittest

import meshdb
import oneqrelay
from test_oneqrelay import Fed, eventually

ROUTE_GW = meshdb.ROUTE_MAX_GATEWAYS


class TestRoutes(Fed):
    N = 2

    async def put_node(self, i, tok, ident, name="gw"):
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.5:5000"], "name": name}
        return await self.http.put(f"{self.urls[i]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(tok))

    async def put_route(self, i, tok, net, via, **extra):
        return await self.http.put(f"{self.urls[i]}/v1/c/lan/routes/{net}", json={"via": via, **extra}, headers=self.hdr(tok))

    async def test_set_list_replace_remove_and_replication(self):
        tok = await self.token(0)
        g1, g2 = self.ident(), self.ident()
        await self.put_node(0, tok, g1, "g1")
        await self.put_node(0, tok, g2, "g2")
        r = await self.put_route(0, tok, "192.168.16.0_24", g1.node_id.hex())
        self.assertEqual(r.status, 200, await r.text())
        self.assertEqual(await r.json(), {"cidr": "192.168.16.0/24", "via": g1.node_id.hex(), "by": "alice", "prio": 100})
        # the same network through a second gateway is a second route (redundancy), not a replacement; the lower priority is listed first
        r = await self.put_route(0, tok, "192.168.16.0_24", g2.node_id.hex(), prio=50)
        self.assertEqual(r.status, 200)
        lst = await (await self.http.get(f"{self.urls[0]}/v1/c/lan/routes", headers=self.hdr(tok))).json()
        self.assertEqual([(x["cidr"], x["via"], x["prio"]) for x in lst["routes"]],
                         [("192.168.16.0/24", g2.node_id.hex(), 50), ("192.168.16.0/24", g1.node_id.hex(), 100)])
        # the member list carries them too (one request for clients)
        nodes = await (await self.http.get(f"{self.urls[0]}/v1/c/lan/nodes", headers=self.hdr(tok))).json()
        self.assertEqual(nodes["routes"], lst["routes"])
        self.assertEqual(len(nodes["nodes"]), 2)

        async def on_other():
            return [(x["via"], x["prio"]) for x in self.nodes[1].reg.routes("lan")] == [(g2.node_id.hex(), 50), (g1.node_id.hex(), 100)]
        await eventually(on_other)                                           # replicated through the federation

        # withdraw one gateway: the other stays; then everything
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24?via={g2.node_id.hex()}", headers=self.hdr(tok))
        self.assertEqual(r.status, 200)
        self.assertEqual([x["via"] for x in self.nodes[0].reg.routes("lan")], [g1.node_id.hex()])
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24?via={g2.node_id.hex()}", headers=self.hdr(tok))
        self.assertEqual(r.status, 404)                                      # not a gateway of that network any more
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24?via=zz", headers=self.hdr(tok))
        self.assertEqual(r.status, 400)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24", headers=self.hdr(tok))
        self.assertEqual(r.status, 200)
        self.assertEqual(self.nodes[0].reg.routes("lan"), [])
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24", headers=self.hdr(tok))
        self.assertEqual(r.status, 404)

        async def gone_on_other():
            return self.nodes[1].reg.routes("lan") == []
        await eventually(gone_on_other)

    async def test_only_administrators_and_validation(self):
        await eventually(lambda: self.nodes[1].reg.community("lan"))
        admin = await self.token(0)
        bob = await self.token(1, "bob", "bob-password!")
        g = self.ident()
        await self.put_node(0, admin, g)
        gid = g.node_id.hex()
        self.assertEqual((await self.put_route(0, bob, "192.168.16.0_24", gid)).status, 403)
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24", headers=self.hdr(bob))
        self.assertEqual(r.status, 403)
        self.assertEqual((await self.http.get(f"{self.urls[0]}/v1/c/lan/routes", headers=self.hdr(bob))).status, 200)   # members may read
        subnet = self.nodes[0].reg.community("lan")["subnet"]
        inside = subnet.rsplit(".", 1)[0] + ".128_25"
        bad = ["0.0.0.0_0", "10.0.0.0_7", "127.0.0.0_8", "224.0.0.0_8", "169.254.0.0_16", "192.168.16.1_24", "nonsense", "192.168.16.0_33", "2001:db8::_32", inside]
        for net in bad:
            r = await self.put_route(0, admin, net, gid)
            self.assertEqual(r.status, 400, f"{net}: {r.status}")
        self.assertEqual((await self.put_route(0, admin, "192.168.16.0_24", "00" * 16)).status, 404)       # unknown gateway
        self.assertEqual((await self.put_route(0, admin, "192.168.16.0_24", "xyz")).status, 400)
        self.assertEqual(self.nodes[0].reg.routes("lan"), [])

    async def test_route_goes_when_its_gateway_is_removed(self):
        tok = await self.token(0)
        g, h = self.ident(), self.ident()
        await self.put_node(0, tok, g, "g")
        await self.put_node(0, tok, h, "h")
        self.assertEqual((await self.put_route(0, tok, "192.168.16.0_24", g.node_id.hex())).status, 200)
        self.assertEqual((await self.put_route(0, tok, "172.20.0.0_16", h.node_id.hex())).status, 200)
        self.nodes[0].reg.delete_node("lan", g.node_id.hex(), "", "admin")
        self.assertEqual([x["cidr"] for x in self.nodes[0].reg.routes("lan")], ["172.20.0.0/16"])

    async def test_limit_and_community_delete(self):
        tok = await self.token(0)
        g = self.ident()
        await self.put_node(0, tok, g)
        reg = self.nodes[0].reg
        for i in range(meshdb.MAX_ROUTES_PER_COMM):
            reg.set_route("lan", f"10.{100 + i // 256}.{i % 256}.0/24", g.node_id.hex(), "t")
        with self.assertRaises(meshdb.RegistryError) as e:
            reg.set_route("lan", "172.30.0.0/24", g.node_id.hex(), "t")
        self.assertEqual(e.exception.status, 409)
        reg.set_route("lan", "10.100.0.0/24", g.node_id.hex(), "again")          # replacing an existing one is still fine
        reg.delete_community("lan")
        self.assertEqual(reg.routes("lan"), [])

    async def test_several_gateways_priorities_and_limits(self):
        tok = await self.token(0)
        gws = [self.ident() for _ in range(ROUTE_GW + 1)]
        for i, g in enumerate(gws):
            await self.put_node(0, tok, g, f"g{i}")
        reg = self.nodes[0].reg
        for i, g in enumerate(gws[:ROUTE_GW]):
            r = await self.put_route(0, tok, "192.168.16.0_24", g.node_id.hex(), prio=10 * (ROUTE_GW - i))
            self.assertEqual(r.status, 200, await r.text())
        r = await self.put_route(0, tok, "192.168.16.0_24", gws[ROUTE_GW].node_id.hex())
        self.assertEqual(r.status, 409, await r.text())                    # too many gateways for one network
        self.assertEqual([x["prio"] for x in reg.routes("lan")], sorted(10 * (ROUTE_GW - i) for i in range(ROUTE_GW)))
        # the priority of an existing gateway can be changed, and that is not a new gateway
        r = await self.put_route(0, tok, "192.168.16.0_24", gws[0].node_id.hex(), prio=1)
        self.assertEqual(r.status, 200)
        self.assertEqual(reg.routes("lan")[0]["via"], gws[0].node_id.hex())
        self.assertEqual(len(reg.routes("lan")), ROUTE_GW)
        for bad in (-1, 1001, "high", True, 1.5):
            r = await self.put_route(0, tok, "172.20.0.0_16", gws[0].node_id.hex(), prio=bad)
            self.assertEqual(r.status, 400, f"{bad!r}: {r.status}")
        # a gateway that is removed takes only its own routes
        reg.delete_node("lan", gws[0].node_id.hex(), "", "admin")
        self.assertNotIn(gws[0].node_id.hex(), [x["via"] for x in reg.routes("lan")])
        self.assertEqual(len(reg.routes("lan")), ROUTE_GW - 1)

    async def test_routes_of_the_older_shape_still_work_and_are_superseded(self):
        tok = await self.token(0)
        g1, g2 = self.ident(), self.ident()
        await self.put_node(0, tok, g1, "g1")
        await self.put_node(0, tok, g2, "g2")
        reg = self.nodes[0].reg
        reg.s.put("route", "lan/192.168.16.0_24", {"cidr": "192.168.16.0/24", "via": g1.node_id.hex(), "by": "old"})   # one gateway per network, no priority
        self.assertEqual(reg.routes("lan"), [{"cidr": "192.168.16.0/24", "via": g1.node_id.hex(), "by": "old", "prio": 100}])
        self.assertEqual((await self.put_route(0, tok, "192.168.16.0_24", g2.node_id.hex(), prio=200)).status, 200)
        self.assertEqual([(x["via"], x["by"]) for x in reg.routes("lan")], [(g1.node_id.hex(), "old"), (g2.node_id.hex(), "alice")])
        self.assertEqual((await self.put_route(0, tok, "192.168.16.0_24", g1.node_id.hex(), prio=5)).status, 200)    # rewritten in the new shape
        self.assertIsNone(reg.s.get("route", "lan/192.168.16.0_24"))
        self.assertEqual([(x["via"], x["prio"]) for x in reg.routes("lan")], [(g1.node_id.hex(), 5), (g2.node_id.hex(), 200)])
        r = await self.http.delete(f"{self.urls[0]}/v1/c/lan/routes/192.168.16.0_24", headers=self.hdr(tok))
        self.assertEqual(r.status, 200)
        self.assertEqual(reg.routes("lan"), [])

    async def test_cli(self):
        tok = await self.token(0)
        g = self.ident()
        await self.put_node(0, tok, g, "bench-gw")
        reg, gid = self.nodes[0].reg, g.node_id.hex()
        self.assertEqual(oneqrelay.resolve_node(reg, "lan", gid), gid)
        self.assertEqual(oneqrelay.resolve_node(reg, "lan", gid[:8]), gid)
        self.assertEqual(oneqrelay.resolve_node(reg, "lan", "bench-gw"), gid)
        with self.assertRaises(meshdb.RegistryError):
            oneqrelay.resolve_node(reg, "lan", gid[:4])                       # too short to be an id, not a name
        with self.assertRaises(meshdb.RegistryError):
            oneqrelay.resolve_node(reg, "lan", "nobody")
        reg.set_route("lan", "192.168.16.0/24", oneqrelay.resolve_node(reg, "lan", "bench-gw"), "admin-cli", 30)
        self.assertEqual((reg.routes("lan")[0]["by"], reg.routes("lan")[0]["prio"]), ("admin-cli", 30))
        reg.del_route("lan", "192.168.16.0/24", gid)
        self.assertEqual(reg.routes("lan"), [])


if __name__ == "__main__":
    unittest.main()
