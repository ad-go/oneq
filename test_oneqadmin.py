#!/usr/bin/env python3
"""Admin page of oneqrelay: operator login, relay overview, federation peers, communities, users, nodes —
and that changes replicate to the other relays of the federation."""
import pqtls  # noqa: F401

import asyncio
import base64
import logging
import os
import tempfile
import time
import unittest

import aiohttp
from aiohttp import web

import meshdb
import oneqadmin
import oneqnat
import oneqrelay as sn
from test_oneqrelay import Fed, SECRET, eventually, free_port, free_udp_port

logging.getLogger("oneqrelay").setLevel(logging.CRITICAL)
ADMIN_PW = "operator-password-1234"


class AdminFed(Fed):
    """Three relays; relay 0 has the admin page."""
    N = 3

    async def start(self, i, fresh=False):
        db = os.path.join(self.tmp, f"s{i}{'b' if fresh else ''}.db")
        store = meshdb.Store(db, f"s{i + 1}")
        peers = [u for j, u in enumerate(self.urls) if j != i]
        stun = oneqnat.StunServer("127.0.0.1", free_udp_port(), free_udp_port(), free_udp_port()) if i == 0 else None
        node = sn.OneqRelay(store, SECRET, peers, sync_interval=self.SYNC, admin_password=ADMIN_PW if i == 0 else None,
                           info={"listen": f"127.0.0.1:{self.ports[i]}", "tls": False, "db": db}, stun=stun)
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

    async def a(self, method, path, body=None, tok=None, i=0):
        r = await self.http.request(method, self.urls[i] + "/admin/api" + path, json=body,
                                    headers=self.hdr(tok) if tok else None)
        text = await r.text()
        return r.status, (__import__("json").loads(text) if text and r.status == 200 else text)

    async def admin_token(self):
        st, body = await self.a("POST", "/login", {"password": ADMIN_PW})
        self.assertEqual(st, 200, body)
        return body["token"]


class TestAdminAuth(AdminFed):
    async def test_page_is_served_without_secrets_and_api_needs_the_operator_token(self):
        r = await self.http.get(self.urls[0] + "/admin/")
        html = await r.text()
        self.assertEqual(r.status, 200)
        self.assertIn("oneq Relay admin", html)
        self.assertNotIn(ADMIN_PW, html)
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual((await self.http.get(self.urls[0] + "/admin", allow_redirects=False)).status, 302)
        for path in ("/overview", "/c/lan"):
            self.assertEqual((await self.a("GET", path))[0], 401)
        self.assertEqual((await self.a("GET", "/overview", tok="garbage"))[0], 401)
        # a community user's token (even an admin role) is not an operator token
        user_tok = await self.token(0)
        self.assertEqual((await self.a("GET", "/overview", tok=user_tok))[0], 401)
        # relays without a password have no admin page at all
        self.assertEqual((await self.http.get(self.urls[1] + "/admin/")).status, 404)

    async def test_login_wrong_password_lockout_and_expiry(self):
        st, _ = await self.a("POST", "/login", {"password": "wrong-password-xx"})
        self.assertEqual(st, 401)
        self.assertEqual((await self.a("POST", "/login", {}))[0], 400)
        tok = await self.admin_token()
        self.assertEqual((await self.a("GET", "/overview", tok=tok))[0], 200)
        old = oneqadmin.make_admin_token(SECRET, now=time.time() - 7200)
        self.assertEqual((await self.a("GET", "/overview", tok=old))[0], 401)
        self.assertFalse(oneqadmin.check_admin_token(b"another secret", tok))
        # lock-out after repeated failures, even with the right password
        for _ in range(sn.LOGIN_MAX_FAILS):
            await self.a("POST", "/login", {"password": "nope-nope-nope"})
        st, body = await self.a("POST", "/login", {"password": ADMIN_PW})
        self.assertEqual(st, 429, body)


class TestAdminOverview(AdminFed):
    async def test_overview_has_relay_settings_federation_and_counts(self):
        tok = await self.admin_token()
        st, o = await self.a("GET", "/overview", tok=tok)
        self.assertEqual(st, 200)
        self.assertEqual((o["relay"]["id"], o["relay"]["version"], o["relay"]["tls"]), ("s1", sn.VERSION, False))
        self.assertEqual({c["name"] for c in o["communities"]}, {"lan", "other"})
        lan = next(c for c in o["communities"] if c["name"] == "lan")
        self.assertEqual((lan["users"], lan["subnet"]), (2, "10.50.0.0/24"))
        self.assertEqual(len(o["federation"]["peers"]), 2)
        self.assertTrue(all(p["source"] == "config" for p in o["federation"]["peers"]))
        self.assertEqual(len(o["federation"]["secret_fingerprint"]), 12)
        self.assertNotIn("hash", str(o))


class TestAdminNat(AdminFed):
    async def test_overview_and_node_list_show_nat_information(self):
        tok = await self.admin_token()
        bob = await self.token(0, "bob", "bob-password!")
        ident = self.ident()
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.5:40000"], "name": "behind-nat",
                "nat": {"type": "port-restricted", "mapped": "203.0.113.5:40000", "inbound": False}}
        r = await self.http.put(f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(bob))
        self.assertEqual(r.status, 200, await r.text())
        st, o = await self.a("GET", "/overview", tok=tok)
        svc = o["nat"]["service"]
        stun = self.nodes[0].stun
        self.assertEqual((svc["port"], svc["alt_port"], svc["change_port"]), (stun.port, stun.alt_port, stun.change_port))
        self.assertIn("requests", svc["stats"])
        self.assertEqual(o["nat"]["online_nodes_by_nat_type"], {"port-restricted": 1})
        cp = o["nat"]["can_punch"]
        self.assertEqual((cp["symmetric"]["symmetric"], cp["symmetric"]["port-restricted"], cp["port-restricted"]["port-restricted"],
                          cp["symmetric"]["cone"], cp["open"]["symmetric"]), (False, False, True, True, True))
        st, c = await self.a("GET", "/c/lan", tok=tok)
        self.assertEqual(c["nodes"][0]["nat"], {"type": "port-restricted", "mapped": "203.0.113.5:40000", "inbound": False})
        # a relay without the service reports that
        self.nodes[0].stun, saved = None, self.nodes[0].stun
        try:
            st, o = await self.a("GET", "/overview", tok=tok)
            self.assertIsNone(o["nat"]["service"])
        finally:
            self.nodes[0].stun = saved


class TestAdminCommunities(AdminFed):
    async def test_community_lifecycle_replicates_and_validates(self):
        tok = await self.admin_token()
        st, _ = await self.a("POST", "/communities", {"name": "home", "subnet": "10.70.0.0/24", "mtu": 1300, "max_nodes": 10}, tok)
        self.assertEqual(st, 200)
        for bad in ({"name": "home", "subnet": "10.71.0.0/24"},                   # exists
                    {"name": "x y", "subnet": "10.71.0.0/24"},                    # bad name
                    {"name": "big", "subnet": "10.0.0.0/8"},                      # too large
                    {"name": "v6", "subnet": "fd00::/64"},
                    {"name": "junk", "subnet": "not-a-subnet"},
                    {"name": "mtu", "subnet": "10.72.0.0/24", "mtu": "big"},
                    {"name": "mtu2", "subnet": "10.72.0.0/24", "mtu": 5000},
                    {"subnet": "10.72.0.0/24"}):
            self.assertEqual((await self.a("POST", "/communities", bad, tok))[0] // 100, 4, bad)
        # it reaches the other relays
        await eventually(lambda: self.nodes[2].reg.community("home") is not None)
        self.assertEqual(self.nodes[2].reg.community("home")["mtu"], 1300)
        # edit
        self.assertEqual((await self.a("PUT", "/c/home", {"mtu": 1200, "max_nodes": 20}, tok))[0], 200)
        self.assertEqual((await self.a("PUT", "/c/home", {"mtu": 99}, tok))[0], 400)
        self.assertEqual((await self.a("PUT", "/c/nope", {"mtu": 1200}, tok))[0], 404)
        await eventually(lambda: self.nodes[1].reg.community("home")["mtu"] == 1200)
        # delete needs the name as confirmation and removes users and nodes everywhere
        await self.a("POST", "/c/home/users", {"user": "ann", "password": "ann-password!", "role": "user"}, tok)
        ann = await self.token(0, "ann", "ann-password!", "home")
        ident = self.ident()
        self.assertEqual((await self.join(0, ann, ident, comm="home")).status, 200)
        await eventually(lambda: len(self.nodes[1].reg.nodes("home")) == 1)
        self.assertEqual((await self.a("DELETE", "/c/home", tok=tok))[0], 400)
        self.assertEqual((await self.a("DELETE", "/c/home?confirm=lan", tok=tok))[0], 400)
        self.assertEqual((await self.a("DELETE", "/c/home?confirm=home", tok=tok))[0], 200)
        await eventually(lambda: self.nodes[1].reg.community("home") is None and not self.nodes[1].reg.nodes("home")
                         and self.nodes[1].reg.s.get("user", "home/ann") is None)
        self.assertEqual((await self.login(1, "ann", "ann-password!", "home"))[0], 401)
        self.assertEqual((await self.a("GET", "/c/home", tok=tok))[0], 404)


class TestAdminUsersAndNodes(AdminFed):
    async def test_user_management(self):
        tok = await self.admin_token()
        add = lambda **kw: self.a("POST", "/c/lan/users", {"user": "carol", "password": "carol-password", **kw}, tok)  # noqa: E731
        self.assertEqual((await add(role="user", max_nodes=3))[0], 200)
        self.assertEqual((await add())[0], 409)                                          # already exists
        self.assertEqual((await self.a("POST", "/c/lan/users", {"user": "dave", "password": "short"}, tok))[0], 400)
        self.assertEqual((await self.a("POST", "/c/lan/users", {"user": "dave", "password": "dave-password", "role": "root"}, tok))[0], 400)
        self.assertEqual((await self.a("POST", "/c/nope/users", {"user": "dave", "password": "dave-password"}, tok))[0], 404)
        st, c = await self.a("GET", "/c/lan", tok=tok)
        carol = next(u for u in c["users"] if u["user"] == "carol")
        self.assertEqual((carol["role"], carol["max_nodes"], carol["disabled"]), ("user", 3, False))
        self.assertNotIn("hash", str(c))
        # works for logins on every relay
        await eventually(lambda: self.nodes[2].reg.s.get("user", "lan/carol") is not None)
        old_tok = await self.token(2, "carol", "carol-password")
        # password change revokes the sessions everywhere
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"password": "carol-newpass-1"}, tok))[0], 200)
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"password": "x"}, tok))[0], 400)
        await eventually(lambda: self.nodes[2].reg.authenticate(old_tok) is None)
        self.assertEqual((await self.login(2, "carol", "carol-newpass-1"))[0], 200)
        # disable / enable
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"disabled": True}, tok))[0], 200)
        await eventually(lambda: self.nodes[1].reg.s.get("user", "lan/carol")["disabled"])
        self.assertEqual((await self.login(1, "carol", "carol-newpass-1"))[0], 401)
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"disabled": "yes"}, tok))[0], 400)
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"disabled": False, "role": "admin", "max_nodes": 9}, tok))[0], 200)
        carol = next(u for u in (await self.a("GET", "/c/lan", tok=tok))[1]["users"] if u["user"] == "carol")
        self.assertEqual((carol["role"], carol["max_nodes"], carol["disabled"]), ("admin", 9, False))
        self.assertEqual((await self.a("PUT", "/c/lan/users/carol", {"role": "root"}, tok))[0], 400)
        self.assertEqual((await self.a("PUT", "/c/lan/users/ghost", {"disabled": True}, tok))[0], 404)
        # delete
        self.assertEqual((await self.a("DELETE", "/c/lan/users/carol", tok=tok))[0], 200)
        self.assertEqual((await self.a("DELETE", "/c/lan/users/carol", tok=tok))[0], 404)
        await eventually(lambda: self.nodes[1].reg.s.get("user", "lan/carol") is None)

    async def test_nodes_are_listed_with_their_relay_and_can_be_removed(self):
        tok = await self.admin_token()
        bob = await self.token(0, "bob", "bob-password!")
        ident = self.ident()
        self.assertEqual((await self.join(0, bob, ident, name="bobs-laptop")).status, 200)
        st, c = await self.a("GET", "/c/lan", tok=tok)
        n = c["nodes"][0]
        self.assertEqual((n["name"], n["owner"], n["id"]), ("bobs-laptop", "bob", ident.node_id.hex()))
        self.assertNotIn("pub", n)
        self.assertEqual(next(u for u in c["users"] if u["user"] == "bob")["nodes"], 1)
        self.assertEqual((await self.a("DELETE", f"/c/lan/nodes/{ident.node_id.hex()}", tok=tok))[0], 200)
        self.assertEqual((await self.a("DELETE", f"/c/lan/nodes/{ident.node_id.hex()}", tok=tok))[0], 404)
        await eventually(lambda: not self.nodes[2].reg.nodes("lan"))


class TestAdminFederation(AdminFed):
    N = 2

    async def test_a_node_that_offered_can_be_delegated_as_a_relay_from_the_page_and_the_role_replicates(self):
        tok = await self.admin_token()
        user = await self.token(0)
        ident = self.ident()
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.5:5000"], "name": "big-node", "offer": True,
                "nat": {"type": "open", "mapped": "203.0.113.5:5000"}}
        r = await self.http.put(f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(user))
        self.assertEqual(r.status, 200)
        nid = ident.node_id.hex()
        st, c = await self.a("GET", "/c/lan", tok=tok)
        node = [n for n in c["nodes"] if n["id"] == nid][0]
        self.assertTrue(node["offer"])
        self.assertIsNone(node["relay_role"])
        for bad in ({"max_kbps": 5}, {"days": -3}):
            self.assertEqual((await self.a("PUT", f"/c/lan/nodes/{nid}/relay-role", bad, tok))[0], 400, bad)
        st, rec = await self.a("PUT", f"/c/lan/nodes/{nid}/relay-role", {"max_kbps": 8000, "days": 30}, tok)
        self.assertEqual(st, 200, rec)
        st, c = await self.a("GET", "/c/lan", tok=tok)
        self.assertEqual([n for n in c["nodes"] if n["id"] == nid][0]["relay_role"]["max_kbps"], 8000)
        self.assertEqual((await self.a("PUT", f"/c/lan/nodes/{nid}/relay-role", {}, None))[0], 401)

        async def on_third():
            return nid in self.nodes[-1].reg.relay_grants("lan")
        await eventually(on_third)
        self.assertEqual((await self.a("DELETE", f"/c/lan/nodes/{nid}/relay-role", None, tok))[0], 200)
        self.assertEqual((await self.a("DELETE", f"/c/lan/nodes/{nid}/relay-role", None, tok))[0], 404)

    async def test_a_node_that_never_offered_cannot_be_delegated(self):
        tok = await self.admin_token()
        user = await self.token(0)
        ident = self.ident()
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.6:5000"], "name": "shy"}
        await self.http.put(f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(user))
        st, text = await self.a("PUT", f"/c/lan/nodes/{ident.node_id.hex()}/relay-role", {}, tok)
        self.assertEqual(st, 409, text)
        self.assertIn("offered", text)

    async def test_routes_are_managed_from_the_admin_page(self):
        tok = await self.admin_token()
        user = await self.token(0)
        ident = self.ident()
        body = {"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["203.0.113.7:5000"], "name": "gw"}
        await self.http.put(f"{self.urls[0]}/v1/c/lan/nodes/{ident.node_id.hex()}", json=body, headers=self.hdr(user))
        nid = ident.node_id.hex()
        st, c = await self.a("GET", "/c/lan", tok=tok)
        self.assertEqual(c["routes"], [])
        for bad in ("0.0.0.0_0", "nonsense", "10.0.0.0_7"):
            self.assertEqual((await self.a("PUT", f"/c/lan/routes/{bad}", {"via": nid}, tok))[0], 400, bad)
        self.assertEqual((await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": "00" * 16}, tok))[0], 404)
        self.assertEqual((await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": 5}, tok))[0], 400)
        self.assertEqual((await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": nid}, None))[0], 401)
        st, rec = await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": nid}, tok)
        self.assertEqual(st, 200, rec)
        self.assertEqual(rec["cidr"], "192.168.16.0/24")
        st, c = await self.a("GET", "/c/lan", tok=tok)
        self.assertEqual([(r["cidr"], r["via"], r["by"], r["prio"]) for r in c["routes"]], [("192.168.16.0/24", nid, "admin-page", 100)])
        self.assertEqual((await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": nid, "prio": 7}, tok))[0], 200)    # same gateway: priority changes
        self.assertEqual((await self.a("PUT", "/c/lan/routes/192.168.16.0_24", {"via": nid, "prio": -1}, tok))[0], 400)
        st, c = await self.a("GET", "/c/lan", tok=tok)
        self.assertEqual([r["prio"] for r in c["routes"]], [7])

        async def on_third():
            return [r["cidr"] for r in self.nodes[-1].reg.routes("lan")] == ["192.168.16.0/24"]
        await eventually(on_third)
        self.assertEqual((await self.a("DELETE", "/c/lan/routes/192.168.16.0_24?via=" + "00" * 16, None, tok))[0], 404)   # not a gateway of that network
        self.assertEqual((await self.a("DELETE", "/c/lan/routes/192.168.16.0_24?via=" + nid, None, tok))[0], 200)
        self.assertEqual((await self.a("DELETE", "/c/lan/routes/192.168.16.0_24", None, tok))[0], 404)

    async def test_peers_can_be_added_and_removed_at_run_time_and_survive_a_restart(self):
        tok = await self.admin_token()
        extra = free_port()
        # a third relay, started without any peers: it learns everything through the new link
        store = meshdb.Store(os.path.join(self.tmp, "late.db"), "s9")
        late = sn.OneqRelay(store, SECRET, [], sync_interval=self.SYNC)
        late.insecure_fed = True
        runner = web.AppRunner(late.make_app(), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", extra, shutdown_timeout=1).start()
        try:
            url = f"http://127.0.0.1:{extra}"
            self.assertEqual((await self.a("POST", "/federation/peers", {"url": "ftp://x"}, tok))[0], 400)
            self.assertEqual((await self.a("POST", "/federation/peers", {"url": "https://a/b"}, tok))[0], 400)
            self.assertEqual((await self.a("POST", "/federation/peers", {"url": self.urls[1]}, tok))[0], 409)   # already there
            st, fed = await self.a("POST", "/federation/peers", {"url": url}, tok)
            self.assertEqual(st, 200, fed)
            self.assertEqual({p["source"] for p in fed["peers"]}, {"config", "admin page"})
            self.assertEqual(self.nodes[0].store._meta("fed_extra"), f'["{url}"]')
            # replication pulls from the peers: the late relay needs the other direction too (same page, on its side)
            late.add_peer(self.urls[0])
            await eventually(lambda: late.reg.community("lan") is not None, timeout=10)
            self.assertEqual((await self.a("POST", "/federation/sync", {}, tok))[0], 200)
            # config peers cannot be removed from the page, admin ones can
            self.assertEqual((await self.a("DELETE", "/federation/peers?url=" + self.urls[1], tok=tok))[0], 409)
            self.assertEqual((await self.a("DELETE", "/federation/peers?url=http://nowhere", tok=tok))[0], 404)
            st, fed = await self.a("DELETE", "/federation/peers?url=" + url, tok=tok)
            self.assertEqual((st, [p["url"] for p in fed["peers"]]), (200, [self.urls[1]]))
            self.assertNotIn(url, self.nodes[0].peer_tasks)
            self.assertEqual(self.nodes[0].store._meta("fed_extra"), "[]")
            # persistence: a peer added before a restart is configured again after it
            await self.a("POST", "/federation/peers", {"url": url}, tok)
        finally:
            await runner.cleanup()
        again = sn.OneqRelay(self.nodes[0].store, SECRET, [self.urls[1]], admin_password=ADMIN_PW)
        self.assertEqual(again.fed_peers, [self.urls[1], url])
        self.assertEqual(again.extra_peers, [url])


if __name__ == "__main__":
    unittest.main()
