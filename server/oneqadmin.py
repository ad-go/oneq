"""Admin page of a oneqrelay: relay settings, federation peers, communities, users and nodes.

Enabled only when the oneqrelay is started with an operator password file (`admin_password_file` in relay.conf).
It is served by the relay itself, on its TLS port:

  GET  /admin/                         the page (no secrets in it)
  POST /admin/api/login                {password} -> {token, expires_in}   (rate limited, locked out after repeated failures)
  everything below needs `Authorization: Bearer <admin token>` (the token lives in the page's memory, never in a cookie,
  so other sites cannot make the browser send it):
  GET  /admin/api/overview             relay settings, federation status, communities with counts
  GET  /admin/api/c/<comm>             users and nodes of a community
  POST /admin/api/communities          {name, subnet, mtu, max_nodes}
  PUT  /admin/api/c/<comm>             {mtu?, max_nodes?}
  DELETE /admin/api/c/<comm>?confirm=<comm>
  POST /admin/api/c/<comm>/users       {user, password, role, max_nodes}
  PUT  /admin/api/c/<comm>/users/<u>   {password?, disabled?, role?, max_nodes?}
  DELETE /admin/api/c/<comm>/users/<u>
  DELETE /admin/api/c/<comm>/nodes/<id>
  POST /admin/api/federation/peers     {url}          DELETE /admin/api/federation/peers?url=
  POST /admin/api/federation/sync      pull from all peers now
  GET  /admin/api/update[?force=1]     newer release available? (cached 6 h; force = manual check, at most once a minute)
  POST /admin/api/update/download      download the offered file into update_dir and verify its SHA-256 (nothing is installed)

Changes go through the same replicated registry as everything else, so they reach every oneqrelay of the federation.
Every change is written to the log with the client address. Educational project, not independently audited.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import sys
import time

from aiohttp import web

import meshdb
import oneqnat
from rendezvous_server import Bucket

log = logging.getLogger("oneqrelay")

ADMIN_TOKEN_TTL = 3600
HERE = os.path.dirname(os.path.abspath(__file__))


def make_admin_token(secret: bytes, ttl: int = ADMIN_TOKEN_TTL, now=None) -> str:
    payload = json.dumps({"a": 1, "e": int((now or time.time()) + ttl)}, separators=(",", ":")).encode()
    return "a1." + meshdb.b64u(payload) + "." + meshdb.b64u(hmac.new(secret, b"admintoken" + payload, hashlib.sha256).digest())


def check_admin_token(secret: bytes, token: str, now=None) -> bool:
    try:
        v, p, s = token.split(".")
        payload = meshdb.unb64u(p)
        if v != "a1" or not hmac.compare_digest(meshdb.unb64u(s), hmac.new(secret, b"admintoken" + payload, hashlib.sha256).digest()):
            return False
        d = json.loads(payload)
        return d.get("a") == 1 and d["e"] > (now or time.time())
    except (ValueError, KeyError, TypeError):
        return False


class AdminUI:
    def __init__(self, relay, password: str, totp=None, allow=()):
        """`totp`: a oneqtotp.TotpStore (second factor at login) or None; `allow`: CIDR networks the page is limited to
        (empty = everybody). Clients outside the list get a plain 404, as if the page did not exist. With a `totp` store every
        login needs the code, from every network."""
        self.relay = relay
        self._pw = hashlib.sha256(password.encode()).digest()
        self.totp = totp
        self.allow = [ipaddress.ip_network(a, strict=False) for a in allow]
        self._page = None
        self.buckets = {}      # own rate limits: the relay's per-address bucket is shared with the client API

    def routes(self):
        a = "/admin/api"
        return [
            web.get("/admin", self.h_redirect),
            web.get("/admin/", self.h_page),
            web.post(a + "/login", self.h_login),
            web.get(a + "/info", self.h_info),
            web.get(a + "/overview", self.api(self.h_overview)),
            web.get(a + "/c/{comm}", self.api(self.h_comm)),
            web.put(a + "/c/{comm}/routes/{net}", self.api(self.h_route_set)),
            web.delete(a + "/c/{comm}/routes/{net}", self.api(self.h_route_del)),
            web.post(a + "/communities", self.api(self.h_comm_add)),
            web.put(a + "/c/{comm}", self.api(self.h_comm_edit)),
            web.delete(a + "/c/{comm}", self.api(self.h_comm_del)),
            web.post(a + "/c/{comm}/users", self.api(self.h_user_add)),
            web.put(a + "/c/{comm}/users/{user}", self.api(self.h_user_edit)),
            web.delete(a + "/c/{comm}/users/{user}", self.api(self.h_user_del)),
            web.get(a + "/c/{comm}/users/{user}/settings", self.api(self.h_user_settings)),
            web.delete(a + "/c/{comm}/nodes/{nid}", self.api(self.h_node_del)),
            web.put(a + "/c/{comm}/nodes/{nid}/relay-role", self.api(self.h_relay_grant)),
            web.delete(a + "/c/{comm}/nodes/{nid}/relay-role", self.api(self.h_relay_revoke)),
            web.put(a + "/c/{comm}/nodes/{nid}/exit-node", self.api(self.h_exit_node_set)),
            web.delete(a + "/c/{comm}/nodes/{nid}/exit-node", self.api(self.h_exit_node_del)),
            web.post(a + "/federation/peers", self.api(self.h_peer_add)),
            web.delete(a + "/federation/peers", self.api(self.h_peer_del)),
            web.post(a + "/federation/sync", self.api(self.h_sync)),
            web.get(a + "/update", self.api(self.h_update)),
            web.post(a + "/update/download", self.api(self.h_update_download)),
        ]

    # ------------------------------------------------------------ plumbing
    def limit(self, request, rps: float):
        ip = self.relay.client_ip(request)
        b = self.buckets.get((ip, rps))
        if b is None:
            if len(self.buckets) > 5000:
                self.buckets.clear()
            b = self.buckets[(ip, rps)] = Bucket(rps, rps * 2)
        if not b.take():
            raise web.HTTPTooManyRequests(text="rate limit")

    def permit(self, request):
        if not self.allow:
            return
        try:
            ip = ipaddress.ip_address(self.relay.client_ip(request))
        except ValueError:
            raise web.HTTPNotFound()
        if not any(ip in n for n in self.allow):
            raise web.HTTPNotFound()

    def api(self, fn):
        async def wrapped(request):
            self.permit(request)
            self.limit(request, 30.0)
            auth = request.headers.get("Authorization", "")
            if not (auth.startswith("Bearer ") and len(auth) < 512 and check_admin_token(self.relay.secret, auth[7:].strip())):
                raise web.HTTPUnauthorized(text="admin login required")
            try:
                r = await fn(request)
            except meshdb.RegistryError as e:
                raise _err(e)
            if request.method != "GET":
                log.info("admin %s %s from %s", request.method, request.path_qs[:200], self.relay.client_ip(request))
            return r
        return wrapped

    async def body(self, request) -> dict:
        return await self.relay.json_body(request)

    def noted(self, comm: str):
        self.relay.poke_peers()

    # ------------------------------------------------------------ page and login
    async def h_redirect(self, request):
        raise web.HTTPFound("/admin/")

    def needs_code(self, request) -> bool:
        """Does this client have to give the authenticator code? Always, whenever a second factor is configured."""
        return self.totp is not None

    async def h_info(self, request):
        """Public: tells the login form whether to ask for an authenticator code."""
        self.permit(request)
        return web.json_response({"two_factor": self.needs_code(request)})

    async def h_page(self, request):
        self.permit(request)
        if self._page is None:
            with open(os.path.join(HERE, "oneqadmin.html"), "rb") as f:
                self._page = f.read()
        return web.Response(body=self._page, content_type="text/html", charset="utf-8", headers={
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})

    async def h_login(self, request):
        relay = self.relay
        self.permit(request)
        self.limit(request, 5.0)
        d = await self.body(request)
        pw = d.get("password")
        if not isinstance(pw, str) or len(pw) > 256:
            raise web.HTTPBadRequest(text="password required")
        keys = (("admin-ip", relay.client_ip(request)), ("admin",))
        wait = relay.guard.blocked(*keys)
        if wait > 0:
            raise web.HTTPTooManyRequests(text=f"too many failures, retry in {int(wait) + 1}s", headers={"Retry-After": str(int(wait) + 1)})
        code = d.get("code", "")
        if not isinstance(code, str) or len(code) > 64:
            raise web.HTTPBadRequest(text="bad code")
        ok = hmac.compare_digest(hashlib.sha256(pw.encode()).digest(), self._pw)
        need_code = self.needs_code(request)
        if ok and need_code:                         # the code is only spent when the password was right
            ok = await asyncio.get_running_loop().run_in_executor(None, self.totp.check, code)
        if not ok:
            relay.guard.failure(*keys)
            log.warning("admin login failed from %s", relay.client_ip(request))
            # one message for both factors: nobody learns which one was right
            raise web.HTTPUnauthorized(text="wrong password or authentication code" if need_code else "wrong password")
        relay.guard.success(*keys)
        log.info("admin login from %s", relay.client_ip(request))
        return web.json_response({"token": make_admin_token(relay.secret), "expires_in": ADMIN_TOKEN_TTL})

    # ------------------------------------------------------------ overview
    def federation(self) -> dict:
        r = self.relay
        now = time.monotonic()
        peers = []
        for p in r.fed_peers:
            ok = r.sync_ok.get(p)
            peers.append({"url": p, "source": "config" if p in r.config_peers else "admin page",
                          "synced_ago_s": None if ok is None else round(now - ok, 1)})
        return {"origin": r.origin, "peers": peers, "links": sorted(r.fed_links),
                "secret_fingerprint": hashlib.sha256(b"fp" + r.secret).hexdigest()[:12],
                "sync_interval_s": r.sync_interval}

    async def h_overview(self, request):
        r = self.relay
        comms = []
        nat_mix = {}
        tot = {"communities": 0, "users": 0, "nodes": 0, "online": 0}
        for name, c, _, _ in r.store.list("comm"):
            members = r.reg.members(name)
            users = r.reg.users(name)
            comms.append({"name": name, "subnet": c["subnet"], "mtu": c["mtu"], "max_nodes": c["max_nodes"],
                          "users": len(users), "nodes": len(members), "online": sum(1 for m in members if m["online"])})
            for m in members:
                if m["online"]:
                    t = (m.get("nat") or {}).get("type", "not measured")
                    nat_mix[t] = nat_mix.get(t, 0) + 1
            tot["communities"] += 1
            tot["users"] += len(users)
            tot["nodes"] += len(members)
            tot["online"] += comms[-1]["online"]
        _n = sys.modules[type(r).__module__]           # oneqrelay, also when it runs as __main__
        return web.json_response({
            "relay": {"id": r.origin, "version": _n.VERSION, "uptime_s": int(time.time() - r.started_at),
                      "attached_nodes": len(r.relays), **{k: v for k, v in r.info.items()},
                      "limits": {"login_failures_before_lockout": _n.LOGIN_MAX_FAILS, "lockout_s": _n.LOGIN_LOCK,
                                 "relay_pps": _n.RELAY_PPS, "relay_bytes_per_s": _n.RELAY_BPS,
                                 "max_relays_per_community": _n.MAX_RELAYS_PER_COMM, "max_relays": _n.MAX_RELAYS,
                                 "max_endpoints_per_node": _n.MAX_ENDPOINTS, "token_ttl_s": meshdb.TOKEN_TTL,
                                 "presence_ttl_s": meshdb.PRESENCE_TTL_MS // 1000}},
            "federation": self.federation(), "totals": tot, "communities": comms,
            "nat": {"service": None if r.stun is None else {"host": r.stun.host, "port": r.stun.port, "alt_port": r.stun.alt_port,
                                                           "change_port": r.stun.change_port, "stats": dict(r.stun.stats)},
                    "online_nodes_by_nat_type": nat_mix,
                    "can_punch": {a: {b: oneqnat.can_punch(a, b) for b in ("open", "cone", "port-restricted", "symmetric")}
                                  for a in ("open", "cone", "port-restricted", "symmetric")}}})

    # ------------------------------------------------------------ communities
    async def h_comm(self, request):
        comm = request.match_info["comm"]
        c = self.relay.reg.community(comm)
        if c is None:
            raise web.HTTPNotFound(text="unknown community")
        nodes = []
        for m in self.relay.reg.members(comm):
            m = dict(m)
            m.pop("pub", None)
            m["relay"] = self.relay.reg.relay_at(comm, m["id"])
            nodes.append(m)
        return web.json_response({"name": comm, **c, "users": self.relay.reg.users(comm), "nodes": nodes, "routes": self.relay.reg.routes(comm)})

    async def h_route_set(self, request):
        comm, net = request.match_info["comm"], request.match_info["net"]
        d = await self.body(request)
        via = d.get("via")
        if not isinstance(via, str) or not meshdb.NAME_RE.match(via):
            raise web.HTTPBadRequest(text="via must be the node id of the gateway")
        rec = self.relay.reg.set_route(comm, net, via, "admin-page", d.get("prio", meshdb.ROUTE_DEFAULT_PRIO))
        self.noted(comm)
        return web.json_response(rec)

    async def h_route_del(self, request):
        via = request.query.get("via")
        if via is not None and not meshdb.NAME_RE.match(via):
            raise web.HTTPBadRequest(text="bad gateway node id")
        self.relay.reg.del_route(request.match_info["comm"], request.match_info["net"], via)
        self.noted(request.match_info["comm"])
        return web.json_response({"ok": True})

    async def h_comm_add(self, request):
        d = await self.body(request)
        name, subnet = d.get("name"), d.get("subnet")
        if not isinstance(name, str) or not isinstance(subnet, str):
            raise web.HTTPBadRequest(text="name and subnet are required")
        if self.relay.reg.community(name) is not None:
            raise web.HTTPConflict(text="community already exists")
        mtu, mx = d.get("mtu", 1380), d.get("max_nodes", 200)
        if any(isinstance(v, bool) or not isinstance(v, int) for v in (mtu, mx)) or not 1 <= mx <= 100000:
            raise web.HTTPBadRequest(text="mtu and max_nodes must be numbers (max_nodes 1-100000)")
        try:
            self.relay.reg.create_community(name, subnet, mtu, mx)
        except ValueError as e:
            raise web.HTTPBadRequest(text=f"bad subnet: {e}")
        self.noted(name)
        return web.json_response({"ok": True})

    async def h_comm_edit(self, request):
        d = await self.body(request)
        self.relay.reg.update_community(request.match_info["comm"], d.get("mtu"), d.get("max_nodes"))
        self.noted(request.match_info["comm"])
        return web.json_response({"ok": True})

    async def h_comm_del(self, request):
        comm = request.match_info["comm"]
        if request.query.get("confirm") != comm:
            raise web.HTTPBadRequest(text="confirm=<community name> is required")
        self.relay.reg.delete_community(comm)
        self.noted(comm)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------ users and nodes
    async def h_user_add(self, request):
        comm = request.match_info["comm"]
        d = await self.body(request)
        user, pw = d.get("user"), d.get("password")
        if not isinstance(user, str) or not isinstance(pw, str):
            raise web.HTTPBadRequest(text="user and password are required")
        if self.relay.reg.s.get("user", f"{comm}/{user}") is not None:
            raise web.HTTPConflict(text="user already exists (use the edit button to change it)")
        mx = d.get("max_nodes", 5)
        if isinstance(mx, bool) or not isinstance(mx, int) or not 0 <= mx <= 10000:
            raise web.HTTPBadRequest(text="bad max_nodes (0-10000)")
        await asyncio.get_running_loop().run_in_executor(None, self.relay.reg.add_user, comm, user, pw, d.get("role", "user"), mx)
        self.noted(comm)
        return web.json_response({"ok": True})

    async def h_user_edit(self, request):
        comm, user = request.match_info["comm"], request.match_info["user"]
        d = await self.body(request)
        reg = self.relay.reg
        if reg.s.get("user", f"{comm}/{user}") is None:
            raise web.HTTPNotFound(text="unknown user")
        if "role" in d or "max_nodes" in d:
            reg.update_user(comm, user, d.get("role"), d.get("max_nodes"))
        if isinstance(d.get("password"), str):
            await asyncio.get_running_loop().run_in_executor(None, reg.set_password, comm, user, d["password"])
        if "disabled" in d:
            if not isinstance(d["disabled"], bool):
                raise web.HTTPBadRequest(text="disabled must be true or false")
            reg.set_disabled(comm, user, d["disabled"])
        self.noted(comm)
        return web.json_response({"ok": True})

    async def h_user_del(self, request):
        comm, user = request.match_info["comm"], request.match_info["user"]
        if self.relay.reg.s.get("user", f"{comm}/{user}") is None:
            raise web.HTTPNotFound(text="unknown user")
        self.relay.reg.delete_user(comm, user)
        self.noted(comm)
        return web.json_response({"ok": True})

    async def h_user_settings(self, request):
        r = self.relay
        comm, user = request.match_info["comm"], request.match_info["user"]
        if r.reg.s.get("user", f"{comm}/{user}") is None:
            raise web.HTTPNotFound(text="unknown user")
        relays = list(dict.fromkeys([r.origin] + list(r.fed_peers)))
        ca_pem = ""
        if r.cafile:
            try:
                with open(r.cafile) as f:
                    ca_pem = f.read().strip()
            except OSError:
                pass
        routes = r.reg.routes(comm)
        settings = {"format": "oneq-settings", "version": 1, "settings": {
            "relays": relays, "community": comm, "user": user, "name": "",
            "ca_pem": ca_pem, "force_relay": False, "auto_start": True,
            "start_hidden": False, "accept_routes": bool(routes),
        }}
        filename = f"oneq-settings-{comm}-{user}.json"
        body = json.dumps(settings, indent=2).encode()
        return web.Response(body=body, content_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    async def h_node_del(self, request):
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        if not meshdb.NAME_RE.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        self.relay.reg.delete_node(comm, nid, "", "admin")
        self.noted(comm)
        return web.json_response({"ok": True})

    async def h_relay_grant(self, request):
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        if not meshdb.NAME_RE.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        d = await self.body(request)
        rec = self.relay.reg.grant_relay(comm, nid, "admin-page", d.get("max_kbps", meshdb.RELAY_DEFAULT_KBPS), d.get("days", 0), d.get("force") is True)
        self.noted(comm)
        return web.json_response(rec)

    async def h_relay_revoke(self, request):
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        if not meshdb.NAME_RE.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        self.relay.reg.revoke_relay(comm, nid)
        self.noted(comm)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------ exit nodes
    async def h_exit_node_set(self, request):
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        if not meshdb.NAME_RE.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        try:
            self.relay.reg.set_exit_node(comm, nid, True, "admin-page")
        except meshdb.RegistryError as e:
            raise web.HTTPBadRequest(text=str(e))
        self.noted(comm)
        return web.json_response({"ok": True})

    async def h_exit_node_del(self, request):
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        if not meshdb.NAME_RE.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        try:
            self.relay.reg.set_exit_node(comm, nid, False, "admin-page")
        except meshdb.RegistryError as e:
            raise web.HTTPBadRequest(text=str(e))
        self.noted(comm)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------ federation
    async def h_peer_add(self, request):
        d = await self.body(request)
        if not isinstance(d.get("url"), str):
            raise web.HTTPBadRequest(text="url is required")
        self.relay.add_peer(d["url"])
        return web.json_response(self.federation())

    async def h_peer_del(self, request):
        self.relay.remove_peer(request.query.get("url", ""))
        return web.json_response(self.federation())

    # ------------------------------------------------------------ update check
    async def h_update(self, request):
        r = self.relay
        res = dict(await r.updater.aget(force=request.query.get("force") == "1"))
        res["automatic"] = bool(r.update_check)
        return web.json_response(res)

    async def h_update_download(self, request):
        r = self.relay
        if r.updater.result is None:
            await r.updater.aget()
        res = await r.updater.adownload(r.update_dir)
        if res.get("ok"):
            log.info("update downloaded and verified: %s (%s bytes)", res["path"], res["size"])
        return web.json_response(res)

    async def h_sync(self, request):
        self.relay.poke.set()
        self.relay.poke_peers()
        return web.json_response({"ok": True})


def _err(e: meshdb.RegistryError) -> web.HTTPException:
    cls = {400: web.HTTPBadRequest, 403: web.HTTPForbidden, 404: web.HTTPNotFound, 409: web.HTTPConflict,
           413: web.HTTPRequestEntityTooLarge, 507: web.HTTPInsufficientStorage}.get(e.status, web.HTTPBadRequest)
    return cls(text=str(e))
