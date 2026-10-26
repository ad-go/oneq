#!/usr/bin/env python3
"""Federated oneqrelay for tunmesh-pq (the rendezvous + relay + registry server).

A community is a virtual L2 network with its own users, a subnet and automatically allocated
IP/MAC addresses. Several oneqrelays form a federation: accounts, node records, addresses and
presence are replicated (meshdb), a node can register on any of them and fail over to another,
and relayed frames are forwarded between oneqrelays.

Client API (TLS 1.3, X25519MLKEM768 only; Bearer = session token from /v1/login)
  POST   /v1/login                      {community,user,password} -> {token,expires_in}
  GET    /v1/c/<comm>                   community parameters
  PUT    /v1/c/<comm>/nodes/<node_id>   {pub,name,endpoints} -> {ip,mac,prefix,mtu,...}   (join/refresh)
  GET    /v1/c/<comm>/nodes             members with address and endpoints
  DELETE /v1/c/<comm>/nodes/<node_id>
  GET    /v1/relay?comm=&node=          WebSocket, frames  dst(16)|datagram -> src(16)|datagram
  GET    /v1/c/<comm>/relays            delegated relay nodes (members that forward datagrams over UDP for the others)
  PUT    /v1/c/<comm>/relays/<node_id>  {max_kbps?,days?,force?}  administrator: delegate a node that offered to relay
  DELETE /v1/c/<comm>/relays/<node_id>  administrator: withdraw the delegation
  GET    /v1/c/<comm>/routes            networks reachable through a gateway member: [{cidr, via, by}] (also in the member list as "routes")
  PUT    /v1/c/<comm>/routes/<a.b.c.d_len>  {via: node_id, prio?}  administrator: announce a network behind a gateway node (e.g. 192.168.16.0_24);
         the same network may have up to 4 gateways (redundancy), lower prio is preferred
  DELETE /v1/c/<comm>/routes/<a.b.c.d_len>[?via=node_id]  administrator: withdraw the route through every gateway, or through one
  GET    /v1/health
Federation API (HMAC-authenticated with the shared federation secret, on top of TLS)
  POST /fed/v1/sync   pull changes since a cursor      POST /fed/v1/poke   "pull from me now"
  GET  /fed/v1/relay  WebSocket between oneqrelays

Trust model: oneqrelays are trusted for *membership* (who may join, which address they get) but
never see traffic: the data plane is end-to-end between nodes, authenticated by their static
keys, and node_id = SHA-256(public key)[:16] means a oneqrelay cannot swap the key of an existing node.
Educational project, not independently audited.
"""
import pqtls  # noqa: F401  (must be first)

import argparse
import asyncio
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import struct
import sys
import time
from typing import Optional

import aiohttp
from aiohttp import WSMsgType, web

import meshdb
import oneqadmin
import oneqconf
import oneqnat
import oneqpop
import oneqtotp
import onequpdate
from rendezvous_server import Bucket, HEX32, valid_endpoint

log = logging.getLogger("oneqrelay")

VERSION = "0.0.1"
MAX_PEERS = 16

PUB_LEN = 1216
MAX_ENDPOINTS = 8
RELAY_MAX_MSG = 2048
RELAY_PPS, RELAY_BPS = 4000.0, 8 * 1024 * 1024
MAX_RELAYS_PER_COMM, MAX_RELAYS = 256, 4096
LOGIN_MAX_FAILS, LOGIN_LOCK = 5, 60.0
SYNC_INTERVAL = 5.0


class LoginGuard:
    """Brute-force protection per source address and per account (lock-out with back-off)."""

    def __init__(self, max_fails=LOGIN_MAX_FAILS, lock=LOGIN_LOCK, clock=time.monotonic):
        self.max, self.lock, self.clock = max_fails, lock, clock
        self.state = {}      # key -> [fails, locked_until, last_lock_len]

    def blocked(self, *keys) -> float:
        now = self.clock()
        return max([self.state[k][1] - now for k in keys if k in self.state] + [0.0])

    def failure(self, *keys):
        now = self.clock()
        if len(self.state) > 20000:
            self.state.clear()
        for k in keys:
            s = self.state.setdefault(k, [0, 0.0, 0.0])
            s[0] += 1
            if s[0] >= self.max:
                s[2] = min(max(s[2] * 2, self.lock), 900.0)      # 60 s, 120 s, ... up to 15 min
                s[1], s[0] = now + s[2], 0

    def success(self, *keys):
        for k in keys:
            self.state.pop(k, None)


def fed_headers(secret: bytes, origin: str, method: str, path: str, body: bytes) -> dict:
    ts = int(time.time())
    return {"X-Fed-Origin": origin, "X-Fed-Ts": str(ts),
            "X-Fed-Sig": meshdb.fed_signature(secret, origin, ts, method, path, hashlib.sha256(body).hexdigest())}


class OneqRelay:
    def __init__(self, store: meshdb.Store, secret: bytes, fed_peers=(), cafile: Optional[str] = None,
                 trust_proxy: bool = False, sync_interval: float = SYNC_INTERVAL,
                 admin_password: Optional[str] = None, info: Optional[dict] = None,
                 stun: Optional["oneqnat.StunServer"] = None, admin_totp: Optional["oneqtotp.TotpStore"] = None,
                 admin_allow=(), require_pop: bool = False,
                 update_check: bool = True, update_url: Optional[str] = None, update_dir: str = "/var/lib/oneq/relay/updates"):
        self.store, self.secret = store, secret
        self.require_pop = require_pop       # every registration must prove possession of the node key (see oneqpop)
        self.pop_key = oneqpop.server_key(secret)
        self.reg = meshdb.Registry(store, secret)
        self.origin = store.origin
        self.config_peers = [p.rstrip("/") for p in fed_peers]
        try:                                 # peers added from the admin page survive restarts (local, not replicated)
            self.extra_peers = [p for p in json.loads(store._meta("fed_extra", "[]")) if isinstance(p, str)]
        except ValueError:
            self.extra_peers = []
        self.fed_peers = list(dict.fromkeys(self.config_peers + self.extra_peers))
        self.peer_tasks = {}             # peer url -> its relay-link task
        self.started_at = time.time()
        self.info = info or {}
        self.cafile, self.trust_proxy, self.sync_interval = cafile, trust_proxy, sync_interval
        self.admin = oneqadmin.AdminUI(self, admin_password, admin_totp, admin_allow) if admin_password else None
        self.stun = stun                     # UDP NAT discovery service (STUN), see oneqnat
        self.nat_test_rate = {}              # (comm, node) -> Bucket
        self.nat_test_loopback = False       # tests only: allow probing 127.0.0.1
        self.guard = LoginGuard()
        self.update_check = update_check     # automatic check for a newer release (the admin page can always check by hand)
        self.update_dir = update_dir
        self.updater = onequpdate.Checker(VERSION, "relay", update_url or None, cafile=None, enabled=update_check)
        self.rate = {}
        self.relays = {}                 # (comm, node_hex) -> (ws, user)
        self.fed_links = {}              # origin -> ws
        self.poke = asyncio.Event()
        self.tasks = []
        self.http: Optional[aiohttp.ClientSession] = None
        self.ssl = pqtls.client_context(cafile) if self.fed_peers else None   # created on the first peer otherwise
        self.sync_ok = {}                # peer url -> last successful sync (monotonic), for health
        self.insecure_fed = False        # tests: peers over plain http

    # ------------------------------------------------------------ helpers
    def client_ip(self, request) -> str:
        """The client's address. With trust_proxy, the proxy in front of the relay appends the address it saw to X-Forwarded-For, so the
        LAST entry is the one to believe; the earlier ones are whatever the client sent. The relay must then be reachable only through
        that proxy (a client that connects directly could write the header itself)."""
        peer = request.remote or "?"
        xff = request.headers.get("X-Forwarded-For") if self.trust_proxy else None
        if not xff:
            return peer
        last = xff.rsplit(",", 1)[-1].strip()
        try:
            return str(ipaddress.ip_address(last))
        except ValueError:
            return peer

    def check_rate(self, request, rps=30.0):
        ip = self.client_ip(request)
        b = self.rate.get(ip)
        if b is None:
            if len(self.rate) > 20000:
                self.rate.clear()
            b = self.rate[ip] = Bucket(rps, rps * 2)
        if not b.take():
            raise web.HTTPTooManyRequests(text="rate limit")

    def claims(self, request, comm: str = None) -> dict:
        auth = request.headers.get("Authorization", "")
        c = self.reg.authenticate(auth[7:].strip()) if auth.startswith("Bearer ") and len(auth) < 2048 else None
        if not c:
            raise web.HTTPUnauthorized(text="invalid or expired token")
        if comm is not None and c["c"] != comm:
            raise web.HTTPForbidden(text="token is for another community")
        return c

    async def json_body(self, request) -> dict:
        try:
            d = json.loads(await request.read())
            if not isinstance(d, dict):
                raise ValueError
            return d
        except ValueError:
            raise web.HTTPBadRequest(text="bad json body")

    def verify_fed(self, request, body: bytes):
        try:
            origin, ts, sig = request.headers["X-Fed-Origin"], int(request.headers["X-Fed-Ts"]), request.headers["X-Fed-Sig"]
        except (KeyError, ValueError):
            raise web.HTTPUnauthorized(text="federation auth required")
        want = meshdb.fed_signature(self.secret, origin, ts, request.method, request.path, hashlib.sha256(body).hexdigest())
        if abs(time.time() - ts) > 60 or not meshdb.NAME_RE.match(origin) or not hmac.compare_digest(sig, want):
            raise web.HTTPUnauthorized(text="bad federation signature")
        return origin

    # ------------------------------------------------------------ client API
    async def h_health(self, request):
        d = {"status": "ok", "origin": self.origin, "peers": len(self.fed_peers), "links": sorted(self.fed_links)}
        if self.stun:
            d["stun"] = {"port": self.stun.port, "alt_port": self.stun.alt_port, "change_port": self.stun.change_port}
        return web.json_response(d)

    async def h_login(self, request):
        self.check_rate(request, 10.0)
        d = await self.json_body(request)
        comm, user, pw = d.get("community"), d.get("user"), d.get("password")
        if not all(isinstance(x, str) for x in (comm, user, pw)) or len(pw) > 256:
            raise web.HTTPBadRequest(text="community, user and password are required")
        ip = self.client_ip(request)
        keys = (("ip", ip), ("acct", comm, user))
        wait = self.guard.blocked(*keys)
        if wait > 0:
            raise web.HTTPTooManyRequests(text=f"too many failures, retry in {int(wait) + 1}s",
                                          headers={"Retry-After": str(int(wait) + 1)})
        tok = await asyncio.get_running_loop().run_in_executor(None, self.reg.login, comm, user, pw)
        if not tok:
            self.guard.failure(*keys)
            log.warning("login failed community=%s user=%s ip=%s", comm[:64], user[:64], ip)
            raise web.HTTPUnauthorized(text="invalid credentials")
        self.guard.success(*keys)
        return web.json_response({"token": tok, "expires_in": meshdb.TOKEN_TTL, "origin": self.origin})

    def comm_info(self, comm: str) -> dict:
        c = self.reg.community(comm)
        if c is None:
            raise web.HTTPNotFound(text="unknown community")
        import ipaddress
        net = ipaddress.ip_network(c["subnet"])
        d = {"name": comm, "subnet": c["subnet"], "prefix": net.prefixlen, "mtu": c["mtu"]}
        if self.stun:
            d["stun"] = {"port": self.stun.port, "alt_port": self.stun.alt_port, "change_port": self.stun.change_port}
        return d

    async def h_comm(self, request):
        self.check_rate(request)
        comm = request.match_info["comm"]
        self.claims(request, comm)
        return web.json_response(self.comm_info(comm))

    async def h_challenge(self, request):
        """A proof-of-possession challenge for a node key (oneqpop): only the holder of the private key can answer it."""
        self.check_rate(request, 5.0)
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        self.claims(request, comm)
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        d = await self.json_body(request)
        try:
            pub = base64.b64decode(d["pub"], validate=True)
            if len(pub) != PUB_LEN or hashlib.sha256(pub).digest()[:16].hex() != nid:
                raise ValueError("node id does not match public key")
            return web.json_response(oneqpop.make_challenge(self.pop_key, pub))
        except (KeyError, TypeError, ValueError):
            raise web.HTTPBadRequest(text="bad public key")

    async def h_put_node(self, request):
        self.check_rate(request)
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        c = self.claims(request, comm)
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        d = await self.json_body(request)
        try:
            pub = base64.b64decode(d["pub"], validate=True)
        except Exception:
            raise web.HTTPBadRequest(text="bad public key")
        eps = d.get("endpoints", [])
        name = d.get("name", "")
        if len(pub) != PUB_LEN or hashlib.sha256(pub).digest()[:16].hex() != nid:
            raise web.HTTPBadRequest(text="node id does not match public key")
        if (not isinstance(eps, list) or len(eps) > MAX_ENDPOINTS or not all(valid_endpoint(e) for e in eps)
                or not isinstance(name, str)):
            raise web.HTTPBadRequest(text="bad endpoints or name")
        pop = d.get("pop")
        verified = pop is not None
        if verified and not oneqpop.verify(self.pop_key, nid, pop):
            raise web.HTTPForbidden(text="bad or expired proof of possession")
        if not verified and self.require_pop:
            raise web.HTTPForbidden(text="proof of possession required")
        info = self.comm_info(comm)
        offer, rl = d.get("offer"), d.get("relays", [])
        if (offer is not None and not isinstance(offer, bool)) or not isinstance(rl, list) or len(rl) > 4 \
                or not all(isinstance(x, str) and HEX32.match(x) for x in rl):
            raise web.HTTPBadRequest(text="bad relay offer or relay list")
        try:
            rec = self.reg.join_node(comm, c["u"], c["r"], bytes.fromhex(nid), d["pub"], name, offer, verified)
        except meshdb.RegistryError as e:
            raise _http_error(e)
        nat = d.get("nat")
        if nat is not None:
            nat = self.valid_nat(nat)
            if nat is None:
                raise web.HTTPBadRequest(text="bad nat description")
        self.reg.set_presence(comm, nid, eps, nat, rl)
        self.reg.fix_ip_conflicts(comm)
        rec = self.store.get("node", f"{comm}/{nid}") or rec
        self.poke_peers()
        out = {"ip": rec["ip"], "mac": rec["mac"], "prefix": info["prefix"], "mtu": info["mtu"],
               "subnet": info["subnet"], "origin": self.origin, "now_ms": int(time.time() * 1000),
               "pop": "required" if self.require_pop else "optional"}
        if "stun" in info:
            out["stun"] = info["stun"]
        g = self.reg.relay_grants(comm).get(nid) if rec.get("offer") else None
        out["relay_role"] = {"max_kbps": g["max_kbps"], "exp": g.get("exp", 0)} if g else None
        return web.json_response(out)

    # ------------------------------------------------------------ delegated relay nodes
    async def h_list_relays(self, request):
        self.check_rate(request)
        comm = request.match_info["comm"]
        self.claims(request, comm)
        return web.json_response({"relays": [{"id": m["id"], "name": m["name"], "ip": m["ip"], "online": m["online"], **m["relay_role"]}
                                             for m in self.reg.members(comm) if m["relay_role"]]})

    async def h_put_relay(self, request):
        self.check_rate(request)
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        c = self.claims(request, comm)
        if c["r"] != "admin":
            raise web.HTTPForbidden(text="administrator only")
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        d = await self.json_body(request)
        try:
            rec = self.reg.grant_relay(comm, nid, c["u"], d.get("max_kbps", meshdb.RELAY_DEFAULT_KBPS), d.get("days", 0),
                                       d.get("force") is True)
        except meshdb.RegistryError as e:
            raise _http_error(e)
        log.info("%s delegated node %s of %s as relay (%s kbit/s)", c["u"], nid[:8], comm, rec["max_kbps"])
        self.poke_peers()
        return web.json_response(rec)

    async def h_del_relay(self, request):
        self.check_rate(request)
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        c = self.claims(request, comm)
        if c["r"] != "admin":
            raise web.HTTPForbidden(text="administrator only")
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        try:
            self.reg.revoke_relay(comm, nid)
        except meshdb.RegistryError as e:
            raise _http_error(e)
        log.info("%s withdrew the relay delegation of node %s of %s", c["u"], nid[:8], comm)
        self.poke_peers()
        return web.json_response({"revoked": nid})

    # ------------------------------------------------------------ routes through a gateway node
    async def h_list_routes(self, request):
        self.check_rate(request)
        comm = request.match_info["comm"]
        self.claims(request, comm)
        return web.json_response({"routes": self.reg.routes(comm)})

    async def h_put_route(self, request):
        self.check_rate(request)
        comm, key = request.match_info["comm"], request.match_info["net"]
        c = self.claims(request, comm)
        if c["r"] != "admin":
            raise web.HTTPForbidden(text="administrator only")
        d = await self.json_body(request)
        via = d.get("via")
        if not isinstance(via, str) or not HEX32.match(via):
            raise web.HTTPBadRequest(text="via must be the node id (32 hex digits) of the gateway")
        try:
            rec = self.reg.set_route(comm, key, via, c["u"], d.get("prio", meshdb.ROUTE_DEFAULT_PRIO))
        except meshdb.RegistryError as e:
            raise _http_error(e)
        log.info("%s routed %s of %s through node %s (priority %s)", c["u"], rec["cidr"], comm, via[:8], rec["prio"])
        self.poke_peers()
        return web.json_response(rec)

    async def h_del_route(self, request):
        self.check_rate(request)
        comm, key = request.match_info["comm"], request.match_info["net"]
        c = self.claims(request, comm)
        if c["r"] != "admin":
            raise web.HTTPForbidden(text="administrator only")
        via = request.query.get("via")
        if via is not None and not HEX32.match(via):
            raise web.HTTPBadRequest(text="via must be the node id of a gateway")
        try:
            self.reg.del_route(comm, key, via)
        except meshdb.RegistryError as e:
            raise _http_error(e)
        log.info("%s withdrew the route %s of %s%s", c["u"], key, comm, f" through {via[:8]}" if via else "")
        self.poke_peers()
        return web.json_response({"removed": key})

    @staticmethod
    def valid_nat(nat) -> Optional[dict]:
        if not isinstance(nat, dict) or nat.get("type") not in oneqnat.NAT_TYPES:
            return None
        mapped = nat.get("mapped")
        if mapped is not None and not (isinstance(mapped, str) and valid_endpoint(mapped)):
            return None
        out = {"type": nat["type"]}
        if mapped:
            out["mapped"] = mapped
        if isinstance(nat.get("inbound"), bool):
            out["inbound"] = nat["inbound"]
        d = nat.get("delta")
        if isinstance(d, int) and not isinstance(d, bool) and 0 < abs(d) <= oneqnat.MAX_DELTA:
            out["delta"] = d                                  # port allocation step of a symmetric NAT
        if isinstance(nat.get("cgnat"), bool) and nat["cgnat"]:
            out["cgnat"] = True                               # a second NAT in front of the node
        if nat.get("via") in ("pcp", "natpmp", "upnp"):
            out["via"] = nat["via"]                           # the open port came from a router mapping
        return out

    async def h_nat_test(self, request):
        """POST {"endpoint": "ip:port"}: the relay sends a STUN Binding request to that address from its alternate UDP port
        (a source the node never talked to) and reports whether it was answered. Only the caller's own public address
        may be tested (operators: any routable address)."""
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        c = self.claims(request, comm)
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        rec = self.store.get("node", f"{comm}/{nid}")
        if not rec or (rec["owner"] != c["u"] and c["r"] != "admin"):
            raise web.HTTPForbidden(text="node is not registered to this account")
        if self.stun is None:
            raise web.HTTPServiceUnavailable(text="this relay has no NAT test service")
        d = await self.json_body(request)
        ip = self.client_ip(request)
        target = oneqnat.probe_target_ok(str(d.get("endpoint", "")), ip, c["r"] == "admin", self.nat_test_loopback)
        if target is None:
            raise web.HTTPBadRequest(text=f"the endpoint must be your own public address (seen as {ip}) as ip:port")
        b = self.nat_test_rate.get((comm, nid))
        if b is None:
            if len(self.nat_test_rate) > 5000:
                self.nat_test_rate.clear()
            b = self.nat_test_rate[(comm, nid)] = Bucket(1 / 5.0, 3)        # one test per 5 s, burst of three
        if not b.take():
            raise web.HTTPTooManyRequests(text="slow down: one NAT test per 5 seconds")
        rtt = await self.stun.probe(target)
        return web.json_response({"endpoint": f"{target[0]}:{target[1]}", "reachable": rtt is not None, "rtt_ms": rtt,
                                  "observed_ip": ip, "probe_from_port": self.stun.change_port})

    async def h_list_nodes(self, request):
        self.check_rate(request)
        comm = request.match_info["comm"]
        self.claims(request, comm)
        return web.json_response({"nodes": self.reg.members(comm), "routes": self.reg.routes(comm), "origin": self.origin})

    async def h_del_node(self, request):
        self.check_rate(request)
        comm, nid = request.match_info["comm"], request.match_info["nid"]
        c = self.claims(request, comm)
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        try:
            self.reg.delete_node(comm, nid, c["u"], c["r"])
        except meshdb.RegistryError as e:
            raise _http_error(e)
        self.poke_peers()
        return web.json_response({"deleted": nid})

    # ------------------------------------------------------------ relay (clients)
    async def h_relay(self, request):
        self.check_rate(request)
        comm, nid = request.query.get("comm", ""), request.query.get("node", "")
        c = self.claims(request, comm)
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        rec = self.store.get("node", f"{comm}/{nid}")
        if not rec or (rec["owner"] != c["u"] and c["r"] != "admin"):
            raise web.HTTPForbidden(text="node is not registered to this account")
        key = (comm, nid)
        if key not in self.relays and (len(self.relays) >= MAX_RELAYS
                                       or sum(1 for k in self.relays if k[0] == comm) >= MAX_RELAYS_PER_COMM):
            raise web.HTTPServiceUnavailable(text="relay full")
        ws = web.WebSocketResponse(max_msg_size=RELAY_MAX_MSG, heartbeat=20.0)
        await ws.prepare(request)
        old = self.relays.get(key)
        self.relays[key] = (ws, c["u"])
        if old and not old[0].closed:
            await old[0].close(code=4000, message=b"replaced")
        self.reg.set_relay_at(comm, nid, True)
        src = bytes.fromhex(nid)
        pps, bps = Bucket(RELAY_PPS, RELAY_PPS), Bucket(RELAY_BPS, RELAY_BPS)
        try:
            async for m in ws:
                if m.type != WSMsgType.BINARY or len(m.data) <= 16:
                    continue
                if not pps.take() or not bps.take(len(m.data)):
                    continue
                await self.route(comm, m.data[:16], src, m.data[16:])
        finally:
            if self.relays.get(key, (None,))[0] is ws:
                del self.relays[key]
                self.reg.set_relay_at(comm, nid, False)
        return ws

    async def route(self, comm: str, dst: bytes, src: bytes, data: bytes):
        """Deliver a datagram to a locally attached node, or forward it to the oneqrelay it is attached to."""
        local = self.relays.get((comm, dst.hex()))
        if local and not local[0].closed:
            try:
                await local[0].send_bytes(src + data)
            except ConnectionError:
                pass
            return
        at = self.reg.relay_at(comm, dst.hex())
        link = self.fed_links.get(at) if at and at != self.origin else None
        if link is not None and not link.closed:
            cb = comm.encode()
            try:
                await link.send_bytes(bytes([len(cb)]) + cb + dst + src + data)
            except ConnectionError:
                pass

    # ------------------------------------------------------------ federation (server side)
    async def h_fed_sync(self, request):
        body = await request.read()
        self.verify_fed(request, body)
        try:
            d = json.loads(body)
            cursor, epoch, limit = int(d["cursor"]), d["epoch"], min(int(d.get("limit", 500)), 500)
        except (ValueError, KeyError, TypeError):
            raise web.HTTPBadRequest(text="bad sync request")
        if epoch != self.store.epoch:
            cursor = 0                       # the requester followed an older incarnation of this store
        recs, last, mx = self.store.changes_since(cursor, limit)
        return web.json_response({"records": recs, "last": last, "max": mx, "epoch": self.store.epoch,
                                  "origin": self.origin})

    async def h_fed_poke(self, request):
        self.verify_fed(request, await request.read())
        self.poke.set()
        return web.json_response({"ok": True})

    async def h_fed_relay(self, request):
        origin = self.verify_fed(request, b"")
        ws = web.WebSocketResponse(max_msg_size=RELAY_MAX_MSG * 2, heartbeat=20.0)
        await ws.prepare(request)
        await self.fed_link(ws, origin_hint=origin)
        return ws

    # ------------------------------------------------------------ federation (client side)
    def poke_peers(self):
        for p in self.fed_peers:
            self.tasks.append(asyncio.ensure_future(self._poke(p)))
        self.tasks = [t for t in self.tasks if not t.done()]

    @staticmethod
    def valid_peer_url(url: str, allow_http: bool = False) -> bool:
        import re
        return bool(re.match(r"^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$", url)
                    or (allow_http and re.match(r"^http://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$", url)))

    def _start_peer(self, peer: str):
        if peer not in self.peer_tasks or self.peer_tasks[peer].done():
            self.peer_tasks[peer] = asyncio.ensure_future(self._fed_relay_client(peer))

    def add_peer(self, url: str):
        """Federation peer added at run time (admin page): persisted locally and started at once."""
        url = url.strip().rstrip("/")
        if not self.valid_peer_url(url, self.insecure_fed):
            raise meshdb.RegistryError("peer must look like https://host[:port]")
        if url in self.fed_peers:
            raise meshdb.RegistryError("peer already configured", 409)
        if len(self.fed_peers) >= MAX_PEERS:
            raise meshdb.RegistryError("too many federation peers", 507)
        if self.ssl is None and not self.insecure_fed:
            self.ssl = pqtls.client_context(self.cafile)
        self.extra_peers.append(url)
        self.fed_peers.append(url)
        self.store._set_meta("fed_extra", json.dumps(self.extra_peers))
        if self.http is not None:
            self._start_peer(url)
            self.poke.set()

    def remove_peer(self, url: str):
        url = url.strip().rstrip("/")
        if url in self.config_peers:
            raise meshdb.RegistryError("this peer comes from the configuration file: edit relay.conf and restart", 409)
        if url not in self.extra_peers:
            raise meshdb.RegistryError("unknown peer", 404)
        self.extra_peers.remove(url)
        self.fed_peers.remove(url)
        self.store._set_meta("fed_extra", json.dumps(self.extra_peers))
        t = self.peer_tasks.pop(url, None)
        if t:
            t.cancel()
        self.sync_ok.pop(url, None)

    async def _fed_request(self, peer: str, path: str, body: dict):
        raw = json.dumps(body).encode()
        h = fed_headers(self.secret, self.origin, "POST", path, raw)
        h["Content-Type"] = "application/json"
        async with self.http.post(peer + path, data=raw, headers=h, ssl=None if self.insecure_fed else self.ssl,
                                  timeout=aiohttp.ClientTimeout(total=15)) as r:
            r.raise_for_status()
            return await r.json()

    async def _poke(self, peer):
        try:
            await self._fed_request(peer, "/fed/v1/poke", {})
        except Exception as e:
            log.debug("poke %s: %s", peer, e)

    async def sync_once(self, peer: str) -> int:
        """Pull everything new from one peer. Returns number of changed records."""
        changed = 0
        ep, cur = self.store.cursor(peer)
        for _ in range(100):
            r = await self._fed_request(peer, "/fed/v1/sync", {"cursor": cur, "epoch": ep, "limit": 500})
            n = await asyncio.get_running_loop().run_in_executor(None, self.store.merge, r["records"])
            changed += n
            cur = r["last"]
            self.store.set_cursor(peer, r["epoch"], cur)
            ep = r["epoch"]
            if not r["records"] or cur >= r["max"]:
                break
        if changed:
            for comm, _ in [(k, 0) for k, _v, _t, _o in self.store.list("comm")]:
                self.reg.fix_ip_conflicts(comm)
        self.sync_ok[peer] = time.monotonic()
        return changed

    async def _sync_loop(self):
        first = True
        while True:
            if not first:                    # first pass is immediate: a fresh oneqrelay must not serve logins unsynced
                try:
                    await asyncio.wait_for(self.poke.wait(), self.sync_interval)
                except asyncio.TimeoutError:
                    pass
            first = False
            self.poke.clear()
            for peer in self.fed_peers:
                try:
                    await self.sync_once(peer)
                except Exception as e:
                    log.warning("sync with %s failed: %s", peer, e)

    async def fed_link(self, ws, origin_hint=None):
        """Both directions of an inter-oneqrelay relay link."""
        await ws.send_str(json.dumps({"hello": self.origin}))
        peer_origin = None
        try:
            async for m in ws:
                if m.type == WSMsgType.TEXT:
                    try:
                        peer_origin = json.loads(m.data)["hello"]
                    except (ValueError, KeyError, TypeError):
                        continue
                    if not meshdb.NAME_RE.match(str(peer_origin)):
                        peer_origin = None
                        continue
                    self.fed_links[peer_origin] = ws
                    log.info("federation relay link with %s", peer_origin)
                elif m.type == WSMsgType.BINARY and peer_origin and len(m.data) > 33:
                    n = m.data[0]
                    comm = m.data[1:1 + n].decode(errors="replace")
                    dst, src, data = m.data[1 + n:17 + n], m.data[17 + n:33 + n], m.data[33 + n:]
                    local = self.relays.get((comm, dst.hex()))
                    if local and not local[0].closed:          # never forwarded a second time: no loops
                        try:
                            await local[0].send_bytes(src + data)
                        except ConnectionError:
                            pass
        finally:
            if peer_origin and self.fed_links.get(peer_origin) is ws:
                del self.fed_links[peer_origin]

    async def _fed_relay_client(self, peer: str):
        backoff = 1.0
        while True:
            try:
                h = fed_headers(self.secret, self.origin, "GET", "/fed/v1/relay", b"")
                async with self.http.ws_connect(peer + "/fed/v1/relay", headers=h, max_msg_size=RELAY_MAX_MSG * 2,
                                                heartbeat=20.0, ssl=None if self.insecure_fed else self.ssl) as ws:
                    backoff = 1.0
                    await self.fed_link(ws)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.debug("fed relay %s: %s", peer, e)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 15.0)

    async def _housekeeping(self):
        while True:
            await asyncio.sleep(30)
            try:
                self.store.gc()
                for (comm, nid) in list(self.relays):
                    self.reg.set_relay_at(comm, nid, True)         # keep the attachment record alive
            except Exception:
                log.exception("housekeeping")

    # ------------------------------------------------------------ app lifecycle
    def make_app(self) -> web.Application:
        app = web.Application(client_max_size=16384)
        app.add_routes([
            web.get("/v1/health", self.h_health),
            web.post("/v1/login", self.h_login),
            web.get("/v1/c/{comm}", self.h_comm),
            web.put("/v1/c/{comm}/nodes/{nid}", self.h_put_node),
            web.get("/v1/c/{comm}/nodes", self.h_list_nodes),
            web.post("/v1/c/{comm}/nodes/{nid}/nat-test", self.h_nat_test),
            web.post("/v1/c/{comm}/nodes/{nid}/challenge", self.h_challenge),
            web.delete("/v1/c/{comm}/nodes/{nid}", self.h_del_node),
            web.get("/v1/relay", self.h_relay),
            web.get("/v1/c/{comm}/relays", self.h_list_relays),
            web.put("/v1/c/{comm}/relays/{nid}", self.h_put_relay),
            web.delete("/v1/c/{comm}/relays/{nid}", self.h_del_relay),
            web.get("/v1/c/{comm}/routes", self.h_list_routes),
            web.put("/v1/c/{comm}/routes/{net}", self.h_put_route),
            web.delete("/v1/c/{comm}/routes/{net}", self.h_del_route),
            web.post("/fed/v1/sync", self.h_fed_sync),
            web.post("/fed/v1/poke", self.h_fed_poke),
            web.get("/fed/v1/relay", self.h_fed_relay),
        ])
        if self.admin:
            app.add_routes(self.admin.routes())
        app.on_startup.append(self._startup)
        app.on_shutdown.append(self._shutdown)      # before aiohttp waits for open websocket handlers
        app.on_cleanup.append(self._cleanup)
        return app

    async def _startup(self, app):
        self.http = aiohttp.ClientSession()
        if self.stun:
            await self.stun.start()
        self.tasks.append(asyncio.ensure_future(self._housekeeping()))
        self.tasks.append(asyncio.ensure_future(self._sync_loop()))        # idle until there is a peer
        if self.update_check:
            self.tasks.append(asyncio.ensure_future(self.updater.loop(log)))
        for p in self.fed_peers:
            self._start_peer(p)

    async def _shutdown(self, app):
        for t in self.tasks + list(self.peer_tasks.values()):
            t.cancel()
        for ws in [w for w, _ in self.relays.values()] + list(self.fed_links.values()):
            try:
                await asyncio.wait_for(ws.close(), 2)
            except Exception:
                pass

    async def _cleanup(self, app):
        for t in self.tasks + list(self.peer_tasks.values()):
            t.cancel()
        if self.stun:
            self.stun.close()
        await self.http.close()


def _http_error(e: meshdb.RegistryError) -> web.HTTPException:
    cls = {400: web.HTTPBadRequest, 403: web.HTTPForbidden, 404: web.HTTPNotFound, 409: web.HTTPConflict,
           413: web.HTTPRequestEntityTooLarge, 507: web.HTTPInsufficientStorage}.get(e.status, web.HTTPBadRequest)
    return cls(text=str(e))


# ---------------------------------------------------------------- CLI

def load_secret(path: str) -> bytes:
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise SystemExit(f"{path}: federation secret must be mode 600")
    with open(path) as f:
        s = base64.b64decode(f.read().strip())
    if len(s) < 24:
        raise SystemExit("federation secret too short (generate with: oneqrelay.py gen-secret)")
    return s


def load_admin_password(path: str) -> str:
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise SystemExit(f"{path}: the admin page password file must be mode 600")
    with open(path) as f:
        pw = f.read().strip()
    if len(pw) < 12:
        raise SystemExit(f"{path}: the admin page password must have at least 12 characters (oneqrelay.py gen-admin-password)")
    return pw


def read_password(args) -> str:
    if getattr(args, "password_file", None):
        with open(args.password_file) as f:
            return f.read().strip()
    if os.environ.get("TUNMESH_PASSWORD"):
        return os.environ["TUNMESH_PASSWORD"]
    p1 = getpass.getpass("password: ")
    if p1 != getpass.getpass("again: "):
        raise SystemExit("passwords differ")
    return p1


def resolve_node(reg, comm: str, ref: str) -> str:
    """A node id, an unambiguous prefix of one (8 hex digits or more) or an exact node name -> the full node id."""
    ids = [(nid, v.get("name", "")) for nid, v, _, _ in reg.nodes(comm)]
    hits = [n for n, name in ids if n == ref.lower()] or [n for n, name in ids if name == ref] \
        or ([n for n, _ in ids if n.startswith(ref.lower())] if len(ref) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", ref) else [])
    if len(hits) != 1:
        raise meshdb.RegistryError("unknown node" if not hits else "ambiguous node: give more of the id", 404 if not hits else 409)
    return hits[0]


def admin(args) -> int:
    reg = meshdb.Registry(meshdb.Store(args.db, args.id), load_secret(args.secret_file))
    try:
        c = args.cmd
        if c == "community-add":
            reg.create_community(args.name, args.subnet, args.mtu, args.max_nodes)
        elif c == "user-add":
            reg.add_user(args.community, args.user, read_password(args), args.role, args.max_nodes)
        elif c == "user-passwd":
            reg.set_password(args.community, args.user, read_password(args))
        elif c == "user-disable":
            reg.set_disabled(args.community, args.user, True)
        elif c == "user-enable":
            reg.set_disabled(args.community, args.user, False)
        elif c == "user-rename":
            n = reg.rename_user(args.community, args.user, args.new_name)
            print(f"{args.user} is now {args.new_name}: {n} node(s) moved (log in again with the new name)")
        elif c == "user-del":
            reg.delete_user(args.community, args.user)
        elif c == "node-del":
            reg.delete_node(args.community, args.node, "", "admin")
        elif c == "relay-grant":
            rec = reg.grant_relay(args.community, args.node, "admin-cli", args.max_kbps, args.days, args.force)
            print(f"node {args.node[:8]} is a delegated relay ({rec['max_kbps']} kbit/s)")
        elif c == "relay-revoke":
            reg.revoke_relay(args.community, args.node)
        elif c == "community-subnet":
            n = reg.change_subnet(args.name, args.subnet)
            print(f"community {args.name} is now {args.subnet}: {n} node(s) re-addressed (restart the nodes so that they take the new address)")
        elif c == "node-ip":
            nid = resolve_node(reg, args.community, args.node)
            rec = reg.set_node_ip(args.community, nid, args.ip)
            print(f"node {nid[:8]} has the address {rec['ip']} (restart the node so that it takes it)")
        elif c == "route-add":
            nid = resolve_node(reg, args.community, args.node)
            rec = reg.set_route(args.community, args.network, nid, "admin-cli", args.prio)
            print(f"{rec['cidr']} is routed through node {nid[:8]} (priority {rec['prio']})")
        elif c == "route-del":
            reg.del_route(args.community, args.network, resolve_node(reg, args.community, args.node) if args.node else None)
        elif c == "list":
            for k, v, _, _ in reg.s.list("comm"):
                print(f"community {k}  {v['subnet']}  mtu {v['mtu']}")
                for uk, uv, _, _ in reg.s.list("user", k + "/"):
                    print(f"  user {uk.split('/', 1)[1]:20} {uv['role']:6} {'DISABLED' if uv['disabled'] else ''}")
                for m in reg.members(k):
                    flag = f" RELAY {m['relay_role']['max_kbps']} kbit/s" if m["relay_role"] else (" offers relay" if m["offer"] else "")
                    print(f"  node {m['id']} {m['ip']:15} {m['mac']}  {m['owner']:12} {'online' if m['online'] else '-'} {m['name']}{flag}")
                for r in reg.routes(k):
                    print(f"  route {r['cidr']:18} via {r['via'][:8]} priority {r['prio']} ({r['by']})")
        return 0
    except meshdb.RegistryError as e:
        print("error:", e, file=sys.stderr)
        return 1


async def serve(args):
    store = meshdb.Store(args.db, args.id)
    info = {"listen": args.listen, "tls": not args.insecure_http, "db": args.db, "cafile": args.cafile or "",
            "trust_proxy": bool(args.trust_proxy), "config_file": getattr(args, "config", None) or ""}
    host, _, port = args.listen.rpartition(":")
    stun = None
    if not args.no_stun:
        sp = args.stun_port or int(port)
        stun = oneqnat.StunServer(host or "0.0.0.0", sp, args.stun_alt_port or sp + 1, args.stun_change_port)
        info["stun"] = f"udp {stun.port}, {stun.alt_port} and {stun.change_port}"
    totp = None
    if args.admin_password_file:
        if args.admin_totp_file:
            totp = oneqtotp.TotpStore(args.admin_totp_file)
            totp.ensure_writable()
        else:
            raise SystemExit("the admin page needs a second factor: create one with `oneqrelay admin-totp --out FILE` and set admin_totp_file")
    sn = OneqRelay(store, load_secret(args.secret_file), args.fed_peer, args.cafile, args.trust_proxy,
                  admin_password=load_admin_password(args.admin_password_file) if args.admin_password_file else None,
                  info=info, stun=stun, admin_totp=totp, admin_allow=args.admin_allow or (), require_pop=bool(args.require_pop),
                  update_check=not args.no_update_check, update_url=args.update_url or None,
                  update_dir=args.update_dir or "/var/lib/oneq/relay/updates")
    ssl_ctx = None
    if not args.insecure_http:
        if not (args.cert and args.key):
            raise SystemExit("--cert and --key are required (or --insecure-http behind a PQ-only reverse proxy)")
        ssl_ctx = pqtls.server_context(args.cert, args.key)
    runner = web.AppRunner(sn.make_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host or "0.0.0.0", int(port), ssl_context=ssl_ctx, shutdown_timeout=5).start()
    log.info("oneqrelay %s listening on %s (%s), federation peers: %s, admin page: %s", args.id, args.listen,
             "TLS1.3 X25519MLKEM768-only" if ssl_ctx else "plain HTTP", sn.fed_peers or "none",
             "/admin/" if sn.admin else "off")
    while True:
        await asyncio.sleep(3600)


RELAY_KEYS = {"id", "db", "secret_file", "listen", "cert", "key", "insecure_http", "trust_proxy",
              "federation_peers", "cafile", "init", "admin_password_file", "stun", "stun_port", "stun_alt_port", "stun_change_port",
              "admin_totp_file", "admin_allow", "require_pop", "update_check", "update_url", "update_dir"}
RELAY_SPEC = {"id": ("id", oneqconf.to_str), "db": ("db", oneqconf.to_str), "secret_file": ("secret_file", oneqconf.to_str),
              "listen": ("listen", oneqconf.to_str), "cert": ("cert", oneqconf.to_str), "key": ("key", oneqconf.to_str),
              "insecure_http": ("insecure_http", oneqconf.to_bool), "trust_proxy": ("trust_proxy", oneqconf.to_bool),
              "fed_peer": ("federation_peers", oneqconf.to_list), "cafile": ("cafile", oneqconf.to_str),
              "admin_password_file": ("admin_password_file", oneqconf.to_str),
              "no_stun": ("stun", lambda v, k: not oneqconf.to_bool(v, k)),
              "stun_port": ("stun_port", lambda v, k: int(v)), "stun_alt_port": ("stun_alt_port", lambda v, k: int(v)),
              "stun_change_port": ("stun_change_port", lambda v, k: int(v)),
              "admin_totp_file": ("admin_totp_file", oneqconf.to_str), "admin_allow": ("admin_allow", oneqconf.to_list),
              "require_pop": ("require_pop", oneqconf.to_bool),
              "no_update_check": ("update_check", lambda v, k: not oneqconf.to_bool(v, k)),
              "update_url": ("update_url", oneqconf.to_str), "update_dir": ("update_dir", oneqconf.to_str)}


def resolve(args, parser, run: bool):
    """Command line > configuration file ([relay] in --config) > built-in default."""
    if args.config:
        try:
            oneqconf.fill(args, oneqconf.load(args.config, ["relay"], RELAY_KEYS),
                         RELAY_SPEC if run else {k: RELAY_SPEC[k] for k in ("id", "db", "secret_file")})
        except oneqconf.ConfigError as e:
            parser.error(str(e))
    args.id = args.id or oneqconf.default_relay_id()
    if not args.db:
        parser.error("the database path is required: --db, or 'db' in the configuration file (--config)")
    if not args.secret_file:
        parser.error("the federation secret is required: --secret-file, or 'secret_file' in the configuration file")
    if run:
        args.listen = args.listen or "0.0.0.0:8443"


def main(argv=None):
    p = argparse.ArgumentParser(prog="oneqrelay")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secret", help="print a new federation secret")
    i = sub.add_parser("init", help="first-time setup in a directory (private CA + relay certificate, secret, admin password and TOTP, relay.conf): "
                                    "for Windows, macOS or any machine without the Debian package")
    i.add_argument("--dir", required=True, help="the directory to create/fill (restricted to the service account)")
    i.add_argument("--name", help="public host name clients use (default: this host's name); it goes into the certificate")
    i.add_argument("--ip", action="append", default=[], help="public/LAN IP address to put into the certificate (repeatable)")
    i.add_argument("--port", type=int, default=8443)
    i.add_argument("--id", default="", help="name of this relay in the federation (default: the short host name)")
    i.add_argument("--no-admin", action="store_true", help="do not enable the admin page")
    t = sub.add_parser("admin-totp", help="create the second factor of the admin page (TOTP for authenticator apps) and show how to enrol it")
    t.add_argument("--out", required=True, metavar="FILE", help="created with mode 600 (refuses to overwrite without --force)")
    t.add_argument("--issuer", default=None, help="name shown in the authenticator app (default: oneqrelay HOST)")
    t.add_argument("--account", default="admin")
    t.add_argument("--force", action="store_true")
    t.add_argument("--save-enrolment", metavar="FILE", help="also write the otpauth link, secret and recovery codes to this file (mode 600) "
                   "instead of relying on the screen; the QR code is printed to the terminal")
    g = sub.add_parser("gen-admin-password", help="write a new random password for the admin page")
    g.add_argument("--out", required=True, metavar="FILE", help="created with mode 600; the password is printed once")
    r = sub.add_parser("run")
    r.add_argument("--config", metavar="FILE", help="configuration file (e.g. /etc/oneq/relay.conf); options given "
                   "on the command line override it")
    r.add_argument("--id", help="stable oneqrelay name, e.g. s1 (default: host name)")
    r.add_argument("--db")
    r.add_argument("--secret-file")
    r.add_argument("--listen", help="default 0.0.0.0:8443")
    r.add_argument("--cert")
    r.add_argument("--key")
    r.add_argument("--insecure-http", action="store_true")
    r.add_argument("--trust-proxy", action="store_true")
    r.add_argument("--fed-peer", action="append", default=[], metavar="URL", help="other oneqrelay, e.g. https://s2:8443")
    r.add_argument("--cafile", help="CA used to verify federation peers")
    r.add_argument("--no-stun", action="store_true", help="do not run the UDP NAT discovery (STUN) service")
    r.add_argument("--stun-port", type=int, help="UDP port of the STUN service (default: the --listen port)")
    r.add_argument("--stun-alt-port", type=int, help="second UDP port, used for the mapping test (default: stun port + 1)")
    r.add_argument("--stun-change-port", type=int, help="third UDP port, source of the filtering test and reachability probes "
                   "(default: alt port + 1)")
    r.add_argument("--admin-totp-file", help="second factor of the admin page: TOTP secret and recovery codes (oneqrelay admin-totp)")
    r.add_argument("--admin-allow", action="append", default=[], metavar="CIDR", help="limit the admin page to these networks (404 for others)")
    r.add_argument("--require-pop", action="store_true", default=None, help="refuse registrations without a proof of possession of the node key "
                   "(older nodes cannot give one); without it a node that registered once with a proof can no longer be updated without one")
    r.add_argument("--no-update-check", action="store_true", help="do not look for a newer release automatically (update_check = no)")
    r.add_argument("--update-url", help="release API URL (default: GitHub releases of ad-go/oneq)")
    r.add_argument("--update-dir", help="where downloaded updates are kept (default /var/lib/oneq/relay/updates)")
    r.add_argument("--admin-password-file", help="enables the admin page at /admin/ (file with the operator password, mode 600)")
    r.add_argument("-v", "--verbose", action="store_true")
    a = sub.add_parser("admin", help="manage communities, users and nodes (works on the same --db as a running server)")
    a.add_argument("--config", metavar="FILE", help="configuration file with db, id and secret_file")
    a.add_argument("--db")
    a.add_argument("--id")
    a.add_argument("--secret-file")
    asub = a.add_subparsers(dest="cmd", required=True)
    x = asub.add_parser("community-add"); x.add_argument("name"); x.add_argument("subnet")
    x.add_argument("--mtu", type=int, default=1380); x.add_argument("--max-nodes", type=int, default=200)
    for name in ("user-add", "user-passwd", "user-disable", "user-enable", "user-del"):
        x = asub.add_parser(name); x.add_argument("community"); x.add_argument("user")
        if name in ("user-add", "user-passwd"):
            x.add_argument("--password-file", help="else $TUNMESH_PASSWORD, else prompt")
        if name == "user-add":
            x.add_argument("--role", choices=("user", "admin"), default="user")
            x.add_argument("--max-nodes", type=int, default=5)
    x = asub.add_parser("user-rename", help="rename an account (password, role and nodes stay; issued tokens are revoked)")
    x.add_argument("community"); x.add_argument("user"); x.add_argument("new_name")
    x = asub.add_parser("node-del"); x.add_argument("community"); x.add_argument("node")
    x = asub.add_parser("relay-grant", help="delegate a node that offered to relay as a relay node of the community")
    x.add_argument("community"); x.add_argument("node")
    x.add_argument("--max-kbps", type=int, default=meshdb.RELAY_DEFAULT_KBPS); x.add_argument("--days", type=int, default=0)
    x.add_argument("--force", action="store_true", help="even if the node is not known to be reachable from outside")
    x = asub.add_parser("relay-revoke"); x.add_argument("community"); x.add_argument("node")
    x = asub.add_parser("community-subnet", help="move a community to another subnet: every node gets a new address (restart the nodes afterwards)")
    x.add_argument("name"); x.add_argument("subnet", help="e.g. 10.10.10.0/24")
    x = asub.add_parser("node-ip", help="give a node a fixed address of the community subnet (restart the node afterwards)")
    x.add_argument("community"); x.add_argument("node", help="node id, a prefix of it (8+ hex digits) or its name"); x.add_argument("ip")
    x = asub.add_parser("route-add", help="announce a network that is reachable through a member node (the gateway forwards IP packets to it)")
    x.add_argument("community"); x.add_argument("network", help="e.g. 192.168.16.0/24"); x.add_argument("node", help="node id, a prefix of it (8+ hex digits) or its name")
    x.add_argument("--prio", type=int, default=meshdb.ROUTE_DEFAULT_PRIO, help="lower is preferred; add the same network through several nodes for redundancy (default 100)")
    x = asub.add_parser("route-del", help="withdraw a route (through every gateway, or only through NODE)"); x.add_argument("community"); x.add_argument("network"); x.add_argument("node", nargs="?")
    asub.add_parser("list")
    args = p.parse_args(argv)
    if args.cmd == "gen-secret":
        print(base64.b64encode(secrets.token_bytes(32)).decode())
        return 0
    if args.cmd == "init":
        import oneqinit
        oneqinit.init(args.dir, args.name or oneqinit.default_name(), args.ip, args.port, args.id, admin=not args.no_admin)
        return 0
    if args.cmd == "admin-totp":
        issuer = args.issuer or f"oneqrelay {oneqconf.default_relay_id()}"
        try:
            secret, codes = oneqtotp.TotpStore.create(args.out, args.force)
        except FileExistsError:
            raise SystemExit(f"{args.out} exists: use --force to replace it (the old authenticator entry stops working)")
        uri = oneqtotp.otpauth_uri(secret, args.account, issuer)
        text = (f"Scan this with the authenticator app (or add it by hand):\n  link:   {uri}\n  secret: {secret}  (time based, 6 digits, 30 s)\n"
                f"Recovery codes, each works once, keep them offline:\n" + "\n".join("  " + c for c in codes) + "\n")
        if args.save_enrolment:
            fd = os.open(args.save_enrolment, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            print(f"written {args.out} (the server side) and {args.save_enrolment} (what to enrol: delete it afterwards)")
        else:
            print(text)
        try:
            import segno
            segno.make(uri, error="m").terminal(compact=True)
        except ImportError:
            print("(no QR code: python module segno is missing; enter the secret by hand)")
        return 0
    if args.cmd == "gen-admin-password":
        pw = secrets.token_urlsafe(18)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw + chr(10))
        print(pw)
        return 0
    if args.cmd == "run":
        resolve(args, p, run=True)
        logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            pass
        return 0
    resolve(args, p, run=False)
    return admin(args)


if __name__ == "__main__":
    sys.exit(main())
