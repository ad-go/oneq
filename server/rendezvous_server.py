#!/usr/bin/env python3
"""Rendezvous + relay server for oneqtunel (HTTPS, TLS 1.3, X25519MLKEM768 only).

  PUT/GET /v1/nodes/<node_id>   register / look up a node (node_id = SHA-256(pubkey)[:16], hex)
  POST    /v1/nodes/<node_id>/challenge   proof-of-possession challenge for the node's key (see oneqpop.py): a node that registers with
                                          a proof can only be updated, and its relay slot only taken, with a proof
  GET     /v1/health            liveness (no auth)
  GET     /v1/relay?node=<id>   WebSocket; binary frames  dest_id(16)|datagram  ->  src_id(16)|datagram

Networks are isolated by Bearer token; only SHA-256(token) is kept. Records expire after 90 s.
The server is NOT trusted for security: it never sees plaintext, and the VPN handshake
authenticates the nodes. A malicious server can only drop, delay or misdirect packets.
Educational project, not independently audited.
"""
import pqtls  # noqa: F401  (must be first: sets OPENSSL_CONF before ssl is loaded)

import argparse
import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import re
import os
import sys
import time

from aiohttp import WSMsgType, web

try:                                    # needs the `cryptography` package; without it the server works as before, without proofs
    import oneqpop
except ImportError:                     # pragma: no cover
    oneqpop = None

log = logging.getLogger("rendezvous")

TTL = 90.0
PUB_LEN = 1216
MAX_BODY = 8192
MAX_ENDPOINTS = 8
MAX_NODES_PER_NET = 64
MAX_NETS = 1024
MAX_RELAYS_PER_NET = 64
RELAY_MAX_MSG = 2048          # 16-byte id + datagram (handshake fragments <= 1200, data <= MTU + 25)
RELAY_PPS = 2000.0
RELAY_BPS = 4 * 1024 * 1024
REST_RPS = 30.0
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Bucket:
    def __init__(self, rate: float, burst: float):
        self.rate, self.burst, self.tokens, self.t = rate, burst, burst, time.monotonic()

    def take(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class Net:
    def __init__(self):
        self.nodes = {}     # id -> dict(pub, endpoints, observed, expires)
        self.relays = {}    # id -> WebSocketResponse


class State:
    def __init__(self, allowed=None, open_=False, trust_proxy=False, require_pop=False):
        self.require_pop = require_pop
        self.pop_key = os.urandom(32)       # challenges are only valid for this process (a restart just means asking again)
        self.allowed = set(allowed or [])
        self.open = open_
        self.trust_proxy = trust_proxy
        self.nets = {}
        self.rate = {}      # remote ip -> Bucket
        self.relay_total = 0

    def net_for(self, request, create=False):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth) > 300:
            raise web.HTTPUnauthorized(text="missing bearer token")
        key = token_hash(auth[7:].strip())
        if not self.open and key not in self.allowed:
            raise web.HTTPUnauthorized(text="unknown token")
        net = self.nets.get(key)
        if net is None:
            if not create:
                return None
            if len(self.nets) >= MAX_NETS:
                raise web.HTTPServiceUnavailable(text="too many networks")
            net = self.nets[key] = Net()
        return net

    def client_ip(self, request):
        if self.trust_proxy:
            xff = request.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return request.remote or "?"

    def check_rate(self, request):
        ip = self.client_ip(request)
        b = self.rate.get(ip)
        if b is None:
            if len(self.rate) > 10000:
                self.rate.clear()
            b = self.rate[ip] = Bucket(REST_RPS, REST_RPS * 2)
        if not b.take():
            raise web.HTTPTooManyRequests(text="rate limit")

    def gc(self):
        now = time.time()
        for net in self.nets.values():
            for k in [k for k, v in net.nodes.items() if v["expires"] <= now]:
                del net.nodes[k]
        for k in [k for k, n in self.nets.items() if not n.nodes and not n.relays]:
            del self.nets[k]


def valid_endpoint(e) -> bool:
    if not isinstance(e, str) or len(e) > 64:
        return False
    host, _, port = e.rpartition(":")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 0 < int(port) < 65536
    except ValueError:
        return False


def make_app(state: State) -> web.Application:
    routes = web.RouteTableDef()

    @routes.get("/v1/health")
    async def health(request):
        return web.json_response({"status": "ok"})

    @routes.put(r"/v1/nodes/{nid}")
    async def put_node(request):
        state.check_rate(request)
        nid = request.match_info["nid"]
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        state.gc()                      # before net_for(): gc drops empty networks
        net = state.net_for(request, create=True)
        try:
            body = json.loads(await request.read())
            pub = base64.b64decode(body["pub"], validate=True)
            eps = body.get("endpoints", [])
        except (ValueError, KeyError, TypeError, binascii.Error):
            raise web.HTTPBadRequest(text="bad body")
        if len(pub) != PUB_LEN or hashlib.sha256(pub).digest()[:16].hex() != nid:
            raise web.HTTPBadRequest(text="node id does not match public key")
        if not isinstance(eps, list) or len(eps) > MAX_ENDPOINTS or not all(valid_endpoint(e) for e in eps):
            raise web.HTTPBadRequest(text="bad endpoints")
        if nid not in net.nodes and len(net.nodes) >= MAX_NODES_PER_NET:
            raise web.HTTPServiceUnavailable(text="network full")
        pop = body.get("pop")
        verified = pop is not None
        if verified and not (oneqpop and oneqpop.verify(state.pop_key, nid, pop)):
            raise web.HTTPForbidden(text="bad or expired proof of possession")
        cur = net.nodes.get(nid)
        if not verified and (state.require_pop or (cur and cur["expires"] > time.time() and cur.get("pop"))):
            raise web.HTTPForbidden(text="proof of possession required")
        net.nodes[nid] = {"pub": body["pub"], "endpoints": eps, "observed": state.client_ip(request),
                          "expires": time.time() + TTL, "pop": verified}
        return web.json_response({"node_id": nid, "ttl": int(TTL), "observed": state.client_ip(request)})

    @routes.post(r"/v1/nodes/{nid}/challenge")
    async def challenge(request):
        state.check_rate(request)
        nid = request.match_info["nid"]
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        if oneqpop is None:
            raise web.HTTPNotFound(text="proofs of possession are not available on this server")
        state.net_for(request)                      # authentication only
        try:
            pub = base64.b64decode(json.loads(await request.read())["pub"], validate=True)
            if len(pub) != PUB_LEN or hashlib.sha256(pub).digest()[:16].hex() != nid:
                raise ValueError("node id does not match public key")
            return web.json_response(oneqpop.make_challenge(state.pop_key, pub))
        except (ValueError, KeyError, TypeError, binascii.Error):
            raise web.HTTPBadRequest(text="bad public key")

    @routes.get(r"/v1/nodes/{nid}")
    async def get_node(request):
        state.check_rate(request)
        nid = request.match_info["nid"]
        if not HEX32.match(nid):
            raise web.HTTPBadRequest(text="bad node id")
        net = state.net_for(request)
        rec = net.nodes.get(nid) if net else None
        if rec is None or rec["expires"] <= time.time():
            raise web.HTTPNotFound(text="unknown node")
        return web.json_response({"node_id": nid, "pub": rec["pub"], "endpoints": rec["endpoints"],
                                  "observed": rec["observed"], "expires_in": int(rec["expires"] - time.time())})

    @routes.get("/v1/relay")
    async def relay(request):
        state.check_rate(request)
        me = request.query.get("node", "")
        if not HEX32.match(me):
            raise web.HTTPBadRequest(text="bad node id")
        net = state.net_for(request, create=True)
        rec = net.nodes.get(me)
        if state.require_pop or (rec and rec["expires"] > time.time() and rec.get("pop")):
            # the relay slot of a node that proved possession of its key is not for anybody else (X-Oneq-Pop: base64 of the JSON proof)
            try:
                pop = json.loads(base64.b64decode(request.headers.get("X-Oneq-Pop", ""), validate=True))
            except (ValueError, binascii.Error):
                pop = None
            if not (pop is not None and oneqpop and oneqpop.verify(state.pop_key, me, pop)):
                raise web.HTTPForbidden(text="proof of possession required")
        if me not in net.relays and len(net.relays) >= MAX_RELAYS_PER_NET:
            raise web.HTTPServiceUnavailable(text="relay full")
        if state.relay_total >= 4096:
            raise web.HTTPServiceUnavailable(text="relay full")
        ws = web.WebSocketResponse(max_msg_size=RELAY_MAX_MSG, heartbeat=20.0)
        await ws.prepare(request)
        old = net.relays.get(me)
        net.relays[me] = ws
        state.relay_total += 1
        if old is not None and not old.closed:
            await old.close(code=4000, message=b"replaced")
        src = bytes.fromhex(me)
        pps, bps = Bucket(RELAY_PPS, RELAY_PPS), Bucket(RELAY_BPS, RELAY_BPS)
        try:
            async for m in ws:
                if m.type != WSMsgType.BINARY or len(m.data) <= 16:
                    continue
                if not pps.take() or not bps.take(len(m.data)):
                    continue                                    # over limit: drop the datagram
                dst = net.relays.get(m.data[:16].hex())
                if dst is None or dst is ws or dst.closed:
                    continue
                try:
                    await dst.send_bytes(src + m.data[16:])
                except ConnectionError:
                    pass
        finally:
            state.relay_total -= 1
            if net.relays.get(me) is ws:
                del net.relays[me]
        return ws

    app = web.Application(client_max_size=MAX_BODY)
    app.add_routes(routes)
    app["state"] = state
    return app


def load_allowed(path):
    with open(path) as f:
        return {ln.split()[0].lower() for ln in f if ln.strip() and not ln.startswith("#")}


async def serve(args):
    state = State(allowed=load_allowed(args.tokens_file) if args.tokens_file else None,
                  open_=args.open, trust_proxy=args.trust_proxy, require_pop=bool(args.require_pop))
    if not state.allowed and not state.open:
        raise SystemExit("no allowed tokens: use --tokens-file (SHA-256 hex per line) or --open")
    ssl_ctx = None
    if not args.insecure_http:
        if not (args.cert and args.key):
            raise SystemExit("--cert and --key are required (or --insecure-http behind a PQ-only reverse proxy)")
        ssl_ctx = pqtls.server_context(args.cert, args.key)
    runner = web.AppRunner(make_app(state), access_log=None)
    await runner.setup()
    host, _, port = args.listen.rpartition(":")
    site = web.TCPSite(runner, host or "0.0.0.0", int(port), ssl_context=ssl_ctx)
    await site.start()
    log.info("listening on %s (%s)", args.listen, "TLS1.3 X25519MLKEM768-only" if ssl_ctx else "plain HTTP")
    while True:
        await asyncio.sleep(3600)


def main(argv=None):
    p = argparse.ArgumentParser(prog="rendezvous_server")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash-token", help="print SHA-256 of a token read from stdin")
    r = sub.add_parser("run")
    r.add_argument("--listen", default="0.0.0.0:8443")
    r.add_argument("--cert")
    r.add_argument("--key")
    r.add_argument("--tokens-file", help="file with SHA-256(token) hex values, one per line")
    r.add_argument("--open", action="store_true", help="accept any token (testing only)")
    r.add_argument("--insecure-http", action="store_true", help="plain HTTP, only behind a reverse proxy")
    r.add_argument("--trust-proxy", action="store_true", help="use X-Forwarded-For for rate limits")
    r.add_argument("--require-pop", action="store_true", help="refuse registrations and relay attachments without a proof of possession of the node key "
                   "(older nodes cannot give one)")
    r.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "hash-token":
        print(token_hash(sys.stdin.readline().strip()))
        return 0
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(a))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
