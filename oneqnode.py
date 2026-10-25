#!/usr/bin/env python3
"""oneqnode: layer-2 mesh node over a TAP interface with a post-quantum hybrid handshake.

A oneqnode logs in to a oneqrelay (user + password), registers its public key and receives an IP
address and MAC address for the community. It then learns the other members from the registry and
opens an end-to-end session (tunmesh-pq/v2: X25519 + ML-KEM-768) with each of them, directly over UDP
(with hole punching) or, when that fails, through the oneqrelay over wss. Ethernet frames are switched
between sessions: broadcast/multicast and unknown unicast are flooded, known MACs go to one peer.
The data plane keeps working when every oneqrelay is down; only discovery needs them.

Educational project, not independently audited.
"""
import pqtls  # noqa: F401  (must be first: sets OPENSSL_CONF before ssl is loaded)

import argparse
import asyncio
import base64
import collections
import dataclasses
import fcntl
import hashlib
import ipaddress
import logging
import math
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
from typing import Optional
from urllib.parse import urlsplit

import aiohttp

import meshproto as mp
import oneqconf
import oneqnat
import oneqpop
import oneqportmap
import oneqtunel as v1
from oneqtunel import HandshakeError, Identity, Reassembler, fragment, node_id, parse_hostport

log = logging.getLogger("oneqnode")

IFF_TAP, IFF_NO_PI, TUNSETIFF = 0x0002, 0x1000, 0x400454CA
REKEY_AFTER, KEEPALIVE, HS_RETRY, PROBE_EVERY, DIRECT_STALE = (v1.REKEY_AFTER, v1.KEEPALIVE, v1.HS_RETRY,
                                                                 v1.PROBE_EVERY, v1.DIRECT_STALE)
MAC_AGE = 300.0

# Delegated relay nodes (members an administrator allowed to forward datagrams for the others, over UDP)
RLY_ALIVE = 40.0               # a relay node counts as reachable while we heard from it this recently (keepalives every 25 s)
RLY_BAD_FOR = 30               # seconds to avoid a relay node that said it cannot deliver to a peer
RLY_MAX_DGRAM = 1600           # largest datagram a relay node forwards
RLY_PROBE_EVERY = 10.0         # round-trip probe to each delegated relay node

# Synchronised hole punching. Two nodes behind port-restricted NATs only open a direct path when both send their first
# packet to the other's public address at (nearly) the same time: a packet that reaches a NAT before that NAT's own
# outgoing packet leaves creates connection-tracking state that moves the next mapping to another port (seen with Linux
# netfilter, i.e. most routers), and repeating it keeps that state alive. So, between two nodes where a NAT filters,
# nobody sends unsolicited packets except in "punch rounds": bursts at the same instants of the relay's clock (every
# PUNCH_PERIOD seconds, in cycles of PUNCH_CYCLE rounds with attempts only in the first PUNCH_ATTEMPTS, so that the
# state of a failed attempt expires - conntrack keeps unanswered UDP entries for 30 s - before the next one).
PUNCH_PERIOD = 4.0
PUNCH_CYCLE = 10
PUNCH_ATTEMPTS = 3
PUNCH_OFFSETS = (0.0, 0.08, 0.2, 0.45)
HOLE_TTL = 4.0                 # after a packet from the peer's address, direct sends to that address are allowed this long
FILTERING = ("port-restricted", "symmetric")
BROADCAST = b"\xff" * 6


class Tap:
    def __init__(self, name: str):
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        res = fcntl.ioctl(self.fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI))
        self.name = res[:16].split(b"\0")[0].decode()

    def fileno(self):
        return self.fd

    def read(self) -> bytes:
        return os.read(self.fd, 65535)

    def write(self, frame: bytes):
        os.write(self.fd, frame)


def configure_tap(name: str, mac: str, ip: str, prefix: int, mtu: int):
    ip_ = ["ip"]
    subprocess.run(ip_ + ["addr", "flush", "dev", name], check=True)
    subprocess.run(ip_ + ["link", "set", "dev", name, "down"], check=True)
    subprocess.run(ip_ + ["link", "set", "dev", name, "address", mac], check=True)
    subprocess.run(ip_ + ["link", "set", "dev", name, "mtu", str(mtu)], check=True)
    subprocess.run(ip_ + ["addr", "add", f"{ip}/{prefix}", "dev", name], check=True)
    subprocess.run(ip_ + ["link", "set", "dev", name, "up"], check=True)


def normalize_addr(addr) -> tuple:
    """A datagram source from a dual-stack socket as (ip, port): IPv4 as itself (not ::ffff:a.b.c.d), IPv6 without scope and flow info."""
    h = addr[0]
    if ":" in h:
        h = h.split("%")[0]
        if h.lower().startswith("::ffff:") and "." in h:
            h = h[7:]
    return (h, addr[1])


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


@dataclasses.dataclass
class NodeConfig:
    relays: list = dataclasses.field(default_factory=list)
    community: str = ""
    user: str = ""
    password: str = ""
    name: str = ""
    ifname: str = "oneq0"
    listen: tuple = ("0.0.0.0", 0)
    via: Optional[str] = None
    advertise: list = dataclasses.field(default_factory=list)
    stun: Optional[str] = None
    cafile: Optional[str] = None
    force_relay: bool = False
    no_relay: bool = False
    relay_after: float = 10.0
    no_config: bool = False
    max_skew: float = 180.0
    refresh_fast: float = 3.0
    refresh_slow: float = 5.0           # member list refresh once everyone known has a session
    register_every: float = 20.0
    relay_always: bool = True           # stay attached to a relay, so peers can always reach us through it
    relay_offer: bool = False           # offer to forward datagrams for the other members; effective once an administrator delegates this node
    use_delegates: bool = True          # send through the delegated relay nodes of the community when a peer cannot be reached directly
    nat_discovery: bool = True          # measure the NAT with the relay STUN service and publish the result
    nat_refresh: float = 300.0          # full re-classification interval
    nat_keepalive: float = 25.0         # mapped-address check interval (also keeps the NAT mapping alive)
    port_mapping: bool = True           # ask the router (PCP, NAT-PMP, UPnP) to forward our UDP port
    ipv6: bool = True                   # dual-stack data socket: publish and try IPv6 addresses


def _ssl_for(url: str, ctx):
    return ctx if url.startswith("https://") else None


class LoginRefused(PermissionError):
    """401 from /v1/login. With several oneqrelays this is not final: a freshly started one may not have
    replicated the accounts yet, so the other oneqrelays are asked before giving up."""


class Control:
    """Talks to the oneqrelays: login, join/refresh, member list. Fails over between several URLs."""

    def __init__(self, urls, community, user, password, cafile=None):
        if not urls:
            raise ValueError("at least one oneqrelay URL is required")
        self.urls = [u.rstrip("/") for u in urls]
        self.i = 0
        self.comm, self.user, self.password = community, user, password
        self.ctx = pqtls.client_context(cafile)
        self.token = None
        self.http: Optional[aiohttp.ClientSession] = None
        self.info = None
        self.clock_offset: Optional[float] = None       # relay clock minus local clock, seconds
        self.clock_rtt = 9.9
        self.prover: Optional["oneqpop.Prover"] = None  # proves possession of the node key at registration (set by the node)
        self.pop_unsupported = set()                    # relays that answered 404 to the challenge request (older than this feature)

    @property
    def base(self) -> str:
        return self.urls[self.i]

    def rotate(self):
        self.i = (self.i + 1) % len(self.urls)
        self.token = None
        log.info("switching to oneqrelay %s", self.base)

    def ws_base(self) -> str:
        return self.base.replace("https://", "wss://", 1).replace("http://", "ws://", 1)

    def _http(self):
        if self.http is None:
            self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self.http

    async def login(self):
        async with self._http().post(self.base + "/v1/login", ssl=_ssl_for(self.base, self.ctx),
                                     json={"community": self.comm, "user": self.user, "password": self.password}) as r:
            if r.status == 401:
                raise LoginRefused("login refused: wrong community, user or password")
            r.raise_for_status()
            self.token = (await r.json())["token"]

    async def _call(self, method, path, **kw):
        """One request with automatic re-login and failover to the next oneqrelay."""
        last, refused = None, 0
        for attempt in range(len(self.urls) * 2 + 2):
            try:
                if not self.token:
                    try:
                        await self.login()
                    except LoginRefused:
                        refused += 1
                        if refused >= len(self.urls):
                            raise
                        log.info("oneqrelay %s refused the login, trying another", self.base)
                        self.rotate()
                        continue
                    refused = 0
                async with self._http().request(method, self.base + path, ssl=_ssl_for(self.base, self.ctx),
                                                headers={"Authorization": "Bearer " + self.token}, **kw) as r:
                    if r.status == 401:
                        self.token = None
                        continue
                    if r.status == 429 or r.status >= 500:
                        raise aiohttp.ClientError(f"HTTP {r.status}")
                    if r.status >= 400:
                        raise PermissionError(f"HTTP {r.status}: {(await r.text())[:200]}")
                    return await r.json()
            except PermissionError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last = e
                log.warning("oneqrelay %s: %s", self.base, e)
                self.rotate()
                await asyncio.sleep(0.2)
        raise ConnectionError(f"no oneqrelay reachable: {last}")

    async def join(self, nid_hex: str, pub: bytes, endpoints: list, name: str, nat: Optional[dict] = None,
                   offer: bool = False, relays: Optional[list] = None):
        body = {"pub": base64.b64encode(pub).decode(), "endpoints": endpoints, "name": name, "offer": bool(offer)}
        if nat:
            body["nat"] = nat
        if relays:
            body["relays"] = relays
        t0 = time.time()
        pop = await self._pop(nid_hex, pub)
        if pop:
            body["pop"] = pop
        try:
            d = await self._call("PUT", f"/v1/c/{self.comm}/nodes/{nid_hex}", json=body)
        except PermissionError as e:
            msg = str(e)
            if self.prover is None or "proof of possession" not in msg:
                raise
            # the relay wants a proof (required, or this id was registered with one) or ours expired: ask for a fresh challenge and retry once
            self.prover.drop()
            self.pop_unsupported.discard(self.base)
            pop = await self._pop(nid_hex, pub)
            if not pop:
                raise
            body["pop"] = pop
            d = await self._call("PUT", f"/v1/c/{self.comm}/nodes/{nid_hex}", json=body)
        t1 = time.time()
        if isinstance(d.get("now_ms"), int) and t1 - t0 < 1.0 and (t1 - t0 <= self.clock_rtt * 1.5 + 0.005 or self.clock_offset is None):
            self.clock_offset = d["now_ms"] / 1000.0 - (t0 + t1) / 2      # the error is at most half the round trip
            self.clock_rtt = min(self.clock_rtt, t1 - t0)
        self.info = d
        return d

    async def _pop(self, nid_hex: str, pub: bytes) -> Optional[dict]:
        """A proof of possession of the node key for the registration, or None (no key here, or a relay that does not know the feature)."""
        if self.prover is None or self.base in self.pop_unsupported:
            return None
        cached = self.prover.fresh()
        if cached is not None:
            return cached
        try:
            ch = await self._call("POST", f"/v1/c/{self.comm}/nodes/{nid_hex}/challenge", json={"pub": base64.b64encode(pub).decode()})
            return self.prover.store(ch)
        except PermissionError as e:
            if "HTTP 404" in str(e) or "HTTP 405" in str(e):
                self.pop_unsupported.add(self.base)
                return None
            raise
        except ValueError as e:
            log.warning("proof of possession: %s", e)
            return None

    async def nat_test(self, nid_hex: str, endpoint: str) -> Optional[dict]:
        """Ask the relay to probe `endpoint` from a fresh UDP port. None if this relay has no such service."""
        try:
            return await self._call("POST", f"/v1/c/{self.comm}/nodes/{nid_hex}/nat-test", json={"endpoint": endpoint})
        except PermissionError as e:
            log.debug("nat-test: %s", e)
            return None

    async def members(self):
        return (await self._call("GET", f"/v1/c/{self.comm}/nodes"))["nodes"]

    async def close(self):
        if self.http:
            await self.http.close()


class RelayLink:
    """The wss connection to the current oneqrelay (opened lazily, only when some peer needs it)."""

    def __init__(self, control: Control, my_id_hex: str, on_msg):
        self.c, self.my_id, self.on_msg = control, my_id_hex, on_msg
        self.q = asyncio.Queue(maxsize=512)
        self.enabled = asyncio.Event()
        self.ready = asyncio.Event()       # set once the node is registered: the relay only accepts registered nodes
        self.connected = False

    def send(self, dest_id: bytes, data: bytes):
        try:
            self.q.put_nowait(dest_id + data)
        except asyncio.QueueFull:
            pass

    async def run(self):
        backoff = 1.0
        while True:
            await self.enabled.wait()
            await self.ready.wait()
            try:
                if not self.c.token:
                    await self.c.login()
                url = f"{self.c.ws_base()}/v1/relay?comm={self.c.comm}&node={self.my_id}"
                async with aiohttp.ClientSession() as s:
                    async with s.ws_connect(url, ssl=_ssl_for(self.c.base, self.c.ctx), max_msg_size=8192,
                                            headers={"Authorization": "Bearer " + self.c.token}) as ws:
                        log.info("relay connected (%s)", self.c.base)
                        self.connected, backoff = True, 1.0
                        pump = asyncio.ensure_future(self._pump(ws))
                        try:
                            async for m in ws:
                                if m.type == aiohttp.WSMsgType.BINARY and len(m.data) > 16:
                                    self.on_msg(m.data[:16], m.data[16:])
                        finally:
                            pump.cancel()
            except asyncio.CancelledError:
                raise
            except aiohttp.WSServerHandshakeError as e:
                log.warning("relay link: %s", e)
                if e.status == 401:
                    self.c.token = None                      # expired token: log in again, stay on this oneqrelay
                elif e.status != 403:                        # 403: not registered on this oneqrelay yet, just retry
                    self.c.rotate()
            except Exception as e:
                log.warning("relay link: %s", e)
                self.c.rotate()
            self.connected = False
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 15.0)

    async def _pump(self, ws):
        while True:
            await ws.send_bytes(await self.q.get())


class Peer:
    def __init__(self, nid: bytes, pub: bytes, ip: str, mac: str):
        self.id, self.pub, self.ip, self.mac = nid, pub, ip, mac
        self.macb = mac_bytes(mac)
        self.initiator = False
        self.cur: Optional[mp.MSession] = None
        self.prev: Optional[mp.MSession] = None
        self.pending = collections.deque()
        self.candidates = []
        self.peer_addr = None
        self.path = "direct"
        self.last_direct_rx = 0.0
        self.last_tx = 0.0
        self.last_probe = 0.0
        self.last_punch = 0.0
        self.last_init = 0.0
        self.last_ts = 0
        self.t_nosession: Optional[float] = time.monotonic()
        self.relay_hs = False            # no direct session for relay_after seconds: handshake through the relay too
        self.force_hs = False            # the peer told us (PUNCH) that it has no session: re-handshake now
        self.last_rehs = 0.0
        self.name = ""
        self.nat = None                  # NAT type the peer published (oneqnat.NAT_TYPES) or None
        self.nat_mapped = None           # "ip:port" the peer measured (the IP also counts for a symmetric NAT)
        self.nat_delta = None            # port step of the peer's symmetric NAT (predictable allocation) or None
        self.nat_cgnat = False           # the peer is behind a second NAT
        self.predicted = []              # (ip, port) the peer's symmetric NAT will probably use for the next mappings
        self.hole_addr = None            # address a packet of this peer just came from: our NAT lets it in, we may send to it
        self.hole_until = 0.0
        self.attached = frozenset()      # delegated relay nodes this peer says it holds a session with (from its registry entry)
        self.rly_via = None              # delegated relay node used for the last packet sent through a relay (None: the oneqrelay)

    @property
    def hexid(self):
        return self.id.hex()


class OneqNode:
    def __init__(self, ident: Identity, cfg: NodeConfig, tap, control: Optional[Control] = None):
        self.me, self.cfg, self.tap = ident, cfg, tap
        self.control = control or Control(cfg.relays, cfg.community, cfg.user, cfg.password, cfg.cafile)
        self.control.prover = oneqpop.Prover(ident)
        self.peers = {}                  # node_id -> Peer
        self.rly_nodes = {}              # node_id -> {"max_kbps"}: the delegated relay nodes of the community (from the registry)
        self.rly_role = None             # {"max_kbps"} when the registry delegates THIS node (and relay_offer is set)
        self.rly_rtt = {}                # relay node id -> smoothed round trip, seconds
        self.rly_probe_sent = {}
        self.rly_probe_open = {}
        self.rly_bad = {}                # (relay node id, destination id) -> until: the relay node said it cannot deliver
        self.rly_nack_t = {}
        self.rly_total = (0.0, 0.0)      # token bucket of the delegation: (tokens, time)
        self.rly_senders = {}
        self.rly_stats = {"packets": 0, "bytes": 0, "dropped": 0}
        self.last_attached = []
        self.by_idx = {}                 # local index -> Peer (sessions and pending INITs)
        self.mac_owner = {}              # registered MAC -> node_id (anti-spoofing)
        self.mac_table = {}              # learned MAC -> (node_id, last_seen)
        self.reasm = Reassembler()
        self.udp = None
        self.relay: Optional[RelayLink] = None
        self.my_ip = self.my_mac = None
        self.mtu = 1380
        self.local_candidates = list(cfg.advertise)
        self.stun_tx = self.stun_result = None
        self.nat = oneqnat.NatInfo()     # what is published: the measured NAT, or "open" through a verified router mapping
        self.nat_raw = oneqnat.NatInfo() # what the STUN measurements said
        self.portmapper = None
        self.mapping = None              # oneqportmap.Mapping held on the router
        self.router_ip = None            # the router's own WAN address, when it told us
        self.cgnat = False
        self.mapping_ok = False          # the relay reached us at the mapped address from a port we never used
        self.dual_stack = False
        self.v6_endpoint = None          # "[addr]:port" when this host has a global IPv6 address
        self.nat_inbound = None          # True/False once the relay probed our public address from a fresh port
        self.prober = oneqnat.NatProber(self._udp_send)
        self._stun_answers = (0, 0.0)
        self.init_budget, self.init_budget_t = 10.0, time.monotonic()
        self.tasks = []
        self.on_session = None            # test hook
        self.last_members = 0.0
        self.last_register = 0.0

    # ------------------------------------------------------------ indexes and sessions
    def new_idx(self) -> int:
        while True:
            i = secrets.randbits(32)
            if i and i not in self.by_idx:
                return i

    def _forget(self, s):
        if s is not None:
            self.by_idx.pop(s.local_idx, None)

    def _install(self, p: Peer, s: mp.MSession, via):
        self._forget(p.prev)
        p.prev, p.cur = p.cur, s
        self.by_idx[s.local_idx] = p
        self._note_path(p, via)
        log.info("session with %s (%s) established (%s), path=%s", p.ip, p.hexid[:8],
                 "initiator" if s.initiator else "responder", p.path)
        if self.on_session:
            self.on_session(self, p)

    def _note_path(self, p: Peer, via):
        now = time.monotonic()
        before = p.path
        if via[0] == "udp":
            p.peer_addr, p.last_direct_rx, p.path = via[1], now, "direct"
            p.hole_addr, p.hole_until = via[1], now + HOLE_TTL
        elif now - p.last_direct_rx > DIRECT_STALE:
            p.path = "relay"
        if p.path != before and p.cur is not None:
            log.info("path to %s: %s -> %s%s", p.ip, before, p.path, f" ({p.peer_addr[0]}:{p.peer_addr[1]})" if p.path == "direct" else "")

    # ------------------------------------------------------------ sending
    def _udp_send(self, data, addr):
        if self.udp is not None:
            if self.dual_stack and ":" not in addr[0]:
                addr = ("::ffff:" + addr[0], addr[1])           # an IPv4 destination on an IPv6 socket
            try:
                self.udp.sendto(data, addr)
            except (OSError, ValueError) as e:
                log.debug("udp send to %s: %s", addr, e)

    def _send_hs(self, p: Peer, msg: bytes, via):
        for d in fragment(msg):
            if via[0] == "udp":
                self._udp_send(d, via[1])
            else:
                self._relay_send(p, d)

    def _send_raw(self, p: Peer, pkt: bytes):
        p.last_tx = time.monotonic()
        if p.path == "relay" or self.cfg.force_relay:
            self._relay_send(p, pkt)
        elif p.peer_addr:
            self._udp_send(pkt, p.peer_addr)
        else:
            for c in self._direct_targets(p, p.last_tx):
                self._udp_send(pkt, c)

    # ------------------------------------------------------------ delegated relay nodes (see ARCHITECTURE.md, "Delegated relay nodes")
    def _rly_usable(self, r: Peer, now: float) -> bool:
        """A delegated relay node we can talk to over UDP right now: a live session and a direct path that is recent (keepalives every 25 s)."""
        return (r.cur is not None and r.cur.usable() and r.path == "direct" and r.peer_addr is not None
                and now - r.last_direct_rx < RLY_ALIVE)

    def _pick_rly(self, p: Peer) -> Optional[Peer]:
        """The best delegated relay node for datagrams to `p`: one that both of us hold a session with, lowest round trip first."""
        if not self.cfg.use_delegates or self.cfg.no_relay or not self.rly_nodes:
            return None
        now = time.monotonic()
        best = None
        for rid in self.rly_nodes:
            if rid == p.id or rid not in p.attached:
                continue
            r = self.peers.get(rid)
            if r is None or not self._rly_usable(r, now) or self.rly_bad.get((rid, p.id), 0.0) > now:
                continue
            k = (self.rly_rtt.get(rid, 9.9), rid)
            if best is None or k < best[0]:
                best = (k, r)
        return best[1] if best else None

    def _send_rly(self, r: Peer, op: int, body: bytes) -> bool:
        s = r.cur
        if s is None or not s.usable() or r.peer_addr is None or r.path != "direct":
            return False
        try:
            self._udp_send(s.encrypt(bytes([op]) + body, mp.M_RLY), r.peer_addr)
        except HandshakeError:
            return False
        r.last_tx = time.monotonic()
        return True

    def _relay_send(self, p: Peer, data: bytes):
        """Datagram for `p` through a relay: a delegated relay node over UDP when one is available, else the oneqrelay (WebSocket)."""
        r = self._pick_rly(p)
        if r is not None and self._send_rly(r, mp.RLY_FWD, p.id + data):
            if p.rly_via != r.id:
                p.rly_via = r.id
                log.info("traffic to %s goes through the relay node %s", p.ip, r.ip)
            return
        if p.rly_via is not None:
            p.rly_via = None
            log.info("traffic to %s goes through the oneqrelay", p.ip)
        if self.relay is not None:
            self.relay.send(p.id, data)

    def _rly_budget(self, sender: bytes, n: int) -> bool:
        """Token buckets of the delegation (total and per sender, bytes per second from the cap in the registry)."""
        now = time.monotonic()
        rate = max(1, self.rly_role["max_kbps"]) * 125.0
        def take(b, r):
            tokens, t = b
            tokens = min(r * 0.5 + 1500, tokens + (now - t) * r)
            if tokens < n:
                return (tokens, now), False
            return (tokens - n, now), True
        tot, ok1 = take(self.rly_total, rate)
        snd, ok2 = take(self.rly_senders.get(sender, (rate * 0.25, now)), rate * 0.5)
        if ok1 and ok2:
            self.rly_total, self.rly_senders[sender] = tot, snd
            if len(self.rly_senders) > 512:
                for k in [k for k, (_, t) in self.rly_senders.items() if now - t > 60]:
                    del self.rly_senders[k]
            return True
        return False

    def _on_rly(self, data: bytes, addr):
        idx = mp.data_receiver_index(data)
        p = self.by_idx.get(idx)
        if p is None:
            return
        s = next((x for x in (p.cur, p.prev) if x is not None and x.local_idx == idx), None)
        pt = s.decrypt(data) if s else None
        if not pt:
            return
        self._note_path(p, ("udp", addr))
        op, body = pt[0], pt[1:]
        if op == mp.RLY_FWD:
            self._rly_forward(p, body)
        elif op == mp.RLY_DLV and p.id in self.rly_nodes and len(body) > 17:
            self.on_relay(body[:16], body[16:], via_node=p.id)
        elif op == mp.RLY_NACK and p.id in self.rly_nodes and len(body) == 17:
            self.rly_bad[(p.id, body[:16])] = time.monotonic() + RLY_BAD_FOR
            log.info("relay node %s cannot deliver to %s (reason %d): using another path for %ds",
                     p.ip, body[:16].hex()[:8], body[16], RLY_BAD_FOR)

    def _rly_forward(self, sender: Peer, body: bytes):
        """We are a delegated relay node: pass a member's datagram to the member it is for. Nothing in it is read."""
        if self.rly_role is None or len(body) < 17 or len(body) > 16 + RLY_MAX_DGRAM:
            return
        dst, dgram = body[:16], body[16:]
        d = self.peers.get(dst)
        if d is None or d is sender or not self._rly_usable(d, time.monotonic()):
            self._rly_nack(sender, dst, mp.NACK_UNREACHABLE)
            return
        if not self._rly_budget(sender.id, len(dgram)):
            self.rly_stats["dropped"] += 1
            self._rly_nack(sender, dst, mp.NACK_RATE)
            return
        if self._send_rly(d, mp.RLY_DLV, sender.id + dgram):
            if self.rly_stats["packets"] == 0:
                log.info("forwarding datagrams for the members (%s -> %s)", sender.id.hex()[:8], dst.hex()[:8])
            self.rly_stats["packets"] += 1
            self.rly_stats["bytes"] += len(dgram)

    def _rly_nack(self, sender: Peer, dst: bytes, reason: int):
        now = time.monotonic()
        if now - self.rly_nack_t.get((sender.id, dst), 0.0) >= 1.0:          # at most one per second and pair
            self.rly_nack_t[(sender.id, dst)] = now
            self._send_rly(sender, mp.RLY_NACK, dst + bytes([reason]))

    def _rly_tick(self, now: float):
        """Round trip to each delegated relay node (a probe every 10 s through the session, answered by CTL_PROBE_REPLY)."""
        for rid in self.rly_nodes:
            r = self.peers.get(rid)
            if r is not None and r.cur is not None and now - self.rly_probe_sent.get(rid, 0.0) >= RLY_PROBE_EVERY and self._rly_usable(r, now):
                self.rly_probe_sent[rid] = now
                self.rly_probe_open[rid] = now
                self._send_payload(r, mp.CTL_PROBE)
        for k in [k for k, t in self.rly_bad.items() if t < now]:
            del self.rly_bad[k]

    def _rly_attached(self) -> list:
        """Delegated relay nodes we can reach: published so that members know through which of them they can reach us."""
        now = time.monotonic()
        return [rid.hex() for rid in self.rly_nodes if rid in self.peers and self._rly_usable(self.peers[rid], now)][:4]

    def _send_payload(self, p: Peer, payload: bytes):
        s = p.cur
        if s is None or not s.usable():
            return
        try:
            self._send_raw(p, s.encrypt(payload))
        except HandshakeError:
            pass

    # ------------------------------------------------------------ L2 switching
    def on_tap_frame(self, frame: bytes):
        if len(frame) < 14 or len(frame) > self.mtu + 22:
            return
        dst = frame[:6]
        if not dst[0] & 1:                                   # unicast
            nid = self.mac_owner.get(dst)
            if nid is None:
                e = self.mac_table.get(dst)
                nid = e[0] if e and time.monotonic() - e[1] < MAC_AGE else None
            if nid is not None and nid in self.peers:
                self._send_payload(self.peers[nid], frame)
                return
        for p in self.peers.values():                        # broadcast, multicast, unknown unicast: flood
            self._send_payload(p, frame)

    def _on_tap_readable(self):
        for _ in range(64):
            try:
                frame = self.tap.read()
            except (BlockingIOError, OSError):
                return
            if frame:
                self.on_tap_frame(frame)

    def _deliver(self, p: Peer, frame: bytes):
        if len(frame) < 14 or len(frame) > self.mtu + 22:
            return
        src = frame[6:12]
        if src[0] & 1 or src == mac_bytes(self.my_mac or "00:00:00:00:00:00"):
            return
        owner = self.mac_owner.get(src)
        if owner is not None and owner != p.id:             # a member claiming another member's MAC
            return
        if owner is None:                                    # bridged host behind this peer: learn it
            if len(self.mac_table) < 4096 or src in self.mac_table:
                self.mac_table[src] = (p.id, time.monotonic())
        try:
            self.tap.write(frame)
        except OSError as e:
            log.debug("tap write: %s", e)

    # ------------------------------------------------------------ receiving
    def on_udp(self, data: bytes, addr):
        if not data:
            return
        if oneqnat.is_stun(data):
            self._on_stun(data, addr)
            return
        if self.stun_tx and v1.is_stun(data):
            r = v1.stun_parse(data, self.stun_tx)
            if r:
                self.stun_result = r
            return
        t = data[0]
        if t == mp.M_DATA:
            self._on_data(data, ("udp", addr))
        elif t == mp.M_RLY:
            self._on_rly(data, addr)
        elif t == mp.T_FRAG:
            msg = self.reasm.feed(("udp", addr), data)
            if msg:
                self._on_hs(msg, ("udp", addr))
        elif t == mp.T_PUNCH:
            # A hole-punch from an address nobody we know advertised: a member we have not heard about yet is trying
            # to reach us (it may be the initiator we are waiting for). Look at the registry now instead of waiting
            # for the next periodic refresh. Costs at most one request per registry-loop tick, whatever is sent.
            if not any(addr == p.peer_addr or addr in p.candidates for p in self.peers.values()):
                self.last_members = 0.0
            if len(data) == 17:
                self._punch_from(data[1:17], addr)
                self._on_punch(data[1:17])

    # ------------------------------------------------------------ synchronised punching (see PUNCH_PERIOD)
    def relay_time(self) -> Optional[float]:
        off = self.control.clock_offset
        return None if off is None else time.time() + off

    def _careful(self, p: Peer) -> bool:
        """Filtering NATs on BOTH sides: unsolicited packets must not be sent outside punch rounds. When one side is open
        or a cone NAT it accepts them, nothing can be poisoned, and the plain continuous attempts are fine."""
        # without the relay's clock there are no punch rounds, so the plain continuous attempts are all we have
        return self.control.clock_offset is not None and self.nat.type in FILTERING and p.nat in FILTERING

    def _direct_targets(self, p: Peer, now: float) -> list:
        if not self._careful(p):
            return list(p.candidates)
        return [p.hole_addr] if p.hole_addr and now < p.hole_until else []

    def _open_hole(self, p: Peer, addr) -> bool:
        """A packet of `p` arrived from `addr`. Only addresses at the IPs it registered count (a forged source address
        must not make us send a 2 KB handshake to a third party). True if the hole was not already open."""
        known = {c[0] for c in p.candidates}
        if p.nat_mapped:
            known.add(p.nat_mapped.rpartition(":")[0])          # a symmetric NAT publishes its address though not its port
        if addr != p.peer_addr and addr[0] not in known:
            return False
        now = time.monotonic()
        fresh = p.hole_addr != addr or now >= p.hole_until
        p.hole_addr, p.hole_until = addr, now + HOLE_TTL
        return fresh

    def _punchable(self, p: Peer) -> bool:
        """Is a direct path worth attempting? NAT types, predictable symmetric NATs and second NATs decide (IPv4); a pair that both
        have a global IPv6 address always is: there is no translation to get through, only a stateful firewall."""
        if self._both_v6(p):
            return True
        return oneqnat.can_punch(self.nat.type, p.nat or "unknown", bool(self.nat.delta), bool(p.nat_delta), self.nat.cgnat, p.nat_cgnat)

    def _both_v6(self, p: Peer) -> bool:
        return bool(self.v6_endpoint) and any(":" in c[0] for c in p.candidates)

    def _punch_peers(self, now: float) -> list:
        return [p for p in self.peers.values()
                if (p.candidates or p.predicted) and self._careful(p) and self._punchable(p)
                and not (p.cur is not None and p.path == "direct" and now - p.last_direct_rx < 2 * KEEPALIVE)
                and not self.cfg.force_relay]

    @staticmethod
    def punch_attempt_round(idx: int) -> bool:
        """Attempts happen in the first rounds of every cycle; the silence that follows lets unanswered NAT state expire."""
        return idx % PUNCH_CYCLE < PUNCH_ATTEMPTS

    async def _punch_loop(self):
        """Rounds at the same instants on both sides: the clock of the relay is the shared reference."""
        while True:
            rt = self.relay_time()
            if rt is None:
                await asyncio.sleep(0.5)
                continue
            nxt = (math.floor(rt / PUNCH_PERIOD) + 1) * PUNCH_PERIOD
            await asyncio.sleep(max(0.0, nxt - rt))
            idx = int(round(nxt / PUNCH_PERIOD))
            if not self.punch_attempt_round(idx):
                continue
            targets = [(p, list(p.candidates) + list(p.predicted)) for p in self._punch_peers(time.monotonic())]
            if not targets:
                continue
            log.debug("punch round %d towards %s", idx, [p.ip for p, _ in targets])
            t0 = time.monotonic()
            for off in PUNCH_OFFSETS:
                await asyncio.sleep(max(0.0, t0 + off - time.monotonic()))
                for p, cands in targets:
                    if p.cur is not None and p.path == "direct":
                        continue
                    punch = bytes([mp.T_PUNCH]) + self.me.node_id
                    for c in cands:
                        self._udp_send(punch, c)

    def _punch_from(self, nid: bytes, addr):
        """A PUNCH arrived over UDP: the NAT in front of us now lets this peer in. Use the hole at once."""
        p = self.peers.get(nid)
        if p is None or not self._open_hole(p, addr):
            return
        now = time.monotonic()
        if now - p.last_punch >= 0.3:                          # answer, so that the peer's NAT also has the entry
            p.last_punch = now
            self._udp_send(bytes([mp.T_PUNCH]) + self.me.node_id, addr)
        if p.cur is None and p.initiator and now - p.last_init >= 0.3:
            self._send_init(p)
        elif p.cur is not None and p.path == "relay" and now - p.last_probe >= 1.0:
            p.last_probe = now
            self._udp_send_probe(p, addr)

    def _udp_send_probe(self, p: Peer, addr):
        pkt = p.cur.encrypt(mp.CTL_PROBE) if p.cur is not None and p.cur.usable() else None
        if pkt:
            self._udp_send(pkt, addr)

    def _on_punch(self, nid: bytes):
        """The peer says it has no session with us. If we are the initiator and believe we have one, it is stale
        (the peer restarted): handshake again now. Unauthenticated, so rate-limited per peer."""
        p = self.peers.get(nid)
        now = time.monotonic()
        if p is None or not p.initiator or p.cur is None or p.cur.age() < 3.0 or now - p.last_rehs < 5.0:
            return
        p.last_rehs = now
        p.force_hs = True
        log.info("%s has no session with us any more: new handshake", p.ip)

    def on_relay(self, src_id: bytes, data: bytes, via_node: Optional[bytes] = None):
        if src_id not in self.peers or not data:
            return
        if data[0] == mp.T_PUNCH and len(data) == 17 and data[1:17] == src_id:
            self._on_punch(src_id)
            return
        if data[0] == mp.M_DATA:
            self._on_data(data, ("relay",))
        elif data[0] == mp.T_FRAG:
            msg = self.reasm.feed(("relay", src_id), data)
            if msg:
                self._on_hs(msg, ("relay",), src_id)

    def _on_data(self, pkt: bytes, via):
        idx = mp.data_receiver_index(pkt)
        p = self.by_idx.get(idx)
        if p is None:
            return
        s = next((x for x in (p.cur, p.prev) if x is not None and x.local_idx == idx), None)
        pt = s.decrypt(pkt) if s else None
        if pt is None:
            return
        was_relay = p.path == "relay"
        self._note_path(p, via)
        if via[0] == "udp" and was_relay and p.path == "direct":
            log.info("back on direct path to %s (%s)", p.ip, p.peer_addr)
        if pt == mp.CTL_PROBE:
            self._send_payload(p, mp.CTL_PROBE_REPLY)
        elif pt == mp.CTL_PROBE_REPLY and p.id in self.rly_probe_open:
            rtt = time.monotonic() - self.rly_probe_open.pop(p.id)
            old = self.rly_rtt.get(p.id)
            self.rly_rtt[p.id] = rtt if old is None else 0.7 * old + 0.3 * rtt
        elif len(pt) > 1:
            self._deliver(p, pt)

    def _budget_ok(self) -> bool:
        now = time.monotonic()
        self.init_budget = min(10.0, self.init_budget + (now - self.init_budget_t) * 5.0)
        self.init_budget_t = now
        if self.init_budget < 1:
            return False
        self.init_budget -= 1
        return True

    def _on_hs(self, msg: bytes, via, relay_src: Optional[bytes] = None):
        if msg[0] == mp.M_INIT:
            self._on_init(msg, via, relay_src)
        elif msg[0] == mp.M_RESP:
            self._on_resp(msg, via)

    def _on_init(self, msg, via, relay_src):
        hint = mp.init_peek(msg)
        if hint is None:
            return
        sidx, nid = hint
        p = self.peers.get(nid)
        if p is None or p.initiator or (relay_src is not None and relay_src != nid):
            if p is None:
                self.last_members = 0.0                      # unknown member: refresh the registry soon
            log.debug("INIT from %s dropped: %s", nid.hex()[:8], "unknown member" if p is None else "not expected")
            return
        if not self._budget_ok():
            log.debug("INIT from %s dropped: rate limit", p.ip)
            return
        try:
            ts, ck, h, E, ek, sidx = mp.init_consume(self.me, p.pub, msg)
        except HandshakeError as e:
            log.debug("INIT rejected: %s", e)
            return
        if ts <= p.last_ts or abs(time.time_ns() // 1000 - ts) > self.cfg.max_skew * 1e6:
            log.debug("INIT from %s dropped: replay or clock skew", p.ip)
            return
        p.last_ts = ts
        my_idx = self.new_idx()
        resp, sk, rk = mp.resp_create(self.me, p.pub, ck, h, E, ek, my_idx, sidx)
        self._install(p, mp.MSession(sk, rk, False, my_idx, sidx), via)
        self._send_hs(p, resp, via)

    def _on_resp(self, msg, via):
        hint = mp.resp_peek(msg)
        if hint is None:
            return
        p = self.by_idx.get(hint[1])
        if p is None:
            return
        for st in list(p.pending):
            if st.idx != hint[1]:
                continue
            try:
                sk, rk, peer_idx = mp.resp_consume(self.me, st, msg)
            except HandshakeError:
                return
            for x in p.pending:
                self.by_idx.pop(x.idx, None)
            p.pending.clear()
            self._install(p, mp.MSession(sk, rk, True, st.idx, peer_idx), via)
            self._send_payload(p, b"")                      # confirm so the responder learns our address
            return

    # ------------------------------------------------------------ periodic work
    def _send_init(self, p: Peer):
        idx = self.new_idx()
        msg, st = mp.init_create(self.me, p.pub, idx)
        while len(p.pending) >= 4:
            self.by_idx.pop(p.pending.popleft().idx, None)
        p.pending.append(st)
        self.by_idx[idx] = p
        p.last_init = time.monotonic()
        p.force_hs = False
        log.debug("INIT to %s via %d candidate(s)%s", p.ip, len(p.candidates), " + relay" if self._hs_via_relay(p) else "")
        if not self.cfg.force_relay:
            for c in self._direct_targets(p, time.monotonic()):
                self._send_hs(p, msg, ("udp", c))
        if self._hs_via_relay(p):
            self._send_hs(p, msg, ("relay",))

    def _hs_via_relay(self, p: Peer) -> bool:
        # a forced re-handshake, or a peer with no known address (behind NAT), can only be reached through the relay
        return (self.relay is not None or self._pick_rly(p) is not None) and (self.cfg.force_relay or p.relay_hs or p.force_hs or not p.candidates)

    def _tick_peer(self, p: Peer, now: float):
        cfg = self.cfg
        if p.cur is not None and not p.cur.usable():
            log.warning("session with %s expired", p.ip)
            self._forget(p.cur)
            p.cur = None
        if p.prev is not None and not p.prev.usable():
            self._forget(p.prev)
            p.prev = None
        while p.pending and now - p.pending[0].created > 10:
            self.by_idx.pop(p.pending.popleft().idx, None)
        cur = p.cur
        if cur is None:
            if p.t_nosession is None:
                p.t_nosession = now
            hopeless = (p.nat is not None and self.nat.type not in ("unknown", "blocked") and not self._punchable(p))
            if ((self.relay is not None or self._pick_rly(p) is not None) and not p.relay_hs
                    and (cfg.force_relay or hopeless or now - p.t_nosession >= cfg.relay_after)):
                p.relay_hs = True
                if hopeless:
                    log.info("%s is behind a %s NAT%s and we are behind a %s one%s: direct UDP cannot be punched, using the relay",
                             p.ip, p.nat, " (second NAT)" if p.nat_cgnat else "", self.nat.type, " (second NAT)" if self.nat.cgnat else "")
                else:
                    log.info("no direct session with %s after %.0fs: enabling relay", p.ip, now - p.t_nosession)
                if self.relay is not None:
                    self.relay.enabled.set()
        else:
            p.t_nosession = None
            p.relay_hs = False
        if cur is None and now - p.last_punch >= 1.0:
            # "I have no session with you": opens NAT mappings and tells an initiator that still holds a (stale)
            # session - e.g. because we restarted - to run a new handshake right away. It carries our node_id.
            p.last_punch = now
            punch = bytes([mp.T_PUNCH]) + self.me.node_id
            if not cfg.force_relay:
                for c in self._direct_targets(p, now):
                    self._udp_send(punch, c)
            if self.relay is not None and self.relay.connected and (cfg.force_relay or p.relay_hs or not p.candidates):
                self.relay.send(p.id, punch)
        if p.initiator and (cur is None or cur.age() >= REKEY_AFTER or p.force_hs) and now - p.last_init >= HS_RETRY:
            if self._direct_targets(p, now) or self._hs_via_relay(p):
                self._send_init(p)
        if cur is not None:
            if now - p.last_tx >= KEEPALIVE:
                self._send_payload(p, b"")
            if p.path == "relay" and not cfg.force_relay and p.candidates and now - p.last_probe >= PROBE_EVERY:
                p.last_probe = now
                pkt = cur.encrypt(mp.CTL_PROBE)
                for c in self._direct_targets(p, now):
                    self._udp_send(pkt, c)
            if (p.path == "direct" and self.relay is not None and not cfg.force_relay
                    and now - p.last_direct_rx > DIRECT_STALE):
                p.path = "relay"
                self.relay.enabled.set()
                log.info("direct path to %s is stale, using relay", p.ip)

    def _tick(self):
        now = time.monotonic()
        for p in list(self.peers.values()):
            self._tick_peer(p, now)
        self._rly_tick(now)
        for mac in [m for m, (_, t) in self.mac_table.items() if now - t > MAC_AGE]:
            del self.mac_table[mac]

    async def _maint(self):
        while True:
            try:
                self._tick()
            except Exception:
                log.exception("tick")
            await asyncio.sleep(0.25)

    # ------------------------------------------------------------ registry
    def apply_members(self, members: list):
        seen = set()
        delegates = {}
        for m in members:
            try:
                pub = base64.b64decode(m["pub"], validate=True)
                nid = bytes.fromhex(m["id"])
                mac_bytes(m["mac"])
            except (ValueError, KeyError, TypeError):
                continue
            if node_id(pub) != nid:                          # never trust the registry for key <-> id binding
                log.warning("registry entry %s does not match its key: ignored", m.get("id"))
                continue
            if nid == self.me.node_id:
                role = m.get("relay_role") if self.cfg.relay_offer else None
                if (role is None) != (self.rly_role is None):
                    log.info("this node is %s a delegated relay node", "now" if role else "no longer")
                self.rly_role = role if isinstance(role, dict) and isinstance(role.get("max_kbps"), int) else None
                continue
            seen.add(nid)
            p = self.peers.get(nid)
            if p is None or p.pub != pub:
                p = self.peers[nid] = Peer(nid, pub, m["ip"], m["mac"])
                p.initiator = self.me.pub < pub
                log.debug("new member %s (%s), I am the %s", m["ip"], m["id"][:8], "initiator" if p.initiator else "responder")
            p.ip, p.name = m["ip"], m.get("name", "")
            p.attached = frozenset(bytes.fromhex(x) for x in m.get("relays", []) if isinstance(x, str) and len(x) == 32)
            role = m.get("relay_role")
            if isinstance(role, dict) and isinstance(role.get("max_kbps"), int):
                delegates[nid] = role
            nat = m.get("nat") or {}
            p.nat, p.nat_mapped = nat.get("type"), nat.get("mapped")
            p.nat_delta = nat.get("delta") if isinstance(nat.get("delta"), int) else None
            p.nat_cgnat = nat.get("cgnat") is True
            p.predicted = oneqnat.punch_ports(p.nat, p.nat_mapped, p.nat_delta)
            if p.mac != m["mac"]:
                self.mac_owner.pop(p.macb, None)
                p.mac, p.macb = m["mac"], mac_bytes(m["mac"])
            self.mac_owner[p.macb] = nid
            own = set(self.local_candidates)
            cands = [c for c in (self.parse_endpoint(e) for e in m.get("endpoints", []) if e not in own) if c][:8]
            if cands != p.candidates:
                log.debug("candidates of %s: %s", p.ip, cands)
            p.candidates = cands
        if set(delegates) != set(self.rly_nodes):
            log.info("delegated relay nodes: %s", ", ".join(self.peers[n].ip for n in delegates) or "none")
        self.rly_nodes = delegates
        for nid in [n for n in self.peers if n not in seen]:
            p = self.peers.pop(nid)
            self.mac_owner.pop(p.macb, None)
            for s in (p.cur, p.prev):
                self._forget(s)
            for st in p.pending:
                self.by_idx.pop(st.idx, None)
            log.info("member %s (%s) left", p.ip, nid.hex()[:8])

    def _apply_identity(self, info: dict):
        if (info["ip"], info["mac"], info["mtu"]) == (self.my_ip, self.my_mac, self.mtu) and self.my_ip:
            return
        self.my_ip, self.my_mac, self.mtu = info["ip"], info["mac"], info["mtu"]
        log.info("address %s/%s mac %s mtu %s", info["ip"], info["prefix"], info["mac"], info["mtu"])
        if not self.cfg.no_config:
            configure_tap(self.tap.name, info["mac"], info["ip"], info["prefix"], info["mtu"])

    # ------------------------------------------------------------ NAT discovery (STUN service of the relay)
    def nat_description(self) -> Optional[dict]:
        if self.nat.type == "unknown" and not self.nat.mapped:
            return None
        d = {"type": self.nat.type}
        if self.nat.mapped:
            d["mapped"] = f"{self.nat.mapped[0]}:{self.nat.mapped[1]}"
        if self.nat_inbound is not None:
            d["inbound"] = self.nat_inbound
        if self.nat.delta:
            d["delta"] = self.nat.delta
        if self.nat.cgnat:
            d["cgnat"] = True
        if self.nat.via:
            d["via"] = self.nat.via
        return d

    def _on_stun(self, data: bytes, addr):
        """Answers of the STUN service of the relay to our probes, and Binding requests from the relay or other tools
        (reachability tests, connectivity checks): those are answered with the address we see them from."""
        msg = oneqnat.parse(data)
        if msg is None:
            return
        if msg[0] == oneqnat.BINDING_SUCCESS:
            self.prober.feed(data, addr)
        elif msg[0] == oneqnat.BINDING_REQUEST:
            now = time.monotonic()
            n, t0 = self._stun_answers
            if now - t0 > 1.0:
                n, t0 = 0, now
            if n < 20:                                      # at most 20 answers per second, whoever asks
                self._stun_answers = (n + 1, t0)
                self._udp_send(oneqnat.binding_response(msg[1], addr), addr)

    async def _stun_server_addrs(self):
        """(main, alt) UDP addresses of the STUN service of the relay we are talking to, or None."""
        st = (self.control.info or {}).get("stun")
        if not st:
            return None
        host = urlsplit(self.control.base).hostname
        loop = asyncio.get_running_loop()
        try:
            ip = (await loop.getaddrinfo(host, st["port"], family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][4][0]
        except (OSError, IndexError):
            return None
        return (ip, st["port"]), (ip, st["alt_port"]), ((ip, st["change_port"]) if st.get("change_port") else None)

    async def _nat_loop(self):
        cfg, last_full = self.cfg, 0.0
        while True:
            try:
                if self.udp is None or not (self.control.info or {}).get("stun"):
                    await asyncio.sleep(1.0)               # not registered yet, or a relay without the service
                    if self.control.info is not None and not self.control.info.get("stun"):
                        await asyncio.sleep(60.0)
                    continue
                addrs = await self._stun_server_addrs()
                if addrs is None:
                    await asyncio.sleep(30.0)
                    continue
                main, alt, third = addrs
                now = time.monotonic()
                if now - last_full >= cfg.nat_refresh or self.nat_raw.mapped is None:
                    bound = self.udp.get_extra_info("sockname")
                    local = (self._guess_ip(), bound[1])
                    old = self.nat
                    self.nat_raw = await oneqnat.classify(self.prober.transact, main, alt, local, third)
                    last_full = time.monotonic()
                    self._update_v6()
                    self._apply_nat()                      # publish what was measured now; the router probing below takes seconds
                    await self._port_mapping(bound[1])
                    self._apply_nat()
                    await self._check_inbound()
                    self._apply_nat()
                    if (old.type, old.mapped, old.cgnat, old.delta, old.via) != (self.nat.type, self.nat.mapped, self.nat.cgnat, self.nat.delta, self.nat.via):
                        log.info("NAT: %s%s%s%s%s", self.nat.type,
                                 f", public UDP address {self.nat.mapped[0]}:{self.nat.mapped[1]}" if self.nat.mapped else "",
                                 f", ports allocated in steps of {self.nat.delta} (predictable)" if self.nat.delta else "",
                                 f", forwarded by the router ({self.nat.via})" if self.nat.via else "",
                                 ", a second NAT in front of the router (carrier-grade): direct UDP is not attempted" if self.nat.cgnat else "")
                        self.last_register = 0.0           # publish the new endpoint and NAT type now
                else:
                    m = await self.prober.transact(main, 0)
                    raw = self.nat_raw.mapped
                    # a predictable symmetric NAT published its newest mapping, not the one towards the main port: only the address must match
                    if m is None or raw is None or (m[0] != raw[0] if self.nat_raw.delta else m != raw):
                        last_full = 0.0                    # mapping changed or lost: classify again
                        continue
                    await self._renew_mapping()
                await asyncio.sleep(cfg.nat_keepalive)
            except asyncio.CancelledError:
                raise
            except Exception as e:                         # noqa: BLE001
                log.warning("nat discovery: %s", e)
                await asyncio.sleep(10.0)

    async def _port_mapping(self, internal_port: int):
        """Hold a router mapping for our UDP port (PCP, NAT-PMP, UPnP) unless a second NAT makes it useless; learn the router's
        WAN address on the way, which is how a second NAT is recognised."""
        pm_ = self.portmapper
        raw = self.nat_raw
        if pm_ is not None and raw.type not in ("open", "blocked") and raw.mapped:
            if self.mapping is None:
                self.mapping = await pm_.map(internal_port, lifetime=3600)
            self.router_ip = self.mapping.ext_ip if self.mapping else await pm_.router_external_ip()
        else:
            self.router_ip = None
        self.cgnat = bool(raw.mapped) and oneqnat.double_nat(raw.mapped[0], self.router_ip)
        if self.cgnat and self.mapping is not None:
            log.info("second NAT in front of the router (router WAN address %s, seen by the relay %s): the router mapping is useless, released",
                     self.router_ip, raw.mapped[0])
            await pm_.unmap(self.mapping)
            self.mapping = None
        self.mapping_ok = False

    async def _renew_mapping(self):
        m = self.mapping
        if m is not None and time.monotonic() >= m.renew_at():
            n = await self.portmapper.renew(m)
            if n is None:
                log.info("port mapping (%s) could not be renewed", m.method)
                self.mapping = None
                self.mapping_ok = False
                self.nat_raw = oneqnat.NatInfo(mapped=self.nat_raw.mapped)      # reclassify
            else:
                self.mapping = n
                if n.endpoint() != m.endpoint():
                    self.mapping_ok = False
                    self.last_register = 0.0
                    self._apply_nat()

    def _apply_nat(self):
        """The NAT we publish: the measured one; "open" when the router mapping was verified from outside (the relay probed
        its external address from a port we never contacted); flags for a second NAT."""
        nat = dataclasses.replace(self.nat_raw, cgnat=self.cgnat)
        m = self.mapping
        if m is not None and self.mapping_ok and m.endpoint() and not self.cgnat:
            nat.type, nat.via = "open", m.method
            nat.mapped = (m.ext_ip, m.ext_port)
            nat.delta = None
        self.nat = nat

    async def _check_inbound(self):
        """Ask the relay to probe our published public address (and any --advertise address, and the address a router mapping
        gave us) from a port we never contacted: an answer means unsolicited packets get through, i.e. peers can reach us
        without a punched hole."""
        pub = self.nat_raw.public_endpoint()
        mapped = self.mapping.endpoint() if self.mapping is not None and self.mapping.ext_ip and ":" not in self.mapping.ext_ip else None
        targets = [e for e in dict.fromkeys(list(self.cfg.advertise) + ([pub] if pub else []) + ([mapped] if mapped else [])) if e]
        res = {}
        for e in targets:
            r = await self.control.nat_test(self.me.node_id.hex(), e)
            if r is not None:
                res[e] = bool(r.get("reachable"))
        for e in self.cfg.advertise:
            if e in res and not res[e]:
                log.warning("advertised address %s did not answer the probe of the relay: wrong address, or a forward or "
                            "firewall rule is missing", e)
        if mapped:
            ok = res.get(mapped) is True
            if ok != self.mapping_ok:
                log.info("router mapping %s (%s): %s", mapped, self.mapping.method,
                         "reachable from outside, published as an open address" if ok else "not reachable from outside (the router's address is not public?)")
                self.mapping_ok = ok
                self.last_register = 0.0
        new = res.get(pub) if pub else None
        if new != self.nat_inbound:
            self.nat_inbound = new
            if new is not None:
                log.info("inbound UDP to %s: %s", pub,
                         "reachable from a port of the relay we never used" if new else "needs a punched hole (normal behind a restricted NAT)")
            self.last_register = 0.0

    def endpoints(self) -> list:
        eps = list(self.local_candidates)
        pub = self.nat.public_endpoint()
        if pub:
            eps.append(pub)
        if self.v6_endpoint:
            eps.append(self.v6_endpoint)
        if self.stun_result:
            eps.append(f"{self.stun_result[0]}:{self.stun_result[1]}")
        return list(dict.fromkeys(eps))[:8]

    async def _registry_loop(self):
        while True:
            try:
                now = time.monotonic()
                attached = self._rly_attached()
                if now - self.last_register >= self.cfg.register_every or not self.my_ip or attached != self.last_attached:
                    self.last_attached = attached
                    info = await self.control.join(self.me.node_id.hex(), self.me.pub, self.endpoints(), self.cfg.name,
                                                   self.nat_description(), self.cfg.relay_offer, attached)
                    self.last_register = now
                    self._apply_identity(info)
                    if self.relay is not None:
                        self.relay.ready.set()
                if now - self.last_members >= self._members_interval():
                    self.apply_members(await self.control.members())
                    self.last_members = now
            except asyncio.CancelledError:
                raise
            except PermissionError as e:
                log.error("%s", e)
                await asyncio.sleep(10)
            except Exception as e:
                log.warning("registry: %s", e)
            await asyncio.sleep(min(1.0, self.cfg.refresh_fast))

    def _members_interval(self) -> float:
        waiting = any(p.cur is None for p in self.peers.values()) or not self.peers
        return self.cfg.refresh_fast if waiting else self.cfg.refresh_slow

    # ------------------------------------------------------------ lifecycle
    def parse_endpoint(self, e: str):
        """"ip:port" or "[v6]:port" -> (ip, port), or None (malformed, or IPv6 while we cannot send IPv6)."""
        try:
            h, port = parse_hostport(e)
            h = h.strip("[]")
            if ":" in h:
                if not self.dual_stack:
                    return None
                h = str(ipaddress.IPv6Address(h))
            return h, port
        except ValueError:
            return None

    def _guess_ip(self) -> str:
        try:
            host = urlsplit(self.cfg.relays[0]).hostname
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, 9))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except (OSError, IndexError):
            return "127.0.0.1"

    async def _bind_dual_stack(self, loop, proto, port):
        """One socket for IPv4 and IPv6 (IPV6_V6ONLY off), or None when this host has no IPv6."""
        if not socket.has_ipv6:
            return None
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::", port))
            sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(proto, sock=sock)
        except (OSError, ValueError) as e:
            log.info("no dual-stack UDP socket (%s): IPv4 only", e)
            if sock is not None:
                sock.close()
            return None
        self.dual_stack = True
        return transport

    def _update_v6(self):
        """The global IPv6 address this host would use towards the internet (the OS picks it; nothing is sent), published as a candidate."""
        old = self.v6_endpoint
        self.v6_endpoint = None
        if self.dual_stack:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                try:
                    s.connect(("2001:4860:4860::8888", 9))
                    ip = s.getsockname()[0].split("%")[0]
                finally:
                    s.close()
                if ipaddress.ip_address(ip).is_global:
                    self.v6_endpoint = f"[{ip}]:{self.udp.get_extra_info('sockname')[1]}"
            except (OSError, ValueError):
                pass
        if self.v6_endpoint != old:
            log.info("IPv6 candidate: %s", self.v6_endpoint or "none")
            self.last_register = 0.0

    async def _stun_once(self, loop):
        host, port = parse_hostport(self.cfg.stun)
        addr = (await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][4]
        for _ in range(3):
            req, self.stun_tx = v1.stun_request()
            self._udp_send(req, addr)
            await asyncio.sleep(1.0)
            if self.stun_result:
                log.info("STUN reflexive address %s:%s", *self.stun_result)
                return

    async def run(self):
        loop = asyncio.get_running_loop()
        cfg = self.cfg
        host, port = cfg.listen
        if cfg.via:
            host = v1.iface_ipv4(cfg.via)

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                self.on_udp(data, normalize_addr(addr))
        transport = None
        if cfg.ipv6 and host == "0.0.0.0" and not cfg.via:
            transport = await self._bind_dual_stack(loop, Proto, port)
        if transport is None:
            transport, _ = await loop.create_datagram_endpoint(Proto, local_addr=(host, port))
        self.udp = transport
        bound = transport.get_extra_info("sockname")
        if cfg.via:
            self.local_candidates.append(f"{bound[0]}:{bound[1]}")
        if not self.local_candidates:
            self.local_candidates.append(f"{host if host != '0.0.0.0' else self._guess_ip()}:{bound[1]}")
        if cfg.port_mapping and not cfg.via:
            self.portmapper = oneqportmap.PortMapper()
        self._update_v6()
        log.info("udp %s:%s, node_id %s", bound[0], bound[1], self.me.node_id.hex())
        loop.add_reader(self.tap.fileno(), self._on_tap_readable)
        if not cfg.no_relay:
            self.relay = RelayLink(self.control, self.me.node_id.hex(), self.on_relay)
            if cfg.relay_always:
                self.relay.enabled.set()
            self.tasks.append(asyncio.ensure_future(self.relay.run()))
        if cfg.stun:
            self.tasks.append(asyncio.ensure_future(self._stun_once(loop)))
        if cfg.nat_discovery:
            self.tasks.append(asyncio.ensure_future(self._nat_loop()))
            self.tasks.append(asyncio.ensure_future(self._punch_loop()))
        self.tasks += [asyncio.ensure_future(self._registry_loop()), asyncio.ensure_future(self._maint())]
        try:
            await asyncio.gather(*self.tasks)
        finally:
            await self.close()

    async def close(self):
        for t in self.tasks:
            t.cancel()
        if self.mapping is not None and self.portmapper is not None:
            try:
                await asyncio.wait_for(self.portmapper.unmap(self.mapping), 2.0)
            except (asyncio.TimeoutError, OSError):
                pass
            self.mapping = None
        if self.udp:
            self.udp.close()
        await self.control.close()
        try:
            asyncio.get_running_loop().remove_reader(self.tap.fileno())
        except Exception:
            pass


# ---------------------------------------------------------------- CLI

def read_password(args) -> str:
    if args.password_file:
        if os.name == "posix" and os.stat(args.password_file).st_mode & 0o077:
            raise PermissionError(f"{args.password_file}: password file must be mode 600")
        with open(args.password_file) as f:
            return f.read().strip()
    if os.environ.get("ONEQ_PASSWORD"):
        return os.environ["ONEQ_PASSWORD"]
    raise SystemExit("password: use --password-file or $ONEQ_PASSWORD (never on the command line)")


NODE_KEYS = {"relays", "community", "user", "label", "key_file", "password_file", "ifname", "listen", "advertise",
             "stun", "cafile", "via", "force_relay", "no_relay", "relay_after", "configure_interface", "init", "nat_discovery", "relay_offer", "use_delegates",
             "port_mapping", "ipv6"}
NODE_SPEC = {"relay": ("relays", oneqconf.to_list), "community": ("community", oneqconf.to_str),
             "user": ("user", oneqconf.to_str), "name": ("label", oneqconf.to_str), "key": ("key_file", oneqconf.to_str),
             "password_file": ("password_file", oneqconf.to_str), "ifname": ("ifname", oneqconf.to_str),
             "listen": ("listen", oneqconf.to_str), "advertise": ("advertise", oneqconf.to_list),
             "stun": ("stun", oneqconf.to_str), "cafile": ("cafile", oneqconf.to_str), "via": ("via", oneqconf.to_str),
             "force_relay": ("force_relay", oneqconf.to_bool), "no_relay": ("no_relay", oneqconf.to_bool),
             "relay_after": ("relay_after", oneqconf.to_float),
             "relay_offer": ("relay_offer", oneqconf.to_bool),
             "no_delegates": ("use_delegates", lambda v, k: not oneqconf.to_bool(v, k)),
             "no_nat_discovery": ("nat_discovery", lambda v, k: not oneqconf.to_bool(v, k)),
             "no_port_mapping": ("port_mapping", lambda v, k: not oneqconf.to_bool(v, k)),
             "no_ipv6": ("ipv6", lambda v, k: not oneqconf.to_bool(v, k)),
             "no_config": ("configure_interface", lambda v, k: not oneqconf.to_bool(v, k))}


def resolve(a, parser):
    """Command line > [NODE] section > [defaults] section of --config > built-in default."""
    if a.config:
        sections = ["defaults"] + ([a.node] if a.node else [])
        try:
            conf = oneqconf.load(a.config, sections, NODE_KEYS)
            if a.node and not oneqconf.has_section(a.config, a.node):
                parser.error(f"{a.config}: no [{a.node}] section")
            oneqconf.fill(a, conf, NODE_SPEC)
        except oneqconf.ConfigError as e:
            parser.error(str(e))
    elif a.node:
        parser.error("--node needs --config")
    a.ifname = a.ifname or (f"oneq-{a.node}" if a.node else "oneq0")
    a.listen = a.listen or "0.0.0.0:0"
    a.relay_after = 10.0 if a.relay_after is None else a.relay_after
    a.name = a.name or ""
    for need, what in ((a.key, "key (--key / key_file)"), (a.relay, "relay (--relay / relays)"),
                       (a.community, "community"), (a.user, "user")):
        if not need:
            parser.error(f"{what} is required")


async def nat_check(host: str, port: int, alt_port: int, local_port: int, as_json: bool, change_port: Optional[int] = None) -> int:
    """Measure the NAT in front of this machine with the STUN service of a oneqrelay, without joining anything."""
    loop = asyncio.get_running_loop()
    ip = (await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][4][0]
    prober = oneqnat.NatProber(lambda d, a: transport.sendto(d, a), timeout=0.8, tries=3)

    class P(asyncio.DatagramProtocol):
        def datagram_received(_s, data, addr):
            prober.feed(data, addr)
    transport, _ = await loop.create_datagram_endpoint(P, local_addr=("0.0.0.0", local_port))
    try:
        bound = transport.get_extra_info("sockname")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((ip, 9))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        info = await oneqnat.classify(prober.transact, (ip, port), (ip, alt_port), (local_ip, bound[1]), (ip, change_port or alt_port + 1))
        router_ip = None
        if info.mapped and info.type != "open":
            router_ip = await oneqportmap.PortMapper(methods=("natpmp", "upnp"), search_time=1.5).router_external_ip()
        info.cgnat = bool(info.mapped) and oneqnat.double_nat(info.mapped[0], router_ip)
    finally:
        transport.close()
    out = {"type": info.type, "public": info.public_endpoint(), "mapped": f"{info.mapped[0]}:{info.mapped[1]}" if info.mapped else None,
           "mapping": info.mapping, "filtering": info.filtering, "local": f"{local_ip}:{bound[1]}",
           "delta": info.delta, "cgnat": info.cgnat, "router_wan": router_ip}
    if as_json:
        import json
        print(json.dumps(out))
    else:
        print(f"NAT type:      {info.type}")
        print(f"local address: {out['local']}")
        print(f"public UDP:    {out['mapped'] or '-'}")
        print(f"mapping:       {info.mapping} (the same public port for every destination = independent)")
        print(f"filtering:     {info.filtering} (open = a packet from a new port of a known IP got through)")
        if info.type == "symmetric":
            print(f"port steps:    {info.delta if info.delta else 'not predictable'} (a constant step lets a peer guess the next port)")
        print(f"second NAT:    {'yes: carrier-grade or a router behind a router; direct UDP only to open peers' if info.cgnat else 'not detected'}"
              + (f" (router WAN address {router_ip})" if router_ip else ""))
        print({"open": "no NAT: peers can reach you directly",
               "cone": "direct connections work with almost everyone (hole punching)",
               "port-restricted": "direct works unless the other side is symmetric; relay otherwise",
               "symmetric": "direct only with open/cone peers; relay with the rest",
               "blocked": "no answer: UDP is blocked or the relay has no STUN service (then everything goes through the relay)",
               "unknown": "inconclusive (packet loss?), run it again"}[info.type])
    return 0 if info.type != "blocked" else 2


def main(argv=None):
    p = argparse.ArgumentParser(prog="oneqnode")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey", help="generate this node's hybrid key pair")
    g.add_argument("--key", required=True)
    nc = sub.add_parser("nat-check", help="measure the NAT in front of this machine with the STUN service of a oneqrelay")
    nc.add_argument("server", metavar="HOST:PORT", help="the relay (its UDP STUN port, the same number as its HTTPS port by default)")
    nc.add_argument("--alt-port", type=int, help="second STUN port of the relay (default: PORT+1)")
    nc.add_argument("--change-port", type=int, help="third STUN port of the relay (default: ALT-PORT+1)")
    nc.add_argument("--local-port", type=int, default=0, help="UDP source port to use (default: any)")
    nc.add_argument("--json", action="store_true")
    cs = sub.add_parser("config-set", help="write/replace the [NAME] section of a node configuration file")
    cs.add_argument("--file", required=True)
    cs.add_argument("name")
    cs.add_argument("values", nargs="+", metavar="option=value")
    cd = sub.add_parser("config-del", help="delete the [NAME] section of a node configuration file")
    cd.add_argument("--file", required=True)
    cd.add_argument("name")
    r = sub.add_parser("run", help="join a community and run the node")
    r.add_argument("--config", metavar="FILE", help="configuration file (e.g. /etc/oneq/node.conf); options given "
                   "on the command line override it")
    r.add_argument("--node", metavar="NAME", help="section of the configuration file to use ([defaults] + [NAME])")
    r.add_argument("--key")
    r.add_argument("--relay", action="append", default=[], metavar="URL", help="oneqrelay (repeat for failover)")
    r.add_argument("--community")
    r.add_argument("--user")
    r.add_argument("--password-file")
    r.add_argument("--name")
    r.add_argument("--ifname", help="default oneq-NAME with --node, else oneq0")
    r.add_argument("--listen", help="default 0.0.0.0:0")
    r.add_argument("--via", metavar="IFACE", help="bind UDP to the address of IFACE (an existing interface, e.g. another tunnel)")
    r.add_argument("--advertise", action="append", default=[], metavar="IP:PORT")
    r.add_argument("--stun", metavar="HOST:PORT", help="extra public STUN server (the service of the relay is used automatically)")
    r.add_argument("--no-nat-discovery", action="store_true", help="do not measure/publish the NAT type with the STUN service of the relay")
    r.add_argument("--no-port-mapping", action="store_true", default=None, help="do not ask the router (PCP, NAT-PMP, UPnP) to forward our UDP port")
    r.add_argument("--no-ipv6", action="store_true", default=None, help="IPv4 only (no dual-stack socket, no IPv6 candidates)")
    r.add_argument("--cafile")
    r.add_argument("--force-relay", action="store_true")
    r.add_argument("--no-relay", action="store_true")
    r.add_argument("--relay-offer", action="store_true", default=None, help="offer to forward datagrams for the other members (takes effect once an administrator delegates this node)")
    r.add_argument("--no-delegates", action="store_true", help="do not use the delegated relay nodes of the community")
    r.add_argument("--relay-after", type=float, help="default 10")
    r.add_argument("--no-config", action="store_true", help="persistent TAP already configured; do not run ip")
    r.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "nat-check":
        h, port = parse_hostport(a.server)
        return asyncio.run(nat_check(h, port, a.alt_port or port + 1, a.local_port, a.json, a.change_port))
    if a.cmd == "genkey":
        ident = Identity.generate()
        v1.save_identity(a.key, ident, a.key + ".pub")
        print("node_id", ident.node_id.hex())
        return 0
    if a.cmd in ("config-set", "config-del"):
        try:
            if a.cmd == "config-del":
                oneqconf.del_section(a.file, a.name)
            else:
                vals = dict(v.split("=", 1) for v in a.values if "=" in v)
                bad = [k for k in vals if k.replace("-", "_") not in NODE_KEYS]
                if bad or len(vals) != len(a.values):
                    p.error(f"unknown or malformed option(s): {bad or a.values}")
                oneqconf.set_section(a.file, a.name, vals)
        except (oneqconf.ConfigError, OSError) as e:
            p.error(str(e))
        return 0
    resolve(a, p)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = NodeConfig(relays=a.relay, community=a.community, user=a.user, password=read_password(a), name=a.name,
                     ifname=a.ifname, listen=parse_hostport(a.listen), via=a.via, advertise=a.advertise, stun=a.stun,
                     cafile=a.cafile, force_relay=a.force_relay, no_relay=a.no_relay, relay_after=a.relay_after, relay_offer=bool(a.relay_offer), use_delegates=not a.no_delegates,
                     no_config=a.no_config, nat_discovery=not a.no_nat_discovery,
                     port_mapping=not a.no_port_mapping, ipv6=not a.no_ipv6)
    node = OneqNode(v1.load_identity(a.key), cfg, Tap(cfg.ifname))
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
