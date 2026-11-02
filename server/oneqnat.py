"""NAT discovery for oneq: a small STUN server (RFC 5389 Binding, with the RFC 5780 CHANGE-REQUEST "change port" flag) that
runs inside every oneqrelay, the matching client-side transaction/classification logic used by oneqnode, and the
hole-punching compatibility rules.

Why STUN and not a private protocol: any STUN client (including public ones) can test a relay, and the nodes' UDP socket
already speaks STUN with the point-to-point mode.

What the relay serves (three UDP sockets on the same address: `port`, `alt_port` and `change_port`)
  * Binding request                      -> success response with XOR-MAPPED-ADDRESS = the source address the packet came from
  * Binding request + CHANGE-REQUEST 0x02 -> the response is sent from `change_port`, a port nodes never send to
    (RFC 5780 "change port"). It must be a port the node has not contacted: a NAT lets the answers of contacted ports through
    and, worse, an unexpected packet can create connection-tracking state that moves the next mapping to another port.
  * Binding request + CHANGE-REQUEST 0x04 (change IP) is not supported: ignored, the client times out
  * the relay can also send a Binding request from the alt socket to a node ("is this address reachable?") and wait for the answer

What a node learns from three transactions (classify):
  1. Binding to `port`                    -> mapped address M1 (None: UDP blocked, or the relay has no STUN service)
  2. Binding to `alt_port` (same socket)  -> M2. M2 != M1: the NAT picks a new port per destination => "symmetric"
  3. Binding to `port` with change-port   -> the answer comes from `change_port`, a port never contacted: if it arrives the NAT
                                             lets unsolicited packets from a known IP through => "cone" (full or address
                                             restricted); no answer => "port-restricted". Done last, after the mapping test.
  M1 equal to the socket's own address means no NAT at all => "open".

Hole punching works unless one side is "symmetric" and the other one is "symmetric" or "port-restricted" (the peer's mapping
changes with the destination, so the address learnt from the relay is useless). Everything else can punch.
Educational project, not independently audited.
"""
import asyncio
import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

log = logging.getLogger("oneqrelay")

COOKIE = 0x2112A442
BINDING_REQUEST, BINDING_SUCCESS, BINDING_ERROR = 0x0001, 0x0101, 0x0111
A_MAPPED, A_CHANGE_REQUEST, A_XOR_MAPPED, A_RESPONSE_ORIGIN, A_OTHER_ADDRESS = 0x0001, 0x0003, 0x0020, 0x802B, 0x802C
CHANGE_IP, CHANGE_PORT = 0x04, 0x02

NAT_TYPES = ("open", "cone", "port-restricted", "symmetric", "blocked", "unknown")


# ---------------------------------------------------------------- codec

def is_stun(data: bytes) -> bool:
    return len(data) >= 20 and data[0] < 0x04 and struct.unpack(">I", data[4:8])[0] == COOKIE \
        and struct.unpack(">H", data[2:4])[0] == len(data) - 20


def build(mtype: int, txid: bytes, attrs: Optional[list] = None) -> bytes:
    body = b""
    for t, v in attrs or []:
        body += struct.pack(">HH", t, len(v)) + v + b"\0" * (-len(v) % 4)
    return struct.pack(">HHI", mtype, len(body), COOKIE) + txid + body


def parse(data: bytes):
    """-> (type, txid, {attr_type: value}) or None for anything that is not a well-formed STUN message."""
    if not is_stun(data):
        return None
    mtype, txid, attrs, i = struct.unpack(">H", data[:2])[0], data[8:20], {}, 20
    while i + 4 <= len(data):
        t, ln = struct.unpack(">HH", data[i:i + 4])
        if i + 4 + ln > len(data):
            return None
        attrs.setdefault(t, data[i + 4:i + 4 + ln])
        i += 4 + ln + (-ln % 4)
    return mtype, txid, attrs


def xor_address(addr: tuple, txid: bytes) -> bytes:
    ip, port = addr[0], addr[1]
    if ":" in ip:
        raw = socket.inet_pton(socket.AF_INET6, ip)
        mask = struct.pack(">I", COOKIE) + txid
        return struct.pack(">BBH", 0, 2, port ^ (COOKIE >> 16)) + bytes(a ^ b for a, b in zip(raw, mask))
    raw = socket.inet_aton(ip)
    return struct.pack(">BBH", 0, 1, port ^ (COOKIE >> 16)) + bytes(a ^ b for a, b in zip(raw, struct.pack(">I", COOKIE)))


def unxor_address(v: bytes, txid: bytes) -> Optional[tuple]:
    try:
        fam, xport = v[1], struct.unpack(">H", v[2:4])[0]
        port = xport ^ (COOKIE >> 16)
        if fam == 1 and len(v) == 8:
            return socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], struct.pack(">I", COOKIE)))), port
        if fam == 2 and len(v) == 20:
            mask = struct.pack(">I", COOKIE) + txid
            return socket.inet_ntop(socket.AF_INET6, bytes(a ^ b for a, b in zip(v[4:20], mask))), port
    except (IndexError, struct.error, OSError):
        pass
    return None


def binding_request(change: int = 0):
    txid = os.urandom(12)
    attrs = [(A_CHANGE_REQUEST, struct.pack(">I", change))] if change else None
    return build(BINDING_REQUEST, txid, attrs), txid


def binding_response(txid: bytes, addr: tuple) -> bytes:
    return build(BINDING_SUCCESS, txid, [(A_XOR_MAPPED, xor_address(addr, txid))])


def mapped_of(msg) -> Optional[tuple]:
    """Mapped address of a parsed binding success response."""
    if not msg or msg[0] != BINDING_SUCCESS:
        return None
    return unxor_address(msg[2][A_XOR_MAPPED], msg[1]) if A_XOR_MAPPED in msg[2] else None


# ---------------------------------------------------------------- server (inside oneqrelay)

class _Bucket:
    def __init__(self, rate: float, burst: float):
        self.rate, self.cap, self.tokens, self.t = rate, burst, burst, time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.cap, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class StunServer:
    """Two UDP sockets, `port` (main) and `alt_port`. Responses are never larger than a few dozen bytes and every source
    address is rate limited, so the service is a poor reflector."""

    def __init__(self, host: str, port: int, alt_port: int, change_port: Optional[int] = None, rate: float = 20.0):
        self.host, self.port, self.alt_port, self.rate = host, port, alt_port, rate
        self.change_port = change_port or alt_port + 1
        self.main = self.alt = self.change = None
        self.buckets = {}
        self.pending = {}                 # txid -> future for reachability probes
        self.stats = {"requests": 0, "responses": 0, "changed_port": 0, "rate_limited": 0, "probes": 0, "probes_answered": 0}

    async def start(self):
        loop = asyncio.get_running_loop()
        srv = self

        def proto(which):
            class P(asyncio.DatagramProtocol):
                def datagram_received(_s, data, addr):
                    srv.on_datagram(which, data, addr)

                def error_received(_s, exc):
                    log.debug("stun socket error: %s", exc)
            return P
        self.main, _ = await loop.create_datagram_endpoint(proto("main"), local_addr=(self.host, self.port))
        self.alt, _ = await loop.create_datagram_endpoint(proto("alt"), local_addr=(self.host, self.alt_port))
        self.change, _ = await loop.create_datagram_endpoint(proto("change"), local_addr=(self.host, self.change_port))

    def close(self):
        for t in (self.main, self.alt, self.change):
            if t:
                t.close()
        for f in self.pending.values():
            if not f.done():
                f.cancel()

    def _allowed(self, ip: str) -> bool:
        if len(self.buckets) > 20000:
            self.buckets.clear()
        b = self.buckets.get(ip)
        if b is None:
            b = self.buckets[ip] = _Bucket(self.rate, self.rate * 2)
        return b.take()

    def on_datagram(self, which: str, data: bytes, addr: tuple):
        msg = parse(data)
        if msg is None:
            return
        mtype, txid, attrs = msg
        if mtype == BINDING_SUCCESS:                       # answer to one of our reachability probes
            fut = self.pending.get(txid)
            if fut is not None and not fut.done():
                fut.set_result(addr)
            return
        if mtype != BINDING_REQUEST:
            return
        self.stats["requests"] += 1
        if not self._allowed(addr[0]):
            self.stats["rate_limited"] += 1
            return
        change = struct.unpack(">I", attrs[A_CHANGE_REQUEST])[0] if len(attrs.get(A_CHANGE_REQUEST, b"")) == 4 else 0
        if change & CHANGE_IP:
            return                                          # one address only: the client times out and knows it
        out = {"main": self.main, "alt": self.alt, "change": self.change}
        reply_from = self.change if change & CHANGE_PORT else out[which]
        if change & CHANGE_PORT:
            self.stats["changed_port"] += 1
        reply_from.sendto(binding_response(txid, addr), addr)
        self.stats["responses"] += 1

    async def probe(self, addr: tuple, timeout: float = 2.0, tries: int = 2) -> Optional[float]:
        """Send a Binding request from the CHANGE socket (a source port no node ever sends to) and wait for any answer.
        Returns the round trip in ms, or None. Answering means the address accepts unsolicited packets from a new port."""
        req, txid = binding_request()
        fut = asyncio.get_running_loop().create_future()
        self.pending[txid] = fut
        self.stats["probes"] += 1
        t0 = time.monotonic()
        try:
            for _ in range(tries):
                self.change.sendto(req, addr)
                try:
                    await asyncio.wait_for(asyncio.shield(fut), timeout / tries)
                    self.stats["probes_answered"] += 1
                    return round((time.monotonic() - t0) * 1000, 1)
                except asyncio.TimeoutError:
                    continue
            return None
        finally:
            self.pending.pop(txid, None)


# ---------------------------------------------------------------- client side

@dataclass
class NatInfo:
    type: str = "unknown"                 # one of NAT_TYPES
    mapped: Optional[tuple] = None        # public (ip, port) of the node's UDP socket as seen by the relay
    mapping: str = "unknown"              # "independent" | "dependent" | "unknown"
    filtering: str = "unknown"            # "open" (change-port answer arrived) | "restricted" | "unknown"
    delta: Optional[int] = None           # symmetric NAT that allocates ports in steps of `delta`: the next mapping is predictable
    cgnat: bool = False                   # a second NAT (carrier-grade, or a router behind another router) sits between us and the internet
    via: Optional[str] = None             # how an open inbound port was obtained: "pcp" | "natpmp" | "upnp" (None: not at all)

    def public_endpoint(self) -> Optional[str]:
        """The address other nodes can try. Useless for a symmetric NAT (the port changes with the destination)."""
        if self.mapped and self.type in ("open", "cone", "port-restricted"):
            return f"{self.mapped[0]}:{self.mapped[1]}"
        return None


Transact = Callable[[tuple, int], Awaitable[Optional[tuple]]]   # (server_addr, change_flags) -> mapped address or None

MAX_DELTA = 64          # a symmetric NAT whose consecutive mappings are further apart than this is treated as random


def predict_delta(ports: list) -> Optional[int]:
    """Port allocation step of a symmetric NAT from the mapped ports of consecutive destinations (at least three), or None when the
    ports do not look sequential. Equal steps (e.g. +1, +1) are a clear pattern; different small positive steps are accepted too
    (a NAT that also served another flow in between) with the last step as the guess."""
    if len(ports) < 3:
        return None
    steps = [(b - a) for a, b in zip(ports, ports[1:])]
    if all(s == steps[0] for s in steps) and 0 < abs(steps[0]) <= MAX_DELTA:
        return steps[0]
    if all(0 < s <= MAX_DELTA for s in steps):
        return steps[-1]
    return None


def predicted_ports(base_port: int, delta: int, count: int = 16) -> list:
    """The ports to probe for a symmetric NAT whose last known mapping was `base_port`: base + delta * k, k = 1..count (the NAT may
    have served other flows meanwhile, so the window is wide). Unprivileged ports only."""
    out = []
    for k in range(1, count + 1):
        p = base_port + delta * k
        if 1024 <= p <= 65535:
            out.append(p)
    return out


CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")        # RFC 6598 shared address space: between a carrier's NAT and its customers


def double_nat(mapped_ip: Optional[str], router_ip: Optional[str]) -> bool:
    """Is there a second NAT between this node and the internet? `mapped_ip` is the address the relay sees; `router_ip` the WAN address
    the home router reports (UPnP / NAT-PMP / PCP), if it answered. Signs: the mapped address is in the carrier-grade range
    100.64.0.0/10; or the router reports a WAN address that is not the one the relay sees (another translator in between).
    A relay on the same private network as the node (a lab) sees the router's own address: equal, not double."""
    def ip(s):
        try:
            return ipaddress.ip_address(s.strip("[]")) if s else None
        except ValueError:
            return None
    m, r = ip(mapped_ip), ip(router_ip)
    if m is not None and m in CGNAT_NET:
        return True
    return r is not None and not r.is_unspecified and r != m


async def classify(transact: Transact, main: tuple, alt: tuple, local: Optional[tuple] = None, third: Optional[tuple] = None) -> NatInfo:
    """`transact` sends one Binding request from the node's data socket and returns the mapped address of the answer
    (whatever source it came from) or None after its retries. `third` is one more destination (the relay's change-port socket),
    used only when the NAT turned out to be symmetric, to see how its ports are allocated."""
    m1 = await transact(main, 0)
    if m1 is None:
        return NatInfo("blocked")
    info = NatInfo(mapped=m1)
    m2 = await transact(alt, 0)
    if m2 is not None:
        info.mapping = "independent" if m2 == m1 else "dependent"
    if info.mapping != "dependent":
        info.filtering = "open" if await transact(main, CHANGE_PORT) is not None else "restricted"
    elif third is not None and m2 is not None and m1[0] == m2[0]:
        m3 = await transact(third, 0)             # no filtering test for a symmetric NAT, so the unsolicited-port rule does not apply
        if m3 is not None and m3[0] == m1[0]:
            info.delta = predict_delta([m1[1], m2[1], m3[1]])
            if info.delta is not None:
                info.mapped = m3                  # the newest mapping: the prediction counts on from here
    if local is not None and tuple(local) == tuple(m1):
        info.type = "open"
    elif info.mapping == "dependent":
        info.type = "symmetric"
    elif info.mapping == "unknown":
        info.type = "unknown"
    elif info.filtering == "open":
        info.type = "cone"
    else:
        info.type = "port-restricted"
    return info


def can_punch(a: str, b: str, a_pred: bool = False, b_pred: bool = False, a_cgnat: bool = False, b_cgnat: bool = False) -> bool:
    """Can two nodes with these NAT types open a direct UDP path with the help of a relay? Unknown types are tried.
    `*_pred`: that side's symmetric NAT allocates ports predictably (see predict_delta), so the peer can probe the ports it will
    use: this rescues symmetric <-> port-restricted and symmetric <-> symmetric. `*_cgnat`: that side is behind a second NAT: a
    punched hole is then not worth waiting for, unless the other side accepts unsolicited packets ("open")."""
    hard = {"symmetric"}
    tough = {"symmetric", "port-restricted"}
    ok = not ((a in hard and b in tough) or (b in hard and a in tough))
    if not ok:
        if a == "symmetric" and b == "symmetric":
            ok = a_pred and b_pred
        elif a == "symmetric":
            ok = a_pred
        else:
            ok = b_pred
    if ok and (a_cgnat or b_cgnat):
        ok = (b == "open") if a_cgnat and not b_cgnat else (a == "open") if b_cgnat and not a_cgnat else False
    return ok


def punch_ports(nat_type: Optional[str], mapped: Optional[str], delta: Optional[int]) -> list:
    """Extra ports to probe on a peer: only for a symmetric NAT with a predictable step and a known last mapping ("ip:port")."""
    if nat_type != "symmetric" or not delta or not mapped:
        return []
    ip, _, port = mapped.rpartition(":")
    try:
        base = int(port)
    except ValueError:
        return []
    return [(ip.strip("[]"), p) for p in predicted_ports(base, delta)]


class NatProber:
    """Client side on the node's own UDP socket: `send(data, addr)` is the socket's sendto, `feed(data, addr)` must be
    called for every datagram that `is_stun`."""

    def __init__(self, send: Callable[[bytes, tuple], None], timeout: float = 0.6, tries: int = 3):
        self.send, self.timeout, self.tries = send, timeout, tries
        self.pending = {}                                  # txid -> (future, expected server ip)

    def feed(self, data: bytes, addr: tuple) -> bool:
        msg = parse(data)
        if not msg or msg[0] != BINDING_SUCCESS:
            return False
        ent = self.pending.get(msg[1])
        if ent is None or addr[0] != ent[1]:
            return False
        m = mapped_of(msg)
        if m and not ent[0].done():
            ent[0].set_result(m)
        return True

    async def transact(self, dst: tuple, change: int = 0) -> Optional[tuple]:
        req, txid = binding_request(change)
        fut = asyncio.get_running_loop().create_future()
        self.pending[txid] = (fut, dst[0])
        try:
            for _ in range(self.tries):
                self.send(req, dst)
                try:
                    return await asyncio.wait_for(asyncio.shield(fut), self.timeout)
                except asyncio.TimeoutError:
                    continue
            return None
        finally:
            self.pending.pop(txid, None)


# ---------------------------------------------------------------- reachability test target rules

def probe_target_ok(endpoint: str, client_ip: str, is_admin: bool = False, allow_loopback: bool = False) -> Optional[tuple]:
    """Where the relay may send a reachability probe: the caller's own address (or anything routable for an operator).
    Returns (ip, port) or None. Loopback, link-local, multicast and unspecified addresses are never allowed, so the
    service cannot be used to poke at the relay's own network."""
    try:
        host, _, port = endpoint.rpartition(":")
        ip = ipaddress.ip_address(host.strip("[]"))
        port = int(port)
    except ValueError:
        return None
    if ip.is_loopback and allow_loopback:                  # tests only
        pass
    elif not 1 <= port <= 65535 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return None
    if not 1 <= port <= 65535:
        return None
    if not is_admin and str(ip) != client_ip:
        return None
    return str(ip), port
