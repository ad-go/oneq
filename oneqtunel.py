#!/usr/bin/env python3
"""oneqtunel: point-to-point VPN over a TUN interface with a hybrid post-quantum handshake.

Educational project, not independently audited.

Static keys   : X25519 (32 B) + ML-KEM-768 (seed 64 B); public key = 32 + 1184 = 1216 B.
Handshake     : 2 messages, both fragmented at application level (<= 1200 B per datagram).
  INIT 0x11 (2329 B) = type | E_i | ek_e | ct_sr | AEAD(k1, timestamp)
  RESP 0x12 (2225 B) = type | E_r | ct_e | ct_si | AEAD(k2, "")
  The ML-KEM secret comes before the X25519 secret in every KDF input (X25519MLKEM768 order).
Data   0x13   : type | counter(8) | ChaCha20-Poly1305, 1024-packet anti-replay window.
Control       : PUNCH 0x14 (NAT hole punching), FRAG 0x15 (handshake fragment).
Transport     : direct UDP, or opaque datagrams relayed over wss://.../v1/relay.
"""
import pqtls  # noqa: F401  (must be first: sets OPENSSL_CONF before ssl is loaded)

import argparse
import asyncio
import base64
import collections
import dataclasses
import fcntl
import hashlib
import json
import logging
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("tunsec")

# Any protocol change gets a new version here.
LABEL = b"tunsec-pq/v1 hybrid X25519+ML-KEM-768 ChaCha20Poly1305 SHA256"

T_INIT, T_RESP, T_DATA, T_PUNCH, T_FRAG = 0x11, 0x12, 0x13, 0x14, 0x15

X_LEN, KEM_PUB_LEN, KEM_CT_LEN, KEM_SEED_LEN = 32, 1184, 1088, 64
PUB_LEN = X_LEN + KEM_PUB_LEN          # 1216
TS_LEN, TAG_LEN = 8, 16
INIT_LEN = 1 + X_LEN + KEM_PUB_LEN + KEM_CT_LEN + TS_LEN + TAG_LEN   # 2329
RESP_LEN = 1 + X_LEN + 2 * KEM_CT_LEN + TAG_LEN                       # 2225

REKEY_AFTER = 120.0
REJECT_AFTER = 180.0
KEEPALIVE = 25.0
HS_RETRY = 2.0
PROBE_EVERY = 20.0
DIRECT_STALE = 75.0
MAX_COUNTER = 2 ** 60

MAX_DGRAM = 1200
FRAG_HDR = struct.Struct(">BIBB")      # type, msg_id, index, total
FRAG_PAYLOAD = MAX_DGRAM - FRAG_HDR.size
MAX_FRAGS = 4

CTL_PROBE, CTL_PROBE_REPLY = b"\x00", b"\x01"   # 1-byte data payloads (IP packets never look like this)


# ---------------------------------------------------------------- crypto primitives

def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def kdf(ck: bytes, ikm: bytes, n: int = 64) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=ck, info=b"tunsec-pq kdf").derive(ikm)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(b"\0" * 12, plaintext, aad)


def aead_decrypt(key: bytes, ct: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(b"\0" * 12, ct, aad)


def x_raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Identity:
    """Hybrid static key: X25519 private key + ML-KEM-768 seed."""

    def __init__(self, x_priv: X25519PrivateKey, kem_priv: MLKEM768PrivateKey):
        self.x = x_priv
        self.kem = kem_priv
        self.pub = x_raw(x_priv.public_key()) + kem_priv.public_key().public_bytes_raw()
        assert len(self.pub) == PUB_LEN

    @classmethod
    def generate(cls):
        return cls(X25519PrivateKey.generate(), MLKEM768PrivateKey.generate())

    def to_bytes(self) -> bytes:
        xr = self.x.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
        return xr + self.kem.private_bytes_raw()

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != X_LEN + KEM_SEED_LEN:
            raise ValueError("bad private key length")
        return cls(X25519PrivateKey.from_private_bytes(b[:X_LEN]), MLKEM768PrivateKey.from_seed_bytes(b[X_LEN:]))

    @property
    def node_id(self) -> bytes:
        return node_id(self.pub)


def node_id(pub: bytes) -> bytes:
    return hashlib.sha256(pub).digest()[:16]


def save_identity(path: str, ident: Identity, pub_path: Optional[str] = None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(ident.to_bytes()).decode() + "\n")
    if pub_path:
        with open(pub_path, "w") as f:
            f.write(base64.b64encode(ident.pub).decode() + "\n")


def load_identity(path: str) -> Identity:
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise PermissionError(f"{path}: private key must not be accessible by group/others (chmod 600)")
    with open(path) as f:
        return Identity.from_bytes(base64.b64decode(f.read().strip()))


def load_public(value: str) -> bytes:
    """`value` is a file with base64 or the base64 string itself."""
    if os.path.isfile(value):
        with open(value) as f:
            value = f.read().strip()
    pub = base64.b64decode(value)
    if len(pub) != PUB_LEN:
        raise ValueError(f"public key must be {PUB_LEN} bytes, got {len(pub)}")
    return pub


# ---------------------------------------------------------------- handshake

class HandshakeError(Exception):
    pass


@dataclasses.dataclass
class InitState:
    ck: bytes
    h: bytes
    e: X25519PrivateKey
    dk: MLKEM768PrivateKey
    created: float


def _split_pub(pub: bytes):
    return pub[:X_LEN], pub[X_LEN:]


def init_create(me: Identity, peer_pub: bytes, now_us: Optional[int] = None):
    """Initiator: build the INIT message. Returns (msg, state)."""
    xr, kemr = _split_pub(peer_pub)
    ck = H(LABEL)
    h = H(ck, me.pub, peer_pub)
    e = X25519PrivateKey.generate()
    E = x_raw(e.public_key())
    dk = MLKEM768PrivateKey.generate()
    ek = dk.public_key().public_bytes_raw()
    k_sr, ct_sr = MLKEM768PublicKey.from_public_bytes(kemr).encapsulate()
    h = H(h, E, ek, ct_sr)
    dh1 = e.exchange(X25519PublicKey.from_public_bytes(xr))
    dh2 = me.x.exchange(X25519PublicKey.from_public_bytes(xr))
    okm = kdf(ck, k_sr + dh1 + dh2 + h)
    ck, k1 = okm[:32], okm[32:]
    ts = struct.pack(">Q", now_us if now_us is not None else time.time_ns() // 1000)
    enc = aead_encrypt(k1, ts, h)
    h = H(h, enc)
    msg = bytes([T_INIT]) + E + ek + ct_sr + enc
    assert len(msg) == INIT_LEN
    return msg, InitState(ck, h, e, dk, time.monotonic())


def init_consume(me: Identity, peer_pub: bytes, msg: bytes):
    """Responder: validate INIT from the configured peer.
    Returns (ts_us, ck, h, E_i, ek_e). Raises HandshakeError."""
    if len(msg) != INIT_LEN or msg[0] != T_INIT:
        raise HandshakeError("bad INIT length/type")
    o = 1
    E = msg[o:o + X_LEN]; o += X_LEN
    ek = msg[o:o + KEM_PUB_LEN]; o += KEM_PUB_LEN
    ct_sr = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    enc = msg[o:]
    xi, _ = _split_pub(peer_pub)
    ck = H(LABEL)
    h = H(ck, peer_pub, me.pub)
    h = H(h, E, ek, ct_sr)
    try:
        k_sr = me.kem.decapsulate(ct_sr)
        dh1 = me.x.exchange(X25519PublicKey.from_public_bytes(E))
        dh2 = me.x.exchange(X25519PublicKey.from_public_bytes(xi))
        okm = kdf(ck, k_sr + dh1 + dh2 + h)
        ck, k1 = okm[:32], okm[32:]
        ts = aead_decrypt(k1, enc, h)
    except (InvalidTag, ValueError) as e:
        raise HandshakeError("INIT authentication failed") from e
    h = H(h, enc)
    return struct.unpack(">Q", ts)[0], ck, h, E, ek


def resp_create(me: Identity, peer_pub: bytes, ck: bytes, h: bytes, E_i: bytes, ek_e: bytes):
    """Responder: build RESP. Returns (msg, send_key, recv_key)."""
    xi, kemi = _split_pub(peer_pub)
    e = X25519PrivateKey.generate()
    E = x_raw(e.public_key())
    k_e, ct_e = MLKEM768PublicKey.from_public_bytes(ek_e).encapsulate()
    k_si, ct_si = MLKEM768PublicKey.from_public_bytes(kemi).encapsulate()
    h = H(h, E, ct_e, ct_si)
    dh_ee = e.exchange(X25519PublicKey.from_public_bytes(E_i))
    dh_se = e.exchange(X25519PublicKey.from_public_bytes(xi))
    okm = kdf(ck, k_e + k_si + dh_ee + dh_se + h)
    ck, k2 = okm[:32], okm[32:]
    enc = aead_encrypt(k2, b"", h)
    h = H(h, enc)
    msg = bytes([T_RESP]) + E + ct_e + ct_si + enc
    assert len(msg) == RESP_LEN
    t = kdf(ck, b"")
    return msg, t[32:], t[:32]          # responder sends with the second half


def resp_consume(me: Identity, st: InitState, msg: bytes):
    """Initiator: validate RESP against a pending INIT. Returns (send_key, recv_key)."""
    if len(msg) != RESP_LEN or msg[0] != T_RESP:
        raise HandshakeError("bad RESP length/type")
    o = 1
    E = msg[o:o + X_LEN]; o += X_LEN
    ct_e = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    ct_si = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    enc = msg[o:]
    h = H(st.h, E, ct_e, ct_si)
    try:
        k_e = st.dk.decapsulate(ct_e)
        k_si = me.kem.decapsulate(ct_si)
        Er = X25519PublicKey.from_public_bytes(E)
        dh_ee = st.e.exchange(Er)
        dh_se = me.x.exchange(Er)
        okm = kdf(st.ck, k_e + k_si + dh_ee + dh_se + h)
        ck, k2 = okm[:32], okm[32:]
        aead_decrypt(k2, enc, h)
    except (InvalidTag, ValueError) as e:
        raise HandshakeError("RESP authentication failed") from e
    t = kdf(ck, b"")
    return t[:32], t[32:]


# ---------------------------------------------------------------- data plane

class ReplayWindow:
    def __init__(self, size: int = 1024):
        self.size = size
        self.mask = (1 << size) - 1
        self.top = -1
        self.bits = 0

    def check(self, c: int) -> bool:
        if c > self.top:
            return True
        d = self.top - c
        return d < self.size and not (self.bits >> d) & 1

    def update(self, c: int):
        if c > self.top:
            self.bits = 1 if self.top < 0 else ((self.bits << (c - self.top)) | 1) & self.mask
            self.top = c
        else:
            self.bits |= 1 << (self.top - c)


class Session:
    def __init__(self, send_key: bytes, recv_key: bytes, initiator: bool,
                 clock: Callable[[], float] = time.monotonic):
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self.initiator = initiator
        self.clock = clock
        self.created = clock()
        self.ctr = 0
        self.window = ReplayWindow()

    def age(self) -> float:
        return self.clock() - self.created

    def usable(self) -> bool:
        return self.age() < REJECT_AFTER and self.ctr < MAX_COUNTER

    def encrypt(self, payload: bytes) -> bytes:
        if not self.usable():
            raise HandshakeError("session expired")
        hdr = bytes([T_DATA]) + struct.pack(">Q", self.ctr)
        self.ctr += 1
        return hdr + self._send.encrypt(b"\0" * 4 + hdr[1:], payload, hdr)

    def decrypt(self, pkt: bytes) -> Optional[bytes]:
        if len(pkt) < 9 + TAG_LEN or pkt[0] != T_DATA or self.age() >= REJECT_AFTER:
            return None
        ctr = struct.unpack(">Q", pkt[1:9])[0]
        if not self.window.check(ctr):
            return None
        try:
            pt = self._recv.decrypt(b"\0" * 4 + pkt[1:9], pkt[9:], pkt[:9])
        except InvalidTag:
            return None
        self.window.update(ctr)
        return pt


# ---------------------------------------------------------------- fragmentation

def fragment(msg: bytes, msg_id: Optional[int] = None) -> list:
    """Split a handshake message into datagrams of at most MAX_DGRAM bytes."""
    if msg_id is None:
        msg_id = secrets.randbits(32)
    chunks = [msg[i:i + FRAG_PAYLOAD] for i in range(0, len(msg), FRAG_PAYLOAD)] or [b""]
    if len(chunks) > MAX_FRAGS:
        raise ValueError("message too large to fragment")
    return [FRAG_HDR.pack(T_FRAG, msg_id, i, len(chunks)) + c for i, c in enumerate(chunks)]


class Reassembler:
    """Bounded reassembly: DoS limits on count, bytes, per-source entries and lifetime."""

    def __init__(self, ttl: float = 5.0, max_entries: int = 16, max_per_src: int = 4,
                 max_bytes: int = 64 * 1024, clock: Callable[[], float] = time.monotonic):
        self.ttl, self.max_entries, self.max_per_src, self.max_bytes = ttl, max_entries, max_per_src, max_bytes
        self.clock = clock
        self.entries = {}   # (src, msg_id) -> [expires, total, {idx: bytes}, nbytes]
        self.bytes = 0

    def _gc(self):
        now = self.clock()
        for k in [k for k, v in self.entries.items() if v[0] <= now]:
            self._drop(k)

    def _drop(self, k):
        e = self.entries.pop(k, None)
        if e:
            self.bytes -= e[3]

    def feed(self, src, dgram: bytes) -> Optional[bytes]:
        if len(dgram) > MAX_DGRAM or len(dgram) < FRAG_HDR.size:
            return None
        t, mid, idx, total = FRAG_HDR.unpack_from(dgram)
        body = dgram[FRAG_HDR.size:]
        if t != T_FRAG or not 1 <= total <= MAX_FRAGS or idx >= total:
            return None
        if idx < total - 1 and len(body) != FRAG_PAYLOAD:     # only the last fragment may be short
            return None
        self._gc()
        key = (src, mid)
        e = self.entries.get(key)
        if e is None:
            if len(self.entries) >= self.max_entries:
                return None
            if sum(1 for k in self.entries if k[0] == src) >= self.max_per_src:
                return None
            e = self.entries[key] = [self.clock() + self.ttl, total, {}, 0]
        elif e[1] != total:
            self._drop(key)
            return None
        if idx in e[2]:
            return None                                       # duplicate
        if self.bytes + len(body) > self.max_bytes:
            return None
        e[2][idx] = body
        e[3] += len(body)
        self.bytes += len(body)
        if len(e[2]) == total:
            msg = b"".join(e[2][i] for i in range(total))
            self._drop(key)
            return msg
        return None


# ---------------------------------------------------------------- STUN (RFC 5389 binding request)

STUN_COOKIE = 0x2112A442


def stun_request():
    txid = secrets.token_bytes(12)
    return struct.pack(">HHI", 0x0001, 0, STUN_COOKIE) + txid, txid


def is_stun(data: bytes) -> bool:
    return len(data) >= 20 and data[0] < 0x04 and struct.unpack(">I", data[4:8])[0] == STUN_COOKIE


def stun_parse(data: bytes, txid: bytes):
    """Return (ip, port) from XOR-MAPPED-ADDRESS (IPv4) or None."""
    if not is_stun(data) or data[8:20] != txid or struct.unpack(">H", data[:2])[0] != 0x0101:
        return None
    o, end = 20, 20 + struct.unpack(">H", data[2:4])[0]
    while o + 4 <= min(end, len(data)):
        at, al = struct.unpack(">HH", data[o:o + 4])
        v = data[o + 4:o + 4 + al]
        if at == 0x0020 and al >= 8 and v[1] == 1:
            port = struct.unpack(">H", v[2:4])[0] ^ (STUN_COOKIE >> 16)
            ip = struct.unpack(">I", v[4:8])[0] ^ STUN_COOKIE
            return socket.inet_ntoa(struct.pack(">I", ip)), port
        o += 4 + ((al + 3) & ~3)
    return None


# ---------------------------------------------------------------- TUN / interface helpers

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
SIOCGIFADDR = 0x8915


class Tun:
    def __init__(self, name: str):
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
        res = fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        self.name = res[:16].split(b"\0")[0].decode()

    def fileno(self):
        return self.fd

    def read(self) -> bytes:
        return os.read(self.fd, 65535)

    def write(self, pkt: bytes):
        os.write(self.fd, pkt)


def iface_ipv4(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", iface.encode()[:15]))
        return socket.inet_ntoa(r[20:24])
    finally:
        s.close()


def configure_tun(name: str, addr: str, mtu: int):
    subprocess.run(["ip", "addr", "add", addr, "dev", name], check=True)
    subprocess.run(["ip", "link", "set", name, "mtu", str(mtu), "up"], check=True)


def parse_hostport(s: str):
    h, _, p = s.rpartition(":")
    return h, int(p)


# ---------------------------------------------------------------- rendezvous + relay clients

class Rendezvous:
    """Client for the HTTPS rendezvous API (TLS 1.3, X25519MLKEM768 only)."""

    def __init__(self, url: str, token: str, cafile: Optional[str], ident_pub: bytes, ident: Optional["Identity"] = None):
        import aiohttp
        self.aiohttp = aiohttp
        self.url = url.rstrip("/")
        self.token = token
        self.pub = ident_pub
        self.ident = ident                  # with the private key the registration proves possession of it (oneqpop)
        self._pop = None
        self._pop_unsupported = False
        self.id = node_id(ident_pub).hex()
        self.ssl = pqtls.client_context(cafile)
        self.session = None

    def _hdr(self):
        return {"Authorization": "Bearer " + self.token}

    async def _s(self):
        if self.session is None:
            self.session = self.aiohttp.ClientSession(timeout=self.aiohttp.ClientTimeout(total=10))
        return self.session

    async def proof(self, force: bool = False) -> Optional[dict]:
        """A proof of possession of our key (cached until shortly before it expires), or None: no key here, or a server without the feature."""
        if self.ident is None or self._pop_unsupported:
            return None
        import time as _time
        if not force and self._pop is not None and self._pop["exp"] - _time.time() > 15:
            return self._pop
        import oneqpop
        s = await self._s()
        async with s.post(f"{self.url}/v1/nodes/{self.id}/challenge", json={"pub": base64.b64encode(self.pub).decode()},
                          headers=self._hdr(), ssl=self.ssl) as r:
            if r.status in (404, 405):
                self._pop_unsupported = True
                return None
            r.raise_for_status()
            self._pop = oneqpop.answer(self.ident, await r.json())
        return self._pop

    async def register(self, endpoints: list):
        body = {"pub": base64.b64encode(self.pub).decode(), "endpoints": endpoints}
        s = await self._s()
        for attempt in (0, 1):
            pop = await self.proof(force=attempt == 1)
            if pop:
                body["pop"] = pop
            async with s.put(f"{self.url}/v1/nodes/{self.id}", json=body, headers=self._hdr(), ssl=self.ssl) as r:
                if r.status == 403 and attempt == 0 and self.ident is not None and "proof of possession" in await r.text():
                    self._pop_unsupported = False        # required, or the proof expired: a fresh challenge, one retry
                    continue
                r.raise_for_status()
                return await r.json()

    async def lookup(self, peer_id_hex: str):
        s = await self._s()
        async with s.get(f"{self.url}/v1/nodes/{peer_id_hex}", headers=self._hdr(), ssl=self.ssl) as r:
            if r.status == 404:
                return None
            r.raise_for_status()
            return await r.json()

    async def close(self):
        if self.session:
            await self.session.close()


class RelayClient:
    """wss relay: binary frames `dest_node_id(16) | datagram` out, `src_node_id(16) | datagram` in."""

    def __init__(self, url: str, token: str, cafile: Optional[str], my_id_hex: str,
                 on_msg: Callable[[bytes, bytes], None], proof: Optional[Callable] = None):
        import aiohttp
        self.aiohttp = aiohttp
        self.url = url.rstrip("/").replace("https://", "wss://", 1) + "/v1/relay"
        self.token, self.my_id, self.on_msg = token, my_id_hex, on_msg
        self.proof = proof                  # async () -> proof dict or None (Rendezvous.proof): the relay slot of a verified node needs it
        self.ssl = pqtls.client_context(cafile)
        self.q = asyncio.Queue(maxsize=512)
        self.connected = False
        self.enabled = asyncio.Event()

    def send(self, dest_id: bytes, data: bytes):
        try:
            self.q.put_nowait(dest_id + data)
        except asyncio.QueueFull:
            pass

    async def run(self):
        backoff = 1.0
        while True:
            await self.enabled.wait()
            try:
                hdr = {"Authorization": "Bearer " + self.token}
                pop = await self.proof() if self.proof else None
                if pop:
                    hdr["X-Oneq-Pop"] = base64.b64encode(json.dumps(pop).encode()).decode()
                async with self.aiohttp.ClientSession() as s:
                    async with s.ws_connect(f"{self.url}?node={self.my_id}", ssl=self.ssl, max_msg_size=8192, headers=hdr) as ws:
                        log.info("relay connected")
                        self.connected, backoff = True, 1.0
                        sender = asyncio.ensure_future(self._pump(ws))
                        try:
                            async for m in ws:
                                if m.type == self.aiohttp.WSMsgType.BINARY and len(m.data) > 16:
                                    self.on_msg(m.data[:16], m.data[16:])
                        finally:
                            sender.cancel()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("relay error: %s", e)
            self.connected = False
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 15.0)

    async def _pump(self, ws):
        while True:
            await ws.send_bytes(await self.q.get())


# ---------------------------------------------------------------- node

@dataclasses.dataclass
class Config:
    ifname: str = "pq0"
    addr: Optional[str] = None
    mtu: Optional[int] = None
    listen: tuple = ("0.0.0.0", 0)
    via: Optional[str] = None
    no_config: bool = False
    advertise: list = dataclasses.field(default_factory=list)
    stun: Optional[str] = None
    rendezvous: Optional[str] = None
    token: Optional[str] = None
    cafile: Optional[str] = None
    peer_endpoints: list = dataclasses.field(default_factory=list)
    force_relay: bool = False
    no_relay: bool = False
    relay_after: float = 10.0
    max_skew: float = 180.0


class UdpProto(asyncio.DatagramProtocol):
    def __init__(self, node):
        self.node = node

    def datagram_received(self, data, addr):
        self.node.on_udp(data, addr)

    def error_received(self, exc):
        log.debug("udp error: %s", exc)


class Node:
    def __init__(self, ident: Identity, peer_pub: bytes, cfg: Config, tun):
        self.me, self.peer_pub, self.cfg, self.tun = ident, peer_pub, cfg, tun
        self.peer_id = node_id(peer_pub)
        self.initiator = ident.pub < peer_pub
        self.cur: Optional[Session] = None
        self.prev: Optional[Session] = None
        self.pending = collections.deque(maxlen=4)
        self.reasm = Reassembler()
        self.udp = None
        self.candidates = [parse_hostport(e) for e in cfg.peer_endpoints]
        self.local_candidates = list(cfg.advertise)
        self.peer_addr = None
        self.path = "direct"
        self.last_direct_rx = 0.0
        self.last_tx = 0.0
        self.last_probe = 0.0
        self.last_punch = 0.0
        self.last_init = 0.0
        self.last_peer_ts = 0
        self.init_budget = 10.0
        self.init_budget_t = time.monotonic()
        self.t_nosession = time.monotonic()
        self.relay: Optional[RelayClient] = None
        self.rv: Optional[Rendezvous] = None
        self.stun_tx = None
        self.stun_result = None
        self.tasks = []
        self.on_session = None   # test hook

    # ---- sending
    def _udp_send(self, data: bytes, addr):
        if self.udp is not None:
            self.udp.sendto(data, addr)

    def _relay_send(self, data: bytes):
        if self.relay is not None:
            self.relay.send(self.peer_id, data)

    def send_hs(self, msg: bytes, via):
        """via: ('udp', addr) | ('relay',)."""
        for d in fragment(msg):
            if via[0] == "udp":
                self._udp_send(d, via[1])
            else:
                self._relay_send(d)

    def _send_raw(self, pkt: bytes):
        self.last_tx = time.monotonic()
        if self.path == "relay" or self.cfg.force_relay:
            self._relay_send(pkt)
        elif self.peer_addr:
            self._udp_send(pkt, self.peer_addr)
        elif self.candidates:
            for c in self.candidates:
                self._udp_send(pkt, c)

    def send_payload(self, payload: bytes):
        s = self.cur
        if s is None or not s.usable():
            return
        try:
            self._send_raw(s.encrypt(payload))
        except HandshakeError:
            pass

    # ---- receiving
    def on_udp(self, data: bytes, addr):
        if not data:
            return
        if self.stun_tx and is_stun(data):
            r = stun_parse(data, self.stun_tx)
            if r:
                self.stun_result = r
            return
        t = data[0]
        if t == T_DATA:
            self._on_data(data, ("udp", addr))
        elif t == T_FRAG:
            msg = self.reasm.feed(addr, data)
            if msg:
                self._on_hs(msg, ("udp", addr))
        elif t == T_PUNCH:
            log.debug("punch from %s", addr)

    def on_relay(self, src_id: bytes, data: bytes):
        if src_id != self.peer_id or not data:
            return
        if data[0] == T_DATA:
            self._on_data(data, ("relay",))
        elif data[0] == T_FRAG:
            msg = self.reasm.feed(("relay",), data)
            if msg:
                self._on_hs(msg, ("relay",))

    def _on_hs(self, msg: bytes, via):
        if msg[0] == T_INIT and not self.initiator:
            self._on_init(msg, via)
        elif msg[0] == T_RESP and self.initiator:
            self._on_resp(msg, via)

    def _budget_ok(self) -> bool:
        now = time.monotonic()
        self.init_budget = min(10.0, self.init_budget + (now - self.init_budget_t) * 5.0)
        self.init_budget_t = now
        if self.init_budget < 1:
            return False
        self.init_budget -= 1
        return True

    def _on_init(self, msg, via):
        if not self._budget_ok():
            return
        try:
            ts, ck, h, E, ek = init_consume(self.me, self.peer_pub, msg)
        except HandshakeError as e:
            log.debug("INIT rejected: %s", e)
            return
        now_us = time.time_ns() // 1000
        if ts <= self.last_peer_ts or abs(now_us - ts) > self.cfg.max_skew * 1e6:
            log.debug("INIT rejected: replay or clock skew")
            return
        self.last_peer_ts = ts
        resp, sk, rk = resp_create(self.me, self.peer_pub, ck, h, E, ek)
        self._install(Session(sk, rk, False), via)
        self.send_hs(resp, via)

    def _on_resp(self, msg, via):
        for st in list(self.pending):
            try:
                sk, rk = resp_consume(self.me, st, msg)
            except HandshakeError:
                continue
            self.pending.clear()
            self._install(Session(sk, rk, True), via)
            self.send_payload(b"")        # confirm so the responder learns our address
            return

    def _install(self, s: Session, via):
        self.prev, self.cur = self.cur, s
        self._note_path(via)
        log.info("session established (%s), path=%s", "initiator" if s.initiator else "responder", self.path)
        if self.on_session:
            self.on_session(self)

    def _note_path(self, via):
        now = time.monotonic()
        if via[0] == "udp":
            self.peer_addr = via[1]
            self.last_direct_rx = now
            self.path = "direct"
        elif now - self.last_direct_rx > DIRECT_STALE:
            self.path = "relay"

    def _on_data(self, pkt: bytes, via):
        pt = None
        for s in (self.cur, self.prev):
            if s is not None:
                pt = s.decrypt(pkt)
                if pt is not None:
                    break
        if pt is None:
            return
        was_relay = self.path == "relay"
        self._note_path(via)
        if via[0] == "udp" and was_relay and self.path == "direct":
            log.info("back on direct path %s", self.peer_addr)
        if pt == CTL_PROBE:
            self.send_payload(CTL_PROBE_REPLY)
        elif len(pt) > 1:
            try:
                self.tun.write(pt)
            except OSError as e:
                log.debug("tun write: %s", e)

    def _on_tun(self):
        for _ in range(64):
            try:
                pkt = self.tun.read()
            except BlockingIOError:
                return
            except OSError:
                return
            if pkt:
                self.send_payload(pkt)

    # ---- periodic work
    def _send_init(self):
        msg, st = init_create(self.me, self.peer_pub)
        self.pending.append(st)
        self.last_init = time.monotonic()
        if not self.cfg.force_relay:
            for c in self.candidates:
                self.send_hs(msg, ("udp", c))
        if self.relay is not None and self.relay.enabled.is_set():
            self.send_hs(msg, ("relay",))

    def _tick(self):
        now = time.monotonic()
        cur = self.cur
        if cur is not None and not cur.usable():
            log.warning("session expired")
            self.cur = None
            cur = None
        if self.prev is not None and not self.prev.usable():
            self.prev = None
        if cur is None:
            if self.t_nosession is None:
                self.t_nosession = now
            if (self.relay is not None and not self.relay.enabled.is_set()
                    and (self.cfg.force_relay or now - self.t_nosession >= self.cfg.relay_after)):
                log.info("no direct session after %.0fs: enabling relay", now - self.t_nosession)
                self.relay.enabled.set()
        else:
            self.t_nosession = None
        # punch + handshake
        if not self.cfg.force_relay and cur is None and self.candidates and now - self.last_punch >= 1.0:
            self.last_punch = now
            for c in self.candidates:
                self._udp_send(bytes([T_PUNCH]) + secrets.token_bytes(8), c)
        if self.initiator and (cur is None or cur.age() >= REKEY_AFTER) and now - self.last_init >= HS_RETRY:
            if self.candidates or (self.relay is not None and self.relay.enabled.is_set()):
                self._send_init()
        if cur is not None:
            if now - self.last_tx >= KEEPALIVE:
                self.send_payload(b"")
            if (self.path == "relay" and not self.cfg.force_relay and self.candidates
                    and now - self.last_probe >= PROBE_EVERY):
                self.last_probe = now
                pkt = cur.encrypt(CTL_PROBE)
                for c in self.candidates:
                    self._udp_send(pkt, c)
            if (self.path == "direct" and self.relay is not None and not self.cfg.force_relay
                    and now - self.last_direct_rx > DIRECT_STALE):
                self.path = "relay"
                log.info("direct path stale, using relay")

    async def _maint(self):
        while True:
            try:
                self._tick()
            except Exception:
                log.exception("tick")
            await asyncio.sleep(0.25)

    async def _rendezvous_loop(self):
        last_reg = 0.0
        while True:
            try:
                now = time.monotonic()
                if now - last_reg >= 20.0:
                    eps = list(dict.fromkeys(self.local_candidates + ([f"{self.stun_result[0]}:{self.stun_result[1]}"]
                                                                     if self.stun_result else [])))
                    await self.rv.register(eps)
                    last_reg = now
                rec = await self.rv.lookup(self.peer_id.hex())
                if rec and base64.b64decode(rec.get("pub", "")) == self.peer_pub:
                    self.candidates = [parse_hostport(e) for e in rec.get("endpoints", [])] or self.candidates
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("rendezvous: %s", e)
            await asyncio.sleep(3.0 if self.cur is None else 20.0)

    async def _stun_once(self, loop):
        host, port = parse_hostport(self.cfg.stun)
        ip = (await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][4]
        for _ in range(3):
            req, self.stun_tx = stun_request()
            self._udp_send(req, ip)
            await asyncio.sleep(1.0)
            if self.stun_result:
                log.info("STUN reflexive address %s:%s", *self.stun_result)
                return

    async def run(self):
        loop = asyncio.get_running_loop()
        cfg = self.cfg
        host, port = cfg.listen
        if cfg.via:
            host = iface_ipv4(cfg.via)
        transport, _ = await loop.create_datagram_endpoint(lambda: UdpProto(self), local_addr=(host, port))
        self.udp = transport
        bound = transport.get_extra_info("sockname")
        if cfg.via:
            self.local_candidates.append(f"{bound[0]}:{bound[1]}")
        if not self.local_candidates:
            self.local_candidates.append(f"{host if host != '0.0.0.0' else self._guess_ip()}:{bound[1]}")
        log.info("udp %s:%s, node_id %s, role %s", bound[0], bound[1], self.me.node_id.hex(),
                 "initiator" if self.initiator else "responder")
        loop.add_reader(self.tun.fileno(), self._on_tun)
        if cfg.rendezvous:
            self.rv = Rendezvous(cfg.rendezvous, cfg.token, cfg.cafile, self.me.pub, self.me)
        if cfg.rendezvous and not cfg.no_relay:
            self.relay = RelayClient(cfg.rendezvous, cfg.token, cfg.cafile, self.me.node_id.hex(), self.on_relay,
                                     proof=self.rv.proof if self.rv else None)
            self.tasks.append(asyncio.ensure_future(self.relay.run()))
        if cfg.rendezvous:
            self.tasks.append(asyncio.ensure_future(self._rendezvous_loop()))
        if cfg.stun:
            self.tasks.append(asyncio.ensure_future(self._stun_once(loop)))
        self.tasks.append(asyncio.ensure_future(self._maint()))
        try:
            await asyncio.gather(*self.tasks)
        finally:
            await self.close()

    def _guess_ip(self) -> str:
        """Local source address towards the rendezvous host (no packet is sent)."""
        from urllib.parse import urlsplit
        try:
            tgt = urlsplit(self.cfg.rendezvous).hostname if self.cfg.rendezvous else "192.0.2.1"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((tgt, 9))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    async def close(self):
        for t in self.tasks:
            t.cancel()
        if self.udp:
            self.udp.close()
        if self.rv:
            await self.rv.close()
        try:
            asyncio.get_running_loop().remove_reader(self.tun.fileno())
        except Exception:
            pass


# ---------------------------------------------------------------- CLI

def read_token(args) -> Optional[str]:
    if args.token_file:
        if os.name == "posix" and os.stat(args.token_file).st_mode & 0o077:
            raise PermissionError(f"{args.token_file}: token file must be mode 600")
        with open(args.token_file) as f:
            return f.read().strip()
    return os.environ.get("TUNSEC_TOKEN")


def main(argv=None):
    p = argparse.ArgumentParser(prog="oneqtunel")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey", help="generate a hybrid key pair")
    g.add_argument("--key", required=True)
    g.add_argument("--pub", help="where to write the public key (default: KEY.pub)")
    pk = sub.add_parser("pubkey", help="print public key (base64) and node id")
    pk.add_argument("--key", required=True)
    r = sub.add_parser("run", help="run the VPN node")
    r.add_argument("--key", required=True)
    r.add_argument("--peer", required=True, help="peer public key (file or base64)")
    r.add_argument("--ifname", default="pq0")
    r.add_argument("--addr", help="address of the TUN interface, e.g. 10.99.0.1/24")
    r.add_argument("--mtu", type=int)
    r.add_argument("--listen", default="0.0.0.0:0")
    r.add_argument("--via", metavar="IFACE", help="bind UDP to the address of IFACE (an existing interface, e.g. another tunnel)")
    r.add_argument("--no-config", action="store_true", help="use an existing persistent TUN, do not run ip")
    r.add_argument("--advertise", action="append", default=[], metavar="IP:PORT")
    r.add_argument("--peer-endpoint", action="append", default=[], metavar="IP:PORT",
                   help="static peer candidate (without rendezvous)")
    r.add_argument("--stun", metavar="HOST:PORT")
    r.add_argument("--rendezvous", metavar="URL")
    r.add_argument("--token-file")
    r.add_argument("--cafile")
    r.add_argument("--force-relay", action="store_true")
    r.add_argument("--no-relay", action="store_true")
    r.add_argument("--relay-after", type=float, default=10.0)
    r.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "genkey":
        ident = Identity.generate()
        save_identity(a.key, ident, a.pub or a.key + ".pub")
        print("node_id", ident.node_id.hex())
        return 0
    if a.cmd == "pubkey":
        ident = load_identity(a.key)
        print(base64.b64encode(ident.pub).decode())
        print("node_id", ident.node_id.hex(), file=sys.stderr)
        return 0

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    ident = load_identity(a.key)
    peer = load_public(a.peer)
    cfg = Config(ifname=a.ifname, addr=a.addr, mtu=a.mtu or (1220 if a.via else 1380),
                 listen=parse_hostport(a.listen), via=a.via, no_config=a.no_config,
                 advertise=a.advertise, stun=a.stun, rendezvous=a.rendezvous, token=read_token(a),
                 cafile=a.cafile, peer_endpoints=a.peer_endpoint, force_relay=a.force_relay,
                 no_relay=a.no_relay, relay_after=a.relay_after)
    if cfg.rendezvous and not cfg.token:
        p.error("rendezvous needs a token: --token-file or TUNSEC_TOKEN")
    tun = Tun(cfg.ifname)
    if not cfg.no_config:
        if not cfg.addr:
            p.error("--addr is required unless --no-config")
        configure_tun(tun.name, cfg.addr, cfg.mtu)
    try:
        asyncio.run(Node(ident, peer, cfg, tun).run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
