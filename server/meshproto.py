"""tunmesh-pq/v2 wire protocol: many peers over one UDP socket, layer-2 payloads.

Same hybrid handshake as tunsec-pq/v1 (X25519 + ML-KEM-768, ML-KEM secret first in every KDF),
with the changes a mesh needs. Because the wire format changes, the LABEL is bumped to v2:

  * INIT carries the initiator's node_id (16 B, cleartext, bound into the transcript) so the
    responder can pick the right peer key out of the registry without trial decryption, plus a
    4-byte sender index.
  * RESP carries the responder's sender index and echoes the initiator's index.
  * DATA carries the receiver index (like WireGuard) so one socket can serve many sessions
    without trying every key.

  INIT 0x21 (2349 B) = type | idx_i(4) | node_id_i(16) | E_i | ek_e | ct_sr | AEAD(k1, timestamp)
  RESP 0x22 (2233 B) = type | idx_r(4) | idx_i(4) | E_r | ct_e | ct_si | AEAD(k2, "")
  DATA 0x23          = type | receiver_idx(4) | counter(8) | ChaCha20-Poly1305(frame), header as AAD

Fragmentation (FRAG 0x15), the anti-replay window and the primitives are reused unchanged from oneqtunel.
PUNCH 0x14 carries the sender's node_id (17 bytes): see oneqnode._on_punch. Educational project, not independently audited.
"""
import pqtls  # noqa: F401

import struct
import time
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import oneqtunel as v1
from oneqtunel import (H, HandshakeError, Identity, ReplayWindow, aead_decrypt, aead_encrypt, kdf, node_id,  # noqa: F401
                       x_raw, KEM_CT_LEN, KEM_PUB_LEN, REJECT_AFTER, TAG_LEN, TS_LEN, X_LEN)

LABEL = b"tunmesh-pq/v2 hybrid X25519+ML-KEM-768 ChaCha20Poly1305 SHA256 L2"

M_INIT, M_RESP, M_DATA = 0x21, 0x22, 0x23
# M_RLY: like M_DATA (same header, same session keys and counter) but the payload is a relay operation between a member and a delegated
# relay node: RLY_FWD dst_id(16)|datagram (member -> relay node), RLY_DLV src_id(16)|datagram (relay node -> member),
# RLY_NACK dst_id(16)|reason(1). The datagram is a complete packet for the other member (an M_DATA or a handshake fragment): the relay
# node never sees inside it.
M_RLY = 0x24
RLY_FWD, RLY_DLV, RLY_NACK = 1, 2, 3
NACK_UNREACHABLE, NACK_RATE = 1, 2
T_PUNCH, T_FRAG = v1.T_PUNCH, v1.T_FRAG

INIT_LEN = 1 + 4 + 16 + X_LEN + KEM_PUB_LEN + KEM_CT_LEN + TS_LEN + TAG_LEN     # 2349
RESP_LEN = 1 + 4 + 4 + X_LEN + 2 * KEM_CT_LEN + TAG_LEN                          # 2233
DATA_HDR = 13

# 1-byte data payloads (an Ethernet frame is at least 14 bytes, so these never collide)
CTL_PROBE, CTL_PROBE_REPLY = b"\x00", b"\x01"


def _split_pub(pub: bytes):
    return pub[:X_LEN], pub[X_LEN:]


class InitState:
    def __init__(self, ck, h, e, dk, idx):
        self.ck, self.h, self.e, self.dk, self.idx = ck, h, e, dk, idx
        self.created = time.monotonic()


def init_create(me: Identity, peer_pub: bytes, my_idx: int, now_us: Optional[int] = None):
    xr, kemr = _split_pub(peer_pub)
    header = bytes([M_INIT]) + struct.pack(">I", my_idx) + me.node_id
    ck = H(LABEL)
    h = H(ck, me.pub, peer_pub, header)
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
    msg = header + E + ek + ct_sr + enc
    assert len(msg) == INIT_LEN
    return msg, InitState(ck, h, e, dk, my_idx)


def init_peek(msg: bytes):
    """-> (sender_idx, sender_node_id) from an unauthenticated INIT, or None."""
    if len(msg) != INIT_LEN or msg[0] != M_INIT:
        return None
    return struct.unpack(">I", msg[1:5])[0], msg[5:21]


def init_consume(me: Identity, peer_pub: bytes, msg: bytes):
    """Returns (ts_us, ck, h, E_i, ek_e, sender_idx)."""
    if len(msg) != INIT_LEN or msg[0] != M_INIT:
        raise HandshakeError("bad INIT length/type")
    header = msg[:21]
    sender_idx = struct.unpack(">I", msg[1:5])[0]
    if msg[5:21] != node_id(peer_pub):
        raise HandshakeError("INIT node_id does not match the claimed peer")
    o = 21
    E = msg[o:o + X_LEN]; o += X_LEN
    ek = msg[o:o + KEM_PUB_LEN]; o += KEM_PUB_LEN
    ct_sr = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    enc = msg[o:]
    xi, _ = _split_pub(peer_pub)
    ck = H(LABEL)
    h = H(ck, peer_pub, me.pub, header)
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
    return struct.unpack(">Q", ts)[0], ck, h, E, ek, sender_idx


def resp_create(me: Identity, peer_pub: bytes, ck, h, E_i, ek_e, my_idx: int, peer_idx: int):
    """Returns (msg, send_key, recv_key)."""
    xi, kemi = _split_pub(peer_pub)
    header = bytes([M_RESP]) + struct.pack(">II", my_idx, peer_idx)
    e = X25519PrivateKey.generate()
    E = x_raw(e.public_key())
    k_e, ct_e = MLKEM768PublicKey.from_public_bytes(ek_e).encapsulate()
    k_si, ct_si = MLKEM768PublicKey.from_public_bytes(kemi).encapsulate()
    h = H(h, header, E, ct_e, ct_si)
    dh_ee = e.exchange(X25519PublicKey.from_public_bytes(E_i))
    dh_se = e.exchange(X25519PublicKey.from_public_bytes(xi))
    okm = kdf(ck, k_e + k_si + dh_ee + dh_se + h)
    ck, k2 = okm[:32], okm[32:]
    enc = aead_encrypt(k2, b"", h)
    h = H(h, enc)
    msg = header + E + ct_e + ct_si + enc
    assert len(msg) == RESP_LEN
    t = kdf(ck, b"")
    return msg, t[32:], t[:32]


def resp_peek(msg: bytes):
    """-> (sender_idx, receiver_idx) from an unauthenticated RESP, or None."""
    if len(msg) != RESP_LEN or msg[0] != M_RESP:
        return None
    return struct.unpack(">II", msg[1:9])


def resp_consume(me: Identity, st: InitState, msg: bytes):
    """Returns (send_key, recv_key, peer_idx)."""
    if len(msg) != RESP_LEN or msg[0] != M_RESP:
        raise HandshakeError("bad RESP length/type")
    peer_idx, my_idx = struct.unpack(">II", msg[1:9])
    if my_idx != st.idx:
        raise HandshakeError("RESP is not for this INIT")
    header = msg[:9]
    o = 9
    E = msg[o:o + X_LEN]; o += X_LEN
    ct_e = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    ct_si = msg[o:o + KEM_CT_LEN]; o += KEM_CT_LEN
    enc = msg[o:]
    h = H(st.h, header, E, ct_e, ct_si)
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
    return t[:32], t[32:], peer_idx


class MSession:
    """Transport session with explicit local/remote indexes."""

    def __init__(self, send_key, recv_key, initiator: bool, local_idx: int, remote_idx: int,
                 clock: Callable[[], float] = time.monotonic):
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self.initiator, self.local_idx, self.remote_idx = initiator, local_idx, remote_idx
        self.clock = clock
        self.created = clock()
        self.ctr = 0
        self.window = ReplayWindow()

    def age(self) -> float:
        return self.clock() - self.created

    def usable(self) -> bool:
        return self.age() < REJECT_AFTER and self.ctr < v1.MAX_COUNTER

    def encrypt(self, payload: bytes, typ: int = M_DATA) -> bytes:
        if not self.usable():
            raise HandshakeError("session expired")
        hdr = bytes([typ]) + struct.pack(">IQ", self.remote_idx, self.ctr)
        self.ctr += 1
        return hdr + self._send.encrypt(b"\0" * 4 + hdr[5:], payload, hdr)

    def decrypt(self, pkt: bytes) -> Optional[bytes]:
        if len(pkt) < DATA_HDR + TAG_LEN or pkt[0] not in (M_DATA, M_RLY) or self.age() >= REJECT_AFTER:
            return None
        ctr = struct.unpack(">Q", pkt[5:13])[0]
        if not self.window.check(ctr):
            return None
        try:
            pt = self._recv.decrypt(b"\0" * 4 + pkt[5:13], pkt[13:], pkt[:13])
        except InvalidTag:
            return None
        self.window.update(ctr)
        return pt


def data_receiver_index(pkt: bytes) -> Optional[int]:
    if len(pkt) < DATA_HDR + TAG_LEN or pkt[0] not in (M_DATA, M_RLY):
        return None
    return struct.unpack(">I", pkt[1:5])[0]
