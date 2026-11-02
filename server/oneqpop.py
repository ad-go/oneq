"""Proof of possession of a node key, for registrations with an untrusted rendezvous server or relay.

A node_id is the hash of a public key, and public keys are public: without a proof, anybody who holds a token (or an account) could register
somebody else's key with endpoints of its own, or occupy the id before its owner joins. The node keys are KEM keys (X25519 + ML-KEM-768), not
signature keys, so the proof is a challenge that only the holder of the private halves can open:

  server -> node : e (ephemeral X25519 public), ct (ML-KEM ciphertext to the node's key), nonce, exp, enc = AEAD(key, R)
                   key = KDF(label, ml-kem secret | x25519(e, node static) | node_id | nonce), R = HMAC(server_key, "R" | node_id | nonce | exp)
  node -> server : proof = HMAC(R, "proof" | node_id | nonce | exp), with nonce and exp

The server keeps no state: it recomputes R from its key (for a federation, a key derived from the shared secret, so any relay can verify a
challenge that another one made). A proof is valid until `exp` (60 s). It does not cover the rest of the request, so it protects against
registration by somebody who does not hold the key, not against an attacker who can read the TLS stream. Educational project, not audited.
"""
import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# sizes of the hybrid node key (same as oneqtunel / meshproto; this module stands alone so that a relay does not need the node code)
X_LEN, KEM_PUB_LEN, KEM_CT_LEN, TAG_LEN = 32, 1184, 1088, 16
PUB_LEN = X_LEN + KEM_PUB_LEN

LABEL = b"oneq-pop-v1"
LIFETIME = 60                         # seconds a challenge (and so a proof) is valid
SKEW = 5


def _kdf(ck: bytes, ikm: bytes, n: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=ck, info=b"tunsec-pq kdf").derive(ikm)


def _node_id(pub: bytes) -> bytes:
    return hashlib.sha256(pub).digest()[:16]


def _aead(key: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(key)


def server_key(secret) -> bytes:
    """The key a relay derives its challenges from, from a secret all relays of a federation share."""
    s = secret.encode() if isinstance(secret, str) else bytes(secret)
    return hmac.new(s, b"oneq proof of possession server key", hashlib.sha256).digest()


def _r(skey: bytes, nid: bytes, nonce: bytes, exp: int) -> bytes:
    return hmac.new(skey, b"R" + nid + nonce + struct.pack(">Q", exp), hashlib.sha256).digest()


def _key(k_kem: bytes, dh: bytes, nid: bytes, nonce: bytes) -> bytes:
    return _kdf(hashlib.sha256(LABEL).digest(), k_kem + dh + nid + nonce, 32)


def _proof(r: bytes, nid: bytes, nonce: bytes, exp: int) -> bytes:
    return hmac.new(r, b"proof" + nid + nonce + struct.pack(">Q", exp), hashlib.sha256).digest()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s, n: Optional[int] = None) -> bytes:
    b = base64.b64decode(s, validate=True)
    if n is not None and len(b) != n:
        raise ValueError("bad length")
    return b


def make_challenge(skey: bytes, pub: bytes, now: Optional[float] = None) -> dict:
    """Server side: a challenge for the holder of `pub` (raises ValueError for a malformed key)."""
    if len(pub) != PUB_LEN:
        raise ValueError("bad public key")
    nid = _node_id(pub)
    xs, kems = pub[:X_LEN], pub[X_LEN:]
    nonce = os.urandom(16)
    exp = int(now if now is not None else time.time()) + LIFETIME
    e = X25519PrivateKey.generate()
    k_kem, ct = MLKEM768PublicKey.from_public_bytes(kems).encapsulate()
    dh = e.exchange(X25519PublicKey.from_public_bytes(xs))
    enc = _aead(_key(k_kem, dh, nid, nonce)).encrypt(bytes(12), _r(skey, nid, nonce, exp), nid + nonce + struct.pack(">Q", exp))
    return {"e": b64(e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "ct": b64(ct), "nonce": b64(nonce), "exp": exp, "enc": b64(enc)}


def answer(ident, ch: dict) -> dict:
    """Node side: open the challenge and prove it. Raises ValueError if it is not addressed to this key or is malformed."""
    try:
        nid = ident.node_id
        e_pub, ct = unb64(ch["e"], X_LEN), unb64(ch["ct"], KEM_CT_LEN)
        nonce, enc = unb64(ch["nonce"], 16), unb64(ch["enc"], 32 + TAG_LEN)
        exp = ch["exp"]
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise ValueError("bad expiry")
        k_kem = ident.kem.decapsulate(ct)
        dh = ident.x.exchange(X25519PublicKey.from_public_bytes(e_pub))
        r = _aead(_key(k_kem, dh, nid, nonce)).decrypt(bytes(12), enc, nid + nonce + struct.pack(">Q", exp))
    except (KeyError, TypeError, ValueError, Exception) as e:      # noqa: BLE001 - anything wrong with a challenge is just "not for us"
        raise ValueError(f"cannot open the challenge: {e}")
    return {"nonce": b64(nonce), "exp": exp, "proof": b64(_proof(r, nid, nonce, exp))}


def verify(skey: bytes, nid_hex: str, pop, now: Optional[float] = None) -> bool:
    """Server side: is `pop` a valid, unexpired proof for node `nid_hex`?"""
    try:
        nid = bytes.fromhex(nid_hex)
        nonce, proof = unb64(pop["nonce"], 16), unb64(pop["proof"], 32)
        exp = pop["exp"]
        if isinstance(exp, bool) or not isinstance(exp, int) or len(nid) != 16:
            return False
    except (KeyError, TypeError, ValueError):
        return False
    t_now = now if now is not None else time.time()
    if exp < t_now - SKEW or exp > t_now + LIFETIME + SKEW:
        return False
    return hmac.compare_digest(proof, _proof(_r(skey, nid, nonce, exp), nid, nonce, exp))


class Prover:
    """Client side cache: one challenge serves several registrations until shortly before it expires."""

    def __init__(self, ident):
        self.ident = ident
        self.cur: Optional[dict] = None

    def fresh(self, margin: float = 15.0) -> Optional[dict]:
        if self.cur is not None and self.cur["exp"] - time.time() > margin:
            return self.cur
        return None

    def store(self, ch: dict) -> dict:
        self.cur = answer(self.ident, ch)
        return self.cur

    def drop(self):
        self.cur = None
