#!/usr/bin/env python3
"""Conformance check of specifications.html: an INDEPENDENT implementation written only from the formulas of the spec
(it imports nothing from the oneq code) is run against the real meshproto.py in both roles.

  python3 spec_check.py        (needs meshproto.py, oneqtunel.py, pqtls.py next to it; Linux/macOS, `cryptography` >= 46)

What is compared: the bytes of the transport keys, a DATA packet in each direction (header, nonce, AAD as in section 6),
the lengths of INIT/RESP, and the transcript values that the spec names h0..h3 / ck0..ck2.
"""
import hashlib
import struct
import sys
import time

import meshproto as real  # the implementation under test (imports pqtls first)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization as ser

LABEL = b"tunmesh-pq/v2 hybrid X25519+ML-KEM-768 ChaCha20Poly1305 SHA256 L2"   # spec 3.1
INFO = b"tunsec-pq kdf"                                                       # spec 4.1


def sha(*p):
    h = hashlib.sha256()
    for x in p:
        h.update(x)
    return h.digest()


def hkdf(salt, ikm, n=64):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=INFO).derive(ikm)


def raw(pub):
    return pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def aead(key, pt, aad):
    return ChaCha20Poly1305(key).encrypt(b"\0" * 12, pt, aad)


class Id:
    def __init__(self):
        self.x = X25519PrivateKey.generate()
        self.k = MLKEM768PrivateKey.generate()
        self.pub = raw(self.x.public_key()) + self.k.public_key().public_bytes_raw()
        self.nid = sha(self.pub)[:16]


def dx(priv, pub_raw):
    return priv.exchange(X25519PublicKey.from_public_bytes(pub_raw))


trace = {}


def spec_initiator(I, R_pub, idx_i):
    """spec section 5.1: builds INIT, then consumes a RESP."""
    hdr = bytes([0x21]) + struct.pack(">I", idx_i) + I.nid
    ck0 = sha(LABEL)
    h0 = sha(ck0, I.pub, R_pub, hdr)
    e = X25519PrivateKey.generate()
    E_i = raw(e.public_key())
    dk = MLKEM768PrivateKey.generate()
    ek_e = dk.public_key().public_bytes_raw()
    k_sr, ct_sr = MLKEM768PublicKey.from_public_bytes(R_pub[32:]).encapsulate()
    h1 = sha(h0, E_i, ek_e, ct_sr)
    dh1 = dx(e, R_pub[:32])
    dh2 = dx(I.x, R_pub[:32])
    okm = hkdf(ck0, k_sr + dh1 + dh2 + h1)
    ck1, k1 = okm[:32], okm[32:]
    enc1 = aead(k1, struct.pack(">Q", time.time_ns() // 1000), h1)
    h2 = sha(h1, enc1)
    init = hdr + E_i + ek_e + ct_sr + enc1
    trace.update(ck0=ck0, h0=h0, h1=h1, ck1=ck1, k1=k1, h2=h2)

    def finish(resp):
        assert len(resp) == 2233 and resp[0] == 0x22
        idx_r, echo = struct.unpack(">II", resp[1:9])
        assert echo == idx_i
        E_r, ct_e, ct_si, enc2 = resp[9:41], resp[41:1129], resp[1129:2217], resp[2217:]
        h3 = sha(h2, resp[:9], E_r, ct_e, ct_si)
        k_e = dk.decapsulate(ct_e)
        k_si = I.k.decapsulate(ct_si)
        dh_ee = dx(e, E_r)
        dh_se = dx(I.x, E_r)
        okm2 = hkdf(ck1, k_e + k_si + dh_ee + dh_se + h3)
        ck2, k2 = okm2[:32], okm2[32:]
        assert ChaCha20Poly1305(k2).decrypt(b"\0" * 12, enc2, h3) == b""
        t = hkdf(ck2, b"")
        trace.update(h3=h3, ck2=ck2, k2=k2)
        return t[:32], t[32:], idx_r          # send (I->R), receive (R->I)
    return init, finish


def spec_responder(R, I_pub, init, idx_r):
    """spec section 5.2: consumes INIT, builds RESP. Returns (resp, k_rx(I->R), k_tx(R->I), idx_i)."""
    assert len(init) == 2349 and init[0] == 0x21
    idx_i = struct.unpack(">I", init[1:5])[0]
    assert init[5:21] == sha(I_pub)[:16]
    hdr = init[:21]
    E_i, ek_e, ct_sr, enc1 = init[21:53], init[53:1237], init[1237:2325], init[2325:]
    ck0 = sha(LABEL)
    h0 = sha(ck0, I_pub, R.pub, hdr)
    h1 = sha(h0, E_i, ek_e, ct_sr)
    k_sr = R.k.decapsulate(ct_sr)
    okm = hkdf(ck0, k_sr + dx(R.x, E_i) + dx(R.x, I_pub[:32]) + h1)
    ck1, k1 = okm[:32], okm[32:]
    ChaCha20Poly1305(k1).decrypt(b"\0" * 12, enc1, h1)
    h2 = sha(h1, enc1)
    rh = bytes([0x22]) + struct.pack(">II", idx_r, idx_i)
    e = X25519PrivateKey.generate()
    E_r = raw(e.public_key())
    k_e, ct_e = MLKEM768PublicKey.from_public_bytes(ek_e).encapsulate()
    k_si, ct_si = MLKEM768PublicKey.from_public_bytes(I_pub[32:]).encapsulate()
    h3 = sha(h2, rh, E_r, ct_e, ct_si)
    okm2 = hkdf(ck1, k_e + k_si + dx(e, E_i) + dx(e, I_pub[:32]) + h3)
    ck2, k2 = okm2[:32], okm2[32:]
    enc2 = aead(k2, b"", h3)
    t = hkdf(ck2, b"")
    return rh + E_r + ct_e + ct_si + enc2, t[:32], t[32:], idx_i


def spec_data(key, receiver_idx, ctr, payload, typ=0x23):
    """spec section 6."""
    hdr = bytes([typ]) + struct.pack(">IQ", receiver_idx, ctr)
    return hdr + ChaCha20Poly1305(key).encrypt(b"\0" * 4 + struct.pack(">Q", ctr), payload, hdr)


def main():
    I, R = real.Identity.generate(), real.Identity.generate()
    # --- our initiator -> real responder
    init, finish = spec_initiator(type("S", (), {"x": I.x, "k": I.kem, "pub": I.pub, "nid": I.node_id})(), R.pub, 0xA1B2C3D4)
    assert len(init) == real.INIT_LEN == 2349
    ts, ck, h, E, ek, sidx = real.init_consume(R, I.pub, init)
    assert (ck, h) == (trace["ck1"], trace["h2"]), "responder transcript differs from spec (ck1/h2)"
    resp, r_send, r_recv = real.resp_create(R, I.pub, ck, h, E, ek, 0x0BADF00D, sidx)
    assert len(resp) == real.RESP_LEN == 2233
    k_i2r, k_r2i, idx_r = finish(resp)
    assert (k_i2r, k_r2i) == (r_recv, r_send), "transport keys differ"
    assert idx_r == 0x0BADF00D
    # DATA both ways: the packet our code builds must be accepted by the real session, and vice versa
    s_r = real.MSession(r_send, r_recv, False, 0x0BADF00D, 0xA1B2C3D4)
    pkt = spec_data(k_i2r, 0x0BADF00D, 0, b"frame-from-initiator")
    assert s_r.decrypt(pkt) == b"frame-from-initiator"
    pkt2 = s_r.encrypt(b"frame-from-responder")
    ctr = struct.unpack(">Q", pkt2[5:13])[0]
    assert pkt2[:5] == bytes([0x23]) + struct.pack(">I", 0xA1B2C3D4)
    assert ChaCha20Poly1305(k_r2i).decrypt(b"\0" * 4 + pkt2[5:13], pkt2[13:], pkt2[:13]) == b"frame-from-responder" and ctr == 0
    rly = s_r.encrypt(bytes([1]) + b"\x11" * 16 + b"dgram", real.M_RLY)
    assert rly[0] == 0x24 and ChaCha20Poly1305(k_r2i).decrypt(b"\0" * 4 + rly[5:13], rly[13:], rly[:13]) == bytes([1]) + b"\x11" * 16 + b"dgram"
    print("ok: spec initiator <-> real responder (INIT 2349 B, RESP 2233 B, keys, DATA, RLY)")

    # --- real initiator -> our responder
    msg, st = real.init_create(I, R.pub, 0x11223344)
    resp2, k_rx, k_tx, idx_i = spec_responder(type("S", (), {"x": R.x, "k": R.kem, "pub": R.pub, "nid": R.node_id})(), I.pub, msg, 0x55667788)
    sk, rk, peer_idx = real.resp_consume(I, st, resp2)
    assert (sk, rk) == (k_rx, k_tx) and peer_idx == 0x55667788 and idx_i == 0x11223344
    print("ok: real initiator <-> spec responder (keys equal)")

    # --- negative: a flipped bit anywhere in INIT/RESP must be rejected (AEAD under the transcript)
    bad = bytearray(init)
    bad[100] ^= 1
    try:
        real.init_consume(R, I.pub, bytes(bad))
        raise SystemExit("FAIL: tampered INIT accepted")
    except real.HandshakeError:
        pass
    bad = bytearray(resp2)
    bad[1200] ^= 1
    try:
        real.resp_consume(I, st, bytes(bad))
        raise SystemExit("FAIL: tampered RESP accepted")
    except real.HandshakeError:
        pass
    print("ok: tampered INIT and RESP are rejected")
    print("all spec formulas confirmed against meshproto.py")


if __name__ == "__main__":
    sys.exit(main())
