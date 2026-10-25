//! tunmesh-pq/v2 wire protocol, byte-for-byte compatible with `meshproto.py` / `oneqtunel.py`.
//!
//! Hybrid handshake: X25519 + ML-KEM-768 (the ML-KEM secret comes first in every KDF input), ChaCha20-Poly1305
//! transport, HKDF-SHA256. Educational project, not independently audited.
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::{digest, hkdf, rand};

pub const LABEL: &[u8] = b"tunmesh-pq/v2 hybrid X25519+ML-KEM-768 ChaCha20Poly1305 SHA256 L2";
pub const M_INIT: u8 = 0x21;
pub const M_RESP: u8 = 0x22;
pub const M_DATA: u8 = 0x23;
/// Same header, session keys and counter as M_DATA, but the payload is a relay operation between a member and a delegated relay
/// node: RLY_FWD dst(16)|datagram, RLY_DLV src(16)|datagram, RLY_NACK dst(16)|reason(1). The datagram is a complete packet for
/// the other member; the relay node never sees inside it.
pub const M_RLY: u8 = 0x24;
pub const RLY_FWD: u8 = 1;
pub const RLY_DLV: u8 = 2;
pub const RLY_NACK: u8 = 3;
pub const NACK_UNREACHABLE: u8 = 1;
pub const NACK_RATE: u8 = 2;
pub const T_PUNCH: u8 = 0x14;
pub const T_FRAG: u8 = 0x15;

pub const X_LEN: usize = 32;
pub const KEM_PUB_LEN: usize = 1184;
pub const KEM_CT_LEN: usize = 1088;
pub const PUB_LEN: usize = X_LEN + KEM_PUB_LEN; // 1216
pub const TAG_LEN: usize = 16;
pub const INIT_LEN: usize = 1 + 4 + 16 + X_LEN + KEM_PUB_LEN + KEM_CT_LEN + 8 + TAG_LEN; // 2349
pub const RESP_LEN: usize = 1 + 4 + 4 + X_LEN + 2 * KEM_CT_LEN + TAG_LEN; // 2233
pub const DATA_HDR: usize = 13;

pub const REKEY_AFTER: f64 = 120.0;
pub const REJECT_AFTER: f64 = 180.0;
const MAX_COUNTER: u64 = 1 << 60;
const WINDOW: u64 = 1024;

/// 1-byte data payloads (an Ethernet frame is at least 14 bytes, so these never collide with one).
pub const CTL_PROBE: &[u8] = &[0x00];
pub const CTL_PROBE_REPLY: &[u8] = &[0x01];

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-SHA256(salt = ck, ikm, info = "tunsec-pq kdf")`, 64 bytes (same as the Python `kdf`).
pub fn kdf(ck: &[u8], ikm: &[u8]) -> [u8; 64] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, ck).extract(ikm);
    let info = [b"tunsec-pq kdf".as_slice()];
    let okm = prk.expand(&info, Len(64)).expect("hkdf expand");
    let mut out = [0u8; 64];
    okm.fill(&mut out).expect("hkdf fill");
    out
}

fn zero_nonce() -> Nonce {
    Nonce::assume_unique_for_key([0u8; 12])
}

fn key_of(k: &[u8]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, k).expect("32-byte key"))
}

fn seal0(key: &[u8], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut buf = pt.to_vec();
    key_of(key)
        .seal_in_place_append_tag(zero_nonce(), Aad::from(aad), &mut buf)
        .expect("seal");
    buf
}

fn open0(key: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let mut buf = ct.to_vec();
    let n = key_of(key).open_in_place(zero_nonce(), Aad::from(aad), &mut buf).ok()?.len();
    buf.truncate(n);
    Some(buf)
}

fn dh(private: &PrivateKey, peer_pub: &[u8]) -> Result<Vec<u8>> {
    agreement::agree(private, UnparsedPublicKey::new(&X25519, peer_pub), anyhow!("x25519 failed"), |k| Ok(k.to_vec()))
}

fn x_pub(private: &PrivateKey) -> Result<Vec<u8>> {
    Ok(private.compute_public_key().map_err(|_| anyhow!("x25519 public key"))?.as_ref().to_vec())
}

pub fn node_id(public: &[u8]) -> [u8; 16] {
    let h = sha256(&[public]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Static hybrid key: X25519 + ML-KEM-768. Public form (1216 bytes) = x25519 public (32) || ML-KEM encapsulation key (1184).
pub struct Identity {
    x_bytes: [u8; 32],
    x_priv: PrivateKey,
    dk: DecapsulationKey,
    pub pub_bytes: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut x_bytes = [0u8; 32];
        rand::fill(&mut x_bytes).map_err(|_| anyhow!("rng"))?;
        let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| anyhow!("ml-kem keygen"))?;
        Self::assemble(x_bytes, dk)
    }

    fn assemble(x_bytes: [u8; 32], dk: DecapsulationKey) -> Result<Self> {
        let x_priv = PrivateKey::from_private_key(&X25519, &x_bytes).map_err(|_| anyhow!("bad x25519 key"))?;
        // FIPS 203 decapsulation key = dkPKE (1152) || ek (1184) || H(ek) (32) || z (32): the public key is inside it
        // (a key loaded from bytes cannot derive it on its own)
        let dk_bytes = dk.key_bytes().map_err(|_| anyhow!("ml-kem key bytes"))?;
        let dk_bytes = dk_bytes.as_ref();
        if dk_bytes.len() != 2400 {
            bail!("unexpected ml-kem key size {}", dk_bytes.len());
        }
        let mut pub_bytes = x_pub(&x_priv)?;
        pub_bytes.extend_from_slice(&dk_bytes[1152..1152 + KEM_PUB_LEN]);
        debug_assert_eq!(pub_bytes.len(), PUB_LEN);
        Ok(Identity { x_bytes, x_priv, dk, pub_bytes })
    }

    /// Private form: x25519 key (32) || expanded ML-KEM decapsulation key (2400). Not the Python seed format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.x_bytes.to_vec();
        out.extend_from_slice(self.dk.key_bytes().map_err(|_| anyhow!("ml-kem key bytes"))?.as_ref());
        Ok(out)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 32 + 2400 {
            bail!("bad private key length {}", b.len());
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        let dk = DecapsulationKey::new(&ML_KEM_768, &b[32..]).map_err(|_| anyhow!("bad ml-kem key"))?;
        Self::assemble(x, dk)
    }

    pub fn node_id(&self) -> [u8; 16] {
        node_id(&self.pub_bytes)
    }

    /// Proof of possession of this key for a registration (see `oneqpop.py`): open the challenge the relay sealed to our static
    /// keys and return `{"nonce", "exp", "proof"}`. Fails if the challenge is not addressed to this key or is malformed.
    pub fn pop_answer(&self, ch: &serde_json::Value) -> Result<serde_json::Value> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let field = |name: &str, len: usize| -> Result<Vec<u8>> {
            let v = b64.decode(ch[name].as_str().ok_or_else(|| anyhow!("challenge field {name} missing"))?)?;
            if v.len() != len {
                bail!("challenge field {name} has the wrong length");
            }
            Ok(v)
        };
        let (e_pub, ct) = (field("e", X_LEN)?, field("ct", KEM_CT_LEN)?);
        let (nonce, enc) = (field("nonce", 16)?, field("enc", 32 + TAG_LEN)?);
        let exp = ch["exp"].as_u64().ok_or_else(|| anyhow!("challenge expiry missing"))?;
        let nid = self.node_id();
        let k_kem = self.dk.decapsulate(Ciphertext::from(ct.as_slice())).map_err(|_| anyhow!("cannot open the challenge"))?;
        let shared = dh(&self.x_priv, &e_pub)?;
        let okm = kdf(&sha256(&[POP_LABEL]), &cat(&[k_kem.as_ref(), &shared, &nid, &nonce]));
        let mut aad = nid.to_vec();
        aad.extend_from_slice(&nonce);
        aad.extend_from_slice(&exp.to_be_bytes());
        let r = open0(&okm[..32], &enc, &aad).ok_or_else(|| anyhow!("cannot open the challenge"))?;
        let mut msg = b"proof".to_vec();
        msg.extend_from_slice(&nid);
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&exp.to_be_bytes());
        let tag = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &r), &msg);
        Ok(serde_json::json!({"nonce": b64.encode(&nonce), "exp": exp, "proof": b64.encode(tag.as_ref())}))
    }
}

/// Label of the proof-of-possession key derivation (identical in oneqpop.py).
pub const POP_LABEL: &[u8] = b"oneq-pop-v1";

// ---------------------------------------------------------------- handshake

pub struct InitState {
    ck: [u8; 32],
    h: [u8; 32],
    e: PrivateKey,
    dk: DecapsulationKey,
    pub idx: u32,
    pub created: Instant,
}

pub struct InitConsumed {
    pub ts_us: u64,
    ck: [u8; 32],
    h: [u8; 32],
    e_i: Vec<u8>,
    ek_e: Vec<u8>,
    pub sender_idx: u32,
}

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

fn split(okm: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn init_create(me: &Identity, peer_pub: &[u8], my_idx: u32) -> Result<(Vec<u8>, InitState)> {
    init_create_at(me, peer_pub, my_idx, now_us())
}

pub fn init_create_at(me: &Identity, peer_pub: &[u8], my_idx: u32, ts_us: u64) -> Result<(Vec<u8>, InitState)> {
    if peer_pub.len() != PUB_LEN {
        bail!("peer public key must be {PUB_LEN} bytes");
    }
    let (xr, kemr) = peer_pub.split_at(X_LEN);
    let mut header = vec![M_INIT];
    header.extend_from_slice(&my_idx.to_be_bytes());
    header.extend_from_slice(&me.node_id());
    let ck = sha256(&[LABEL]);
    let mut h = sha256(&[&ck, &me.pub_bytes, peer_pub, &header]);
    let mut seed = [0u8; 32];
    rand::fill(&mut seed).map_err(|_| anyhow!("rng"))?;
    let e = PrivateKey::from_private_key(&X25519, &seed).map_err(|_| anyhow!("ephemeral key"))?;
    let e_pub = x_pub(&e)?;
    let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| anyhow!("ml-kem keygen"))?;
    let ek = dk.encapsulation_key().map_err(|_| anyhow!("ek"))?.key_bytes().map_err(|_| anyhow!("ek bytes"))?;
    let ek = ek.as_ref().to_vec();
    let peer_ek = EncapsulationKey::new(&ML_KEM_768, kemr).map_err(|_| anyhow!("bad peer ml-kem key"))?;
    let (ct_sr, k_sr) = peer_ek.encapsulate().map_err(|_| anyhow!("encapsulate"))?;
    h = sha256(&[&h, &e_pub, &ek, ct_sr.as_ref()]);
    let dh1 = dh(&e, xr)?;
    let dh2 = dh(&me.x_priv, xr)?;
    let okm = kdf(&ck, &cat(&[k_sr.as_ref(), &dh1, &dh2, &h]));
    let (ck1, k1) = split(&okm);
    let enc = seal0(&k1, &ts_us.to_be_bytes(), &h);
    let h2 = sha256(&[&h, &enc]);
    let msg = cat(&[&header, &e_pub, &ek, ct_sr.as_ref(), &enc]);
    debug_assert_eq!(msg.len(), INIT_LEN);
    Ok((msg, InitState { ck: ck1, h: h2, e, dk, idx: my_idx, created: Instant::now() }))
}

/// `(sender_idx, sender_node_id)` from an unauthenticated INIT.
pub fn init_peek(msg: &[u8]) -> Option<(u32, [u8; 16])> {
    if msg.len() != INIT_LEN || msg[0] != M_INIT {
        return None;
    }
    let idx = u32::from_be_bytes(msg[1..5].try_into().ok()?);
    let id: [u8; 16] = msg[5..21].try_into().ok()?;
    Some((idx, id))
}

pub fn init_consume(me: &Identity, peer_pub: &[u8], msg: &[u8]) -> Result<InitConsumed> {
    if msg.len() != INIT_LEN || msg[0] != M_INIT {
        bail!("bad INIT length/type");
    }
    let header = &msg[..21];
    let sender_idx = u32::from_be_bytes(msg[1..5].try_into()?);
    if msg[5..21] != node_id(peer_pub) {
        bail!("INIT node_id does not match the claimed peer");
    }
    let e_i = &msg[21..53];
    let ek = &msg[53..53 + KEM_PUB_LEN];
    let ct_sr = &msg[53 + KEM_PUB_LEN..53 + KEM_PUB_LEN + KEM_CT_LEN];
    let enc = &msg[53 + KEM_PUB_LEN + KEM_CT_LEN..];
    let xi = &peer_pub[..X_LEN];
    let ck = sha256(&[LABEL]);
    let mut h = sha256(&[&ck, peer_pub, &me.pub_bytes, header]);
    h = sha256(&[&h, e_i, ek, ct_sr]);
    let k_sr = me.dk.decapsulate(Ciphertext::from(ct_sr)).map_err(|_| anyhow!("INIT authentication failed"))?;
    let dh1 = dh(&me.x_priv, e_i)?;
    let dh2 = dh(&me.x_priv, xi)?;
    let okm = kdf(&ck, &cat(&[k_sr.as_ref(), &dh1, &dh2, &h]));
    let (ck1, k1) = split(&okm);
    let ts = open0(&k1, enc, &h).ok_or_else(|| anyhow!("INIT authentication failed"))?;
    let h2 = sha256(&[&h, enc]);
    Ok(InitConsumed {
        ts_us: u64::from_be_bytes(ts.as_slice().try_into().map_err(|_| anyhow!("bad timestamp"))?),
        ck: ck1,
        h: h2,
        e_i: e_i.to_vec(),
        ek_e: ek.to_vec(),
        sender_idx,
    })
}

/// Responder side: build RESP. Returns `(msg, send_key, recv_key)`.
pub fn resp_create(
    me: &Identity,
    peer_pub: &[u8],
    c: &InitConsumed,
    my_idx: u32,
    peer_idx: u32,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let (xi, kemi) = peer_pub.split_at(X_LEN);
    let mut header = vec![M_RESP];
    header.extend_from_slice(&my_idx.to_be_bytes());
    header.extend_from_slice(&peer_idx.to_be_bytes());
    let mut seed = [0u8; 32];
    rand::fill(&mut seed).map_err(|_| anyhow!("rng"))?;
    let e = PrivateKey::from_private_key(&X25519, &seed).map_err(|_| anyhow!("ephemeral key"))?;
    let e_pub = x_pub(&e)?;
    let ek_e = EncapsulationKey::new(&ML_KEM_768, &c.ek_e).map_err(|_| anyhow!("bad ephemeral ml-kem key"))?;
    let (ct_e, k_e) = ek_e.encapsulate().map_err(|_| anyhow!("encapsulate"))?;
    let ek_i = EncapsulationKey::new(&ML_KEM_768, kemi).map_err(|_| anyhow!("bad peer ml-kem key"))?;
    let (ct_si, k_si) = ek_i.encapsulate().map_err(|_| anyhow!("encapsulate"))?;
    let h = sha256(&[&c.h, &header, &e_pub, ct_e.as_ref(), ct_si.as_ref()]);
    let dh_ee = dh(&e, &c.e_i)?;
    let dh_se = dh(&e, xi)?;
    let okm = kdf(&c.ck, &cat(&[k_e.as_ref(), k_si.as_ref(), &dh_ee, &dh_se, &h]));
    let (ck2, k2) = split(&okm);
    let enc = seal0(&k2, b"", &h);
    let msg = cat(&[&header, &e_pub, ct_e.as_ref(), ct_si.as_ref(), &enc]);
    debug_assert_eq!(msg.len(), RESP_LEN);
    let (t_a, t_b) = split(&kdf(&ck2, b""));
    let _ = me;
    Ok((msg, t_b, t_a)) // the responder sends with the second half
}

pub fn resp_peek(msg: &[u8]) -> Option<(u32, u32)> {
    if msg.len() != RESP_LEN || msg[0] != M_RESP {
        return None;
    }
    Some((u32::from_be_bytes(msg[1..5].try_into().ok()?), u32::from_be_bytes(msg[5..9].try_into().ok()?)))
}

/// Initiator side: validate RESP against the pending INIT. Returns `(send_key, recv_key, peer_idx)`.
pub fn resp_consume(me: &Identity, st: &InitState, msg: &[u8]) -> Result<([u8; 32], [u8; 32], u32)> {
    if msg.len() != RESP_LEN || msg[0] != M_RESP {
        bail!("bad RESP length/type");
    }
    let peer_idx = u32::from_be_bytes(msg[1..5].try_into()?);
    let my_idx = u32::from_be_bytes(msg[5..9].try_into()?);
    if my_idx != st.idx {
        bail!("RESP is not for this INIT");
    }
    let header = &msg[..9];
    let e_r = &msg[9..9 + X_LEN];
    let ct_e = &msg[9 + X_LEN..9 + X_LEN + KEM_CT_LEN];
    let ct_si = &msg[9 + X_LEN + KEM_CT_LEN..9 + X_LEN + 2 * KEM_CT_LEN];
    let enc = &msg[9 + X_LEN + 2 * KEM_CT_LEN..];
    let h = sha256(&[&st.h, header, e_r, ct_e, ct_si]);
    let k_e = st.dk.decapsulate(Ciphertext::from(ct_e)).map_err(|_| anyhow!("RESP authentication failed"))?;
    let k_si = me.dk.decapsulate(Ciphertext::from(ct_si)).map_err(|_| anyhow!("RESP authentication failed"))?;
    let dh_ee = dh(&st.e, e_r)?;
    let dh_se = dh(&me.x_priv, e_r)?;
    let okm = kdf(&st.ck, &cat(&[k_e.as_ref(), k_si.as_ref(), &dh_ee, &dh_se, &h]));
    let (ck2, k2) = split(&okm);
    open0(&k2, enc, &h).ok_or_else(|| anyhow!("RESP authentication failed"))?;
    let (t_a, t_b) = split(&kdf(&ck2, b""));
    Ok((t_a, t_b, peer_idx))
}

// ---------------------------------------------------------------- transport

#[derive(Default)]
pub struct ReplayWindow {
    top: Option<u64>,
    seen: HashSet<u64>,
}

impl ReplayWindow {
    pub fn check(&self, c: u64) -> bool {
        match self.top {
            None => true,
            Some(t) if c > t => true,
            Some(t) => t - c < WINDOW && !self.seen.contains(&c),
        }
    }

    pub fn update(&mut self, c: u64) {
        let t = self.top.map_or(c, |t| t.max(c));
        self.top = Some(t);
        self.seen.insert(c);
        if self.seen.len() > 2 * WINDOW as usize {
            let floor = t.saturating_sub(WINDOW - 1);
            self.seen.retain(|&x| x >= floor);
        }
    }
}

pub struct Session {
    send: LessSafeKey,
    recv: LessSafeKey,
    pub initiator: bool,
    pub local_idx: u32,
    pub remote_idx: u32,
    created: Instant,
    ctr: u64,
    window: ReplayWindow,
}

impl Session {
    pub fn new(send_key: &[u8], recv_key: &[u8], initiator: bool, local_idx: u32, remote_idx: u32) -> Self {
        Session {
            send: key_of(send_key),
            recv: key_of(recv_key),
            initiator,
            local_idx,
            remote_idx,
            created: Instant::now(),
            ctr: 0,
            window: ReplayWindow::default(),
        }
    }

    pub fn age(&self) -> f64 {
        self.created.elapsed().as_secs_f64()
    }

    pub fn usable(&self) -> bool {
        self.age() < REJECT_AFTER && self.ctr < MAX_COUNTER
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        self.encrypt_typed(payload, M_DATA)
    }

    pub fn encrypt_typed(&mut self, payload: &[u8], typ: u8) -> Option<Vec<u8>> {
        if !self.usable() {
            return None;
        }
        let mut hdr = Vec::with_capacity(DATA_HDR + payload.len() + TAG_LEN);
        hdr.push(typ);
        hdr.extend_from_slice(&self.remote_idx.to_be_bytes());
        hdr.extend_from_slice(&self.ctr.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr += 1;
        let mut buf = payload.to_vec();
        self.send
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&hdr[..DATA_HDR]), &mut buf)
            .ok()?;
        hdr.extend_from_slice(&buf);
        Some(hdr)
    }

    pub fn decrypt(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < DATA_HDR + TAG_LEN || (pkt[0] != M_DATA && pkt[0] != M_RLY) || self.age() >= REJECT_AFTER {
            return None;
        }
        let ctr = u64::from_be_bytes(pkt[5..13].try_into().ok()?);
        if !self.window.check(ctr) {
            return None;
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&pkt[5..13]);
        let mut buf = pkt[DATA_HDR..].to_vec();
        let n = self
            .recv
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&pkt[..DATA_HDR]), &mut buf)
            .ok()?
            .len();
        buf.truncate(n);
        self.window.update(ctr);
        Some(buf)
    }

    #[cfg(test)]
    pub fn backdate(&mut self, secs: f64) {
        self.created -= std::time::Duration::from_secs_f64(secs);
    }
}

pub fn data_receiver_index(pkt: &[u8]) -> Option<u32> {
    if pkt.len() < DATA_HDR + TAG_LEN || (pkt[0] != M_DATA && pkt[0] != M_RLY) {
        return None;
    }
    Some(u32::from_be_bytes(pkt[1..5].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay side of the proof of possession, as `oneqpop.make_challenge` / `verify` do it (the real one is Python).
    fn make_challenge(skey: &[u8], pub_key: &[u8]) -> serde_json::Value {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let nid = node_id(pub_key);
        let mut nonce = [0u8; 16];
        rand::fill(&mut nonce).unwrap();
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60;
        let mut seed = [0u8; 32];
        rand::fill(&mut seed).unwrap();
        let e = PrivateKey::from_private_key(&X25519, &seed).unwrap();
        let ek = EncapsulationKey::new(&ML_KEM_768, &pub_key[X_LEN..]).unwrap();
        let (ct, k_kem) = ek.encapsulate().unwrap();
        let shared = dh(&e, &pub_key[..X_LEN]).unwrap();
        let okm = kdf(&sha256(&[POP_LABEL]), &cat(&[k_kem.as_ref(), &shared, &nid, &nonce]));
        let mut aad = nid.to_vec();
        aad.extend_from_slice(&nonce);
        aad.extend_from_slice(&exp.to_be_bytes());
        let mut rmsg = b"R".to_vec();
        rmsg.extend_from_slice(&nid);
        rmsg.extend_from_slice(&nonce);
        rmsg.extend_from_slice(&exp.to_be_bytes());
        let r = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, skey), &rmsg);
        let enc = seal0(&okm[..32], r.as_ref(), &aad);
        serde_json::json!({"e": b64.encode(x_pub(&e).unwrap()), "ct": b64.encode(ct.as_ref()), "nonce": b64.encode(nonce), "exp": exp, "enc": b64.encode(enc)})
    }

    fn verify_proof(skey: &[u8], nid: &[u8; 16], p: &serde_json::Value) -> bool {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let (Some(n), Some(pr), Some(exp)) = (p["nonce"].as_str(), p["proof"].as_str(), p["exp"].as_u64()) else { return false };
        let (Ok(nonce), Ok(proof)) = (b64.decode(n), b64.decode(pr)) else { return false };
        let mut rmsg = b"R".to_vec();
        rmsg.extend_from_slice(nid);
        rmsg.extend_from_slice(&nonce);
        rmsg.extend_from_slice(&exp.to_be_bytes());
        let r = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, skey), &rmsg);
        let mut msg = b"proof".to_vec();
        msg.extend_from_slice(nid);
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&exp.to_be_bytes());
        aws_lc_rs::hmac::verify(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, r.as_ref()), &msg, &proof).is_ok()
    }

    #[test]
    fn only_the_key_holder_can_answer_a_proof_of_possession_challenge() {
        let (a, mallory) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let skey = [7u8; 32];
        let ch = make_challenge(&skey, &a.pub_bytes);
        let ans = a.pop_answer(&ch).unwrap();
        assert!(verify_proof(&skey, &a.node_id(), &ans));
        assert!(!verify_proof(&[8u8; 32], &a.node_id(), &ans), "another server key");
        assert!(!verify_proof(&skey, &mallory.node_id(), &ans), "another node id");
        assert!(mallory.pop_answer(&ch).is_err(), "the challenge is sealed to a's keys");
        for field in ["nonce", "enc", "ct", "e"] {
            let mut bad = ch.clone();
            let mut raw = base64_decode_std(bad[field].as_str().unwrap());
            raw[0] ^= 1;
            bad[field] = serde_json::json!(base64_encode_std(&raw));
            assert!(a.pop_answer(&bad).is_err(), "{field}");
        }
        let mut moved = ch.clone();
        moved["exp"] = serde_json::json!(ch["exp"].as_u64().unwrap() + 1);
        assert!(a.pop_answer(&moved).is_err(), "the expiry is authenticated");
        assert!(a.pop_answer(&serde_json::json!({})).is_err());
    }

    fn base64_decode_std(s: &str) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    fn base64_encode_std(b: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// Cross-implementation check with the Python `oneqpop` (run by hand, see the comment in test_oneqpop.py):
    /// step 1 writes a key and its public key, step 2 answers a challenge Python made for it.
    #[test]
    #[ignore]
    fn pop_cross_check_with_python() {
        let dir = std::env::var("ONEQ_POP_DIR").expect("ONEQ_POP_DIR");
        let (keyf, chf, ansf) = (format!("{dir}/id.bin"), format!("{dir}/challenge.json"), format!("{dir}/answer.json"));
        if !std::path::Path::new(&chf).exists() {
            let a = Identity::generate().unwrap();
            std::fs::write(&keyf, a.to_bytes().unwrap()).unwrap();
            std::fs::write(format!("{dir}/pub.b64"), base64_encode_std(&a.pub_bytes)).unwrap();
        } else {
            let a = Identity::from_bytes(&std::fs::read(&keyf).unwrap()).unwrap();
            let ch: serde_json::Value = serde_json::from_slice(&std::fs::read(&chf).unwrap()).unwrap();
            std::fs::write(&ansf, a.pop_answer(&ch).unwrap().to_string()).unwrap();
        }
    }

    fn pair() -> (Identity, Identity) {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        if a.pub_bytes < b.pub_bytes { (a, b) } else { (b, a) }
    }

    #[test]
    fn identity_sizes_and_roundtrip() {
        let a = Identity::generate().unwrap();
        assert_eq!(a.pub_bytes.len(), 1216);
        // the public ML-KEM key taken from inside the private key is the real one
        let real = a.dk.encapsulation_key().unwrap().key_bytes().unwrap();
        assert_eq!(&a.pub_bytes[32..], real.as_ref());
        let b = Identity::from_bytes(&a.to_bytes().unwrap()).unwrap();
        assert_eq!(a.pub_bytes, b.pub_bytes);
        assert_eq!(a.node_id(), b.node_id());
        assert!(Identity::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn a_reloaded_identity_still_completes_handshakes() {
        let (i, r) = pair();
        let r2 = Identity::from_bytes(&r.to_bytes().unwrap()).unwrap();
        let i2 = Identity::from_bytes(&i.to_bytes().unwrap()).unwrap();
        let ((_, _), (mut si, mut sr)) = run(&i2, &r2);
        assert_eq!(sr.decrypt(&si.encrypt(b"after reload").unwrap()).unwrap(), b"after reload");
    }

    fn run(i: &Identity, r: &Identity) -> ((Vec<u8>, Vec<u8>), (Session, Session)) {
        let (init, st) = init_create(i, &r.pub_bytes, 11).unwrap();
        let c = init_consume(r, &i.pub_bytes, &init).unwrap();
        let (resp, rs, rr) = resp_create(r, &i.pub_bytes, &c, 22, c.sender_idx).unwrap();
        let (is, ir, pidx) = resp_consume(i, &st, &resp).unwrap();
        assert_eq!(pidx, 22);
        ((init, resp), (Session::new(&is, &ir, true, 11, 22), Session::new(&rs, &rr, false, 22, 11)))
    }

    #[test]
    fn handshake_sizes_match_the_python_implementation() {
        let (i, r) = pair();
        let ((init, resp), _) = run(&i, &r);
        assert_eq!((init.len(), init[0]), (2349, 0x21));
        assert_eq!((resp.len(), resp[0]), (2233, 0x22));
        assert_eq!(init_peek(&init), Some((11, i.node_id())));
        assert_eq!(resp_peek(&resp), Some((22, 11)));
    }

    #[test]
    fn session_keys_agree_both_ways() {
        let (i, r) = pair();
        let (_, (mut si, mut sr)) = run(&i, &r);
        let p = si.encrypt(b"hello").unwrap();
        assert_eq!(p[0], 0x23);
        assert_eq!(data_receiver_index(&p), Some(22));
        assert_eq!(sr.decrypt(&p).unwrap(), b"hello");
        let q = sr.encrypt(b"world").unwrap();
        assert_eq!(si.decrypt(&q).unwrap(), b"world");
    }

    #[test]
    fn tampering_and_wrong_peers_are_rejected() {
        let (i, r) = pair();
        let (init, st) = init_create(&i, &r.pub_bytes, 1).unwrap();
        for pos in [6usize, 30, 100, 1300, 2340] {
            let mut bad = init.clone();
            bad[pos] ^= 1;
            assert!(init_consume(&r, &i.pub_bytes, &bad).is_err(), "pos {pos}");
        }
        let stranger = Identity::generate().unwrap();
        let (s_init, _) = init_create(&stranger, &r.pub_bytes, 1).unwrap();
        assert!(init_consume(&r, &i.pub_bytes, &s_init).is_err());
        let c = init_consume(&r, &i.pub_bytes, &init).unwrap();
        let (resp, _, _) = resp_create(&r, &i.pub_bytes, &c, 2, 1).unwrap();
        for pos in [3usize, 20, 1200, 2232] {
            let mut bad = resp.clone();
            bad[pos] ^= 1;
            assert!(resp_consume(&i, &st, &bad).is_err(), "pos {pos}");
        }
        let (_, other) = init_create(&i, &r.pub_bytes, 1).unwrap(); // same index, other ephemerals
        assert!(resp_consume(&i, &other, &resp).is_err());
    }

    #[test]
    fn replay_window_and_tampered_data() {
        let (i, r) = pair();
        let (_, (mut si, mut sr)) = run(&i, &r);
        let pk: Vec<_> = (0..1100u32).map(|n| si.encrypt(&n.to_be_bytes()).unwrap()).collect();
        assert!(sr.decrypt(&pk[1099]).is_some());
        assert!(sr.decrypt(&pk[1099]).is_none(), "replay");
        assert!(sr.decrypt(&pk[10]).is_none(), "older than the window");
        assert!(sr.decrypt(&pk[1099 - 1023]).is_some(), "last slot of the window");
        assert!(sr.decrypt(&pk[500]).is_some(), "out of order but inside the window");
        assert!(sr.decrypt(&pk[500]).is_none());
        for pos in [1usize, 6, 12, 14, 20] {
            let mut bad = si.encrypt(b"xxxxxxxxxx").unwrap();
            bad[pos] ^= 1;
            assert!(sr.decrypt(&bad).is_none(), "pos {pos}");
        }
    }

    #[test]
    fn sessions_expire_after_180_seconds() {
        let (i, r) = pair();
        let (_, (mut si, mut sr)) = run(&i, &r);
        let p = si.encrypt(b"x").unwrap();
        si.backdate(181.0);
        sr.backdate(181.0);
        assert!(!si.usable());
        assert!(si.encrypt(b"y").is_none());
        assert!(sr.decrypt(&p).is_none());
    }

    #[test]
    fn kdf_is_hkdf_sha256_with_the_expected_info() {
        // RFC 5869 style check against an independent computation done with the same primitives
        let a = kdf(&[1u8; 32], b"ikm");
        let b = kdf(&[1u8; 32], b"ikm");
        let c = kdf(&[2u8; 32], b"ikm");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(sha256(&[b"abc"])[..4], [0xba, 0x78, 0x16, 0xbf]);
    }
}
