//! Entry points for the fuzz targets (`client/fuzz`) and for the randomized robustness test below, which runs under plain `cargo test`.
//!
//! Every function takes attacker-controlled bytes, must never panic, and checks one property: a datagram that differs from a valid
//! one in any byte is refused (the handshake and the transport are authenticated), and fragments reassemble to what was sent.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use crate::frag::{fragment, Reassembler, Src};
use crate::l3::Directory;
use crate::wire::*;

fn pair() -> &'static (Identity, Identity) {
    static P: OnceLock<(Identity, Identity)> = OnceLock::new();
    P.get_or_init(|| (Identity::generate().unwrap(), Identity::generate().unwrap()))
}

/// `base` with the changes `script` describes: two bytes of new length, then (position, xor) triples. Returns `base` itself for an empty script.
fn mutate(base: &[u8], script: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    if script.len() < 2 {
        return out;
    }
    let len = u16::from_be_bytes([script[0], script[1]]) as usize % (base.len() + 8);
    out.resize(len, 0);
    for t in script[2..].chunks_exact(3) {
        if !out.is_empty() {
            let pos = u16::from_be_bytes([t[0], t[1]]) as usize % out.len();
            out[pos] ^= t[2];
        }
    }
    out
}

/// INIT and RESP: arbitrary bytes are refused without a panic, and a valid message changed in any way fails authentication.
pub fn handshake(data: &[u8]) {
    let (a, b) = pair();
    let (init, st) = init_create(a, &b.pub_bytes, 7).unwrap();
    let _ = (init_peek(data), resp_peek(data));
    let _ = init_consume(b, &a.pub_bytes, data);
    let _ = resp_consume(a, &st, data);

    let bad = mutate(&init, data);
    let r = init_consume(b, &a.pub_bytes, &bad);
    assert_eq!(r.is_ok(), bad == init, "a changed INIT was accepted");

    let c = init_consume(b, &a.pub_bytes, &init).unwrap();
    let (resp, _, _) = resp_create(b, &a.pub_bytes, &c, 9, 7).unwrap();
    let bad = mutate(&resp, data);
    let r = resp_consume(a, &st, &bad);
    assert_eq!(r.is_ok(), bad == resp, "a changed RESP was accepted");
}

/// Transport packets: arbitrary bytes are dropped, a changed valid packet is dropped, the valid one opens exactly once.
pub fn transport(data: &[u8]) {
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let mut tx = Session::new(&k1, &k2, true, 11, 22);
    let mut rx = Session::new(&k2, &k1, false, 22, 11);
    let _ = data_receiver_index(data);
    assert!(rx.decrypt(data).is_none() || data.len() >= DATA_HDR + TAG_LEN);

    let pkt = tx.encrypt(data).unwrap();
    let bad = mutate(&pkt, data);
    if bad != pkt {
        assert!(rx.decrypt(&bad).is_none(), "a changed packet was accepted");
    }
    assert_eq!(rx.decrypt(&pkt).as_deref(), Some(data));
    assert!(rx.decrypt(&pkt).is_none(), "replay accepted");
}

/// Fragments: arbitrary datagrams never panic or exceed the limits, and a fragmented message reassembles to itself.
pub fn fragments(data: &[u8]) {
    let src = Src::Udp(SocketAddr::from(([192, 0, 2, 1], 4000)));
    let mut r = Reassembler::default();
    let _ = r.feed(&src, data);
    for chunk in data.chunks(1 + data.first().copied().unwrap_or(0) as usize * 8) {
        let _ = r.feed(&src, chunk);
    }
    assert!(r.entries() <= 16 && r.bytes() <= 64 * 1024, "reassembly limits exceeded");

    let mut r = Reassembler::default();
    let mut got = None;
    for f in fragment(data, 5) {
        got = r.feed(&src, &f);
    }
    if let Some(m) = got {
        assert_eq!(m, data);
    }
}

/// Ethernet and IP parsing of the layer-3 adapter.
pub fn frames(data: &[u8]) {
    let mut d = Directory::new(Ipv4Addr::new(10, 10, 10, 5), [2, 0, 0, 0, 0, 5], 24);
    d.set(Ipv4Addr::new(10, 10, 10, 7), [2, 0, 0, 0, 0, 7], [7u8; 16]);
    let _ = d.frame_in(data);
    let _ = d.ip_to_frame(data);
}

/// The registry's JSON: member lists and routes.
pub fn registry_json(data: &[u8]) {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = crate::control::parse_members(&v);
        let _ = crate::control::parse_routes(&v, (Ipv4Addr::new(10, 10, 10, 0), 24));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift, so the test is the same on every run and every platform
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = (self.next() as usize) % (max + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn random_and_mutated_input_never_panics_and_never_authenticates() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for i in 0..300 {
            let d = rng.bytes(if i % 10 == 0 { 3000 } else { 120 });
            handshake(&d);
            transport(&d);
            fragments(&d);
            frames(&d);
        }
        // shaped input: right type byte, right lengths
        for _ in 0..40 {
            for (t, n) in [(M_INIT, INIT_LEN), (M_RESP, RESP_LEN), (M_DATA, 80), (T_FRAG, 100), (0x45, 60)] {
                let mut d = rng.bytes(n);
                d.resize(n, 0);
                d[0] = t;
                handshake(&d);
                transport(&d);
                fragments(&d);
                frames(&d);
            }
        }
    }

    #[test]
    fn json_from_the_registry_never_panics() {
        let mut rng = Rng(42);
        for _ in 0..500 {
            registry_json(&rng.bytes(200));
        }
        for s in [
            r#"{"nodes":[{"id":"zz","pub":"AA==","ip":"1.2.3.4","mac":"x"}],"routes":[{"cidr":"1.2.3.4/99","via":"00","prio":-1}]}"#,
            r#"{"nodes":"x","routes":5}"#,
            r#"{"routes":[{"cidr":"192.168.16.0/24","via":"00000000000000000000000000000000","prio":18446744073709551615}]}"#,
            "[]", "null", "",
        ] {
            registry_json(s.as_bytes());
        }
    }
}
