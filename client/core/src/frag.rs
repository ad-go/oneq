//! Application-level fragmentation of the handshake messages (<= 1200 bytes per datagram), same format and the
//! same DoS limits as `oneqtunel.fragment` / `Reassembler`.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::wire::T_FRAG;

pub const MAX_DGRAM: usize = 1200;
const HDR: usize = 7; // type, msg_id (4), index, total
pub const FRAG_PAYLOAD: usize = MAX_DGRAM - HDR;
pub const MAX_FRAGS: usize = 4;

pub fn fragment(msg: &[u8], msg_id: u32) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = if msg.is_empty() { vec![&[][..]] } else { msg.chunks(FRAG_PAYLOAD).collect() };
    assert!(chunks.len() <= MAX_FRAGS, "message too large to fragment");
    let total = chunks.len() as u8;
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut d = Vec::with_capacity(HDR + c.len());
            d.push(T_FRAG);
            d.extend_from_slice(&msg_id.to_be_bytes());
            d.push(i as u8);
            d.push(total);
            d.extend_from_slice(c);
            d
        })
        .collect()
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum Src {
    Udp(SocketAddr),
    Relay([u8; 16]),
}

struct Entry {
    expires: Instant,
    total: u8,
    parts: HashMap<u8, Vec<u8>>,
    nbytes: usize,
}

/// Bounded reassembly: limits on entries, entries per source, total bytes and lifetime.
pub struct Reassembler {
    entries: HashMap<(Src, u32), Entry>,
    bytes: usize,
    ttl: Duration,
    max_entries: usize,
    max_per_src: usize,
    max_bytes: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Reassembler {
            entries: HashMap::new(),
            bytes: 0,
            ttl: Duration::from_secs(5),
            max_entries: 16,
            max_per_src: 4,
            max_bytes: 64 * 1024,
        }
    }
}

impl Reassembler {
    pub fn entries(&self) -> usize {
        self.entries.len()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn gc(&mut self) {
        let now = Instant::now();
        let dead: Vec<_> = self.entries.iter().filter(|(_, e)| e.expires <= now).map(|(k, _)| k.clone()).collect();
        for k in dead {
            self.drop_entry(&k);
        }
    }

    fn drop_entry(&mut self, k: &(Src, u32)) {
        if let Some(e) = self.entries.remove(k) {
            self.bytes -= e.nbytes;
        }
    }

    pub fn feed(&mut self, src: &Src, dgram: &[u8]) -> Option<Vec<u8>> {
        if dgram.len() > MAX_DGRAM || dgram.len() < HDR || dgram[0] != T_FRAG {
            return None;
        }
        let mid = u32::from_be_bytes(dgram[1..5].try_into().ok()?);
        let (idx, total) = (dgram[5], dgram[6]);
        let body = &dgram[HDR..];
        if total == 0 || total as usize > MAX_FRAGS || idx >= total {
            return None;
        }
        if idx < total - 1 && body.len() != FRAG_PAYLOAD {
            return None; // only the last fragment may be short
        }
        self.gc();
        let key = (src.clone(), mid);
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.max_entries {
                return None;
            }
            if self.entries.keys().filter(|k| &k.0 == src).count() >= self.max_per_src {
                return None;
            }
            self.entries.insert(key.clone(), Entry { expires: Instant::now() + self.ttl, total, parts: HashMap::new(), nbytes: 0 });
        } else if self.entries[&key].total != total {
            self.drop_entry(&key);
            return None;
        }
        if self.entries[&key].parts.contains_key(&idx) {
            return None; // duplicate
        }
        if self.bytes + body.len() > self.max_bytes {
            return None;
        }
        let e = self.entries.get_mut(&key)?;
        e.parts.insert(idx, body.to_vec());
        e.nbytes += body.len();
        self.bytes += body.len();
        if e.parts.len() == total as usize {
            let msg: Vec<u8> = (0..total).flat_map(|i| e.parts[&i].clone()).collect();
            self.drop_entry(&key);
            return Some(msg);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Src {
        Src::Udp(format!("10.0.0.{n}:5000").parse().unwrap())
    }

    #[test]
    fn split_limits_and_any_order() {
        for size in [1usize, 1193, 1194, 2349, 2233, 4772] {
            let msg: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let fr = fragment(&msg, 7);
            assert!(fr.iter().all(|f| f.len() <= 1200), "{size}");
            let mut r = Reassembler::default();
            let mut out = None;
            for f in fr.iter().rev() {
                out = r.feed(&addr(1), f).or(out);
            }
            assert_eq!(out.as_deref(), Some(&msg[..]), "{size}");
            assert_eq!((r.entries(), r.bytes()), (0, 0));
        }
    }

    #[test]
    #[should_panic]
    fn too_large_is_refused() {
        fragment(&vec![0u8; 4773], 1);
    }

    #[test]
    fn duplicates_missing_and_malformed_are_dropped() {
        let msg = vec![9u8; 2349];
        let fr = fragment(&msg, 3);
        let mut r = Reassembler::default();
        assert!(r.feed(&addr(1), &fr[0]).is_none());
        let before = r.bytes();
        for _ in 0..20 {
            assert!(r.feed(&addr(1), &fr[0]).is_none());
        }
        assert_eq!(r.bytes(), before);
        let mut other = Reassembler::default();
        assert!(other.feed(&addr(1), &fr[0]).is_none()); // the second fragment never arrives
        let full = vec![0u8; FRAG_PAYLOAD];
        let mut bad: Vec<Vec<u8>> = vec![vec![], vec![T_FRAG]];
        for (idx, total, body) in [(0u8, 0u8, &full[..]), (2, 2, &full[..]), (0, 5, &full[..]), (0, 2, &b"short"[..])] {
            let mut d = vec![T_FRAG, 0, 0, 0, 1, idx, total];
            d.extend_from_slice(body);
            bad.push(d);
        }
        let mut huge = vec![T_FRAG, 0, 0, 0, 1, 0, 2];
        huge.extend(vec![0u8; 1300]);
        bad.push(huge);
        let mut r2 = Reassembler::default();
        for d in bad {
            assert!(r2.feed(&addr(2), &d).is_none());
        }
        assert_eq!(r2.entries(), 0);
        // a total that changes midway drops the entry
        let mut r3 = Reassembler::default();
        r3.feed(&addr(1), &fragment(&msg, 9)[0]);
        let mut bad = vec![T_FRAG, 0, 0, 0, 9, 1, 3];
        bad.extend(vec![0u8; FRAG_PAYLOAD]);
        assert!(r3.feed(&addr(1), &bad).is_none());
        assert_eq!(r3.entries(), 0);
    }

    #[test]
    fn memory_exhaustion_is_bounded() {
        let mut r = Reassembler::default();
        for mid in 0..100u32 {
            let mut d = vec![T_FRAG];
            d.extend_from_slice(&mid.to_be_bytes());
            d.extend_from_slice(&[0, 2]);
            d.extend(vec![0u8; FRAG_PAYLOAD]);
            r.feed(&addr(9), &d);
        }
        assert_eq!(r.entries(), 4, "per-source limit");
        let mut r = Reassembler::default();
        for i in 0..500u32 {
            let mut d = vec![T_FRAG];
            d.extend_from_slice(&i.to_be_bytes());
            d.extend_from_slice(&[0, 4]);
            d.extend(vec![0u8; FRAG_PAYLOAD]);
            r.feed(&Src::Udp(format!("10.1.{}.{}:1", i / 250, i % 250).parse().unwrap()), &d);
        }
        assert!(r.entries() <= 16 && r.bytes() <= 64 * 1024);
    }
}
