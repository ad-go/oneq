//! NAT discovery, client side: STUN binding codec (RFC 5389, with the RFC 5780 CHANGE-REQUEST "change port" flag),
//! the classification the nodes publish, and the hole-punching compatibility rules. Same logic and same constants as
//! `oneqnat.py` (see its documentation for the reasoning, in particular why the filtering test goes last and comes from a
//! third port).
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

pub const COOKIE: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;
const A_CHANGE_REQUEST: u16 = 0x0003;
const A_XOR_MAPPED: u16 = 0x0020;
pub const CHANGE_PORT: u32 = 0x02;

/// Fixed timing of the synchronised punch rounds (identical in oneqnode.py: both implementations must agree).
pub const PUNCH_PERIOD: f64 = 4.0;
pub const PUNCH_CYCLE: i64 = 10;
pub const PUNCH_ATTEMPTS: i64 = 3;
pub const PUNCH_OFFSETS: [f64; 4] = [0.0, 0.08, 0.2, 0.45];
pub const HOLE_TTL: Duration = Duration::from_secs(4);

pub fn punch_attempt_round(idx: i64) -> bool {
    idx.rem_euclid(PUNCH_CYCLE) < PUNCH_ATTEMPTS
}

// ---------------------------------------------------------------- codec

pub fn is_stun(d: &[u8]) -> bool {
    d.len() >= 20 && d[0] < 0x04 && u32::from_be_bytes([d[4], d[5], d[6], d[7]]) == COOKIE && u16::from_be_bytes([d[2], d[3]]) as usize == d.len() - 20
}

pub struct Msg {
    pub mtype: u16,
    pub txid: [u8; 12],
    pub attrs: Vec<(u16, Vec<u8>)>,
}

pub fn parse(d: &[u8]) -> Option<Msg> {
    if !is_stun(d) {
        return None;
    }
    let mut attrs = Vec::new();
    let mut i = 20;
    while i + 4 <= d.len() {
        let t = u16::from_be_bytes([d[i], d[i + 1]]);
        let l = u16::from_be_bytes([d[i + 2], d[i + 3]]) as usize;
        if i + 4 + l > d.len() {
            return None;
        }
        attrs.push((t, d[i + 4..i + 4 + l].to_vec()));
        i += 4 + l + (4 - l % 4) % 4;
    }
    Some(Msg { mtype: u16::from_be_bytes([d[0], d[1]]), txid: d[8..20].try_into().unwrap(), attrs })
}

fn build(mtype: u16, txid: &[u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, v) in attrs {
        body.extend_from_slice(&t.to_be_bytes());
        body.extend_from_slice(&(v.len() as u16).to_be_bytes());
        body.extend_from_slice(v);
        body.extend(std::iter::repeat(0u8).take((4 - v.len() % 4) % 4));
    }
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(&mtype.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&COOKIE.to_be_bytes());
    out.extend_from_slice(txid);
    out.extend_from_slice(&body);
    out
}

pub fn xor_address(a: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let xport = a.port() ^ (COOKIE >> 16) as u16;
    match a.ip() {
        IpAddr::V4(ip) => {
            let mut v = vec![0, 1];
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend(ip.octets().iter().zip(COOKIE.to_be_bytes()).map(|(a, b)| a ^ b));
            v
        }
        IpAddr::V6(ip) => {
            let mut mask = COOKIE.to_be_bytes().to_vec();
            mask.extend_from_slice(txid);
            let mut v = vec![0, 2];
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend(ip.octets().iter().zip(mask).map(|(a, b)| a ^ b));
            v
        }
    }
}

pub fn unxor_address(v: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ (COOKIE >> 16) as u16;
    match (v[1], v.len()) {
        (1, 8) => {
            let o: Vec<u8> = v[4..8].iter().zip(COOKIE.to_be_bytes()).map(|(a, b)| a ^ b).collect();
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])), port))
        }
        (2, 20) => {
            let mut mask = COOKIE.to_be_bytes().to_vec();
            mask.extend_from_slice(txid);
            let o: Vec<u8> = v[4..20].iter().zip(mask).map(|(a, b)| a ^ b).collect();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&o);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(arr)), port))
        }
        _ => None,
    }
}

pub fn binding_request(change: u32) -> (Vec<u8>, [u8; 12]) {
    let mut txid = [0u8; 12];
    let _ = aws_lc_rs::rand::fill(&mut txid);
    let attrs = if change != 0 { vec![(A_CHANGE_REQUEST, change.to_be_bytes().to_vec())] } else { vec![] };
    (build(BINDING_REQUEST, &txid, &attrs), txid)
}

pub fn binding_response(txid: &[u8; 12], to: SocketAddr) -> Vec<u8> {
    build(BINDING_SUCCESS, txid, &[(A_XOR_MAPPED, xor_address(to, txid))])
}

pub fn mapped_of(m: &Msg) -> Option<SocketAddr> {
    if m.mtype != BINDING_SUCCESS {
        return None;
    }
    m.attrs.iter().find(|(t, _)| *t == A_XOR_MAPPED).and_then(|(_, v)| unxor_address(v, &m.txid))
}

// ---------------------------------------------------------------- classification

#[derive(Clone, Debug, PartialEq)]
pub struct NatInfo {
    /// open | cone | port-restricted | symmetric | blocked | unknown
    pub kind: String,
    pub mapped: Option<SocketAddr>,
    pub mapping: &'static str,
    pub filtering: &'static str,
    pub inbound: Option<bool>,
    /// symmetric NAT that allocates ports in steps of `delta`: the next mapping is predictable (see `predict_delta`)
    pub delta: Option<i32>,
    /// a second NAT (carrier-grade, or a router behind another router) sits between us and the internet
    pub cgnat: bool,
    /// how an open inbound port was obtained: pcp | natpmp | upnp
    pub via: Option<String>,
}

impl Default for NatInfo {
    fn default() -> Self {
        NatInfo { kind: "unknown".into(), mapped: None, mapping: "unknown", filtering: "unknown", inbound: None, delta: None, cgnat: false, via: None }
    }
}

/// A symmetric NAT whose consecutive mappings are further apart than this is treated as random.
pub const MAX_DELTA: i32 = 64;

/// Port allocation step of a symmetric NAT from the mapped ports of consecutive destinations (at least three), or None when the
/// ports do not look sequential. Equal steps are a clear pattern; different small positive steps are accepted too (a NAT that also
/// served another flow in between) with the last step as the guess.
pub fn predict_delta(ports: &[u16]) -> Option<i32> {
    if ports.len() < 3 {
        return None;
    }
    let steps: Vec<i32> = ports.windows(2).map(|w| w[1] as i32 - w[0] as i32).collect();
    if steps.iter().all(|s| *s == steps[0]) && steps[0] != 0 && steps[0].abs() <= MAX_DELTA {
        return Some(steps[0]);
    }
    if steps.iter().all(|s| *s > 0 && *s <= MAX_DELTA) {
        return steps.last().copied();
    }
    None
}

/// The ports to probe for a symmetric NAT whose last known mapping was `base`: base + delta * k, k = 1..=count (the NAT may have
/// served other flows meanwhile, so the window is wide). Unprivileged ports only.
pub fn predicted_ports(base: u16, delta: i32, count: i32) -> Vec<u16> {
    (1..=count).map(|k| base as i32 + delta * k).filter(|p| (1024..=65535).contains(p)).map(|p| p as u16).collect()
}

/// Extra addresses to probe on a peer: only for a symmetric NAT with a predictable step and a known last mapping ("ip:port").
pub fn punch_ports(kind: Option<&str>, mapped: Option<&str>, delta: Option<i32>) -> Vec<SocketAddr> {
    let (Some("symmetric"), Some(m), Some(d)) = (kind, mapped, delta) else { return vec![] };
    if d == 0 {
        return vec![];
    }
    let Ok(base) = m.parse::<SocketAddr>() else { return vec![] };
    predicted_ports(base.port(), d, 16).into_iter().map(|p| SocketAddr::new(base.ip(), p)).collect()
}

/// RFC 6598 shared address space (100.64.0.0/10): between a carrier's NAT and its customers.
pub fn is_cgnat_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64)
}

/// Is there a second NAT between this node and the internet? `mapped` is the address the relay sees, `router_wan` the WAN address the
/// home router reports (UPnP / NAT-PMP / PCP), if it answered. Signs: the mapped address is in 100.64.0.0/10, or the router reports
/// a WAN address that is not the one the relay sees. A relay on the same private network (a lab) sees the router's own address.
pub fn double_nat(mapped: Option<IpAddr>, router_wan: Option<IpAddr>) -> bool {
    if mapped.map_or(false, is_cgnat_ip) {
        return true;
    }
    matches!((mapped, router_wan), (m, Some(r)) if !r.is_unspecified() && m != Some(r))
}

impl NatInfo {
    /// The address other nodes can try; useless for a symmetric NAT (the port changes with the destination).
    pub fn public_endpoint(&self) -> Option<String> {
        match (&self.mapped, self.kind.as_str()) {
            (Some(m), "open" | "cone" | "port-restricted") => Some(m.to_string()),
            _ => None,
        }
    }

    /// What the registry stores: {"type", "mapped"?, "inbound"?}; None while nothing is known.
    pub fn description(&self) -> Option<Value> {
        if self.kind == "unknown" && self.mapped.is_none() {
            return None;
        }
        let mut d = json!({"type": self.kind});
        if let Some(m) = self.mapped {
            d["mapped"] = json!(m.to_string());
        }
        if let Some(i) = self.inbound {
            d["inbound"] = json!(i);
        }
        if let Some(x) = self.delta {
            d["delta"] = json!(x);
        }
        if self.cgnat {
            d["cgnat"] = json!(true);
        }
        if let Some(v) = &self.via {
            d["via"] = json!(v);
        }
        Some(d)
    }
}

pub type Fut<'a> = Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send + 'a>>;

pub trait Transact: Sync {
    fn transact(&self, dst: SocketAddr, change: u32) -> Fut<'_>;
}

/// Three transactions: main (mapping 1), alt (mapping 2: different => symmetric), then main with change-port answered from
/// a port never contacted (filtering). `local` is the socket's own address: the same as the mapped one means no NAT. `third` is one
/// more destination, used only for a symmetric NAT, to see how its ports are allocated.
pub async fn classify(t: &dyn Transact, main: SocketAddr, alt: SocketAddr, local: Option<SocketAddr>, third: Option<SocketAddr>) -> NatInfo {
    let Some(m1) = t.transact(main, 0).await else {
        return NatInfo { kind: "blocked".into(), ..Default::default() };
    };
    let mut info = NatInfo { mapped: Some(m1), ..Default::default() };
    let m2 = t.transact(alt, 0).await;
    if let Some(m2) = m2 {
        info.mapping = if m2 == m1 { "independent" } else { "dependent" };
    }
    if info.mapping != "dependent" {
        info.filtering = if t.transact(main, CHANGE_PORT).await.is_some() { "open" } else { "restricted" };
    } else if let (Some(third), Some(m2)) = (third, m2) {
        // no filtering test for a symmetric NAT, so the unsolicited-port rule does not apply to this one
        if let Some(m3) = t.transact(third, 0).await {
            if m3.ip() == m1.ip() && m2.ip() == m1.ip() {
                info.delta = predict_delta(&[m1.port(), m2.port(), m3.port()]);
                if info.delta.is_some() {
                    info.mapped = Some(m3); // the newest mapping: the prediction counts on from here
                }
            }
        }
    }
    info.kind = if local == Some(m1) {
        "open"
    } else if info.mapping == "dependent" {
        "symmetric"
    } else if info.mapping == "unknown" {
        "unknown"
    } else if info.filtering == "open" {
        "cone"
    } else {
        "port-restricted"
    }
    .into();
    info
}

/// Can two nodes with these NAT types open a direct UDP path with the help of the relay?
pub fn can_punch(a: &str, b: &str) -> bool {
    let tough = |x: &str| x == "symmetric" || x == "port-restricted";
    !((a == "symmetric" && tough(b)) || (b == "symmetric" && tough(a)))
}

/// `can_punch` with what the registry says about predictable symmetric NATs (`*_pred`: the side's ports can be guessed, which rescues
/// symmetric <-> port-restricted and symmetric <-> symmetric) and second NATs (`*_cgnat`: a punched hole is not worth waiting for,
/// unless the other side accepts unsolicited packets). Same rules as `oneqnat.can_punch`.
pub fn can_punch_ex(a: &str, b: &str, a_pred: bool, b_pred: bool, a_cgnat: bool, b_cgnat: bool) -> bool {
    let mut ok = can_punch(a, b);
    if !ok {
        ok = match (a, b) {
            ("symmetric", "symmetric") => a_pred && b_pred,
            ("symmetric", _) => a_pred,
            _ => b_pred,
        };
    }
    if ok && (a_cgnat || b_cgnat) {
        ok = if a_cgnat && !b_cgnat { b == "open" } else if b_cgnat && !a_cgnat { a == "open" } else { false };
    }
    ok
}

/// Filtering NATs on both sides: the only case where an early unsolicited packet can poison the other side's NAT state.
pub fn filtering(a: &str) -> bool {
    a == "port-restricted" || a == "symmetric"
}

// ---------------------------------------------------------------- prober on the node's own UDP socket

/// The address as the socket wants it: an IPv4 destination on a dual-stack (IPv6) socket is written ::ffff:a.b.c.d.
pub fn wire_addr(dst: SocketAddr, dual: bool) -> SocketAddr {
    match (dst.ip(), dual) {
        (IpAddr::V4(v), true) => SocketAddr::new(IpAddr::V6(v.to_ipv6_mapped()), dst.port()),
        _ => dst,
    }
}

pub struct Prober {
    udp: Arc<UdpSocket>,
    /// the socket is IPv6 with IPV6_V6ONLY off
    pub dual: bool,
    pending: Mutex<HashMap<[u8; 12], (oneshot::Sender<SocketAddr>, IpAddr)>>,
    pub timeout: Duration,
    pub tries: usize,
}

impl Prober {
    pub fn new(udp: Arc<UdpSocket>) -> Self {
        Prober { udp, dual: false, pending: Mutex::new(HashMap::new()), timeout: Duration::from_millis(600), tries: 3 }
    }

    /// Feed every datagram that `is_stun`. Answers count only from the IP the question went to.
    pub fn feed(&self, data: &[u8], from: SocketAddr) -> bool {
        let Some(m) = parse(data) else { return false };
        if m.mtype != BINDING_SUCCESS {
            return false;
        }
        let mut p = self.pending.lock().unwrap();
        match p.get(&m.txid) {
            Some((_, ip)) if *ip == from.ip() => {}
            _ => return false,
        }
        let Some(mapped) = mapped_of(&m) else { return false };
        if let Some((tx, _)) = p.remove(&m.txid) {
            let _ = tx.send(mapped);
        }
        true
    }
}

impl Transact for Prober {
    fn transact(&self, dst: SocketAddr, change: u32) -> Fut<'_> {
        Box::pin(async move {
            let (req, txid) = binding_request(change);
            let (tx, mut rx) = oneshot::channel();
            self.pending.lock().unwrap().insert(txid, (tx, dst.ip()));
            let mut result = None;
            for _ in 0..self.tries {
                let _ = self.udp.send_to(&req, wire_addr(dst, self.dual)).await;
                match tokio::time::timeout(self.timeout, &mut rx).await {
                    Ok(Ok(m)) => {
                        result = Some(m);
                        break;
                    }
                    _ => continue,
                }
            }
            self.pending.lock().unwrap().remove(&txid);
            result
        })
    }
}

/// The relay's clock, as measured by the registry client (offset = relay minus local, error at most half the round trip).
/// Both ends of a connection align their punch rounds to it.
#[derive(Default)]
pub struct ClockSync {
    offset: std::sync::atomic::AtomicU64,
    rtt: std::sync::atomic::AtomicU64,
    valid: std::sync::atomic::AtomicBool,
}

impl ClockSync {
    pub fn update(&self, offset: f64, rtt: f64) {
        use std::sync::atomic::Ordering::Relaxed;
        let best = f64::from_bits(self.rtt.load(Relaxed));
        if !self.valid.load(Relaxed) || rtt <= best * 1.5 + 0.005 {
            self.offset.store(offset.to_bits(), Relaxed);
            self.rtt.store(if self.valid.load(Relaxed) { best.min(rtt) } else { rtt }.to_bits(), Relaxed);
            self.valid.store(true, Relaxed);
        }
    }

    pub fn offset(&self) -> Option<f64> {
        use std::sync::atomic::Ordering::Relaxed;
        self.valid.load(Relaxed).then(|| f64::from_bits(self.offset.load(Relaxed)))
    }

    /// Seconds since the epoch on the relay's clock.
    pub fn now(&self) -> Option<f64> {
        let off = self.offset()?;
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs_f64();
        Some(t + off)
    }
}

/// Where the relay may probe: only the caller's own address is tested server side; this is for completeness of the API.
pub fn guess_local_ip(towards: IpAddr) -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind(if towards.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    s.connect(SocketAddr::new(towards, 9)).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rfc5769_xor_mapped_address_vector() {
        let tx: [u8; 12] = hex::decode("b7e7a701bc34d686fa87dfae").unwrap().try_into().unwrap();
        assert_eq!(xor_address(sa("192.0.2.1:32853"), &tx), hex::decode("0001a147e112a643").unwrap());
        assert_eq!(unxor_address(&hex::decode("0001a147e112a643").unwrap(), &tx), Some(sa("192.0.2.1:32853")));
    }

    #[test]
    fn roundtrip_and_malformed_input() {
        let (req, tx) = binding_request(CHANGE_PORT);
        let m = parse(&req).unwrap();
        assert_eq!((m.mtype, m.txid), (BINDING_REQUEST, tx));
        assert_eq!(m.attrs[0], (A_CHANGE_REQUEST, CHANGE_PORT.to_be_bytes().to_vec()));
        for a in ["203.0.113.9:40001", "[2001:db8::7]:65535"] {
            let r = parse(&binding_response(&tx, sa(a))).unwrap();
            assert_eq!(mapped_of(&r), Some(sa(a)));
        }
        let mut bad_len = req.clone();
        bad_len.push(0);
        let mut bad_attr = build(BINDING_REQUEST, &tx, &[]);
        bad_attr.extend_from_slice(&[0x00, 0x20, 0xff, 0xff]);
        bad_attr[2..4].copy_from_slice(&4u16.to_be_bytes());
        for bad in [vec![], vec![0u8; 19], req[..req.len() - 1].to_vec(), bad_len, bad_attr, [&[0x23u8][..], &[0u8; 30][..]].concat()] {
            assert!(parse(&bad).is_none(), "{bad:?}");
        }
        assert!(!is_stun(&[0x23; 40]), "a mesh DATA packet is not STUN");
    }

    struct Model {
        kind: &'static str,
        calls: Mutex<Vec<(SocketAddr, u32)>>,
    }

    impl Transact for Model {
        fn transact(&self, dst: SocketAddr, change: u32) -> Fut<'_> {
            self.calls.lock().unwrap().push((dst, change));
            let r = match self.kind {
                "blocked" => None,
                "open" => Some(sa("192.168.1.10:4000")),
                "symmetric" => Some(SocketAddr::new("203.0.113.5".parse().unwrap(), 40000 + dst.port() % 997)),
                "cone" => Some(sa("203.0.113.5:40000")),
                _ if change & CHANGE_PORT != 0 => None, // port-restricted drops the new source port
                _ => Some(sa("203.0.113.5:40000")),
            };
            Box::pin(async move { r })
        }
    }

    #[tokio::test]
    async fn every_kind_is_classified_and_the_filtering_test_goes_last() {
        let (main, alt, local) = (sa("198.51.100.1:3478"), sa("198.51.100.1:3479"), Some(sa("192.168.1.10:4000")));
        for (kind, want, public) in [
            ("open", "open", Some("192.168.1.10:4000")),
            ("cone", "cone", Some("203.0.113.5:40000")),
            ("port-restricted", "port-restricted", Some("203.0.113.5:40000")),
            ("symmetric", "symmetric", None),
            ("blocked", "blocked", None),
        ] {
            let m = Model { kind, calls: Mutex::new(vec![]) };
            let info = classify(&m, main, alt, local, None).await;
            assert_eq!(info.kind, want, "{kind}");
            assert_eq!(info.public_endpoint().as_deref(), public, "{kind}");
            let calls = m.calls.lock().unwrap().clone();
            assert!(calls.len() <= 3);
            if matches!(kind, "cone" | "port-restricted" | "open") {
                assert_eq!(calls.last(), Some(&(main, CHANGE_PORT)), "{kind}");
            }
            if kind == "symmetric" {
                assert_eq!((info.mapping, info.filtering), ("dependent", "unknown"));
            }
        }
    }

    #[test]
    fn hole_punching_rules_and_round_pattern() {
        let t = ["open", "cone", "port-restricted", "symmetric"];
        let impossible = [("symmetric", "symmetric"), ("symmetric", "port-restricted"), ("port-restricted", "symmetric")];
        for a in t {
            for b in t {
                assert_eq!(can_punch(a, b), !impossible.contains(&(a, b)), "{a} {b}");
            }
        }
        assert!(can_punch("unknown", "symmetric") && can_punch("blocked", "symmetric"));
        let rounds: Vec<i64> = (0..40).filter(|i| punch_attempt_round(*i)).collect();
        assert_eq!(rounds, vec![0, 1, 2, 10, 11, 12, 20, 21, 22, 30, 31, 32]);
        let gap = (PUNCH_CYCLE - PUNCH_ATTEMPTS + 1) as f64 * PUNCH_PERIOD - PUNCH_OFFSETS[3];
        assert!(gap > 30.0, "conntrack keeps an unanswered UDP entry for 30 s");
        assert!(filtering("symmetric") && filtering("port-restricted") && !filtering("cone") && !filtering("open"));
    }

    #[test]
    fn predictable_symmetric_nats_second_nats_and_the_ports_to_probe() {
        assert!(can_punch_ex("symmetric", "port-restricted", true, false, false, false));
        assert!(can_punch_ex("port-restricted", "symmetric", false, true, false, false));
        assert!(!can_punch_ex("port-restricted", "symmetric", true, false, false, false), "the prediction belongs to the symmetric side");
        assert!(!can_punch_ex("symmetric", "symmetric", true, false, false, false));
        assert!(can_punch_ex("symmetric", "symmetric", true, true, false, false));
        for other in ["cone", "port-restricted", "symmetric", "unknown"] {
            assert!(!can_punch_ex("cone", other, false, false, true, false), "{other}");
            assert!(!can_punch_ex(other, "cone", false, false, false, true), "{other}");
        }
        assert!(can_punch_ex("port-restricted", "open", false, false, true, false));
        assert!(can_punch_ex("open", "symmetric", false, true, false, true));
        assert!(!can_punch_ex("open", "cone", false, false, true, true), "two second NATs");
        // the old two-argument rules are unchanged
        assert!(can_punch_ex("cone", "symmetric", false, false, false, false) && !can_punch_ex("symmetric", "symmetric", false, false, false, false));

        assert_eq!(predict_delta(&[100, 101, 102]), Some(1));
        assert_eq!(predict_delta(&[100, 102, 104]), Some(2));
        assert_eq!(predict_delta(&[100, 102, 105]), Some(3));
        assert_eq!(predict_delta(&[100, 99, 98]), Some(-1));
        for none in [&[100u16, 100, 100][..], &[100, 5000, 9000], &[100, 99, 101], &[100, 101]] {
            assert_eq!(predict_delta(none), None, "{none:?}");
        }
        let ports = punch_ports(Some("symmetric"), Some("203.0.113.5:40010"), Some(2));
        assert_eq!(ports[..3], [sa("203.0.113.5:40012"), sa("203.0.113.5:40014"), sa("203.0.113.5:40016")]);
        assert_eq!(ports.len(), 16);
        assert!(punch_ports(Some("cone"), Some("203.0.113.5:40010"), Some(2)).is_empty());
        assert!(punch_ports(Some("symmetric"), Some("203.0.113.5:40010"), None).is_empty());
        assert!(punch_ports(Some("symmetric"), Some("garbage"), Some(1)).is_empty());
        assert_eq!(punch_ports(Some("symmetric"), Some("203.0.113.5:65530"), Some(1)).len(), 5);
        let low: Vec<u16> = punch_ports(Some("symmetric"), Some("203.0.113.5:1030"), Some(-1)).iter().map(|a| a.port()).collect();
        assert_eq!(low, vec![1029, 1028, 1027, 1026, 1025, 1024]);

        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert!(double_nat(ip("100.64.3.9"), None) && double_nat(ip("100.127.255.254"), ip("100.70.0.1")));
        assert!(double_nat(ip("203.0.113.5"), ip("192.168.0.2")) && double_nat(ip("203.0.113.5"), ip("198.51.100.8")));
        assert!(!double_nat(ip("203.0.113.5"), ip("203.0.113.5")) && !double_nat(ip("203.0.113.5"), None));
        assert!(!double_nat(ip("203.0.113.5"), ip("0.0.0.0")) && !double_nat(ip("10.0.0.5"), ip("10.0.0.5")));
        assert!(!is_cgnat_ip("100.128.0.1".parse().unwrap()) && is_cgnat_ip("100.64.0.1".parse().unwrap()));
    }

    /// A symmetric NAT that hands out consecutive ports (every `step`) as new destinations are contacted.
    struct Sequential {
        step: u16,
        /// when not empty: the port of the n-th destination, whatever the step
        ports: Vec<u16>,
        seen: Mutex<Vec<SocketAddr>>,
    }

    impl Transact for Sequential {
        fn transact(&self, dst: SocketAddr, _change: u32) -> Fut<'_> {
            let mut seen = self.seen.lock().unwrap();
            if !seen.contains(&dst) {
                seen.push(dst);
            }
            let idx = seen.iter().position(|d| *d == dst).unwrap() as u16;
            let port = self.ports.get(idx as usize).copied().unwrap_or(40000 + self.step * idx);
            let r = Some(SocketAddr::new("203.0.113.5".parse().unwrap(), port));
            Box::pin(async move { r })
        }
    }

    #[tokio::test]
    async fn a_sequential_symmetric_nat_is_predictable_and_others_are_left_alone() {
        let (main, alt, third, local) = (sa("198.51.100.1:3478"), sa("198.51.100.1:3479"), Some(sa("198.51.100.1:3480")), Some(sa("192.168.1.10:4000")));
        for step in [1u16, 2, 4] {
            let m = Sequential { step, ports: vec![], seen: Mutex::new(vec![]) };
            let info = classify(&m, main, alt, local, third).await;
            assert_eq!((info.kind.as_str(), info.delta), ("symmetric", Some(step as i32)));
            assert_eq!(info.mapped, Some(sa(&format!("203.0.113.5:{}", 40000 + 2 * step))), "the newest mapping is the base");
            assert_eq!(info.description().unwrap()["delta"], json!(step));
        }
        // random-looking ports: no delta
        let m = Sequential { step: 0, ports: vec![41000, 52000, 43500], seen: Mutex::new(vec![]) };
        let info = classify(&m, main, alt, local, third).await;
        assert_eq!((info.kind.as_str(), info.delta), ("symmetric", None));
        // the third destination is never used where it could disturb the filtering test
        for kind in ["cone", "port-restricted", "open"] {
            let m = Model { kind, calls: Mutex::new(vec![]) };
            let info = classify(&m, main, alt, local, third).await;
            assert!(m.calls.lock().unwrap().iter().all(|(d, _)| Some(*d) != third), "{kind}");
            assert_eq!(info.delta, None);
        }
        let mut i = NatInfo { kind: "symmetric".into(), mapped: Some(sa("203.0.113.5:40000")), delta: Some(2), cgnat: true, via: Some("upnp".into()), ..Default::default() };
        assert_eq!(i.description().unwrap(), json!({"type": "symmetric", "mapped": "203.0.113.5:40000", "delta": 2, "cgnat": true, "via": "upnp"}));
        i.delta = None;
        i.cgnat = false;
        i.via = None;
        assert_eq!(i.description().unwrap(), json!({"type": "symmetric", "mapped": "203.0.113.5:40000"}));
    }

    #[test]
    fn registry_description() {
        assert!(NatInfo::default().description().is_none());
        let i = NatInfo { kind: "port-restricted".into(), mapped: Some(sa("203.0.113.5:40000")), inbound: Some(false), ..Default::default() };
        assert_eq!(i.description().unwrap(), json!({"type": "port-restricted", "mapped": "203.0.113.5:40000", "inbound": false}));
    }

    /// The prober against a tiny in-process STUN responder on loopback: answers, ignores forged ones.
    #[tokio::test]
    async fn prober_talks_to_a_server_and_ignores_forged_answers() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let saddr = server.local_addr().unwrap();
        let s2 = server.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 200];
            while let Ok((n, from)) = s2.recv_from(&mut b).await {
                if let Some(m) = parse(&b[..n]) {
                    let _ = s2.send_to(&binding_response(&m.txid, from), from).await;
                }
            }
        });
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let me = client.local_addr().unwrap();
        let prober = Arc::new(Prober::new(client.clone()));
        let (p2, c2) = (prober.clone(), client.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 200];
            while let Ok((n, from)) = c2.recv_from(&mut b).await {
                p2.feed(&b[..n], from);
            }
        });
        assert_eq!(prober.transact(saddr, 0).await, Some(me));
        // forged: right transaction id but from another IP, and an unknown id
        let (_, tx) = binding_request(0);
        let (otx, mut orx) = oneshot::channel();
        prober.pending.lock().unwrap().insert(tx, (otx, "127.0.0.1".parse().unwrap()));
        assert!(!prober.feed(&binding_response(&tx, sa("6.6.6.6:1")), sa("10.9.9.9:1")));
        assert!(!prober.feed(&binding_response(&[7u8; 12], sa("6.6.6.6:1")), sa("127.0.0.1:1")));
        assert!(orx.try_recv().is_err());
        // nobody answers: None after the retries
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let mut quick = Prober::new(client);
        quick.timeout = Duration::from_millis(80);
        quick.tries = 2;
        assert_eq!(quick.transact(dead, 0).await, None);
    }
}
