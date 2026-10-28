//! The mesh engine: peers, sessions, direct/relay paths, hole punching and the L3 adapter. A single task owns all
//! state and is driven by events (datagrams, relay frames, TUN packets, registry updates) and a 250 ms tick, the same
//! structure and the same rules as `OneqNode` in `oneqnode.py`.
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::control::{JoinInfo, Member};
use crate::frag::{fragment, Reassembler, Src};
use crate::l3::{mac_to_string, Directory, In, Out, Route};
use crate::nat::{self, ClockSync, NatInfo, HOLE_TTL, PUNCH_OFFSETS, PUNCH_PERIOD};
use crate::status::{PeerInfo, Status};
use crate::wire::*;

const KEEPALIVE: Duration = Duration::from_secs(25);
const HS_RETRY: Duration = Duration::from_secs(2);
const PROBE_EVERY: Duration = Duration::from_secs(20);
const DIRECT_STALE: Duration = Duration::from_secs(75);
const MAX_CANDIDATES: usize = 8;
// Delegated relay nodes (members an administrator allowed to forward datagrams for the others, over UDP)
const RLY_ALIVE: Duration = Duration::from_secs(40);
const RLY_BAD_FOR: Duration = Duration::from_secs(30);
const RLY_MAX_DGRAM: usize = 1600;
const RLY_PROBE_EVERY: Duration = Duration::from_secs(10);
/// A member counts as alive for the choice of a gateway if a packet arrived within this time (keepalives come every 25 s)
const GATEWAY_ALIVE: Duration = Duration::from_secs(45);

pub enum Event {
    Udp(Vec<u8>, SocketAddr),
    Relay([u8; 16], Vec<u8>),
    Tun(Vec<u8>),
    Members(Vec<Member>),
    /// networks routed through a gateway member (already filtered: private, outside the mesh)
    Routes(Vec<Route>),
    Stop,
}

#[derive(Clone)]
pub struct EngineCfg {
    pub force_relay: bool,
    pub use_relay: bool,
    pub relay_after: Duration,
    pub max_skew: Duration,
    /// our own advertised addresses, never used as candidates of a peer
    pub local_candidates: Vec<String>,
    /// offer to forward datagrams for the others (effective once the administrator delegates this node)
    pub relay_offer: bool,
    /// send through the delegated relay nodes of the community when a peer cannot be reached directly
    pub use_delegates: bool,
}

impl Default for EngineCfg {
    fn default() -> Self {
        EngineCfg { force_relay: false, use_relay: true, relay_after: Duration::from_secs(10), max_skew: Duration::from_secs(180), local_candidates: vec![], relay_offer: false, use_delegates: true }
    }
}

#[derive(Clone)]
pub struct Io {
    pub udp: Arc<UdpSocket>,
    pub relay_tx: mpsc::Sender<Vec<u8>>,
    pub tun_tx: mpsc::Sender<Vec<u8>>,
    pub relay_connected: Arc<AtomicBool>,
    /// ask the registry task to refresh the member list soon
    pub refresh_members: Arc<AtomicBool>,
    /// every known member has a session (the registry task then polls less often)
    pub all_connected: Arc<AtomicBool>,
    /// our NAT as measured with the relay's STUN service (written by the NAT task)
    pub nat: Arc<std::sync::Mutex<NatInfo>>,
    /// the data socket is IPv6 with IPV6_V6ONLY off (IPv4 peers are addressed as ::ffff:a.b.c.d)
    pub dual: bool,
    /// this host has a global IPv6 address: IPv6 candidates are worth trying
    pub v6: Arc<AtomicBool>,
    /// the relay's clock: the punch rounds of both ends are aligned to it
    pub clock: Arc<ClockSync>,
    /// state shared with the free sending functions and the registry task (delegated relay nodes)
    pub rly: Arc<std::sync::Mutex<RlyShared>>,
}

#[derive(Default)]
pub struct RlyShared {
    /// destination -> delegated relay node chosen by the engine at its last tick
    pub choice: HashMap<[u8; 16], [u8; 16]>,
    /// (relay node, destination || datagram) waiting for the engine to send them
    pub outbox: VecDeque<([u8; 16], Vec<u8>)>,
    /// delegated relay nodes we hold a live session with (published in the registry, so the others know how to reach us)
    pub attached: Vec<[u8; 16]>,
}

#[derive(Default)]
struct Rly {
    /// the delegated relay nodes of the community and their caps (kbit/s)
    nodes: HashMap<[u8; 16], u32>,
    /// set when the registry delegates THIS node and relay_offer is on
    role: Option<u32>,
    rtt: HashMap<[u8; 16], f64>,
    probe_sent: HashMap<[u8; 16], Instant>,
    probe_open: HashMap<[u8; 16], Instant>,
    bad: HashMap<([u8; 16], [u8; 16]), Instant>,
    nack_t: HashMap<([u8; 16], [u8; 16]), Instant>,
    total: Option<(f64, Instant)>,
    senders: HashMap<[u8; 16], (f64, Instant)>,
    packets: u64,
    bytes: u64,
    dropped: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Path {
    Direct,
    Relay,
}

#[derive(Clone, Copy)]
enum Via {
    Udp(SocketAddr),
    Relay,
}

struct Peer {
    id: [u8; 16],
    pub_key: Vec<u8>,
    ip: Ipv4Addr,
    mac: [u8; 6],
    name: String,
    online: bool,
    initiator: bool,
    cur: Option<Session>,
    prev: Option<Session>,
    pending: VecDeque<InitState>,
    candidates: Vec<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    path: Path,
    last_direct_rx: Option<Instant>,
    /// the last authenticated packet of any kind (data or keepalive, direct or through a relay)
    last_rx: Option<Instant>,
    last_tx: Instant,
    last_probe: Option<Instant>,
    last_punch: Option<Instant>,
    last_init: Option<Instant>,
    last_ts: u64,
    t_nosession: Option<Instant>,
    relay_hs: bool,
    force_hs: bool,
    last_rehs: Option<Instant>,
    /// NAT type the peer published and the address it measured (the IP also counts for a symmetric NAT)
    nat: Option<String>,
    nat_mapped: Option<String>,
    /// port allocation step of the peer's symmetric NAT, and whether a second NAT sits in front of it
    nat_delta: Option<i32>,
    nat_cgnat: bool,
    /// addresses a predictable symmetric NAT will probably use for its next mappings (see nat::punch_ports)
    predicted: Vec<SocketAddr>,
    /// filtering NATs on both sides: no unsolicited packets outside punch rounds (see nat.rs)
    careful: bool,
    /// an address a packet of this peer just came from: our NAT lets it in, so we may send to it
    hole_addr: Option<SocketAddr>,
    hole_until: Option<Instant>,
    /// delegated relay nodes this peer says it holds a session with
    attached: Vec<[u8; 16]>,
    /// administrator marked this node as an exit node
    exit_node: bool,
}

impl Peer {
    /// Where unsolicited packets may go now: every candidate, or - between two filtering NATs - only an open hole.
    fn direct_targets(&self, now: Instant) -> Vec<SocketAddr> {
        if !self.careful {
            return self.candidates.clone();
        }
        match (self.hole_addr, self.hole_until) {
            (Some(a), Some(t)) if now < t => vec![a],
            _ => vec![],
        }
    }

    /// A packet of this peer arrived from `addr`. Only addresses at the IPs it registered count: a forged source
    /// address must not make us send a 2 KB handshake to a third party. True if the hole was not already open.
    fn open_hole(&mut self, addr: SocketAddr) -> bool {
        let mut known: Vec<std::net::IpAddr> = self.candidates.iter().map(|c| c.ip()).collect();
        if let Some(m) = self.nat_mapped.as_deref().and_then(|m| m.parse::<SocketAddr>().ok()) {
            known.push(m.ip());
        }
        if Some(addr) != self.peer_addr && !known.contains(&addr.ip()) {
            return false;
        }
        let now = Instant::now();
        let fresh = self.hole_addr != Some(addr) || self.hole_until.map_or(true, |t| now >= t);
        self.hole_addr = Some(addr);
        self.hole_until = Some(now + HOLE_TTL);
        fresh
    }

    /// Is a direct path worth attempting? NAT types, predictable symmetric NATs and second NATs decide (IPv4); a pair that both
    /// have a global IPv6 address always is: there is no translation to get through, only a stateful firewall.
    fn punchable(&self, mine: &NatInfo, v6: bool) -> bool {
        if v6 && self.candidates.iter().any(|c| c.is_ipv6()) {
            return true;
        }
        nat::can_punch_ex(&mine.kind, self.nat.as_deref().unwrap_or("unknown"), mine.delta.is_some(), self.nat_delta.is_some(), mine.cgnat, self.nat_cgnat)
    }

    fn new(m: &Member, me_pub: &[u8]) -> Self {
        Peer {
            id: m.id,
            pub_key: m.pub_key.clone(),
            ip: m.ip,
            mac: m.mac,
            name: m.name.clone(),
            online: m.online,
            initiator: me_pub < m.pub_key.as_slice(),
            cur: None,
            prev: None,
            pending: VecDeque::new(),
            candidates: vec![],
            peer_addr: None,
            path: Path::Direct,
            last_direct_rx: None,
            last_rx: None,
            last_tx: Instant::now(),
            last_probe: None,
            last_punch: None,
            last_init: None,
            last_ts: 0,
            t_nosession: Some(Instant::now()),
            relay_hs: false,
            force_hs: false,
            last_rehs: None,
            nat: m.nat.clone(),
            nat_mapped: m.nat_mapped.clone(),
            nat_delta: m.nat_delta,
            nat_cgnat: m.nat_cgnat,
            predicted: nat::punch_ports(m.nat.as_deref(), m.nat_mapped.as_deref(), m.nat_delta),
            careful: false,
            hole_addr: None,
            hole_until: None,
            attached: m.relays.clone(),
            exit_node: m.exit_node,
        }
    }
}

/// A delegated relay node we can talk to over UDP right now: a live session and a direct path that is recent (keepalives every 25 s).
fn rly_usable(p: &Peer, now: Instant) -> bool {
    p.cur.as_ref().map_or(false, |s| s.usable()) && p.path == Path::Direct && p.peer_addr.is_some() && p.last_direct_rx.map_or(false, |t| now.duration_since(t) < RLY_ALIVE)
}

fn due(last: Option<Instant>, every: Duration) -> bool {
    last.map_or(true, |t| t.elapsed() >= every)
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = rand::fill(&mut b);
    u32::from_be_bytes(b)
}

fn udp_send(io: &Io, data: &[u8], addr: SocketAddr) {
    let _ = io.udp.try_send_to(data, nat::wire_addr(addr, io.dual));
}

fn relay_send(io: &Io, cfg: &EngineCfg, dst: &[u8; 16], data: &[u8]) {
    if !cfg.use_relay {
        return;
    }
    if cfg.use_delegates {
        // a delegated relay node chosen for this destination: the engine sends it over UDP right after the current event
        let mut g = io.rly.lock().unwrap();
        if let Some(r) = g.choice.get(dst).copied() {
            if g.outbox.len() < 512 {
                let mut f = Vec::with_capacity(16 + data.len());
                f.extend_from_slice(dst);
                f.extend_from_slice(data);
                g.outbox.push_back((r, f));
            }
            return;
        }
    }
    let mut f = Vec::with_capacity(16 + data.len());
    f.extend_from_slice(dst);
    f.extend_from_slice(data);
    let _ = io.relay_tx.try_send(f);
}

fn send_hs(io: &Io, cfg: &EngineCfg, p: &Peer, msg: &[u8], via: Via) {
    for d in fragment(msg, rand_u32()) {
        match via {
            Via::Udp(a) => udp_send(io, &d, a),
            Via::Relay => relay_send(io, cfg, &p.id, &d),
        }
    }
}

fn send_raw(io: &Io, cfg: &EngineCfg, p: &mut Peer, pkt: &[u8]) {
    p.last_tx = Instant::now();
    if p.path == Path::Relay || cfg.force_relay {
        relay_send(io, cfg, &p.id, pkt);
    } else if let Some(a) = p.peer_addr {
        udp_send(io, pkt, a);
    } else {
        for c in p.direct_targets(Instant::now()) {
            udp_send(io, pkt, c);
        }
    }
}

fn send_payload(io: &Io, cfg: &EngineCfg, p: &mut Peer, payload: &[u8]) {
    let Some(s) = p.cur.as_mut() else { return };
    if !s.usable() {
        return;
    }
    if let Some(pkt) = s.encrypt(payload) {
        send_raw(io, cfg, p, &pkt);
    }
}

fn note_path(p: &mut Peer, via: &Via) {
    match via {
        Via::Udp(a) => {
            p.peer_addr = Some(*a);
            p.last_direct_rx = Some(Instant::now());
            p.path = Path::Direct;
            p.hole_addr = Some(*a);
            p.hole_until = Some(Instant::now() + HOLE_TTL);
        }
        Via::Relay => {
            if p.last_direct_rx.map_or(true, |t| t.elapsed() > DIRECT_STALE) {
                p.path = Path::Relay;
            }
        }
    }
}

pub struct Engine {
    me: Arc<Identity>,
    cfg: EngineCfg,
    io: Io,
    status: Arc<Status>,
    dir: Directory,
    peers: HashMap<[u8; 16], Peer>,
    by_idx: HashMap<u32, [u8; 16]>,
    mac_owner: HashMap<[u8; 6], [u8; 16]>,
    reasm: Reassembler,
    rly: Rly,
    budget: f64,
    budget_t: Instant,
    mtu: usize,
    tx_bytes: u64,
    rx_bytes: u64,
    ticks: u64,
    /// relay-clock time of the next punch round, and the burst packets still to send
    punch_boundary: f64,
    punch_due: VecDeque<f64>,
}

impl Engine {
    pub fn new(me: Arc<Identity>, cfg: EngineCfg, io: Io, status: Arc<Status>, info: &JoinInfo) -> Self {
        Engine {
            me,
            cfg,
            io,
            status,
            dir: Directory::new(info.ip, info.mac, info.prefix),
            peers: HashMap::new(),
            by_idx: HashMap::new(),
            mac_owner: HashMap::new(),
            reasm: Reassembler::default(),
            rly: Rly::default(),
            budget: 10.0,
            budget_t: Instant::now(),
            mtu: info.mtu as usize,
            tx_bytes: 0,
            rx_bytes: 0,
            ticks: 0,
            punch_boundary: 0.0,
            punch_due: VecDeque::new(),
        }
    }

    fn new_idx(&self) -> u32 {
        loop {
            let i = rand_u32();
            if i != 0 && !self.by_idx.contains_key(&i) {
                return i;
            }
        }
    }

    fn take(&mut self, id: &[u8; 16]) -> Option<Peer> {
        self.peers.remove(id)
    }

    fn put(&mut self, p: Peer) {
        self.peers.insert(p.id, p);
    }

    fn install(&mut self, p: &mut Peer, s: Session, via: &Via) {
        if let Some(old) = p.prev.take() {
            self.by_idx.remove(&old.local_idx);
        }
        let (idx, initiator) = (s.local_idx, s.initiator);
        p.prev = p.cur.take();
        p.cur = Some(s);
        self.by_idx.insert(idx, p.id);
        note_path(p, via);
        self.status.note(format!(
            "session with {} ({}) established ({}), path={}",
            p.ip,
            hex::encode(&p.id[..4]),
            if initiator { "initiator" } else { "responder" },
            if p.path == Path::Direct { "direct" } else { "relay" }
        ));
    }

    // ------------------------------------------------------------ events
    pub fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Udp(d, a) => self.on_udp(&d, a),
            Event::Relay(src, d) => self.on_relay(src, &d),
            Event::Tun(pkt) => self.on_tun(&pkt),
            Event::Members(m) => self.apply_members(&m),
            Event::Routes(r) => self.dir.set_routes(r),
            Event::Stop => {}
        }
        self.flush_rly();
    }

    fn on_tun(&mut self, pkt: &[u8]) {
        let (io, cfg) = (self.io.clone(), self.cfg.clone());
        match self.dir.ip_to_frame(pkt) {
            Some(Out::Unicast(id, frame)) => {
                if let Some(p) = self.peers.get_mut(&id) {
                    send_payload(&io, &cfg, p, &frame);
                    self.tx_bytes += pkt.len() as u64;
                }
            }
            Some(Out::Flood(frame)) => {
                for p in self.peers.values_mut() {
                    send_payload(&io, &cfg, p, &frame);
                }
                self.tx_bytes += pkt.len() as u64;
            }
            None => {}
        }
    }

    fn deliver(&mut self, p: &mut Peer, frame: &[u8]) {
        if frame.len() < 14 || frame.len() > self.mtu + 22 {
            return;
        }
        let src: [u8; 6] = frame[6..12].try_into().unwrap();
        if src[0] & 1 != 0 || src == self.dir.my_mac {
            return;
        }
        if let Some(owner) = self.mac_owner.get(&src) {
            if *owner != p.id {
                return; // a member claiming another member's MAC
            }
        }
        match self.dir.frame_in(frame) {
            Some(In::Ip(pkt)) => {
                self.rx_bytes += pkt.len() as u64;
                let _ = self.io.tun_tx.try_send(pkt);
            }
            Some(In::Reply(f)) => {
                let (io, cfg) = (self.io.clone(), self.cfg.clone());
                send_payload(&io, &cfg, p, &f);
            }
            None => {}
        }
    }

    fn on_udp(&mut self, data: &[u8], addr: SocketAddr) {
        let Some(&t) = data.first() else { return };
        match t {
            M_DATA => self.on_data(data, Via::Udp(addr)),
            M_RLY => self.on_rly(data, addr),
            T_FRAG => {
                if let Some(msg) = self.reasm.feed(&Src::Udp(addr), data) {
                    self.on_hs(&msg, Via::Udp(addr), None);
                }
            }
            T_PUNCH => {
                // a hole-punch from an address nobody we know advertised: a member we have not heard about yet is
                // trying to reach us; look at the registry now instead of at the next periodic refresh
                if !self.peers.values().any(|p| p.peer_addr == Some(addr) || p.candidates.contains(&addr)) {
                    self.io.refresh_members.store(true, Ordering::Relaxed);
                }
                if data.len() == 17 {
                    let nid: [u8; 16] = data[1..17].try_into().unwrap();
                    self.punch_from(nid, addr);
                    self.on_punch(nid);
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ delegated relay nodes
    /// Decrypts a packet of the session `idx` of `p`.
    fn open_for(p: &mut Peer, idx: u32, pkt: &[u8]) -> Option<Vec<u8>> {
        let s = if p.cur.as_ref().map_or(false, |s| s.local_idx == idx) {
            p.cur.as_mut()
        } else if p.prev.as_ref().map_or(false, |s| s.local_idx == idx) {
            p.prev.as_mut()
        } else {
            None
        };
        s.and_then(|s| s.decrypt(pkt))
    }

    fn on_rly(&mut self, pkt: &[u8], addr: SocketAddr) {
        let Some(idx) = data_receiver_index(pkt) else { return };
        let Some(nid) = self.by_idx.get(&idx).copied() else { return };
        let Some(mut p) = self.take(&nid) else { return };
        let plain = Self::open_for(&mut p, idx, pkt);
        if plain.is_some() {
            note_path(&mut p, &Via::Udp(addr));
        }
        let ip = p.ip;
        self.put(p);
        let Some(pt) = plain else { return };
        if pt.is_empty() {
            return;
        }
        let body = &pt[1..];
        match pt[0] {
            RLY_FWD => self.rly_forward(nid, body),
            RLY_DLV if self.rly.nodes.contains_key(&nid) && body.len() > 17 => {
                let src: [u8; 16] = body[..16].try_into().unwrap();
                self.on_relay(src, &body[16..]);
            }
            RLY_NACK if self.rly.nodes.contains_key(&nid) && body.len() == 17 => {
                let dst: [u8; 16] = body[..16].try_into().unwrap();
                self.rly.bad.insert((nid, dst), Instant::now() + RLY_BAD_FOR);
                self.status.note(format!("relay node {ip} cannot deliver to {} (reason {}): using another path for {}s", hex::encode(&dst[..4]), body[16], RLY_BAD_FOR.as_secs()));
            }
            _ => {}
        }
    }

    /// Sends `op || body` to the delegated relay node `r` in its session, over UDP. False if it is not reachable right now.
    fn send_rly(&mut self, r: &[u8; 16], op: u8, body: &[u8]) -> bool {
        let io = self.io.clone();
        let Some(p) = self.peers.get_mut(r) else { return false };
        let (Some(addr), Path::Direct) = (p.peer_addr, p.path) else { return false };
        let Some(s) = p.cur.as_mut() else { return false };
        if !s.usable() {
            return false;
        }
        let mut pl = Vec::with_capacity(1 + body.len());
        pl.push(op);
        pl.extend_from_slice(body);
        let Some(pkt) = s.encrypt_typed(&pl, M_RLY) else { return false };
        p.last_tx = Instant::now();
        udp_send(&io, &pkt, addr);
        true
    }

    /// Sends what the free functions queued for the delegated relay nodes; whatever cannot be sent goes to the oneqrelay.
    fn flush_rly(&mut self) {
        let items: Vec<([u8; 16], Vec<u8>)> = self.io.rly.lock().unwrap().outbox.drain(..).collect();
        for (r, body) in items {
            if !self.send_rly(&r, RLY_FWD, &body) && self.cfg.use_relay {
                let _ = self.io.relay_tx.try_send(body);
            }
        }
    }

    /// Chooses, for every peer, the delegated relay node both of us hold a session with that answers fastest; publishes which of them we reach.
    fn update_rly_choice(&mut self) {
        let now = Instant::now();
        let mut choice: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        let mut attached: Vec<[u8; 16]> = vec![];
        if self.cfg.use_delegates && self.cfg.use_relay && !self.rly.nodes.is_empty() {
            for rid in self.rly.nodes.keys() {
                if self.peers.get(rid).map_or(false, |r| rly_usable(r, now)) {
                    attached.push(*rid);
                }
            }
            attached.sort();
            attached.truncate(4);
            for p in self.peers.values() {
                let mut best: Option<(f64, [u8; 16])> = None;
                for rid in &attached {
                    if *rid == p.id || !p.attached.contains(rid) || self.rly.bad.get(&(*rid, p.id)).map_or(false, |t| now < *t) {
                        continue;
                    }
                    let rtt = self.rly.rtt.get(rid).copied().unwrap_or(9.9);
                    if best.map_or(true, |(b, i)| rtt < b || (rtt == b && *rid < i)) {
                        best = Some((rtt, *rid));
                    }
                }
                if let Some((_, r)) = best {
                    choice.insert(p.id, r);
                }
            }
        }
        self.rly.bad.retain(|_, t| now < *t);
        let mut g = self.io.rly.lock().unwrap();
        g.choice = choice;
        g.attached = attached;
    }

    /// We are a delegated relay node: pass a member's datagram to the member it is for. Nothing in it is read.
    fn rly_forward(&mut self, sender: [u8; 16], body: &[u8]) {
        let Some(kbps) = self.rly.role else { return };
        if body.len() < 17 || body.len() > 16 + RLY_MAX_DGRAM {
            return;
        }
        let dst: [u8; 16] = body[..16].try_into().unwrap();
        let dgram = &body[16..];
        let now = Instant::now();
        if dst == sender || !self.peers.get(&dst).map_or(false, |d| rly_usable(d, now)) {
            self.rly_nack(sender, dst, NACK_UNREACHABLE);
            return;
        }
        if !self.rly_budget(sender, dgram.len(), kbps) {
            self.rly.dropped += 1;
            self.rly_nack(sender, dst, NACK_RATE);
            return;
        }
        let mut b = Vec::with_capacity(16 + dgram.len());
        b.extend_from_slice(&sender);
        b.extend_from_slice(dgram);
        if self.send_rly(&dst, RLY_DLV, &b) {
            if self.rly.packets == 0 {
                self.status.note(format!("forwarding datagrams for the members ({} -> {})", hex::encode(&sender[..4]), hex::encode(&dst[..4])));
            }
            self.rly.packets += 1;
            self.rly.bytes += dgram.len() as u64;
        }
    }

    fn rly_nack(&mut self, sender: [u8; 16], dst: [u8; 16], reason: u8) {
        let now = Instant::now();
        if self.rly.nack_t.get(&(sender, dst)).map_or(true, |t| now.duration_since(*t) >= Duration::from_secs(1)) {
            self.rly.nack_t.insert((sender, dst), now);
            if self.rly.nack_t.len() > 1024 {
                self.rly.nack_t.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
            }
            let mut b = dst.to_vec();
            b.push(reason);
            self.send_rly(&sender, RLY_NACK, &b);
        }
    }

    /// Token buckets of the delegation: total and per sender, bytes per second from the cap in the registry.
    fn rly_budget(&mut self, sender: [u8; 16], n: usize, kbps: u32) -> bool {
        let now = Instant::now();
        let rate = (kbps.max(1) as f64) * 125.0;
        let n = n as f64;
        let take = |b: Option<(f64, Instant)>, r: f64, init: f64| -> ((f64, Instant), bool) {
            let (tokens, t) = b.unwrap_or((init, now));
            let tokens = (tokens + now.duration_since(t).as_secs_f64() * r).min(r * 0.5 + 1500.0);
            if tokens < n {
                ((tokens, now), false)
            } else {
                ((tokens - n, now), true)
            }
        };
        let (tot, ok1) = take(self.rly.total, rate, rate * 0.5 + 1500.0);
        let (snd, ok2) = take(self.rly.senders.get(&sender).copied(), rate * 0.5, rate * 0.25);
        if ok1 && ok2 {
            self.rly.total = Some(tot);
            self.rly.senders.insert(sender, snd);
            if self.rly.senders.len() > 512 {
                self.rly.senders.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
            }
            true
        } else {
            false
        }
    }

    fn on_relay(&mut self, src: [u8; 16], data: &[u8]) {
        if !self.peers.contains_key(&src) {
            return;
        }
        let Some(&t) = data.first() else { return };
        match t {
            T_PUNCH if data.len() == 17 && data[1..17] == src => self.on_punch(src),
            M_DATA => self.on_data(data, Via::Relay),
            T_FRAG => {
                if let Some(msg) = self.reasm.feed(&Src::Relay(src), data) {
                    self.on_hs(&msg, Via::Relay, Some(src));
                }
            }
            _ => {}
        }
    }

    /// The peer says it has no session with us. If we are the initiator and believe we have one it is stale (the
    /// peer restarted): handshake again now. Unauthenticated, so rate-limited per peer.
    fn on_punch(&mut self, nid: [u8; 16]) {
        let Some(p) = self.peers.get_mut(&nid) else { return };
        let young = p.cur.as_ref().map_or(true, |s| s.age() < 3.0);
        if !p.initiator || young || !due(p.last_rehs, Duration::from_secs(5)) {
            return;
        }
        p.last_rehs = Some(Instant::now());
        p.force_hs = true;
        self.status.note(format!("{} has no session with us any more: new handshake", p.ip));
    }

    fn on_data(&mut self, pkt: &[u8], via: Via) {
        let Some(idx) = data_receiver_index(pkt) else { return };
        let Some(nid) = self.by_idx.get(&idx).copied() else { return };
        let Some(mut p) = self.take(&nid) else { return };
        let plain = {
            let s = if p.cur.as_ref().map_or(false, |s| s.local_idx == idx) {
                p.cur.as_mut()
            } else if p.prev.as_ref().map_or(false, |s| s.local_idx == idx) {
                p.prev.as_mut()
            } else {
                None
            };
            s.and_then(|s| s.decrypt(pkt))
        };
        if let Some(pt) = plain {
            p.last_rx = Some(Instant::now());
            let was_relay = p.path == Path::Relay;
            note_path(&mut p, &via);
            if matches!(via, Via::Udp(_)) && was_relay && p.path == Path::Direct {
                self.status.note(format!("back on direct path to {} ({})", p.ip, p.peer_addr.map(|a| a.to_string()).unwrap_or_default()));
            }
            let (io, cfg) = (self.io.clone(), self.cfg.clone());
            if pt == CTL_PROBE {
                send_payload(&io, &cfg, &mut p, CTL_PROBE_REPLY);
            } else if pt == CTL_PROBE_REPLY {
                if let Some(t) = self.rly.probe_open.remove(&p.id) {
                    let rtt = t.elapsed().as_secs_f64();
                    let e = self.rly.rtt.entry(p.id).or_insert(rtt);
                    *e = 0.7 * *e + 0.3 * rtt;
                }
            } else if pt.len() > 1 {
                self.deliver(&mut p, &pt);
            }
        }
        self.put(p);
    }

    fn budget_ok(&mut self) -> bool {
        let now = Instant::now();
        self.budget = (self.budget + now.duration_since(self.budget_t).as_secs_f64() * 5.0).min(10.0);
        self.budget_t = now;
        if self.budget < 1.0 {
            return false;
        }
        self.budget -= 1.0;
        true
    }

    fn on_hs(&mut self, msg: &[u8], via: Via, relay_src: Option<[u8; 16]>) {
        match msg.first() {
            Some(&M_INIT) => self.on_init(msg, via, relay_src),
            Some(&M_RESP) => self.on_resp(msg, via),
            _ => {}
        }
    }

    fn on_init(&mut self, msg: &[u8], via: Via, relay_src: Option<[u8; 16]>) {
        let Some((_, nid)) = init_peek(msg) else { return };
        let ok = self.peers.get(&nid).map_or(false, |p| !p.initiator) && relay_src.map_or(true, |s| s == nid);
        if !ok {
            if !self.peers.contains_key(&nid) {
                self.io.refresh_members.store(true, Ordering::Relaxed); // unknown member: refresh the registry soon
            }
            return;
        }
        if !self.budget_ok() {
            return;
        }
        let Some(mut p) = self.take(&nid) else { return };
        let c = match init_consume(&self.me, &p.pub_key, msg) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("INIT rejected: {e:#}");
                self.put(p);
                return;
            }
        };
        let now_us = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
        let skew = now_us.abs_diff(c.ts_us) as f64 / 1e6;
        if c.ts_us <= p.last_ts || skew > self.cfg.max_skew.as_secs_f64() {
            tracing::debug!("INIT from {} dropped: replay or clock skew", p.ip);
            self.put(p);
            return;
        }
        p.last_ts = c.ts_us;
        let my_idx = self.new_idx();
        match resp_create(&self.me, &p.pub_key, &c, my_idx, c.sender_idx) {
            Ok((resp, sk, rk)) => {
                self.install(&mut p, Session::new(&sk, &rk, false, my_idx, c.sender_idx), &via);
                send_hs(&self.io, &self.cfg, &p, &resp, via);
            }
            Err(e) => tracing::debug!("RESP failed: {e:#}"),
        }
        self.put(p);
    }

    fn on_resp(&mut self, msg: &[u8], via: Via) {
        let Some((_, my_idx)) = resp_peek(msg) else { return };
        let Some(nid) = self.by_idx.get(&my_idx).copied() else { return };
        let Some(mut p) = self.take(&nid) else { return };
        if let Some(pos) = p.pending.iter().position(|st| st.idx == my_idx) {
            if let Ok((sk, rk, peer_idx)) = resp_consume(&self.me, &p.pending[pos], msg) {
                for st in p.pending.drain(..) {
                    self.by_idx.remove(&st.idx);
                }
                self.install(&mut p, Session::new(&sk, &rk, true, my_idx, peer_idx), &via);
                let (io, cfg) = (self.io.clone(), self.cfg.clone());
                send_payload(&io, &cfg, &mut p, b""); // confirm, so the responder learns our address
            }
        }
        self.put(p);
    }

    // ------------------------------------------------------------ periodic work
    fn hs_via_relay(&self, p: &Peer) -> bool {
        // a rekey that the direct handshake did not complete in `relay_after` seconds goes through the relay too: otherwise the session
        // reaches REJECT_AFTER, expires and the peer is cut off until the relay handshake starts, another `relay_after` seconds later
        let rekey_stuck = p.cur.as_ref().map_or(false, |s| s.age() >= REKEY_AFTER + self.cfg.relay_after.as_secs_f64());
        self.cfg.use_relay && (self.cfg.force_relay || p.relay_hs || p.force_hs || p.candidates.is_empty() || rekey_stuck)
    }

    fn send_init(&mut self, p: &mut Peer) {
        let idx = self.new_idx();
        let Ok((msg, st)) = init_create(&self.me, &p.pub_key, idx) else { return };
        while p.pending.len() >= 4 {
            if let Some(old) = p.pending.pop_front() {
                self.by_idx.remove(&old.idx);
            }
        }
        p.pending.push_back(st);
        self.by_idx.insert(idx, p.id);
        p.last_init = Some(Instant::now());
        p.force_hs = false;
        if !self.cfg.force_relay {
            for c in p.direct_targets(Instant::now()) {
                send_hs(&self.io, &self.cfg, p, &msg, Via::Udp(c));
            }
        }
        if self.hs_via_relay(p) {
            send_hs(&self.io, &self.cfg, p, &msg, Via::Relay);
        }
    }

    fn tick_peer(&mut self, p: &mut Peer) {
        let (io, cfg) = (self.io.clone(), self.cfg.clone());
        let now = Instant::now();
        let mine = self.io.nat.lock().unwrap().clone();
        let my_nat = mine.kind.clone();
        // without the relay's clock there are no punch rounds: keep the plain continuous attempts
        p.careful = self.io.clock.offset().is_some() && nat::filtering(&my_nat) && p.nat.as_deref().map_or(false, nat::filtering);
        if p.cur.as_ref().map_or(false, |s| !s.usable()) {
            self.status.note(format!("session with {} expired", p.ip));
            if let Some(s) = p.cur.take() {
                self.by_idx.remove(&s.local_idx);
            }
        }
        if p.prev.as_ref().map_or(false, |s| !s.usable()) {
            if let Some(s) = p.prev.take() {
                self.by_idx.remove(&s.local_idx);
            }
        }
        while p.pending.front().map_or(false, |st| st.created.elapsed() > Duration::from_secs(10)) {
            if let Some(st) = p.pending.pop_front() {
                self.by_idx.remove(&st.idx);
            }
        }
        let has_session = p.cur.is_some();
        if !has_session {
            let since = *p.t_nosession.get_or_insert(now);
            let hopeless = p.nat.is_some() && my_nat != "unknown" && my_nat != "blocked" && !p.punchable(&mine, self.io.v6.load(Ordering::Relaxed));
            if cfg.use_relay && !p.relay_hs && (cfg.force_relay || hopeless || now.duration_since(since) >= cfg.relay_after) {
                p.relay_hs = true;
                if hopeless {
                    self.status.note(format!(
                        "{} is behind a {} NAT{} and we are behind a {} one{}: direct UDP cannot be punched, using the relay",
                        p.ip,
                        p.nat.as_deref().unwrap_or("?"),
                        if p.nat_cgnat { " (second NAT)" } else { "" },
                        my_nat,
                        if mine.cgnat { " (second NAT)" } else { "" }
                    ));
                } else {
                    self.status.note(format!("no direct session with {} after {:.0}s: using the relay too", p.ip, now.duration_since(since).as_secs_f64()));
                }
            }
        } else {
            p.t_nosession = None;
            p.relay_hs = false;
        }
        if !has_session && due(p.last_punch, Duration::from_secs(1)) {
            // "I have no session with you": opens NAT mappings and tells an initiator that still holds a stale
            // session (we restarted) to handshake right away. Carries our node id.
            p.last_punch = Some(now);
            let mut punch = vec![T_PUNCH];
            punch.extend_from_slice(&self.me.node_id());
            if !cfg.force_relay {
                for c in p.direct_targets(now) {
                    udp_send(&io, &punch, c);
                }
            }
            if io.relay_connected.load(Ordering::Relaxed) && (cfg.force_relay || p.relay_hs || p.candidates.is_empty()) {
                relay_send(&io, &cfg, &p.id, &punch);
            }
        }
        let rekey = p.cur.as_ref().map_or(true, |s| s.age() >= REKEY_AFTER) || p.force_hs;
        if p.initiator && rekey && due(p.last_init, HS_RETRY) && (!p.direct_targets(now).is_empty() || self.hs_via_relay(p)) {
            self.send_init(p);
        }
        if has_session && p.cur.is_some() {
            if now.duration_since(p.last_tx) >= KEEPALIVE {
                send_payload(&io, &cfg, p, b"");
            }
            if self.rly.nodes.contains_key(&p.id) && rly_usable(p, now) && self.rly.probe_sent.get(&p.id).map_or(true, |t| now.duration_since(*t) >= RLY_PROBE_EVERY) {
                self.rly.probe_sent.insert(p.id, now);
                self.rly.probe_open.insert(p.id, now);
                send_payload(&io, &cfg, p, CTL_PROBE);
            }
            if p.path == Path::Relay && !cfg.force_relay && !p.candidates.is_empty() && due(p.last_probe, PROBE_EVERY) {
                p.last_probe = Some(now);
                if let Some(pkt) = p.cur.as_mut().and_then(|s| s.encrypt(CTL_PROBE)) {
                    for c in p.direct_targets(now) {
                        udp_send(&io, &pkt, c);
                    }
                }
            }
            if p.path == Path::Direct && cfg.use_relay && !cfg.force_relay && p.last_direct_rx.map_or(true, |t| t.elapsed() > DIRECT_STALE) {
                p.path = Path::Relay;
                self.status.note(format!("direct path to {} is stale, using the relay", p.ip));
            }
        }
    }

    pub fn tick(&mut self) {
        let ids: Vec<[u8; 16]> = self.peers.keys().copied().collect();
        for id in ids {
            if let Some(mut p) = self.take(&id) {
                self.tick_peer(&mut p);
                self.put(p);
            }
        }
        // members that answer: the gateways of a routed network are chosen among them (l3.rs)
        let alive: std::collections::HashSet<[u8; 16]> =
            self.peers.values().filter(|p| p.cur.is_some() && p.last_rx.map_or(false, |t| t.elapsed() < GATEWAY_ALIVE)).map(|p| p.id).collect();
        self.dir.set_alive(alive);
        self.update_rly_choice();
        self.flush_rly();
        self.io.all_connected.store(!self.peers.is_empty() && self.peers.values().all(|p| p.cur.is_some()), Ordering::Relaxed);
        self.ticks += 1;
        if self.ticks % 4 == 0 {
            let mut peers: Vec<PeerInfo> = self
                .peers
                .values()
                .map(|p| PeerInfo {
                    name: if p.name.is_empty() { hex::encode(&p.id[..4]) } else { p.name.clone() },
                    ip: p.ip.to_string(),
                    online: p.online,
                    session: p.cur.is_some(),
                    path: match (&p.cur, p.path) {
                        (None, _) => "-".into(),
                        (_, Path::Direct) => "direct".into(),
                        (_, Path::Relay) => "relay".into(),
                    },
                    exit_node: p.exit_node,
                    public_ip: p.nat_mapped.as_deref().and_then(|m| m.split(':').next()).unwrap_or("").to_string(),
                })
                .collect();
            peers.sort_by(|a, b| a.ip.cmp(&b.ip));
            let (tx, rx) = (self.tx_bytes, self.rx_bytes);
            self.status.update(|s| {
                s.peers = peers;
                s.tx_bytes = tx;
                s.rx_bytes = rx;
            });
        }
    }

    // ------------------------------------------------------------ registry
    pub fn apply_members(&mut self, members: &[Member]) {
        let me_id = self.me.node_id();
        let mut seen = std::collections::HashSet::new();
        let mut delegates: HashMap<[u8; 16], u32> = HashMap::new();
        self.dir.clear();
        for m in members {
            if m.id == me_id {
                let role = if self.cfg.relay_offer { m.relay_kbps } else { None };
                if role.is_some() != self.rly.role.is_some() {
                    self.status.note(if role.is_some() { "this node is now a delegated relay node".to_string() } else { "this node is no longer a delegated relay node".to_string() });
                }
                self.rly.role = role;
                continue;
            }
            seen.insert(m.id);
            self.dir.set(m.ip, m.mac, m.id);
            self.mac_owner.insert(m.mac, m.id);
            let me_pub = self.me.pub_bytes.clone();
            let p = self.peers.entry(m.id).or_insert_with(|| Peer::new(m, &me_pub));
            if p.pub_key != m.pub_key {
                *p = Peer::new(m, &me_pub);
            }
            p.ip = m.ip;
            p.mac = m.mac;
            p.name = m.name.clone();
            p.online = m.online;
            p.nat = m.nat.clone();
            p.nat_mapped = m.nat_mapped.clone();
            p.nat_delta = m.nat_delta;
            p.nat_cgnat = m.nat_cgnat;
            p.predicted = nat::punch_ports(p.nat.as_deref(), p.nat_mapped.as_deref(), p.nat_delta);
            p.attached = m.relays.clone();
            p.exit_node = m.exit_node;
            if let Some(k) = m.relay_kbps {
                delegates.insert(m.id, k);
            }
            let cands: Vec<SocketAddr> = m
                .endpoints
                .iter()
                .filter(|e| !self.cfg.local_candidates.contains(e))
                .filter_map(|e| e.parse::<SocketAddr>().ok())
                .filter(|a| a.is_ipv4() || self.io.dual)
                .take(MAX_CANDIDATES)
                .collect();
            p.candidates = cands;
        }
        if delegates.keys().collect::<std::collections::BTreeSet<_>>() != self.rly.nodes.keys().collect::<std::collections::BTreeSet<_>>() {
            let names: Vec<String> = delegates.keys().filter_map(|k| self.peers.get(k).map(|p| p.ip.to_string())).collect();
            self.status.note(format!("delegated relay nodes: {}", if names.is_empty() { "none".to_string() } else { names.join(", ") }));
        }
        self.rly.nodes = delegates;
        let gone: Vec<[u8; 16]> = self.peers.keys().filter(|k| !seen.contains(*k)).copied().collect();
        for id in gone {
            if let Some(p) = self.peers.remove(&id) {
                self.mac_owner.remove(&p.mac);
                for s in [&p.cur, &p.prev].into_iter().flatten() {
                    self.by_idx.remove(&s.local_idx);
                }
                for st in &p.pending {
                    self.by_idx.remove(&st.idx);
                }
                self.status.note(format!("member {} ({}) left", p.ip, hex::encode(&id[..4])));
            }
        }
    }

    // ------------------------------------------------------------ synchronised punching (see nat.rs)
    /// The peer's PUNCH came from `addr`: the NAT in front of us now lets it in. Answer, and use the hole at once.
    fn punch_from(&mut self, nid: [u8; 16], addr: SocketAddr) {
        let (io, cfg) = (self.io.clone(), self.cfg.clone());
        let Some(mut p) = self.take(&nid) else { return };
        if p.open_hole(addr) {
            let now = Instant::now();
            if due(p.last_punch, Duration::from_millis(300)) {
                p.last_punch = Some(now);
                let mut punch = vec![T_PUNCH];
                punch.extend_from_slice(&self.me.node_id());
                udp_send(&io, &punch, addr);
            }
            if p.cur.is_none() && p.initiator && due(p.last_init, Duration::from_millis(300)) {
                self.send_init(&mut p);
            } else if p.cur.is_some() && p.path == Path::Relay && due(p.last_probe, Duration::from_secs(1)) {
                p.last_probe = Some(now);
                if let Some(pkt) = p.cur.as_mut().and_then(|s| s.encrypt(CTL_PROBE)) {
                    udp_send(&io, &pkt, addr);
                }
            }
        }
        let _ = cfg;
        self.put(p);
    }

    /// When the engine must wake up for the next punch burst (None until the relay's clock is known).
    pub fn punch_deadline(&mut self) -> Option<Instant> {
        let rt = self.io.clock.now()?;
        if self.punch_boundary == 0.0 || rt - self.punch_boundary > 2.0 * PUNCH_PERIOD {
            self.punch_boundary = ((rt / PUNCH_PERIOD).floor() + 1.0) * PUNCH_PERIOD;
        }
        let next = self.punch_due.front().copied().map_or(self.punch_boundary, |t| t.min(self.punch_boundary));
        Some(Instant::now() + Duration::from_secs_f64((next - rt).max(0.0)))
    }

    /// Run what is due: open a round at its boundary, send the packets of a burst.
    pub fn punch_due(&mut self) {
        let Some(rt) = self.io.clock.now() else { return };
        if self.punch_boundary == 0.0 {
            return;
        }
        if rt + 0.001 >= self.punch_boundary {
            let idx = (self.punch_boundary / PUNCH_PERIOD).round() as i64;
            if nat::punch_attempt_round(idx) {
                for off in PUNCH_OFFSETS {
                    self.punch_due.push_back(self.punch_boundary + off);
                }
            }
            self.punch_boundary += PUNCH_PERIOD;
        }
        while let Some(&t) = self.punch_due.front() {
            if rt + 0.001 < t {
                break;
            }
            self.punch_due.pop_front();
            self.send_punches();
        }
    }

    fn send_punches(&self) {
        if self.cfg.force_relay {
            return;
        }
        let mine = self.io.nat.lock().unwrap().clone();
        let v6 = self.io.v6.load(Ordering::Relaxed);
        let mut punch = vec![T_PUNCH];
        punch.extend_from_slice(&self.me.node_id());
        for p in self.peers.values() {
            let direct_ok = p.cur.is_some() && p.path == Path::Direct && p.last_direct_rx.map_or(false, |t| t.elapsed() < 2 * KEEPALIVE);
            let careful = nat::filtering(&mine.kind) && p.nat.as_deref().map_or(false, nat::filtering);
            if careful && (!p.candidates.is_empty() || !p.predicted.is_empty()) && p.punchable(&mine, v6) && !direct_ok {
                for c in p.candidates.iter().chain(p.predicted.iter()) {
                    udp_send(&self.io, &punch, *c);
                }
            }
        }
    }

    pub fn describe(&self) -> String {
        format!("{} {} mtu {}", self.dir.my_ip, mac_to_string(&self.dir.my_mac), self.mtu)
    }
}

pub async fn engine_task(mut eng: Engine, mut rx: mpsc::Receiver<Event>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let wake = eng.punch_deadline();
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(Event::Stop) | None => break,
                Some(ev) => eng.on_event(ev),
            },
            _ = tick.tick() => eng.tick(),
            _ = async {
                match wake {
                    Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                    None => std::future::pending::<()>().await,
                }
            } => eng.punch_due(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::mac_from_str;

    struct Node {
        id: Arc<Identity>,
        events: mpsc::Sender<Event>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
        addr: SocketAddr,
        info: JoinInfo,
        status: Arc<Status>,
        /// frames this node sent to the oneqrelay (WebSocket) link
        relay_frames: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn spawn_node(n: u8) -> Node {
        spawn_node_with(n, EngineCfg { use_relay: false, ..Default::default() }).await
    }

    async fn spawn_node_with(n: u8, base: EngineCfg) -> Node {
        let id = Arc::new(Identity::generate().unwrap());
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = udp.local_addr().unwrap();
        let (events, rx) = mpsc::channel(256);
        let (relay_tx, mut relay_rx) = mpsc::channel(8);
        let relay_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rc = relay_count.clone();
        tokio::spawn(async move { while relay_rx.recv().await.is_some() { rc.fetch_add(1, Ordering::Relaxed); } }); // no oneqrelay in this test: frames are only counted
        let (tun_tx, tun_rx) = mpsc::channel(256);
        let io = Io {
            udp: udp.clone(),
            relay_tx,
            tun_tx,
            relay_connected: Arc::new(AtomicBool::new(false)),
            refresh_members: Arc::new(AtomicBool::new(false)),
            all_connected: Arc::new(AtomicBool::new(false)),
            nat: Arc::new(std::sync::Mutex::new(NatInfo::default())),
            dual: false,
            v6: Arc::new(AtomicBool::new(false)),
            clock: Arc::new(ClockSync::default()),
            rly: Default::default(),
        };
        let info = JoinInfo { ip: Ipv4Addr::new(10, 9, 0, n), mac: mac_from_str(&format!("02:00:00:00:00:0{n}")).unwrap(), prefix: 24, mtu: 1220, stun: None, stun_change: None };
        let status = Arc::new(Status::new());
        let cfg = EngineCfg { local_candidates: vec![addr.to_string()], ..base };
        let eng = Engine::new(id.clone(), cfg, io, status.clone(), &info);
        tokio::spawn(engine_task(eng, rx));
        let ev = events.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, a)) = udp.recv_from(&mut buf).await {
                if ev.send(Event::Udp(buf[..n].to_vec(), a)).await.is_err() {
                    break;
                }
            }
        });
        Node { id, events, tun_rx, addr, info, status, relay_frames: relay_count }
    }

    fn member_of(n: &Node, name: &str) -> Member {
        Member { id: n.id.node_id(), pub_key: n.id.pub_bytes.clone(), name: name.into(), ip: n.info.ip, mac: n.info.mac, endpoints: vec![n.addr.to_string()], online: true, nat: None, nat_mapped: None, nat_delta: None, nat_cgnat: false, offer: false, relay_kbps: None, relays: vec![], exit_node: false }
    }

    fn ip_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 1, 0, 0];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    /// Two engines over real loopback UDP: handshake in whichever role, then IP packets both ways.
    #[tokio::test]
    async fn two_engines_exchange_ip_packets_over_udp() {
        let mut a = spawn_node(1).await;
        let mut b = spawn_node(2).await;
        a.events.send(Event::Members(vec![member_of(&a, "a"), member_of(&b, "b")])).await.unwrap();
        b.events.send(Event::Members(vec![member_of(&a, "a"), member_of(&b, "b")])).await.unwrap();
        let pkt_ab = ip_packet(a.info.ip, b.info.ip, b"hello from a");
        let pkt_ba = ip_packet(b.info.ip, a.info.ip, b"hello from b");
        let mut got_b = None;
        let mut got_a = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while (got_a.is_none() || got_b.is_none()) && tokio::time::Instant::now() < deadline {
            a.events.send(Event::Tun(pkt_ab.clone())).await.unwrap();
            b.events.send(Event::Tun(pkt_ba.clone())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            while let Ok(p) = b.tun_rx.try_recv() {
                got_b = Some(p);
            }
            while let Ok(p) = a.tun_rx.try_recv() {
                got_a = Some(p);
            }
        }
        assert_eq!(got_b.as_deref(), Some(&pkt_ab[..]), "a -> b");
        assert_eq!(got_a.as_deref(), Some(&pkt_ba[..]), "b -> a");
        let snap = a.status.snapshot();
        assert!(snap.log.iter().any(|l| l.contains("established")), "{:?}", snap.log);
    }

    #[tokio::test]
    async fn arp_requests_for_our_address_are_answered_and_packets_to_strangers_dropped() {
        let mut a = spawn_node(1).await;
        let b = spawn_node(2).await;
        a.events.send(Event::Members(vec![member_of(&a, "a"), member_of(&b, "b")])).await.unwrap();
        b.events.send(Event::Members(vec![member_of(&a, "a"), member_of(&b, "b")])).await.unwrap();
        // nothing for an unknown address
        a.events.send(Event::Tun(ip_packet(a.info.ip, Ipv4Addr::new(10, 9, 0, 77), b"x"))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(a.tun_rx.try_recv().is_err());
    }

    // ------------------------------------------------------------ NAT-aware punching
    fn member(nat: Option<&str>, endpoints: Vec<String>, mapped: Option<&str>) -> Member {
        let id = Identity::generate().unwrap();
        Member {
            id: id.node_id(),
            pub_key: id.pub_bytes.clone(),
            name: "peer".into(),
            ip: Ipv4Addr::new(10, 9, 0, 9),
            mac: mac_from_str("02:00:00:00:00:09").unwrap(),
            endpoints,
            online: true,
            nat: nat.map(String::from),
            nat_mapped: mapped.map(String::from),
            nat_delta: None,
            nat_cgnat: false,
            offer: false,
            relay_kbps: None,
            relays: vec![],
            exit_node: false,
        }
    }

    async fn bare_engine(my_nat: &str) -> (Engine, Arc<ClockSync>) {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (relay_tx, _r) = mpsc::channel(8);
        let (tun_tx, _t) = mpsc::channel(8);
        let clock = Arc::new(ClockSync::default());
        let io = Io {
            udp,
            relay_tx,
            tun_tx,
            relay_connected: Arc::new(AtomicBool::new(false)),
            refresh_members: Arc::new(AtomicBool::new(false)),
            all_connected: Arc::new(AtomicBool::new(false)),
            nat: Arc::new(std::sync::Mutex::new(NatInfo { kind: my_nat.into(), ..Default::default() })),
            dual: false,
            v6: Arc::new(AtomicBool::new(false)),
            clock: clock.clone(),
            rly: Default::default(),
        };
        let info = JoinInfo { ip: Ipv4Addr::new(10, 9, 0, 1), mac: mac_from_str("02:00:00:00:00:01").unwrap(), prefix: 24, mtu: 1220, stun: None, stun_change: None };
        let cfg = EngineCfg { use_relay: false, ..Default::default() };
        // a fresh tokio socket only accepts try_send_to after the I/O driver reported it writable
        tokio::time::sleep(Duration::from_millis(30)).await;
        (Engine::new(Arc::new(Identity::generate().unwrap()), cfg, io, Arc::new(Status::new()), &info), clock)
    }

    #[tokio::test]
    async fn unsolicited_sends_wait_for_a_hole_only_between_two_filtering_nats() {
        let (mut eng, _) = bare_engine("port-restricted").await;
        let m = member(Some("port-restricted"), vec!["203.0.113.9:5000".into()], None);
        eng.apply_members(&[m.clone()]);
        let mut p = eng.take(&m.id).unwrap();
        let now = Instant::now();
        p.careful = true;
        assert!(p.direct_targets(now).is_empty(), "nothing outside punch rounds");
        assert!(p.open_hole(sa("203.0.113.9:5000")));
        assert_eq!(p.direct_targets(now), vec![sa("203.0.113.9:5000")]);
        assert!(!p.open_hole(sa("203.0.113.9:5000")), "already open");
        assert!(p.direct_targets(now + HOLE_TTL + Duration::from_secs(1)).is_empty(), "closes again");
        p.careful = false;
        assert_eq!(p.direct_targets(now), vec![sa("203.0.113.9:5000")], "a cone/open side: plain behaviour");
    }


    #[tokio::test]
    async fn predictable_symmetric_peers_second_nats_and_ipv6_decide_whether_to_punch() {
        let (mut eng, _) = bare_engine("port-restricted").await;
        let mut hard = member(Some("symmetric"), vec![], Some("203.0.113.9:5000"));
        eng.apply_members(&[hard.clone()]);
        let mine = eng.io.nat.lock().unwrap().clone();
        assert!(!eng.peers[&hard.id].punchable(&mine, false), "symmetric with random ports: hopeless for a port-restricted node");
        hard.nat_delta = Some(2);
        eng.apply_members(&[hard.clone()]);
        let p = &eng.peers[&hard.id];
        assert!(p.punchable(&mine, false));
        assert_eq!(p.predicted[0], sa("203.0.113.9:5002"));
        assert_eq!(p.predicted.len(), 16);
        // both symmetric: both sides must be predictable
        eng.io.nat.lock().unwrap().kind = "symmetric".into();
        let mine = eng.io.nat.lock().unwrap().clone();
        assert!(!eng.peers[&hard.id].punchable(&mine, false));
        eng.io.nat.lock().unwrap().delta = Some(1);
        let mine = eng.io.nat.lock().unwrap().clone();
        assert!(eng.peers[&hard.id].punchable(&mine, false));
        // a second NAT: relay at once, unless the other side accepts unsolicited packets
        eng.io.nat.lock().unwrap().kind = "cone".into();
        eng.io.nat.lock().unwrap().delta = None;
        eng.io.nat.lock().unwrap().cgnat = true;
        let mine = eng.io.nat.lock().unwrap().clone();
        let cone = member(Some("cone"), vec!["203.0.113.20:5000".into()], None);
        let open = member(Some("open"), vec!["203.0.113.21:5000".into()], None);
        eng.apply_members(&[cone.clone(), open.clone()]);
        assert!(!eng.peers[&cone.id].punchable(&mine, false));
        assert!(eng.peers[&open.id].punchable(&mine, false));
        // two hosts with global IPv6 always try direct (candidates need a dual-stack socket)
        eng.io.dual = true;
        let v6 = member(Some("symmetric"), vec!["[2001:db8::2]:6000".into(), "203.0.113.9:5000".into()], None);
        eng.apply_members(&[v6.clone()]);
        assert_eq!(eng.peers[&v6.id].candidates, vec![sa("[2001:db8::2]:6000"), sa("203.0.113.9:5000")]);
        assert!(eng.peers[&v6.id].punchable(&mine, true));
        assert!(!eng.peers[&v6.id].punchable(&mine, false), "no IPv6 of our own: the NAT rules apply");
        eng.io.dual = false;
        eng.apply_members(&[v6.clone()]);
        assert_eq!(eng.peers[&v6.id].candidates, vec![sa("203.0.113.9:5000")], "no IPv6 socket: IPv6 candidates are skipped");
    }


    // ------------------------------------------------------------ delegated relay nodes
    fn delegate_view(n: &Node, name: &str, kbps: Option<u32>, endpoints: Vec<String>, attached: &[[u8; 16]]) -> Member {
        let mut m = member_of(n, name);
        m.endpoints = endpoints;
        m.offer = kbps.is_some();
        m.relay_kbps = kbps;
        m.relays = attached.to_vec();
        m
    }

    async fn pump(a: &mut Node, b: &mut Node, pkt_ab: &[u8], pkt_ba: &[u8], secs: u64) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let (mut got_a, mut got_b) = (None, None);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while (got_a.is_none() || got_b.is_none()) && tokio::time::Instant::now() < deadline {
            a.events.send(Event::Tun(pkt_ab.to_vec())).await.unwrap();
            b.events.send(Event::Tun(pkt_ba.to_vec())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            while let Ok(p) = b.tun_rx.try_recv() {
                got_b = Some(p);
            }
            while let Ok(p) = a.tun_rx.try_recv() {
                got_a = Some(p);
            }
        }
        (got_a, got_b)
    }

    /// a and b know no address of each other; r (delegated) is reachable by both. Everything between a and b must go through r over UDP.
    #[tokio::test]
    async fn a_delegated_node_carries_two_members_that_cannot_reach_each_other() {
        let base = EngineCfg { use_relay: true, ..Default::default() };
        let r = spawn_node_with(3, EngineCfg { relay_offer: true, ..base.clone() }).await;
        let mut a = spawn_node_with(1, base.clone()).await;
        let mut b = spawn_node_with(2, base.clone()).await;
        let rid = r.id.node_id();
        let r_addr = vec![r.addr.to_string()];
        for (n, me) in [(&a, 'a'), (&b, 'b'), (&r, 'r')] {
            let ma = delegate_view(&a, "a", None, if me == 'b' { vec![] } else { vec![a.addr.to_string()] }, &[rid]);
            let mb = delegate_view(&b, "b", None, if me == 'a' { vec![] } else { vec![b.addr.to_string()] }, &[rid]);
            let mr = delegate_view(&r, "r", Some(20_000), r_addr.clone(), &[]);
            n.events.send(Event::Members(vec![ma, mb, mr])).await.unwrap();
        }
        let pkt_ab = ip_packet(a.info.ip, b.info.ip, b"a to b via r");
        let pkt_ba = ip_packet(b.info.ip, a.info.ip, b"b to a via r");
        let (got_a, got_b) = pump(&mut a, &mut b, &pkt_ab, &pkt_ba, 20).await;
        assert_eq!(got_b.as_deref(), Some(&pkt_ab[..]), "a -> b through r");
        assert_eq!(got_a.as_deref(), Some(&pkt_ba[..]), "b -> a through r");
        let log = r.status.snapshot().log;
        assert!(log.iter().any(|l| l.contains("forwarding datagrams")), "r must have forwarded: {log:?}");
        // once the delegate is chosen nothing goes to the oneqrelay any more
        let (fa, fb) = (a.relay_frames.load(Ordering::Relaxed), b.relay_frames.load(Ordering::Relaxed));
        let _ = pump(&mut a, &mut b, &pkt_ab, &pkt_ba, 2).await;
        assert_eq!((a.relay_frames.load(Ordering::Relaxed), b.relay_frames.load(Ordering::Relaxed)), (fa, fb), "traffic stays on the delegate");
        assert!(a.status.snapshot().log.iter().any(|l| l.contains("delegated relay nodes")));
    }

    /// Without the delegation (the registry does not list r as a relay role) r forwards nothing.
    #[tokio::test]
    async fn a_node_that_is_not_delegated_forwards_nothing() {
        let base = EngineCfg { use_relay: true, ..Default::default() };
        let r = spawn_node_with(3, EngineCfg { relay_offer: true, ..base.clone() }).await;
        let mut a = spawn_node_with(1, base.clone()).await;
        let mut b = spawn_node_with(2, base.clone()).await;
        let rid = r.id.node_id();
        for (n, me) in [(&a, 'a'), (&b, 'b'), (&r, 'r')] {
            let ma = delegate_view(&a, "a", None, if me == 'b' { vec![] } else { vec![a.addr.to_string()] }, &[rid]);
            let mb = delegate_view(&b, "b", None, if me == 'a' { vec![] } else { vec![b.addr.to_string()] }, &[rid]);
            let mut mr = delegate_view(&r, "r", None, vec![r.addr.to_string()], &[]);
            mr.offer = true; // offered, never granted
            n.events.send(Event::Members(vec![ma, mb, mr])).await.unwrap();
        }
        let pkt_ab = ip_packet(a.info.ip, b.info.ip, b"nobody carries this");
        let pkt_ba = ip_packet(b.info.ip, a.info.ip, b"nor this");
        let (got_a, got_b) = pump(&mut a, &mut b, &pkt_ab, &pkt_ba, 4).await;
        assert!(got_a.is_none() && got_b.is_none());
        assert!(!r.status.snapshot().log.iter().any(|l| l.contains("forwarding")));
    }

    #[tokio::test]
    async fn the_bandwidth_cap_and_the_per_sender_share_are_enforced() {
        let (mut eng, _) = bare_engine("open").await;
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        // 100 kbit/s = 12.5 kB/s; the bucket holds ~0.5 s plus 1500 B
        let mut ok = 0usize;
        for _ in 0..200 {
            if eng.rly_budget(s1, 1000, 100) {
                ok += 1;
            }
        }
        assert!(ok >= 1 && ok < 12, "a burst is limited: {ok}");
        assert!(eng.rly_budget(s2, 100, 100), "another sender still gets its share");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(eng.rly_budget(s1, 1000, 100), "tokens come back with time");
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn forged_sources_do_not_open_holes() {
        let (mut eng, _) = bare_engine("port-restricted").await;
        let m = member(Some("symmetric"), vec!["203.0.113.9:5000".into(), "10.100.1.2:5000".into()], Some("192.0.2.12:50001"));
        eng.apply_members(&[m.clone()]);
        let mut p = eng.take(&m.id).unwrap();
        assert!(!p.open_hole(sa("6.6.6.6:5000")), "a stranger");
        assert!(p.open_hole(sa("203.0.113.9:61000")), "same IP, the NAT chose another port");
        p.hole_until = None;
        assert!(p.open_hole(sa("192.0.2.12:33333")), "the IP a symmetric NAT published");
        eng.put(p);
        // punch_from with a stranger or an unknown id sends nothing
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        eng.punch_from(m.id, sa("6.6.6.6:1"));
        eng.punch_from([0u8; 16], probe.local_addr().unwrap());
        let mut b = [0u8; 100];
        assert!(tokio::time::timeout(Duration::from_millis(100), probe.recv_from(&mut b)).await.is_err());
    }

    #[tokio::test]
    async fn a_punch_is_answered_and_the_initiator_starts_the_handshake_at_that_address() {
        let (mut eng, _) = bare_engine("port-restricted").await;
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let paddr = peer_sock.local_addr().unwrap();
        // make us the initiator: keep generating members until our key sorts first
        let m = loop {
            let m = member(Some("port-restricted"), vec![paddr.to_string()], None);
            if eng.me.pub_bytes.as_slice() < m.pub_key.as_slice() {
                break m;
            }
        };
        eng.apply_members(&[m.clone()]);
        eng.punch_from(m.id, paddr);
        let mut got = Vec::new();
        let mut b = [0u8; 2048];
        while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(200), peer_sock.recv_from(&mut b)).await {
            got.push(b[0]);
            let _ = n;
        }
        assert!(got.contains(&T_PUNCH), "answered with a punch of our own: {got:?}");
        assert!(got.contains(&T_FRAG), "INIT fragments went to the hole: {got:?}");
    }

    #[tokio::test]
    async fn punch_rounds_follow_the_relay_clock_and_only_filtering_pairs_get_bursts() {
        let (mut eng, clock) = bare_engine("port-restricted").await;
        assert!(eng.punch_deadline().is_none(), "no relay clock yet");
        clock.update(0.0, 0.001);
        let hard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let easy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        eng.apply_members(&[
            member(Some("port-restricted"), vec![hard.local_addr().unwrap().to_string()], None),
            member(Some("cone"), vec![easy.local_addr().unwrap().to_string()], None),
        ]);
        let mut p: Vec<[u8; 16]> = eng.peers.keys().copied().collect();
        p.sort();
        // a boundary at an attempt round (index % cycle < attempts) in the past: the whole burst is due at once
        eng.punch_boundary = 10.0 * PUNCH_PERIOD;
        assert!(eng.punch_deadline().is_some());
        eng.punch_boundary = 10.0 * PUNCH_PERIOD;
        eng.punch_due();
        assert_eq!(eng.punch_boundary, 11.0 * PUNCH_PERIOD, "the next round is scheduled");
        let mut b = [0u8; 100];
        let mut n_hard = 0;
        while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(150), hard.recv_from(&mut b)).await {
            assert_eq!((n, b[0]), (17, T_PUNCH));
            n_hard += 1;
        }
        assert_eq!(n_hard, PUNCH_OFFSETS.len(), "one punch per burst offset");
        assert!(tokio::time::timeout(Duration::from_millis(100), easy.recv_from(&mut b)).await.is_err(), "no rounds towards an open/cone peer");
        // a round outside the attempt window sends nothing
        eng.punch_boundary = 15.0 * PUNCH_PERIOD;
        eng.punch_due();
        assert!(tokio::time::timeout(Duration::from_millis(100), hard.recv_from(&mut b)).await.is_err());
        // peers with no punchable pair (symmetric against port-restricted) are left alone as well
        let (mut eng2, clock2) = bare_engine("symmetric").await;
        clock2.update(0.0, 0.001);
        eng2.apply_members(&[member(Some("port-restricted"), vec![hard.local_addr().unwrap().to_string()], None)]);
        eng2.punch_boundary = 10.0 * PUNCH_PERIOD;
        eng2.punch_due();
        assert!(tokio::time::timeout(Duration::from_millis(100), hard.recv_from(&mut b)).await.is_err());
        let _ = p;
    }
}
