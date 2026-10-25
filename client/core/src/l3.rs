//! Layer-3 view of the layer-2 mesh. Windows (Wintun), macOS (utun) and Android (VpnService) only offer IP
//! interfaces, while the mesh switches Ethernet frames. This module wraps outgoing IP packets in Ethernet frames
//! (destination MAC taken from the registry, so the client never has to ARP), unwraps incoming ones, and answers
//! ARP requests for our own address so that the TAP-based nodes can find us.
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_HDR: usize = 14;
const BROADCAST: [u8; 6] = [0xff; 6];

pub fn mac_from_str(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n >= 6 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

pub fn mac_to_string(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

#[derive(Debug, PartialEq)]
pub enum Out {
    /// Send to one member.
    Unicast([u8; 16], Vec<u8>),
    /// Broadcast / multicast: send to every member.
    Flood(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum In {
    /// An IP packet for the TUN device.
    Ip(Vec<u8>),
    /// An Ethernet frame to send back to the member that sent the request (ARP reply).
    Reply(Vec<u8>),
}

/// A network the administrator announced as reachable through a member (the gateway): packets for it are sent to the gateway's MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub net: Ipv4Addr,
    pub prefix: u8,
    /// node id of the gateway
    pub via: [u8; 16],
    /// the same network may have several gateways: the lowest number that is alive is used
    pub prio: u16,
}

impl Route {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix as u32) };
        u32::from(ip) & mask == u32::from(self.net) & mask
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.net, self.prefix)
    }
}

pub struct Directory {
    pub my_ip: Ipv4Addr,
    pub my_mac: [u8; 6],
    pub prefix: u8,
    by_ip: HashMap<Ipv4Addr, ([u8; 6], [u8; 16])>,
    routes: Vec<Route>,
    /// members that answer (session up, packets received lately); None = not known, every gateway counts as alive
    alive: Option<HashSet<[u8; 16]>>,
    /// the gateway in use for each routed network: kept while it is alive, so that connections through its NAT are not moved without a reason
    active: RefCell<HashMap<(Ipv4Addr, u8), [u8; 16]>>,
}

impl Directory {
    pub fn new(my_ip: Ipv4Addr, my_mac: [u8; 6], prefix: u8) -> Self {
        Directory { my_ip, my_mac, prefix, by_ip: HashMap::new(), routes: Vec::new(), alive: None, active: RefCell::new(HashMap::new()) }
    }

    pub fn clear(&mut self) {
        self.by_ip.clear();
    }

    /// The accepted routes (replaces the previous set). They do not depend on [`Directory::clear`]: the member list is refreshed all the time.
    pub fn set_routes(&mut self, routes: Vec<Route>) {
        self.routes = routes;
    }

    /// Which members answer (a session is up and packets arrived lately). Gateways that do not are skipped when another one is available.
    pub fn set_alive(&mut self, alive: HashSet<[u8; 16]>) {
        self.alive = Some(alive);
    }

    fn is_alive(&self, id: &[u8; 16]) -> bool {
        self.alive.as_ref().map_or(true, |a| a.contains(id))
    }

    /// MAC and node id of the gateway for `dst`. The longest matching network wins (among those with a gateway we know). Within a network:
    /// the gateway in use while it is alive, otherwise the best (lowest `prio`, then id) that is alive, otherwise the best one anyway
    /// (nothing answers: keep trying the preferred one). There is no switch back to a preferred gateway that comes back: connections that
    /// went through the other gateway's NAT would break for nothing.
    fn gateway_for(&self, dst: Ipv4Addr) -> Option<([u8; 6], [u8; 16])> {
        let known = |r: &&Route| self.by_ip.values().any(|(_, id)| *id == r.via);
        let longest = self.routes.iter().filter(|r| r.contains(dst)).filter(known).map(|r| r.prefix).max()?;
        let mut group: Vec<&Route> = self.routes.iter().filter(|r| r.contains(dst) && r.prefix == longest).filter(known).collect();
        group.sort_by_key(|r| (r.prio, r.via));
        let key = (group[0].net, longest);
        let current = self.active.borrow().get(&key).copied();
        let pick = match current {
            Some(c) if group.iter().any(|r| r.via == c) && self.is_alive(&c) => c,
            _ => group.iter().find(|r| self.is_alive(&r.via)).unwrap_or(&group[0]).via,
        };
        self.active.borrow_mut().insert(key, pick);
        self.by_ip.values().find(|(_, id)| *id == pick).copied()
    }

    /// The gateway in use for the network of `dst`, for the status page (a member id), if any.
    pub fn active_gateway(&self, net: Ipv4Addr, prefix: u8) -> Option<[u8; 16]> {
        self.active.borrow().get(&(net, prefix)).copied()
    }

    pub fn set(&mut self, ip: Ipv4Addr, mac: [u8; 6], id: [u8; 16]) {
        self.by_ip.insert(ip, (mac, id));
    }

    fn broadcast_addr(&self) -> Ipv4Addr {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix as u32) };
        Ipv4Addr::from(u32::from(self.my_ip) | !mask)
    }

    fn frame(&self, dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETH_HDR + payload.len());
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&self.my_mac);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// An IP packet read from the TUN device -> what to send into the mesh.
    pub fn ip_to_frame(&self, pkt: &[u8]) -> Option<Out> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return None; // IPv4 only
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        if dst == self.my_ip {
            return None;
        }
        if dst == self.broadcast_addr() || dst == Ipv4Addr::BROADCAST {
            return Some(Out::Flood(self.frame(BROADCAST, ETH_IPV4, pkt)));
        }
        if dst.is_multicast() {
            let o = dst.octets();
            let mac = [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]];
            return Some(Out::Flood(self.frame(mac, ETH_IPV4, pkt)));
        }
        // a member of the mesh, or else a network behind a gateway member (the gateway's MAC; the IP packet is unchanged)
        let (mac, id) = self.by_ip.get(&dst).copied().or_else(|| self.gateway_for(dst))?;
        Some(Out::Unicast(id, self.frame(mac, ETH_IPV4, pkt)))
    }

    /// An Ethernet frame received from a member.
    pub fn frame_in(&self, frame: &[u8]) -> Option<In> {
        if frame.len() < ETH_HDR {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let body = &frame[ETH_HDR..];
        match ethertype {
            ETH_IPV4 => {
                if body.len() < 20 || body[0] >> 4 != 4 {
                    return None;
                }
                let total = u16::from_be_bytes([body[2], body[3]]) as usize;
                if total < 20 || total > body.len() {
                    return None; // truncated; frames may be padded, never shorter
                }
                let dst = Ipv4Addr::new(body[16], body[17], body[18], body[19]);
                if dst != self.my_ip && dst != self.broadcast_addr() && dst != Ipv4Addr::BROADCAST && !dst.is_multicast() {
                    return None; // we are a host, not a router
                }
                Some(In::Ip(body[..total].to_vec()))
            }
            ETH_ARP => {
                // htype=1 ptype=0x0800 hlen=6 plen=4 oper=1 (who-has) for our address -> is-at
                if body.len() < 28 || body[..6] != [0, 1, 8, 0, 6, 4] || body[6..8] != [0, 1] {
                    return None;
                }
                let (sha, spa, tpa) = (&body[8..14], &body[14..18], &body[24..28]);
                if tpa != self.my_ip.octets() {
                    return None;
                }
                let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2];
                arp.extend_from_slice(&self.my_mac);
                arp.extend_from_slice(&self.my_ip.octets());
                arp.extend_from_slice(sha);
                arp.extend_from_slice(spa);
                let sha6: [u8; 6] = sha.try_into().ok()?;
                Some(In::Reply(self.frame(sha6, ETH_ARP, &arp)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> Directory {
        let mut d = Directory::new("10.78.0.5".parse().unwrap(), [2, 0, 0, 0, 0, 5], 24);
        d.set("10.78.0.9".parse().unwrap(), [2, 0, 0, 0, 0, 9], [9; 16]);
        d
    }

    fn ip_packet(src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let total = 20 + payload;
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 1, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend(vec![0xab; payload]);
        p
    }

    #[test]
    fn mac_text_roundtrip() {
        assert_eq!(mac_from_str("02:9d:5e:29:6d:9c"), Some([2, 0x9d, 0x5e, 0x29, 0x6d, 0x9c]));
        assert_eq!(mac_to_string(&[2, 0x9d, 0x5e, 0x29, 0x6d, 0x9c]), "02:9d:5e:29:6d:9c");
        for bad in ["", "02:9d", "02:9d:5e:29:6d:9c:00", "zz:00:00:00:00:00", "2:9d:5e:29:6d:9c"] {
            assert_eq!(mac_from_str(bad), None, "{bad}");
        }
    }

    #[test]
    fn unicast_is_wrapped_with_the_members_registered_mac() {
        let d = dir();
        let p = ip_packet([10, 78, 0, 5], [10, 78, 0, 9], 30);
        match d.ip_to_frame(&p) {
            Some(Out::Unicast(id, f)) => {
                assert_eq!(id, [9; 16]);
                assert_eq!(&f[..6], &[2, 0, 0, 0, 0, 9]);
                assert_eq!(&f[6..12], &[2, 0, 0, 0, 0, 5]);
                assert_eq!(&f[12..14], &[8, 0]);
                assert_eq!(&f[14..], &p[..]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn route_contains_and_longest_prefix_wins() {
        let r = |net: [u8; 4], prefix, via| Route { net: Ipv4Addr::from(net), prefix, via: [via; 16], prio: 100 };
        assert!(r([192, 168, 16, 0], 24, 1).contains("192.168.16.254".parse().unwrap()));
        assert!(!r([192, 168, 16, 0], 24, 1).contains("192.168.17.1".parse().unwrap()));
        assert!(r([10, 0, 0, 0], 8, 1).contains("10.200.1.1".parse().unwrap()));
        assert!(r([1, 2, 3, 4], 32, 1).contains("1.2.3.4".parse().unwrap()) && !r([1, 2, 3, 4], 32, 1).contains("1.2.3.5".parse().unwrap()));
        assert_eq!(r([192, 168, 16, 0], 24, 1).cidr(), "192.168.16.0/24");

        let mut d = dir();
        d.set("10.78.0.20".parse().unwrap(), [2, 0, 0, 0, 0, 20], [20; 16]);
        d.set_routes(vec![r([192, 168, 0, 0], 16, 9), r([192, 168, 16, 0], 24, 20)]);
        let id_for = |d: &Directory, dst: [u8; 4]| match d.ip_to_frame(&ip_packet([10, 78, 0, 5], dst, 8)) {
            Some(Out::Unicast(id, f)) => Some((id[0], f[..6].to_vec())),
            None => None,
            other => panic!("{other:?}"),
        };
        assert_eq!(id_for(&d, [192, 168, 16, 7]), Some((20, vec![2, 0, 0, 0, 0, 20])), "the more specific route wins");
        assert_eq!(id_for(&d, [192, 168, 99, 7]), Some((9, vec![2, 0, 0, 0, 0, 9])), "the shorter route covers the rest");
        assert_eq!(id_for(&d, [172, 16, 0, 1]), None, "no route");
        assert_eq!(id_for(&d, [10, 78, 0, 9]), Some((9, vec![2, 0, 0, 0, 0, 9])), "a member is never sent through a gateway");
    }

    #[test]
    fn a_route_whose_gateway_is_unknown_or_gone_is_not_used() {
        let mut d = dir();
        d.set_routes(vec![Route { net: "192.168.16.0".parse().unwrap(), prefix: 24, via: [77; 16], prio: 100 }]);
        assert_eq!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [192, 168, 16, 1], 8)), None);
        // the member list is replaced all the time; the routes stay while the gateway reappears in it
        d.clear();
        d.set("10.78.0.77".parse().unwrap(), [2, 0, 0, 0, 0, 77], [77; 16]);
        assert!(matches!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [192, 168, 16, 1], 8)), Some(Out::Unicast(id, _)) if id == [77; 16]));
        d.set_routes(vec![]);
        assert_eq!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [192, 168, 16, 1], 8)), None);
    }

    fn two_gateways() -> Directory {
        let mut d = dir();
        d.set("10.78.0.20".parse().unwrap(), [2, 0, 0, 0, 0, 20], [20; 16]);
        d.set("10.78.0.30".parse().unwrap(), [2, 0, 0, 0, 0, 30], [30; 16]);
        let net: Ipv4Addr = "192.168.16.0".parse().unwrap();
        d.set_routes(vec![Route { net, prefix: 24, via: [30; 16], prio: 200 }, Route { net, prefix: 24, via: [20; 16], prio: 100 }]);
        d
    }

    fn via(d: &Directory) -> Option<u8> {
        match d.ip_to_frame(&ip_packet([10, 78, 0, 5], [192, 168, 16, 9], 8)) {
            Some(Out::Unicast(id, _)) => Some(id[0]),
            None => None,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_preferred_gateway_is_used_and_the_next_one_takes_over_when_it_stops_answering() {
        let mut d = two_gateways();
        assert_eq!(via(&d), Some(20), "lowest priority number first");
        d.set_alive([[20; 16], [30; 16], [9; 16]].into_iter().collect());
        assert_eq!(via(&d), Some(20));
        d.set_alive([[30; 16], [9; 16]].into_iter().collect());
        assert_eq!(via(&d), Some(30), "the preferred one is silent: the backup is used");
        // the preferred gateway answers again: no switch back, connections through the backup's NAT keep working
        d.set_alive([[20; 16], [30; 16]].into_iter().collect());
        assert_eq!(via(&d), Some(30), "no switch back while the one in use is alive");
        // the one in use goes silent: back to the best one that is alive
        d.set_alive([[20; 16]].into_iter().collect());
        assert_eq!(via(&d), Some(20));
        // nobody answers: keep using the one in use rather than dropping the traffic
        d.set_alive(HashSet::new());
        assert_eq!(via(&d), Some(20));
    }

    #[test]
    fn with_nothing_alive_from_the_start_the_best_gateway_is_tried_and_a_changed_priority_is_followed() {
        let mut d = two_gateways();
        d.set_alive(HashSet::new());
        assert_eq!(via(&d), Some(20), "nobody answers: the preferred gateway");
        // a new route list with other priorities: the active one stays while it is alive and listed
        let net: Ipv4Addr = "192.168.16.0".parse().unwrap();
        d.set_alive([[20; 16], [30; 16]].into_iter().collect());
        d.set_routes(vec![Route { net, prefix: 24, via: [30; 16], prio: 1 }, Route { net, prefix: 24, via: [20; 16], prio: 100 }]);
        assert_eq!(via(&d), Some(20), "the active gateway is kept");
        // it is withdrawn from the list: the other one takes over
        d.set_routes(vec![Route { net, prefix: 24, via: [30; 16], prio: 1 }]);
        assert_eq!(via(&d), Some(30));
        assert_eq!(d.active_gateway(net, 24), Some([30; 16]));
    }

    #[test]
    fn a_gateway_that_is_not_a_known_member_is_skipped_and_the_longer_network_still_wins() {
        let mut d = two_gateways();
        let net: Ipv4Addr = "192.168.16.0".parse().unwrap();
        d.set_routes(vec![Route { net, prefix: 24, via: [99; 16], prio: 1 }, Route { net, prefix: 24, via: [30; 16], prio: 500 }]);
        assert_eq!(via(&d), Some(30), "gateway 99 is not in the member list");
        d.set_routes(vec![Route { net: "192.168.0.0".parse().unwrap(), prefix: 16, via: [20; 16], prio: 1 }, Route { net, prefix: 24, via: [30; 16], prio: 500 }]);
        assert_eq!(via(&d), Some(30), "the /24 beats the /16 whatever the priorities");
    }

    #[test]
    fn replies_from_a_routed_network_arrive_as_ordinary_packets_for_us() {
        // the gateway sends the (NATed) answer from 192.168.16.1 to our own mesh address
        let d = dir();
        let p = ip_packet([192, 168, 16, 1], [10, 78, 0, 5], 20);
        let mut f = vec![2, 0, 0, 0, 0, 5, 2, 0, 0, 0, 0, 9, 8, 0];
        f.extend_from_slice(&p);
        assert_eq!(d.frame_in(&f), Some(In::Ip(p)));
    }

    #[test]
    fn broadcast_multicast_unknown_and_non_ipv4() {
        let d = dir();
        assert!(matches!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [10, 78, 0, 255], 8)), Some(Out::Flood(f)) if f[..6] == [0xff; 6]));
        assert!(matches!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [255, 255, 255, 255], 8)), Some(Out::Flood(_))));
        assert!(matches!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [224, 0, 0, 251], 8)), Some(Out::Flood(f)) if f[..6] == [1, 0, 0x5e, 0, 0, 251]));
        assert_eq!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [10, 78, 0, 77], 8)), None, "unknown member");
        assert_eq!(d.ip_to_frame(&ip_packet([10, 78, 0, 5], [10, 78, 0, 5], 8)), None, "to ourselves");
        assert_eq!(d.ip_to_frame(&[0x60; 40]), None, "IPv6");
        assert_eq!(d.ip_to_frame(&[0x45; 10]), None, "runt");
    }

    #[test]
    fn incoming_ip_is_unwrapped_and_padding_removed() {
        let d = dir();
        let p = ip_packet([10, 78, 0, 9], [10, 78, 0, 5], 4);
        let mut f = vec![2, 0, 0, 0, 0, 5, 2, 0, 0, 0, 0, 9, 8, 0];
        f.extend_from_slice(&p);
        f.extend(vec![0u8; 22]); // Ethernet minimum-size padding
        assert_eq!(d.frame_in(&f), Some(In::Ip(p.clone())));
        let mut other = f.clone();
        other[14 + 19] = 77; // destined to another host
        assert_eq!(d.frame_in(&other), None);
        let mut cut = vec![0u8; 12];
        cut.extend_from_slice(&[8, 0]);
        cut.extend_from_slice(&p[..10]);
        assert_eq!(d.frame_in(&cut), None, "truncated IP packet");
        assert_eq!(d.frame_in(&[0u8; 5]), None);
    }

    #[test]
    fn arp_request_for_our_address_gets_a_reply_and_others_are_ignored() {
        let d = dir();
        let asker_mac = [2, 0, 0, 0, 0, 9];
        let asker_ip = [10, 78, 0, 9];
        let mut req = vec![0xff; 6];
        req.extend_from_slice(&asker_mac);
        req.extend_from_slice(&[8, 6]);
        req.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        req.extend_from_slice(&asker_mac);
        req.extend_from_slice(&asker_ip);
        req.extend_from_slice(&[0; 6]);
        req.extend_from_slice(&[10, 78, 0, 5]);
        match d.frame_in(&req) {
            Some(In::Reply(f)) => {
                assert_eq!(&f[..6], &asker_mac);
                assert_eq!(&f[6..12], &[2, 0, 0, 0, 0, 5]);
                assert_eq!(&f[12..14], &[8, 6]);
                assert_eq!(&f[14..22], &[0, 1, 8, 0, 6, 4, 0, 2]);
                assert_eq!(&f[22..28], &[2, 0, 0, 0, 0, 5]);
                assert_eq!(&f[28..32], &[10, 78, 0, 5]);
                assert_eq!(&f[32..38], &asker_mac);
                assert_eq!(&f[38..42], &asker_ip);
            }
            other => panic!("{other:?}"),
        }
        let mut other = req.clone();
        other[14 + 27] = 99; // who-has somebody else
        assert_eq!(d.frame_in(&other), None);
        let mut reply = req.clone();
        reply[14 + 7] = 2; // an ARP reply (is-at) is not a request: nothing to answer
        assert_eq!(d.frame_in(&reply), None);
    }
}
