//! Automatic port mapping: ask the home router to forward a UDP port to this node, so that other nodes can reach it without hole
//! punching. Three protocols, tried in this order: PCP (RFC 6887), NAT-PMP (RFC 6886), UPnP IGD (SSDP discovery, SOAP over HTTP).
//! Same behaviour as `oneqportmap.py` (see its documentation).
//!
//! Safety of the UPnP part: an SSDP answer is trusted only from a private or link-local address, its LOCATION and the control URL
//! must name that very address (a forged answer must not make the node talk to a third host), and every download is size-limited.
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const PORT: u16 = 5351;
const PROTO_UDP: u8 = 17;
const MAX_BODY: usize = 64 * 1024;
const UDP_RETRIES: [Duration; 3] = [Duration::from_millis(250), Duration::from_millis(500), Duration::from_millis(1000)];
const IGD_TARGETS: [&str; 2] = ["urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2"];
const WAN_SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

#[derive(Clone, Debug)]
pub struct Igd {
    pub service: String,
    pub control: String,
    pub host: IpAddr,
}

#[derive(Clone, Debug)]
pub struct Mapping {
    /// "pcp" | "natpmp" | "upnp"
    pub method: &'static str,
    /// the router's WAN address as the router reports it
    pub ext_ip: Option<IpAddr>,
    pub ext_port: u16,
    pub internal_port: u16,
    pub lifetime: u32,
    pub gateway: IpAddr,
    pub created: Instant,
    pub igd: Option<Igd>,
}

impl Mapping {
    pub fn endpoint(&self) -> Option<String> {
        self.ext_ip.map(|ip| SocketAddr::new(ip, self.ext_port).to_string())
    }

    pub fn renew_at(&self) -> Instant {
        self.created + Duration::from_secs_f64((self.lifetime as f64 / 2.0).max(30.0))
    }
}

// ---------------------------------------------------------------- local network facts

/// The IPv4 default gateway of this machine (Linux /proc/net/route, macOS `route`, Windows `route print`).
pub fn default_gateway_v4() -> Option<IpAddr> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let t = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in t.lines().skip(1) {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 8 && p[1] == "00000000" && u32::from_str_radix(p[3], 16).ok()? & 2 != 0 {
                let g = u32::from_str_radix(p[2], 16).ok()?;
                return Some(IpAddr::V4(Ipv4Addr::from(g.to_le_bytes())));
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output().ok()?;
        let t = String::from_utf8_lossy(&out.stdout).to_string();
        t.lines().find_map(|l| l.trim().strip_prefix("gateway:").and_then(|g| g.trim().parse().ok()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("route").args(["print", "-4", "0.0.0.0"]).creation_flags(0x0800_0000).output().ok()?;
        let t = String::from_utf8_lossy(&out.stdout).to_string();
        let mut best: Option<(u32, IpAddr)> = None;
        for line in t.lines() {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 5 && p[0] == "0.0.0.0" && p[1] == "0.0.0.0" {
                if let (Ok(g), Ok(m)) = (p[2].parse::<Ipv4Addr>(), p[4].parse::<u32>()) {
                    if best.map_or(true, |(bm, _)| m < bm) {
                        best = Some((m, IpAddr::V4(g)));
                    }
                }
            }
        }
        best.map(|b| b.1)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", windows)))]
    {
        None
    }
}

/// An address in the 16-byte form PCP uses (IPv4 as ::ffff:a.b.c.d).
pub fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
        IpAddr::V6(v) => v.octets(),
    }
}

pub fn from_ip16(b: &[u8]) -> Option<IpAddr> {
    let a = Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?);
    Some(a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)))
}

// ---------------------------------------------------------------- PCP (RFC 6887)

pub fn pcp_map_request(client: IpAddr, internal_port: u16, ext_port: u16, lifetime: u32, nonce: &[u8; 12]) -> Vec<u8> {
    let mut d = vec![2, 1, 0, 0];
    d.extend_from_slice(&lifetime.to_be_bytes());
    d.extend_from_slice(&ip16(client));
    d.extend_from_slice(nonce);
    d.extend_from_slice(&[PROTO_UDP, 0, 0, 0]);
    d.extend_from_slice(&internal_port.to_be_bytes());
    d.extend_from_slice(&ext_port.to_be_bytes());
    d.extend_from_slice(&ip16(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    d
}

#[derive(Debug, PartialEq)]
pub struct PcpMap {
    pub result: u8,
    pub lifetime: u32,
    pub ext_port: u16,
    pub ext_ip: Option<IpAddr>,
    pub internal_port: u16,
}

/// A MAP response to our nonce; None for anything else.
pub fn pcp_parse_map_response(d: &[u8], nonce: &[u8; 12]) -> Option<PcpMap> {
    if d.len() < 60 || d[0] != 2 || d[1] != 0x81 || d[24..36] != nonce[..] {
        return None;
    }
    Some(PcpMap {
        result: d[3],
        lifetime: u32::from_be_bytes(d[4..8].try_into().ok()?),
        internal_port: u16::from_be_bytes([d[40], d[41]]),
        ext_port: u16::from_be_bytes([d[42], d[43]]),
        ext_ip: from_ip16(&d[44..60]),
    })
}

// ---------------------------------------------------------------- NAT-PMP (RFC 6886)

pub fn natpmp_map_request(internal_port: u16, ext_port: u16, lifetime: u32) -> Vec<u8> {
    let mut d = vec![0, 1, 0, 0];
    d.extend_from_slice(&internal_port.to_be_bytes());
    d.extend_from_slice(&ext_port.to_be_bytes());
    d.extend_from_slice(&lifetime.to_be_bytes());
    d
}

/// -> (result, external address)
pub fn natpmp_parse_addr_response(d: &[u8]) -> Option<(u16, Ipv4Addr)> {
    if d.len() != 12 || d[0] != 0 || d[1] != 128 {
        return None;
    }
    Some((u16::from_be_bytes([d[2], d[3]]), Ipv4Addr::new(d[8], d[9], d[10], d[11])))
}

/// -> (result, external port, lifetime)
pub fn natpmp_parse_map_response(d: &[u8], internal_port: u16) -> Option<(u16, u16, u32)> {
    if d.len() != 16 || d[0] != 0 || d[1] != 129 || u16::from_be_bytes([d[8], d[9]]) != internal_port {
        return None;
    }
    Some((u16::from_be_bytes([d[2], d[3]]), u16::from_be_bytes([d[10], d[11]]), u32::from_be_bytes(d[12..16].try_into().ok()?)))
}

// ---------------------------------------------------------------- UPnP IGD

pub fn ssdp_search(target: &str) -> Vec<u8> {
    format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n").into_bytes()
}

pub fn ssdp_location(d: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(d);
    if !head.starts_with("HTTP/1.1 200") {
        return None;
    }
    head.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case("location")).then(|| v.trim().to_string())
    })
}

/// A UPnP URL is followed only if it names the very address that answered, and that address is on the local network.
pub fn trusted_lan_host(host: &str, responder: IpAddr, allow_loopback: bool) -> bool {
    let Ok(a) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() else { return false };
    if a != responder {
        return false;
    }
    if a.is_loopback() {
        return allow_loopback;
    }
    match a {
        IpAddr::V4(v) => (v.is_private() || v.is_link_local()) && !v.is_unspecified() && !v.is_multicast(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00 == 0xfc00) || (v.segments()[0] & 0xffc0 == 0xfe80),
    }
}

/// "http://host[:port]/path" -> (host, port, path)
pub fn split_url(u: &str) -> Option<(String, u16, String)> {
    let rest = u.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, p) = r.split_once(']')?;
        (h.to_string(), p.strip_prefix(':').map_or(Some(80), |x| x.parse().ok())?)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (hostport.to_string(), 80),
        }
    };
    (!host.is_empty()).then_some((host, port, path))
}

fn join_url(base: &str, reference: &str) -> Option<String> {
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Some(reference.to_string());
    }
    let (host, port, path) = split_url(base)?;
    let h = if host.contains(':') { format!("[{host}]") } else { host };
    let new_path = if reference.starts_with('/') {
        reference.to_string()
    } else {
        let dir = path.rsplit_once('/').map_or("", |x| x.0);
        format!("{dir}/{reference}")
    };
    Some(format!("http://{h}:{port}{new_path}"))
}

/// Text of the first `<name>...</name>` in `s` (case-insensitive tag name), trimmed.
fn tag(s: &str, name: &str) -> Option<String> {
    let low = s.to_ascii_lowercase();
    let open = format!("<{}>", name.to_ascii_lowercase());
    let close = format!("</{}>", name.to_ascii_lowercase());
    let a = low.find(&open)? + open.len();
    let b = low[a..].find(&close)? + a;
    Some(s[a..b].trim().to_string())
}

/// -> (serviceType, controlURL) of the first WAN connection service. Plain string search, not an XML parser: the document comes
/// from the LAN and is size-limited, but nothing in it can make the parser expand or recurse.
pub fn parse_igd_description(xml: &str) -> Option<(String, String)> {
    let low = xml.to_ascii_lowercase();
    for st in WAN_SERVICES {
        let mut from = 0;
        while let Some(i) = low[from..].find("<service>") {
            let a = from + i + "<service>".len();
            let Some(j) = low[a..].find("</service>") else { break };
            let blk = &xml[a..a + j];
            from = a + j;
            if let (Some(t), Some(c)) = (tag(blk, "serviceType"), tag(blk, "controlURL")) {
                if t == st {
                    return Some((t, c));
                }
            }
        }
    }
    None
}

pub fn soap_envelope(service: &str, action: &str, args: &[(&str, String)]) -> Vec<u8> {
    let body: String = args.iter().map(|(k, v)| format!("<{k}>{v}</{k}>")).collect();
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{body}</u:{action}></s:Body></s:Envelope>"
    )
    .into_bytes()
}

pub fn soap_error(xml: &str) -> Option<u32> {
    tag(xml, "errorCode")?.parse().ok()
}

/// A tiny HTTP/1.1 client (no redirects, no TLS, size-limited): UPnP devices speak plain HTTP on the LAN. -> (status, body)
async fn http_request(method: &str, url: &str, headers: &[(&str, String)], body: &[u8]) -> Option<(u16, String)> {
    let (host, port, path) = split_url(url)?;
    let t = Duration::from_secs(4);
    let mut s = tokio::time::timeout(t, TcpStream::connect((host.as_str(), port))).await.ok()?.ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    s.write_all(body).await.ok()?;
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while data.len() < MAX_BODY {
        match tokio::time::timeout(t, s.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => data.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
        }
    }
    let at = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..at]).to_string();
    let mut rest = data[at + 4..].to_vec();
    let status = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let (mut out, mut i) = (Vec::new(), 0);
        while i < rest.len() {
            let Some(j) = rest[i..].windows(2).position(|w| w == b"\r\n") else { break };
            let size = String::from_utf8_lossy(&rest[i..i + j]).split(';').next().and_then(|x| usize::from_str_radix(x.trim(), 16).ok());
            let Some(n) = size.filter(|n| *n > 0 && i + j + 2 + n <= rest.len()) else { break };
            out.extend_from_slice(&rest[i + j + 2..i + j + 2 + n]);
            i += j + 2 + n + 2;
        }
        rest = out;
    }
    Some((status, String::from_utf8_lossy(&rest).to_string()))
}

// ---------------------------------------------------------------- the mapper

/// Send `payload` to `dst` from a fresh socket and wait for an answer that `check` accepts (retransmitting, as the RFCs do).
async fn udp_exchange<T>(dst: SocketAddr, payload: &[u8], check: impl Fn(&[u8]) -> Option<T>, retries: &[Duration]) -> Option<T> {
    let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let s = UdpSocket::bind(bind).await.ok()?;
    s.connect(dst).await.ok()?;
    let mut buf = [0u8; 1100];
    for wait in retries {
        s.send(payload).await.ok()?;
        let end = tokio::time::Instant::now() + *wait;
        while let Ok(Ok(n)) = tokio::time::timeout_at(end, s.recv(&mut buf)).await {
            if let Some(r) = check(&buf[..n]) {
                return Some(r);
            }
        }
    }
    None
}

/// `gateway`, `pcp_port`, `natpmp_port`, `ssdp_addr`, `allow_loopback` and `local_ip` exist so that the protocols can be tested against
/// simulated gateways on the loopback interface; a node leaves them at their defaults.
pub struct PortMapper {
    pub gateway: Option<IpAddr>,
    pub methods: Vec<&'static str>,
    pub pcp_port: u16,
    pub natpmp_port: u16,
    pub ssdp_addr: SocketAddr,
    pub allow_loopback: bool,
    pub local_ip: Option<IpAddr>,
    pub search_time: Duration,
    igd: Option<Igd>,
    /// methods that answered "unsupported": not tried again
    pub disabled: HashSet<&'static str>,
}

impl Default for PortMapper {
    fn default() -> Self {
        PortMapper {
            gateway: None,
            methods: vec!["pcp", "natpmp", "upnp"],
            pcp_port: PORT,
            natpmp_port: PORT,
            ssdp_addr: "239.255.255.250:1900".parse().unwrap(),
            allow_loopback: false,
            local_ip: None,
            search_time: Duration::from_secs(2),
            igd: None,
            disabled: HashSet::new(),
        }
    }
}

impl PortMapper {
    async fn gw(&self) -> Option<IpAddr> {
        match self.gateway {
            Some(g) => Some(g),
            None => tokio::task::spawn_blocking(default_gateway_v4).await.ok().flatten(),
        }
    }

    fn me(&self, towards: IpAddr) -> Option<IpAddr> {
        self.local_ip.or_else(|| crate::nat::guess_local_ip(towards))
    }

    async fn pcp(&mut self, gw: IpAddr, internal: u16, want: u16, lifetime: u32) -> Option<Mapping> {
        let me = self.me(gw)?;
        let mut nonce = [0u8; 12];
        let _ = aws_lc_rs::rand::fill(&mut nonce);
        let req = pcp_map_request(me, internal, want, lifetime, &nonce);
        let r = udp_exchange(
            SocketAddr::new(gw, self.pcp_port),
            &req,
            |d| pcp_parse_map_response(d, &nonce).or_else(|| (d.len() >= 4 && d[0] == 0).then_some(PcpMap { result: 1, lifetime: 0, ext_port: 0, ext_ip: None, internal_port: 0 })),
            &UDP_RETRIES,
        )
        .await?;
        if r.result != 0 {
            tracing::debug!("PCP: result code {}", r.result);
            if r.result == 1 {
                self.disabled.insert("pcp");
            }
            return None;
        }
        Some(Mapping { method: "pcp", ext_ip: r.ext_ip, ext_port: r.ext_port, internal_port: internal, lifetime: r.lifetime, gateway: gw, created: Instant::now(), igd: None })
    }

    async fn natpmp_ext_ip(&self, gw: IpAddr) -> Option<Ipv4Addr> {
        let r = udp_exchange(SocketAddr::new(gw, self.natpmp_port), &[0, 0], natpmp_parse_addr_response, &UDP_RETRIES).await?;
        (r.0 == 0).then_some(r.1)
    }

    async fn natpmp(&mut self, gw: IpAddr, internal: u16, want: u16, lifetime: u32) -> Option<Mapping> {
        let ext = self.natpmp_ext_ip(gw).await?;
        let (result, port, granted) = udp_exchange(
            SocketAddr::new(gw, self.natpmp_port),
            &natpmp_map_request(internal, want, lifetime),
            |d| natpmp_parse_map_response(d, internal),
            &UDP_RETRIES,
        )
        .await?;
        if result != 0 {
            tracing::debug!("NAT-PMP: result code {result}");
            return None;
        }
        Some(Mapping { method: "natpmp", ext_ip: Some(IpAddr::V4(ext)), ext_port: port, internal_port: internal, lifetime: granted, gateway: gw, created: Instant::now(), igd: None })
    }

    async fn igd_discover(&mut self) -> Option<Igd> {
        if let Some(i) = &self.igd {
            return Some(i.clone());
        }
        let s = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let _ = s.set_multicast_ttl_v4(2);
        for st in IGD_TARGETS {
            let _ = s.send_to(&ssdp_search(st), self.ssdp_addr).await;
        }
        let end = tokio::time::Instant::now() + self.search_time;
        let mut buf = [0u8; 2048];
        let (loc, host) = loop {
            let (n, from) = tokio::time::timeout_at(end, s.recv_from(&mut buf)).await.ok()?.ok()?;
            let Some(loc) = ssdp_location(&buf[..n]) else { continue };
            let Some((h, _, _)) = split_url(&loc) else { continue };
            if trusted_lan_host(&h, from.ip(), self.allow_loopback) {
                break (loc, from.ip());
            }
        };
        let (status, xml) = http_request("GET", &loc, &[], &[]).await?;
        if status != 200 {
            return None;
        }
        let (service, control) = parse_igd_description(&xml)?;
        let control = join_url(&loc, &control)?;
        if split_url(&control)?.0 != split_url(&loc)?.0 {
            tracing::debug!("UPnP: the control URL points elsewhere than the device: ignored");
            return None;
        }
        let igd = Igd { service, control, host };
        self.igd = Some(igd.clone());
        Some(igd)
    }

    async fn soap(igd: &Igd, action: &str, args: &[(&str, String)]) -> Option<(u16, String)> {
        let hdr = [("Content-Type", "text/xml; charset=\"utf-8\"".to_string()), ("SOAPAction", format!("\"{}#{}\"", igd.service, action))];
        http_request("POST", &igd.control, &hdr, &soap_envelope(&igd.service, action, args)).await
    }

    async fn upnp_ext_ip(igd: &Igd) -> Option<IpAddr> {
        let (status, text) = Self::soap(igd, "GetExternalIPAddress", &[]).await?;
        if status != 200 {
            return None;
        }
        tag(&text, "NewExternalIPAddress")?.parse().ok()
    }

    async fn upnp(&mut self, internal: u16, want: u16, lifetime: u32) -> Option<Mapping> {
        let igd = self.igd_discover().await?;
        let me = self.me(igd.host)?;
        let ext_ip = Self::upnp_ext_ip(&igd).await;
        let (mut port, mut lease) = (want, lifetime);
        for _ in 0..4 {
            let args = [
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", port.to_string()),
                ("NewProtocol", "UDP".into()),
                ("NewInternalPort", internal.to_string()),
                ("NewInternalClient", me.to_string()),
                ("NewEnabled", "1".into()),
                ("NewPortMappingDescription", "oneq".into()),
                ("NewLeaseDuration", lease.to_string()),
            ];
            let (status, text) = Self::soap(&igd, "AddPortMapping", &args).await?;
            if status == 200 {
                return Some(Mapping {
                    method: "upnp",
                    ext_ip,
                    ext_port: port,
                    internal_port: internal,
                    lifetime: if lease == 0 { 7200 } else { lease },
                    gateway: igd.host,
                    created: Instant::now(),
                    igd: Some(igd),
                });
            }
            match soap_error(&text) {
                Some(725) if lease != 0 => lease = 0, // only permanent leases: ask for one (removed at exit)
                Some(718) | Some(727) => {
                    let mut r = [0u8; 2];
                    let _ = aws_lc_rs::rand::fill(&mut r);
                    port = 20000 + (u16::from_be_bytes(r) % 40000);
                }
                e => {
                    tracing::debug!("UPnP AddPortMapping: HTTP {status}, error {e:?}");
                    return None;
                }
            }
        }
        None
    }

    /// The router's WAN address without creating a mapping (NAT-PMP, then UPnP), or None. Used to recognise a second NAT.
    pub async fn router_external_ip(&mut self) -> Option<IpAddr> {
        if let Some(gw) = self.gw().await {
            if self.methods.contains(&"natpmp") && !self.disabled.contains("natpmp") {
                if let Some(ip) = self.natpmp_ext_ip(gw).await {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
        if self.methods.contains(&"upnp") {
            let igd = self.igd_discover().await?;
            return Self::upnp_ext_ip(&igd).await;
        }
        None
    }

    pub async fn map(&mut self, internal: u16, want: Option<u16>, lifetime: u32) -> Option<Mapping> {
        let gw = self.gw().await;
        let want = want.unwrap_or(internal);
        for m in self.methods.clone() {
            if self.disabled.contains(m) {
                continue;
            }
            let r = match (m, gw) {
                ("pcp", Some(g)) => self.pcp(g, internal, want, lifetime).await,
                ("natpmp", Some(g)) => self.natpmp(g, internal, want, lifetime).await,
                ("upnp", _) => self.upnp(internal, want, lifetime).await,
                _ => None,
            };
            if let Some(r) = r {
                tracing::info!("port mapping ({}): {} -> {:?}:{} lifetime {}s", r.method, internal, r.ext_ip, r.ext_port, r.lifetime);
                return Some(r);
            }
        }
        None
    }

    /// The same request again (the protocols treat it as a renewal), asking for the port we already have.
    pub async fn renew(&mut self, m: &Mapping) -> Option<Mapping> {
        match m.method {
            "pcp" => self.pcp(m.gateway, m.internal_port, m.ext_port, m.lifetime.max(120)).await,
            "natpmp" => self.natpmp(m.gateway, m.internal_port, m.ext_port, m.lifetime.max(120)).await,
            _ => {
                if self.igd.is_none() {
                    self.igd = m.igd.clone();
                }
                self.upnp(m.internal_port, m.ext_port, m.lifetime).await
            }
        }
    }

    /// Release the mapping (best effort, quick): PCP and NAT-PMP with lifetime 0, UPnP DeletePortMapping.
    pub async fn unmap(&mut self, m: &Mapping) {
        let quick = [Duration::from_millis(300)];
        match m.method {
            "pcp" => {
                if let Some(me) = self.me(m.gateway) {
                    let mut nonce = [0u8; 12];
                    let _ = aws_lc_rs::rand::fill(&mut nonce);
                    let req = pcp_map_request(me, m.internal_port, m.ext_port, 0, &nonce);
                    let _ = udp_exchange(SocketAddr::new(m.gateway, self.pcp_port), &req, |d| pcp_parse_map_response(d, &nonce), &quick).await;
                }
            }
            "natpmp" => {
                let ip = m.internal_port;
                let _ = udp_exchange(SocketAddr::new(m.gateway, self.natpmp_port), &natpmp_map_request(ip, 0, 0), |d| natpmp_parse_map_response(d, ip), &quick).await;
            }
            _ => {
                if let Some(igd) = m.igd.as_ref().or(self.igd.as_ref()) {
                    let args = [("NewRemoteHost", String::new()), ("NewExternalPort", m.ext_port.to_string()), ("NewProtocol", "UDP".into())];
                    let _ = Self::soap(igd, "DeletePortMapping", &args).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const EXT: &str = "203.0.113.7";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pcp_request_and_response_layouts() {
        let nonce = [7u8; 12];
        let d = pcp_map_request(ip("192.168.1.10"), 51820, 51820, 3600, &nonce);
        assert_eq!(d.len(), 60);
        assert_eq!(d[..4], [2, 1, 0, 0]);
        assert_eq!(u32::from_be_bytes(d[4..8].try_into().unwrap()), 3600);
        assert_eq!(d[8..24], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 10]);
        assert_eq!((d[24..36].to_vec(), d[36]), (nonce.to_vec(), 17));
        assert_eq!(d[40..44], [0xca, 0x6c, 0xca, 0x6c]);
        let mut good = vec![2, 0x81, 0, 0];
        good.extend_from_slice(&120u32.to_be_bytes());
        good.extend_from_slice(&[0; 16]);
        good.extend_from_slice(&nonce);
        good.extend_from_slice(&[17, 0, 0, 0, 0x0f, 0xa0, 0x0f, 0xa1]);
        good.extend_from_slice(&ip16(ip("198.51.100.4")));
        let r = pcp_parse_map_response(&good, &nonce).unwrap();
        assert_eq!((r.result, r.lifetime, r.ext_port, r.internal_port, r.ext_ip), (0, 120, 4001, 4000, Some(ip("198.51.100.4"))));
        assert!(pcp_parse_map_response(&good, &[8u8; 12]).is_none(), "somebody else's nonce");
        assert!(pcp_parse_map_response(&good[..50], &nonce).is_none());
        let mut v0 = good.clone();
        v0[0] = 0;
        assert!(pcp_parse_map_response(&v0, &nonce).is_none(), "wrong version");
    }

    #[test]
    fn natpmp_messages() {
        assert_eq!(natpmp_map_request(4000, 4001, 7200), vec![0, 1, 0, 0, 0x0f, 0xa0, 0x0f, 0xa1, 0, 0, 0x1c, 0x20]);
        assert_eq!(natpmp_parse_addr_response(&[0, 128, 0, 0, 0, 0, 0, 5, 198, 51, 100, 9]), Some((0, Ipv4Addr::new(198, 51, 100, 9))));
        assert_eq!(natpmp_parse_addr_response(&[0, 128]), None);
        let mut m = vec![0, 129, 0, 0, 0, 0, 0, 5, 0x0f, 0xa0, 0x0f, 0xa2];
        m.extend_from_slice(&3600u32.to_be_bytes());
        assert_eq!(natpmp_parse_map_response(&m, 4000), Some((0, 4002, 3600)));
        assert_eq!(natpmp_parse_map_response(&m, 4001), None, "another internal port");
    }

    #[test]
    fn upnp_description_urls_and_trust_rules() {
        let xml = "<root><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>\
                   <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/ip</controlURL></service></root>";
        assert_eq!(parse_igd_description(xml), Some(("urn:schemas-upnp-org:service:WANIPConnection:1".into(), "/ctl/ip".into())));
        assert_eq!(parse_igd_description("<root></root>"), None);
        assert!(trusted_lan_host("192.168.1.1", ip("192.168.1.1"), false));
        assert!(!trusted_lan_host("192.168.1.1", ip("192.168.1.2"), false), "the URL must name the address that answered");
        assert!(!trusted_lan_host("8.8.8.8", ip("8.8.8.8"), false), "a public address is not a router on the LAN");
        assert!(!trusted_lan_host("127.0.0.1", ip("127.0.0.1"), false) && trusted_lan_host("127.0.0.1", ip("127.0.0.1"), true));
        assert!(trusted_lan_host("169.254.1.1", ip("169.254.1.1"), false) && trusted_lan_host("fd00::1", ip("fd00::1"), false));
        assert!(!trusted_lan_host("host.example", ip("192.168.1.1"), false));
        assert_eq!(soap_error("<detail><errorCode>718</errorCode></detail>"), Some(718));
        assert_eq!(ssdp_location(b"HTTP/1.1 404 Not Found\r\nLOCATION: http://x/\r\n\r\n"), None);
        assert_eq!(ssdp_location(b"HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1:5000/d.xml\r\n\r\n").as_deref(), Some("http://192.168.1.1:5000/d.xml"));
        assert_eq!(split_url("http://192.168.1.1:5000/d.xml"), Some(("192.168.1.1".into(), 5000, "/d.xml".into())));
        assert_eq!(split_url("http://[fd00::1]/d"), Some(("fd00::1".into(), 80, "/d".into())));
        assert_eq!(split_url("https://x/"), None);
        assert_eq!(join_url("http://10.0.0.1:5000/dir/desc.xml", "ctl").as_deref(), Some("http://10.0.0.1:5000/dir/ctl"));
        assert_eq!(join_url("http://10.0.0.1:5000/dir/desc.xml", "/ctl").as_deref(), Some("http://10.0.0.1:5000/ctl"));
        let m = Mapping { method: "pcp", ext_ip: Some(ip("2001:db8::1")), ext_port: 4001, internal_port: 4000, lifetime: 3600, gateway: ip("10.0.0.1"), created: Instant::now(), igd: None };
        assert_eq!(m.endpoint().as_deref(), Some("[2001:db8::1]:4001"));
    }

    // ---- simulated gateways on loopback

    async fn udp_server(handler: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(vec![]));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                seen2.lock().unwrap().push(b[..n].to_vec());
                if let Some(out) = handler(&b[..n]) {
                    let _ = s.send_to(&out, from).await;
                }
            }
        });
        (port, seen)
    }

    fn pcp_handler(result: u8, ext_ip: &'static str) -> impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static {
        move |d| {
            if d.len() < 60 || d[0] != 2 {
                return None;
            }
            let mut o = vec![2, 0x81, 0, result];
            o.extend_from_slice(&d[4..8]);
            o.extend_from_slice(&[0; 16]);
            o.extend_from_slice(&d[24..36]);
            o.extend_from_slice(&[17, 0, 0, 0]);
            o.extend_from_slice(&d[40..44]);
            o.extend_from_slice(&ip16(ip(ext_ip)));
            Some(o)
        }
    }

    fn natpmp_handler() -> impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static {
        |d| {
            if d == [0, 0] {
                return Some(vec![0, 128, 0, 0, 0, 0, 0, 99, 203, 0, 113, 7]);
            }
            if d.len() == 12 && d[1] == 1 {
                let mut o = vec![0, 129, 0, 0, 0, 0, 0, 99];
                o.extend_from_slice(&d[4..6]);
                o.extend_from_slice(&[0x9c, 0x41]); // external port 40001
                o.extend_from_slice(&d[8..12]);
                return Some(o);
            }
            None
        }
    }

    fn mapper(methods: &[&'static str], pcp: u16, natpmp: u16) -> PortMapper {
        PortMapper { gateway: Some(ip("127.0.0.1")), methods: methods.to_vec(), pcp_port: pcp, natpmp_port: natpmp, local_ip: Some(ip("192.168.1.10")), ..Default::default() }
    }

    #[tokio::test]
    async fn pcp_maps_renews_and_releases() {
        let (port, seen) = udp_server(pcp_handler(0, EXT)).await;
        let mut pm = mapper(&["pcp"], port, port);
        let m = pm.map(51820, None, 3600).await.unwrap();
        assert_eq!((m.method, m.ext_ip, m.ext_port), ("pcp", Some(ip(EXT)), 51820));
        assert_eq!(m.endpoint().as_deref(), Some("203.0.113.7:51820"));
        assert_eq!(pm.renew(&m).await.unwrap().ext_port, 51820);
        pm.unmap(&m).await;
        let last = seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(u32::from_be_bytes(last[4..8].try_into().unwrap()), 0, "release = lifetime 0");
    }

    #[tokio::test]
    async fn pcp_refusal_and_old_routers_fall_through_to_nat_pmp() {
        let (port, _) = udp_server(pcp_handler(2, EXT)).await;
        assert!(mapper(&["pcp"], port, port).map(51820, None, 3600).await.is_none());
        let np = natpmp_handler();
        let (port2, _) = udp_server(move |d| if d[0] == 2 { Some(vec![0, 0x81, 0, 1]) } else { np(d) }).await;
        let mut pm = mapper(&["pcp", "natpmp"], port2, port2);
        let m = pm.map(51820, None, 3600).await.unwrap();
        assert_eq!((m.method, m.ext_port), ("natpmp", 40001), "the router may choose another external port");
        assert!(pm.disabled.contains("pcp"));
        assert_eq!(pm.router_external_ip().await, Some(ip(EXT)));
    }

    #[tokio::test]
    async fn nothing_answering_means_no_mapping_quickly() {
        let (port, _) = udp_server(|_| None).await;
        let t0 = Instant::now();
        assert!(mapper(&["pcp", "natpmp"], port, port).map(51820, None, 3600).await.is_none());
        assert!(t0.elapsed() < Duration::from_secs(6));
    }

    /// An UPnP gateway on loopback: SSDP answer on a unicast UDP port, device description and control URL over HTTP.
    struct FakeIgd {
        ssdp_port: u16,
        calls: Arc<Mutex<Vec<(String, String)>>>,
        maps: Arc<Mutex<Vec<u16>>>,
    }

    async fn fake_igd(location_host: Option<&'static str>, control_host: Option<&'static str>, add_errors: Vec<u32>) -> FakeIgd {
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hport = http.local_addr().unwrap().port();
        let calls = Arc::new(Mutex::new(vec![]));
        let maps = Arc::new(Mutex::new(vec![]));
        let errors = Arc::new(Mutex::new(add_errors));
        let (c2, m2) = (calls.clone(), maps.clone());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = http.accept().await {
                let (calls, maps, errors) = (c2.clone(), m2.clone(), errors.clone());
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut b = [0u8; 4096];
                    loop {
                        let n = s.read(&mut b).await.unwrap_or(0);
                        data.extend_from_slice(&b[..n]);
                        let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") else { if n == 0 { return } else { continue } };
                        let head = String::from_utf8_lossy(&data[..at]).to_string();
                        let want: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())).unwrap_or(0);
                        if data.len() >= at + 4 + want {
                            break;
                        }
                        if n == 0 {
                            return;
                        }
                    }
                    let at = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let head = String::from_utf8_lossy(&data[..at]).to_string();
                    let body = String::from_utf8_lossy(&data[at + 4..]).to_string();
                    let (mut code, mut out) = (200, String::new());
                    if head.starts_with("GET /desc.xml") {
                        let ctl = match control_host {
                            Some(h) => format!("http://{h}/ctl/ip"),
                            None => "/ctl/ip".into(),
                        };
                        out = format!("<root><device><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>{ctl}</controlURL></service></device></root>");
                    } else if head.starts_with("POST /ctl/ip") {
                        let action = head.lines().find(|l| l.to_ascii_lowercase().starts_with("soapaction")).and_then(|l| l.split('#').nth(1)).unwrap_or("").trim_matches('"').to_string();
                        calls.lock().unwrap().push((action.clone(), body.clone()));
                        match action.as_str() {
                            "GetExternalIPAddress" => out = format!("<NewExternalIPAddress>{EXT}</NewExternalIPAddress>"),
                            "AddPortMapping" => {
                                let port: u16 = tag(&body, "NewExternalPort").unwrap().parse().unwrap();
                                let lease: u32 = tag(&body, "NewLeaseDuration").unwrap().parse().unwrap();
                                let err = { let mut e = errors.lock().unwrap(); if e.is_empty() { None } else { Some(e.remove(0)) } };
                                match err {
                                    Some(725) if lease == 0 => maps.lock().unwrap().push(port),
                                    Some(e) => {
                                        code = 500;
                                        out = format!("<errorCode>{e}</errorCode>");
                                    }
                                    None => maps.lock().unwrap().push(port),
                                }
                            }
                            "DeletePortMapping" => {
                                let port: u16 = tag(&body, "NewExternalPort").unwrap().parse().unwrap();
                                maps.lock().unwrap().retain(|p| *p != port);
                            }
                            _ => {}
                        }
                    } else {
                        code = 404;
                    }
                    let resp = format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        let (ssdp_port, _) = udp_server(move |d| {
            d.starts_with(b"M-SEARCH").then(|| format!("HTTP/1.1 200 OK\r\nLOCATION: http://{}:{hport}/desc.xml\r\nST: x\r\n\r\n", location_host.unwrap_or("127.0.0.1")).into_bytes())
        })
        .await;
        FakeIgd { ssdp_port, calls, maps }
    }

    fn upnp_mapper(g: &FakeIgd, allow_loopback: bool) -> PortMapper {
        PortMapper {
            methods: vec!["upnp"],
            ssdp_addr: SocketAddr::new(ip("127.0.0.1"), g.ssdp_port),
            allow_loopback,
            local_ip: Some(ip("192.168.1.10")),
            search_time: Duration::from_millis(800),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn upnp_discovers_maps_and_deletes() {
        let g = fake_igd(None, None, vec![]).await;
        let mut pm = upnp_mapper(&g, true);
        assert_eq!(pm.router_external_ip().await, Some(ip(EXT)));
        let m = pm.map(51820, None, 3600).await.unwrap();
        assert_eq!((m.method, m.ext_ip, m.ext_port), ("upnp", Some(ip(EXT)), 51820));
        assert_eq!(*g.maps.lock().unwrap(), vec![51820]);
        let add = g.calls.lock().unwrap().iter().find(|c| c.0 == "AddPortMapping").unwrap().1.clone();
        for n in ["<NewProtocol>UDP<", "<NewInternalClient>192.168.1.10<", "<NewInternalPort>51820<", "<NewPortMappingDescription>oneq<"] {
            assert!(add.contains(n), "{n}");
        }
        pm.unmap(&m).await;
        assert!(g.maps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn upnp_permanent_lease_and_port_conflict() {
        let g = fake_igd(None, None, vec![725]).await;
        let m = upnp_mapper(&g, true).map(51820, None, 3600).await.unwrap();
        assert_eq!(m.ext_port, 51820);
        let leases: Vec<String> = g.calls.lock().unwrap().iter().filter(|c| c.0 == "AddPortMapping").map(|c| tag(&c.1, "NewLeaseDuration").unwrap()).collect();
        assert_eq!(leases, vec!["3600", "0"], "first a lease, then the permanent one the router insists on");
        let g2 = fake_igd(None, None, vec![718]).await;
        let m2 = upnp_mapper(&g2, true).map(51820, None, 3600).await.unwrap();
        assert_ne!(m2.ext_port, 51820, "conflict: another external port");
        assert_eq!(*g2.maps.lock().unwrap(), vec![m2.ext_port]);
    }

    #[tokio::test]
    async fn upnp_refuses_foreign_hosts_and_non_lan_devices() {
        let g = fake_igd(None, Some("192.0.2.99:80"), vec![]).await;
        assert!(upnp_mapper(&g, true).map(51820, None, 3600).await.is_none());
        assert!(g.calls.lock().unwrap().is_empty(), "nothing was sent to the foreign control URL");
        let g = fake_igd(Some("192.0.2.50"), None, vec![]).await; // LOCATION names a third host
        assert!(upnp_mapper(&g, true).map(51820, None, 3600).await.is_none());
        let g = fake_igd(None, None, vec![]).await; // loopback is no router on the LAN
        assert!(upnp_mapper(&g, false).map(51820, None, 3600).await.is_none());
    }
}
