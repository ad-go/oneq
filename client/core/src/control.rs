//! Registry client: login, join (address and MAC allocation), member list. A minimal HTTPS/1.1 client over
//! tokio-rustls (TLS 1.3, X25519MLKEM768 only), with failover between several oneqrelays like the Python node.
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::l3::mac_from_str;
use crate::nat::ClockSync;
use crate::wire::{node_id, Identity, PUB_LEN};

#[derive(Clone, Debug, PartialEq)]
pub struct JoinInfo {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub prefix: u8,
    pub mtu: u16,
    /// UDP ports (main, alt) of the relay's STUN service, if it runs one
    pub stun: Option<(u16, u16)>,
    /// third UDP port of the STUN service (the one that answers from a source port nobody contacted), if announced
    pub stun_change: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub id: [u8; 16],
    pub pub_key: Vec<u8>,
    pub name: String,
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub endpoints: Vec<String>,
    pub online: bool,
    /// NAT type the member measured (open, cone, port-restricted, symmetric, ...) and its public address
    pub nat: Option<String>,
    pub nat_mapped: Option<String>,
    /// port allocation step of the member's symmetric NAT (predictable ports) and whether a second NAT sits in front of it
    pub nat_delta: Option<i32>,
    pub nat_cgnat: bool,
    /// the member offers to forward datagrams, and the delegation (bandwidth cap in kbit/s) the administrator granted it, if any
    pub offer: bool,
    pub relay_kbps: Option<u32>,
    /// delegated relay nodes the member holds a session with
    pub relays: Vec<[u8; 16]>,
}

/// The login was refused (HTTP 401). With several oneqrelays this is not final: a freshly started one may not have
/// replicated the accounts yet, so the others are asked before giving up.
#[derive(Debug)]
pub struct LoginRefused;
impl std::fmt::Display for LoginRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "login refused: wrong community, user or password")
    }
}
impl std::error::Error for LoginRefused {}

pub struct Control {
    urls: Vec<String>,
    i: usize,
    community: String,
    user: String,
    password: String,
    tls: Arc<ClientConfig>,
    token: Option<String>,
    /// the relay's clock, measured at every join
    pub clock: Arc<ClockSync>,
    /// our node key: lets the registration prove possession of it (a relay that knows the feature sends a challenge only we can open)
    identity: Option<Arc<Identity>>,
    /// the last proof (expiry in seconds since the epoch, proof): one challenge serves several registrations
    pop: Option<(u64, Value)>,
    /// relays that answered 404 to the challenge request (older than the feature)
    pop_unsupported: std::collections::HashSet<String>,
}

fn split_url(url: &str) -> Result<(bool, String, u16)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("relay URL must start with https:// (or http:// for tests): {url}");
    };
    let hostport = rest.trim_end_matches('/');
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>()?),
        _ => (hostport, if tls { 443 } else { 80 }),
    };
    Ok((tls, host.to_string(), port))
}

/// Decode an HTTP/1.1 chunked body.
fn dechunk(mut b: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n").ok_or_else(|| anyhow!("bad chunked body"))?;
        let size = usize::from_str_radix(std::str::from_utf8(&b[..nl])?.split(';').next().unwrap().trim(), 16)?;
        b = &b[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 {
            bail!("truncated chunked body");
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

/// One request, `Connection: close`. Returns the status code and the body.
pub async fn http_request(
    tls: &Arc<ClientConfig>,
    base: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>)> {
    let (use_tls, host, port) = split_url(base)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: oneq-client\r\nAccept: application/json\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    let tcp = timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow!("connect to {host}:{port} timed out"))?
        .with_context(|| format!("connect to {host}:{port}"))?;
    let mut raw = Vec::new();
    let io = async {
        if use_tls {
            let name = ServerName::try_from(host.clone()).map_err(|e| anyhow!("bad server name {host}: {e}"))?;
            let mut s = tokio_rustls::TlsConnector::from(tls.clone())
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {host}:{port} (requires TLS 1.3 + X25519MLKEM768)"))?;
            s.write_all(req.as_bytes()).await?;
            let _ = s.read_to_end(&mut raw).await; // a missing close_notify is fine: the headers say how long the body is
        } else {
            let mut s = tcp;
            s.write_all(req.as_bytes()).await?;
            s.read_to_end(&mut raw).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    timeout(Duration::from_secs(15), io).await.map_err(|_| anyhow!("request to {host}:{port} timed out"))??;
    if raw.len() > 4 * 1024 * 1024 {
        bail!("response too large");
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let head = std::str::from_utf8(&raw[..split])?;
    let status: u16 = head.split_whitespace().nth(1).ok_or_else(|| anyhow!("no status line"))?.parse()?;
    let mut body = raw[split + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body)?;
    }
    Ok((status, body))
}

impl Control {
    pub fn new(urls: Vec<String>, community: &str, user: &str, password: &str, tls: Arc<ClientConfig>) -> Result<Self> {
        if urls.is_empty() {
            bail!("at least one oneqrelay URL is required");
        }
        for u in &urls {
            split_url(u)?;
        }
        Ok(Control {
            urls: urls.into_iter().map(|u| u.trim_end_matches('/').to_string()).collect(),
            i: 0,
            community: community.into(),
            user: user.into(),
            password: password.into(),
            tls,
            token: None,
            clock: Arc::new(ClockSync::default()),
            identity: None,
            pop: None,
            pop_unsupported: Default::default(),
        })
    }

    /// Give the control the node key, so registrations prove possession of it.
    pub fn set_identity(&mut self, id: Arc<Identity>) {
        self.identity = Some(id);
    }

    fn epoch() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// A proof of possession for the registration, or None (no key here, or a relay without the feature).
    async fn pop_proof(&mut self, id: &[u8; 16], pub_key: &[u8]) -> Result<Option<Value>> {
        let Some(ident) = self.identity.clone() else { return Ok(None) };
        if self.pop_unsupported.contains(self.base()) {
            return Ok(None);
        }
        if let Some((exp, p)) = &self.pop {
            if *exp > Self::epoch() + 15 {
                return Ok(Some(p.clone()));
            }
        }
        let body = json!({"pub": base64::engine::general_purpose::STANDARD.encode(pub_key)}).to_string();
        let path = format!("/v1/c/{}/nodes/{}/challenge", self.community, hex::encode(id));
        match self.call("POST", &path, Some(body)).await {
            Ok(ch) => match ident.pop_answer(&ch) {
                Ok(p) => {
                    self.pop = Some((p["exp"].as_u64().unwrap_or(0), p.clone()));
                    Ok(Some(p))
                }
                Err(e) => {
                    tracing::warn!("proof of possession: {e:#}");
                    Ok(None)
                }
            },
            Err(e) if e.to_string().starts_with("HTTP 404") || e.to_string().starts_with("HTTP 405") => {
                self.pop_unsupported.insert(self.base().to_string());
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn base(&self) -> &str {
        &self.urls[self.i]
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn community(&self) -> &str {
        &self.community
    }

    pub fn tls(&self) -> Arc<ClientConfig> {
        self.tls.clone()
    }

    pub fn invalidate_token(&mut self) {
        self.token = None;
    }

    pub fn rotate(&mut self) {
        self.i = (self.i + 1) % self.urls.len();
        self.token = None;
        tracing::info!("switching to oneqrelay {}", self.base());
    }

    /// `wss://host/v1/relay?comm=..&node=..` on the oneqrelay currently in use.
    pub fn relay_ws_url(&self, node: &[u8; 16]) -> String {
        let b = self.base().replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
        format!("{b}/v1/relay?comm={}&node={}", self.community, hex::encode(node))
    }

    pub async fn login(&mut self) -> Result<()> {
        let body = json!({"community": self.community, "user": self.user, "password": self.password}).to_string();
        let (code, resp) = http_request(&self.tls, self.base(), "POST", "/v1/login", None, Some(&body)).await?;
        match code {
            200 => {
                let v: Value = serde_json::from_slice(&resp)?;
                self.token = Some(v["token"].as_str().ok_or_else(|| anyhow!("no token in the login response"))?.to_string());
                Ok(())
            }
            401 => Err(LoginRefused.into()),
            _ => bail!("login: HTTP {code}"),
        }
    }

    /// Authenticated request with automatic re-login and failover to the next oneqrelay.
    async fn call(&mut self, method: &str, path: &str, body: Option<String>) -> Result<Value> {
        let mut last: Option<anyhow::Error> = None;
        let mut refused = 0;
        for _ in 0..(self.urls.len() * 2 + 2) {
            if self.token.is_none() {
                match self.login().await {
                    Ok(()) => refused = 0,
                    Err(e) if e.downcast_ref::<LoginRefused>().is_some() => {
                        refused += 1;
                        if refused >= self.urls.len() {
                            return Err(e);
                        }
                        tracing::info!("oneqrelay {} refused the login, trying another", self.base());
                        self.rotate();
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("oneqrelay {}: {e:#}", self.base());
                        last = Some(e);
                        self.rotate();
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            }
            match http_request(&self.tls, self.base(), method, path, self.token.as_deref(), body.as_deref()).await {
                Ok((401, _)) => self.token = None,
                Ok((code, _)) if code == 429 || code >= 500 => {
                    last = Some(anyhow!("HTTP {code}"));
                    self.rotate();
                }
                Ok((code, b)) if code >= 400 => {
                    bail!("HTTP {code}: {}", String::from_utf8_lossy(&b).chars().take(200).collect::<String>())
                }
                Ok((_, b)) => return Ok(serde_json::from_slice(&b)?),
                Err(e) => {
                    tracing::warn!("oneqrelay {}: {e:#}", self.base());
                    last = Some(e);
                    self.rotate();
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        Err(anyhow!("no oneqrelay reachable: {}", last.map(|e| format!("{e:#}")).unwrap_or_default()))
    }

    pub async fn join(&mut self, id: &[u8; 16], pub_key: &[u8], endpoints: &[String], name: &str, nat: Option<&Value>, offer: bool, relays: &[[u8; 16]]) -> Result<JoinInfo> {
        let mut body = json!({"pub": base64::engine::general_purpose::STANDARD.encode(pub_key), "endpoints": endpoints, "name": name, "offer": offer});
        if !relays.is_empty() {
            body["relays"] = json!(relays.iter().map(hex::encode).collect::<Vec<_>>());
        }
        if let Some(n) = nat {
            body["nat"] = n.clone();
        }
        let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let t0 = now();
        if let Some(p) = self.pop_proof(id, pub_key).await? {
            body["pop"] = p;
        }
        let path = format!("/v1/c/{}/nodes/{}", self.community, hex::encode(id));
        let v = match self.call("PUT", &path, Some(body.to_string())).await {
            Ok(v) => v,
            Err(e) if self.identity.is_some() && e.to_string().contains("proof of possession") => {
                // the relay wants a proof (required, or this id was registered with one) or ours expired: a fresh challenge, one retry
                self.pop = None;
                let base = self.base().to_string();
                self.pop_unsupported.remove(&base);
                let Some(p) = self.pop_proof(id, pub_key).await? else { return Err(e) };
                body["pop"] = p;
                self.call("PUT", &path, Some(body.to_string())).await?
            }
            Err(e) => return Err(e),
        };
        let t1 = now();
        if let Some(ms) = v["now_ms"].as_i64() {
            if t1 - t0 < 1.0 {
                self.clock.update(ms as f64 / 1000.0 - (t0 + t1) / 2.0, t1 - t0);
            }
        }
        Ok(JoinInfo {
            ip: v["ip"].as_str().ok_or_else(|| anyhow!("no ip"))?.parse()?,
            mac: mac_from_str(v["mac"].as_str().unwrap_or("")).ok_or_else(|| anyhow!("bad mac"))?,
            prefix: v["prefix"].as_u64().ok_or_else(|| anyhow!("no prefix"))? as u8,
            mtu: v["mtu"].as_u64().ok_or_else(|| anyhow!("no mtu"))? as u16,
            stun: match (v["stun"]["port"].as_u64(), v["stun"]["alt_port"].as_u64()) {
                (Some(a), Some(b)) => Some((a as u16, b as u16)),
                _ => None,
            },
            stun_change: v["stun"]["change_port"].as_u64().and_then(|p| u16::try_from(p).ok()),
        })
    }

    /// Ask the relay to probe `endpoint` (our public address) from a UDP port we never contacted. None: no such service
    /// here, or the address was refused.
    pub async fn nat_test(&mut self, id: &[u8; 16], endpoint: &str) -> Option<bool> {
        let body = json!({"endpoint": endpoint}).to_string();
        let v = self.call("POST", &format!("/v1/c/{}/nodes/{}/nat-test", self.community, hex::encode(id)), Some(body)).await.ok()?;
        v["reachable"].as_bool()
    }

    pub async fn members(&mut self) -> Result<Vec<Member>> {
        let v = self.call("GET", &format!("/v1/c/{}/nodes", self.community), None).await?;
        Ok(parse_members(&v))
    }

    /// The member list and the routes announced for the community (one request). `mesh` is our own address and prefix: routes into the
    /// mesh itself are dropped (see [`parse_routes`]).
    pub async fn nodes(&mut self, mesh: (Ipv4Addr, u8)) -> Result<(Vec<Member>, Vec<Route>)> {
        let v = self.call("GET", &format!("/v1/c/{}/nodes", self.community), None).await?;
        Ok((parse_members(&v), parse_routes(&v, mesh)))
    }
}

pub use crate::l3::Route;

fn private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && o[1] & 0xc0 == 64) // 10/8, 172.16/12, 192.168/16, 100.64/10 (shared address space)
}

/// May this announced route be installed? The relay is trusted for membership, not for steering our traffic: only private networks
/// (RFC 1918 and 100.64/10), at least a /8, never overlapping the mesh subnet. Anything else is ignored.
pub fn route_acceptable(net: Ipv4Addr, prefix: u8, mesh: (Ipv4Addr, u8)) -> bool {
    if !(8..=32).contains(&prefix) {
        return false;
    }
    let mask = |p: u8| if p == 0 { 0 } else { u32::MAX << (32 - p as u32) };
    let (first, last) = (u32::from(net) & mask(prefix), u32::from(net) | !mask(prefix));
    if first != u32::from(net) || !private_v4(Ipv4Addr::from(first)) || !private_v4(Ipv4Addr::from(last)) {
        return false; // host bits set, or part of the range is public
    }
    let (mfirst, mlast) = (u32::from(mesh.0) & mask(mesh.1), u32::from(mesh.0) | !mask(mesh.1));
    last < mfirst || first > mlast
}

/// The `routes` of a member-list reply: `{"cidr": "192.168.16.0/24", "via": "<node id>", "prio": 100}`, one entry per gateway of a
/// network; malformed or unacceptable entries are ignored.
pub fn parse_routes(v: &Value, mesh: (Ipv4Addr, u8)) -> Vec<Route> {
    let mut out = Vec::new();
    for r in v["routes"].as_array().into_iter().flatten() {
        let parsed = (|| -> Option<Route> {
            let (net, prefix) = r["cidr"].as_str()?.split_once('/')?;
            let (net, prefix): (Ipv4Addr, u8) = (net.parse().ok()?, prefix.parse().ok()?);
            let via: [u8; 16] = hex::decode(r["via"].as_str()?).ok()?.try_into().ok()?;
            let prio = r["prio"].as_u64().map_or(100, |p| p.min(1000) as u16); // older relays send none
            route_acceptable(net, prefix, mesh).then_some(Route { net, prefix, via, prio })
        })();
        if let Some(r) = parsed {
            out.push(r);
        } else {
            tracing::debug!("route {} ignored", r["cidr"]);
        }
    }
    out
}

/// Registry entries whose id does not match their key are ignored: never trust the registry for the key <-> id binding.
pub fn parse_members(v: &Value) -> Vec<Member> {
    let mut out = Vec::new();
    for m in v["nodes"].as_array().into_iter().flatten() {
        let parsed = (|| -> Option<Member> {
            let pub_key = base64::engine::general_purpose::STANDARD.decode(m["pub"].as_str()?).ok()?;
            if pub_key.len() != PUB_LEN {
                return None;
            }
            let id: [u8; 16] = hex::decode(m["id"].as_str()?).ok()?.try_into().ok()?;
            if node_id(&pub_key) != id {
                tracing::warn!("registry entry {} does not match its key: ignored", m["id"]);
                return None;
            }
            Some(Member {
                id,
                pub_key,
                name: m["name"].as_str().unwrap_or("").to_string(),
                ip: m["ip"].as_str()?.parse().ok()?,
                mac: mac_from_str(m["mac"].as_str()?)?,
                endpoints: m["endpoints"].as_array().map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect()).unwrap_or_default(),
                online: m["online"].as_bool().unwrap_or(false),
                nat: m["nat"]["type"].as_str().map(String::from),
                nat_mapped: m["nat"]["mapped"].as_str().map(String::from),
                nat_delta: m["nat"]["delta"].as_i64().filter(|d| *d != 0 && d.abs() <= crate::nat::MAX_DELTA as i64).map(|d| d as i32),
                nat_cgnat: m["nat"]["cgnat"].as_bool().unwrap_or(false),
                offer: m["offer"].as_bool().unwrap_or(false),
                relay_kbps: m["relay_role"]["max_kbps"].as_u64().map(|k| k.min(u32::MAX as u64) as u32),
                relays: m["relays"].as_array().map(|a| a.iter().filter_map(|e| hex::decode(e.as_str()?).ok()?.try_into().ok()).collect()).unwrap_or_default(),
            })
        })();
        if let Some(m) = parsed {
            out.push(m);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Identity;

    #[test]
    fn urls_are_parsed() {
        assert_eq!(split_url("https://10.1.0.1:8443").unwrap(), (true, "10.1.0.1".into(), 8443));
        assert_eq!(split_url("https://relay.example.org/").unwrap(), (true, "relay.example.org".into(), 443));
        assert_eq!(split_url("http://127.0.0.1:18080").unwrap(), (false, "127.0.0.1".into(), 18080));
        assert!(split_url("ftp://x").is_err());
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap(), b"hello world");
        assert!(dechunk(b"zz\r\nhello").is_err());
        assert!(dechunk(b"5\r\nhe").is_err());
    }

    #[test]
    fn only_private_networks_outside_the_mesh_are_accepted_as_routes() {
        let mesh: (Ipv4Addr, u8) = ("10.78.0.5".parse().unwrap(), 24);
        let ok = |net: &str, p| route_acceptable(net.parse().unwrap(), p, mesh);
        assert!(ok("192.168.16.0", 24) && ok("192.168.0.0", 16) && ok("172.16.0.0", 12) && ok("10.1.0.0", 16) && ok("100.64.0.0", 10) && ok("192.168.16.7", 32));
        assert!(ok("10.0.0.0", 8) == false, "10/8 contains the mesh subnet");
        assert!(ok("10.78.0.0", 24) == false && ok("10.78.0.128", 25) == false && ok("10.78.0.5", 32) == false, "inside the mesh");
        assert!(ok("10.78.1.0", 24), "a neighbour of the mesh subnet is fine");
        for (net, p) in [("0.0.0.0", 0), ("0.0.0.0", 1), ("8.8.8.0", 24), ("172.0.0.0", 8), ("172.32.0.0", 16), ("192.168.16.1", 24), ("169.254.0.0", 16), ("127.0.0.0", 8), ("224.0.0.0", 8), ("192.168.16.0", 7), ("100.0.0.0", 8)] {
            assert!(!ok(net, p), "{net}/{p}");
        }
    }

    #[test]
    fn routes_of_a_reply_are_parsed_and_filtered() {
        let mesh: (Ipv4Addr, u8) = ("10.78.0.5".parse().unwrap(), 24);
        let gw = hex::encode([7u8; 16]);
        let v = json!({"nodes": [], "routes": [
            {"cidr": "192.168.16.0/24", "via": gw, "by": "alice", "prio": 40},
            {"cidr": "192.168.16.0/24", "via": hex::encode([8u8; 16]), "prio": 5000},
            {"cidr": "8.8.8.0/24", "via": gw},
            {"cidr": "10.78.0.0/24", "via": gw},
            {"cidr": "192.168.17.0/24", "via": "zz"},
            {"cidr": "nonsense", "via": gw},
            {"via": gw},
        ]});
        assert_eq!(
            parse_routes(&v, mesh),
            vec![
                Route { net: "192.168.16.0".parse().unwrap(), prefix: 24, via: [7; 16], prio: 40 },
                Route { net: "192.168.16.0".parse().unwrap(), prefix: 24, via: [8; 16], prio: 1000 },
            ]
        );
        let old = json!({"routes": [{"cidr": "192.168.16.0/24", "via": gw}]});
        assert_eq!(parse_routes(&old, mesh)[0].prio, 100, "an older relay sends no priority");
        assert!(parse_routes(&json!({"nodes": []}), mesh).is_empty(), "an older relay sends none");
    }

    #[test]
    fn members_with_a_forged_id_or_bad_fields_are_ignored() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let enc = |p: &[u8]| base64::engine::general_purpose::STANDARD.encode(p);
        let v = json!({"nodes": [
            {"id": hex::encode(a.node_id()), "pub": enc(&a.pub_bytes), "name": "ok", "ip": "10.78.0.9", "mac": "02:00:00:00:00:09", "endpoints": ["1.2.3.4:5"], "online": true},
            {"id": hex::encode(a.node_id()), "pub": enc(&b.pub_bytes), "name": "forged", "ip": "10.78.0.8", "mac": "02:00:00:00:00:08"},
            {"id": "zz", "pub": "AAAA", "ip": "x", "mac": "y"},
            {"id": hex::encode(b.node_id()), "pub": enc(&b.pub_bytes), "ip": "10.78.0.7", "mac": "bad"},
        ]});
        let m = parse_members(&v);
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].name.as_str(), m[0].ip, m[0].online, m[0].endpoints.len()), ("ok", "10.78.0.9".parse().unwrap(), true, 1));
    }
}
