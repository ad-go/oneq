//! Orchestration: identity file, registry loop, UDP/TUN/relay I/O tasks around the [`Engine`].
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::control::{Control, JoinInfo, LoginRefused};
use crate::engine::{engine_task, Engine, EngineCfg, Event, Io};
use crate::l3::{mac_to_string, Route};
use crate::nat::{self, NatInfo, Prober, Transact};
use crate::portmap::{Mapping, PortMapper};
use crate::status::{RouteInfo, Status};
use crate::tls;
use crate::wire::Identity;

#[derive(Clone, Debug, Default)]
pub struct Config {
    /// oneqrelay URLs, tried in order (failover)
    pub relays: Vec<String>,
    pub community: String,
    pub user: String,
    pub password: String,
    /// name shown in the member list
    pub name: String,
    /// private CA / self-signed relay certificate (PEM); empty = the public web roots
    pub ca_pem: Option<Vec<u8>>,
    /// where the node key lives (created on first use)
    pub key_file: String,
    /// UDP bind address, default 0.0.0.0:0
    pub listen: String,
    /// addresses other nodes can reach us on directly (host:port); empty when behind NAT
    pub advertise: Vec<String>,
    pub force_relay: bool,
    pub no_relay: bool,
    pub relay_after_s: f64,
    /// offer to forward datagrams for the other members (effective once an administrator delegates this node)
    pub relay_offer: bool,
    /// do not use the delegated relay nodes of the community
    pub no_delegates: bool,
    /// do not ask the router (PCP, NAT-PMP, UPnP) to forward our UDP port
    pub no_port_mapping: bool,
    /// IPv4 only: no dual-stack socket, no IPv6 candidates
    pub no_ipv6: bool,
    /// use the networks the administrator routed through a gateway member (only private networks outside the mesh; installed in the operating system)
    pub accept_routes: bool,
}

pub struct Prepared {
    pub info: JoinInfo,
    identity: Arc<Identity>,
    control: Arc<Mutex<Control>>,
    cfg: Config,
}

pub fn load_or_create_identity(path: &str) -> Result<Identity> {
    let p = Path::new(path);
    if p.exists() {
        let txt = std::fs::read_to_string(p).with_context(|| format!("read {path}"))?;
        let raw = base64_decode(txt.trim())?;
        return Identity::from_bytes(&raw);
    }
    let id = Identity::generate()?;
    if let Some(dir) = p.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    write_private(p, &base64_encode(&id.to_bytes()?))?;
    Ok(id)
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn write_private(p: &Path, text: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(p)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(p, format!("{text}\n"))?; // per-user profile directory; NTFS ACLs inherit from it
    }
    Ok(())
}

/// Log in and join once: this gives the address, MAC and MTU the TUN device needs. Call [`run`] afterwards.
pub async fn prepare(cfg: Config, status: &Status) -> Result<Prepared> {
    status.set_state("connecting", "logging in");
    status.update(|s| s.community = cfg.community.clone());
    let identity = Arc::new(load_or_create_identity(&cfg.key_file)?);
    let tls = tls::client_config(cfg.ca_pem.as_deref())?;
    let mut control = Control::new(cfg.relays.clone(), &cfg.community, &cfg.user, &cfg.password, tls)?;
    control.set_identity(identity.clone());
    let info = control
        .join(&identity.node_id(), &identity.pub_bytes, &cfg.advertise, &cfg.name, None, cfg.relay_offer, &[])
        .await
        .map_err(|e| {
            let msg = if e.downcast_ref::<LoginRefused>().is_some() { "wrong community, user or password".to_string() } else { format!("{e:#}") };
            status.set_state("error", &msg);
            e
        })?;
    status.update(|s| {
        s.ip = info.ip.to_string();
        s.mac = mac_to_string(&info.mac);
        s.prefix = info.prefix;
        s.mtu = info.mtu;
        s.relay_url = control.base().to_string();
    });
    status.note(format!("address {}/{} mac {} mtu {}", info.ip, info.prefix, mac_to_string(&info.mac), info.mtu));
    // the routed networks are known before the interface exists: Android needs them to build the VPN interface
    if cfg.accept_routes {
        if let Ok((_, routes)) = control.nodes((info.ip, info.prefix)).await {
            status.update(|s| s.route_nets = route_nets(&routes));
        }
    }
    Ok(Prepared { info, identity, control: Arc::new(Mutex::new(control)), cfg })
}

/// Create the TUN device on desktop systems (Wintun on Windows, utun on macOS, /dev/net/tun on Linux).
#[cfg(not(target_os = "android"))]
pub fn create_tun(name: &str, info: &JoinInfo, wintun_dll: Option<&str>) -> Result<tun_rs::AsyncDevice> {
    // macOS only accepts utunN: any other name (the default "oneq") means "let the system pick the next free utun"
    #[cfg(target_os = "macos")]
    let b = if name.starts_with("utun") { tun_rs::DeviceBuilder::new().name(name) } else { tun_rs::DeviceBuilder::new() };
    #[cfg(not(target_os = "macos"))]
    let b = tun_rs::DeviceBuilder::new().name(name);
    let b = b.ipv4(info.ip, info.prefix, None);
    // Windows refuses an IPv6 MTU below 1280 (error 87), and the community MTU can be lower (1220 when the node is bound to another tunnel's interface): set IPv4 only
    #[cfg(windows)]
    let mut b = b.mtu_v4(info.mtu);
    #[cfg(not(windows))]
    #[allow(unused_mut)] // only the Windows branch below reassigns it
    let mut b = b.mtu(info.mtu);
    #[cfg(windows)]
    if let Some(dll) = wintun_dll {
        b = b.wintun_file(dll.to_string());
    }
    #[cfg(not(windows))]
    let _ = wintun_dll;
    b.build_async().map_err(|e| anyhow!("cannot create the TUN device: {e} (administrator/root rights and wintun.dll are required on Windows)"))
}

/// Android has no interface creation of its own: the VpnService hands over the descriptor (see ffi.rs).
#[cfg(target_os = "android")]
pub fn create_tun(_name: &str, _info: &JoinInfo, _wintun_dll: Option<&str>) -> Result<tun_rs::AsyncDevice> {
    Err(anyhow!("on Android the TUN descriptor comes from the VpnService"))
}

/// The distinct networks of the routes, sorted ("192.168.16.0/24").
fn route_nets(routes: &[Route]) -> Vec<String> {
    let mut nets: Vec<(std::net::Ipv4Addr, u8)> = routes.iter().map(|r| (r.net, r.prefix)).collect();
    nets.sort();
    nets.dedup();
    nets.into_iter().map(|(n, p)| format!("{n}/{p}")).collect()
}

/// One line per routed network: the preferred gateway (lowest priority number among the members we know) and the others as backups.
fn route_infos(routes: &[Route], members: &[crate::control::Member]) -> Vec<RouteInfo> {
    let mut nets: Vec<(std::net::Ipv4Addr, u8)> = routes.iter().map(|r| (r.net, r.prefix)).collect();
    nets.sort();
    nets.dedup();
    let mut out = Vec::new();
    for (net, prefix) in nets {
        let mut gws: Vec<&Route> = routes.iter().filter(|r| r.net == net && r.prefix == prefix).collect();
        gws.sort_by_key(|r| (r.prio, r.via));
        let known: Vec<&crate::control::Member> = gws.iter().filter_map(|r| members.iter().find(|m| m.id == r.via)).collect();
        if let Some(first) = known.first() {
            out.push(RouteInfo {
                net: format!("{net}/{prefix}"),
                via: first.ip.to_string(),
                gateway: first.name.clone(),
                backups: known.iter().skip(1).map(|m| if m.name.is_empty() { m.ip.to_string() } else { m.name.clone() }).collect(),
            });
        }
    }
    out
}

/// Name of the TUN interface, for the operating-system routes (Android: the VpnService owns the routes, no name needed).
#[cfg(not(target_os = "android"))]
fn tun_name(tun: &tun_rs::AsyncDevice) -> String {
    tun.name().unwrap_or_else(|_| "oneq".into())
}

#[cfg(target_os = "android")]
fn tun_name(_tun: &tun_rs::AsyncDevice) -> String {
    "oneq".into()
}

/// Run until `stop` is notified. `tun` is any TUN device (desktop: [`create_tun`]; Android: from the VpnService fd).
pub async fn run(p: Prepared, tun: Arc<tun_rs::AsyncDevice>, status: Arc<Status>, stop: Arc<Notify>) -> Result<()> {
    let (to_dev_tx, mut to_dev_rx) = mpsc::channel::<Vec<u8>>(512);
    let (from_dev_tx, from_dev_rx) = mpsc::channel::<Vec<u8>>(512);
    // device -> engine
    let (t, st) = (tun.clone(), status.clone());
    let own = p.info.ip.octets();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match t.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    // macOS has no local route for the address of a utun interface: what the host sends to itself reaches the device and goes nowhere. Hand it back.
                    if cfg!(target_os = "macos") && n >= 20 && buf[0] >> 4 == 4 && buf[16..20] == own {
                        let _ = t.send(&buf[..n]).await;
                        continue;
                    }
                    if from_dev_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    st.set_state("error", &format!("TUN read failed: {e}"));
                    break;
                }
            }
        }
    });
    // engine -> device
    let t = tun.clone();
    let writer = tokio::spawn(async move {
        while let Some(pkt) = to_dev_rx.recv().await {
            if let Err(e) = t.send(&pkt).await {
                tracing::debug!("tun write: {e}");
            }
        }
    });
    // networks routed through a gateway member (accept_routes): the operating system sends them to the TUN device
    let keeper = p.cfg.accept_routes.then(|| {
        let k = crate::routes_os::Keeper::new();
        let ifname = tun_name(&tun);
        (k.clone(), ifname.clone(), tokio::spawn(k.follow(ifname, status.clone())))
    });
    let r = run_port(p, from_dev_rx, to_dev_tx, status, stop).await;
    reader.abort();
    writer.abort();
    if let Some((k, ifname, task)) = keeper {
        task.abort();
        let _ = tokio::task::spawn_blocking(move || k.clear(&ifname)).await;
    }
    r
}

/// The same node without any operating-system device: `from_stack` delivers the IP packets the local side sends into the mesh, `to_stack`
/// takes the IP packets that arrive from it (a userspace TCP/IP stack sits on the other end: see netstack.rs, `oneqclient proxy`).
pub async fn run_port(p: Prepared, mut from_stack: mpsc::Receiver<Vec<u8>>, to_stack: mpsc::Sender<Vec<u8>>, status: Arc<Status>, stop: Arc<Notify>) -> Result<()> {
    let Prepared { info, identity, control, cfg } = p;
    let listen = if cfg.listen.is_empty() { "0.0.0.0:0" } else { cfg.listen.as_str() };
    let (udp, dual) = bind_udp(listen, !cfg.no_ipv6).await.with_context(|| format!("bind UDP {listen}"))?;
    let udp = Arc::new(udp);
    status.note(format!("udp {}{}", udp.local_addr()?, if dual { " (IPv4 and IPv6)" } else { "" }));

    let (ev_tx, ev_rx) = mpsc::channel::<Event>(512);
    let (relay_tx, relay_rx) = mpsc::channel::<Vec<u8>>(512);
    let tun_tx = to_stack;
    let relay_connected = Arc::new(AtomicBool::new(false));
    let refresh = Arc::new(AtomicBool::new(true));
    let all_connected = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Notify::new());
    ready.notify_one(); // prepare() already joined

    let nat_state = Arc::new(std::sync::Mutex::new(NatInfo::default()));
    let register_now = Arc::new(AtomicBool::new(false));
    let mut pr0 = Prober::new(udp.clone());
    pr0.dual = dual;
    let prober = Arc::new(pr0);
    let v6_flag = Arc::new(AtomicBool::new(false));
    let v6_ep: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let maps = (!cfg.no_port_mapping).then(|| Arc::new(Mutex::new(MapState { mapper: PortMapper::default(), mapping: None })));
    let clock = control.lock().await.clock.clone();
    let io = Io {
        udp: udp.clone(),
        relay_tx,
        tun_tx,
        relay_connected: relay_connected.clone(),
        refresh_members: refresh.clone(),
        all_connected: all_connected.clone(),
        nat: nat_state.clone(),
        dual,
        v6: v6_flag.clone(),
        clock,
        rly: Arc::new(std::sync::Mutex::new(Default::default())),
    };
    let rly_shared = io.rly.clone();
    let ecfg = EngineCfg {
        force_relay: cfg.force_relay,
        use_relay: !cfg.no_relay,
        relay_after: Duration::from_secs_f64(if cfg.relay_after_s > 0.0 { cfg.relay_after_s } else { 10.0 }),
        local_candidates: cfg.advertise.clone(),
        relay_offer: cfg.relay_offer,
        use_delegates: !cfg.no_delegates,
        ..Default::default()
    };
    let engine = Engine::new(identity.clone(), ecfg, io, status.clone(), &info);
    let mut tasks = vec![tokio::spawn(engine_task(engine, ev_rx))];

    // UDP -> engine
    let ev = ev_tx.clone();
    let u = udp.clone();
    let pr = prober.clone();
    tasks.push(tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut answers = (0u32, Instant::now());
        loop {
            match u.recv_from(&mut buf).await {
                Ok((n, a)) => {
                    let a = std::net::SocketAddr::new(a.ip().to_canonical(), a.port()); // ::ffff:a.b.c.d is the IPv4 peer a.b.c.d
                    if nat::is_stun(&buf[..n]) {
                        answer_stun(&u, &pr, &buf[..n], a, &mut answers, dual);
                        continue;
                    }
                    if ev.send(Event::Udp(buf[..n].to_vec(), a)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    // ICMP errors for unreachable candidates show up here on some systems: harmless
                    tracing::debug!("udp recv: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }));
    // local side -> engine (the engine's mesh view: IP packets in, IP packets out through `to_stack`)
    let ev = ev_tx.clone();
    tasks.push(tokio::spawn(async move {
        while let Some(pkt) = from_stack.recv().await {
            if ev.send(Event::Tun(pkt)).await.is_err() {
                break;
            }
        }
    }));
    // relay link
    if !cfg.no_relay {
        let ctx = crate::relay::RelayCtx {
            control: control.clone(),
            node_id: identity.node_id(),
            events: ev_tx.clone(),
            outgoing: relay_rx,
            connected: relay_connected.clone(),
            ready: ready.clone(),
            status: status.clone(),
            stop: stop.clone(),
        };
        tasks.push(tokio::spawn(crate::relay::run(ctx)));
    }
    // registry loop
    tasks.push(tokio::spawn(registry_loop(
        control.clone(),
        identity.clone(),
        cfg.clone(),
        info.clone(),
        ev_tx.clone(),
        refresh,
        all_connected,
        status.clone(),
        nat_state.clone(),
        register_now.clone(),
        rly_shared,
        v6_ep.clone(),
    )));
    tasks.push(tokio::spawn(nat_task(
        control.clone(),
        prober.clone(),
        udp.clone(),
        nat_state.clone(),
        status.clone(),
        register_now.clone(),
        info.stun.map(|(a, b)| (a, b, info.stun_change)),
        cfg.advertise.clone(),
        identity.node_id(),
        maps.clone(),
        v6_ep.clone(),
        dual.then(|| v6_flag.clone()),
    )));

    status.set_state("connected", "");
    stop.notified().await;
    status.set_state("stopped", "");
    let _ = ev_tx.send(Event::Stop).await;
    for t in tasks {
        t.abort();
    }
    if let Some(m) = maps {
        // release the router mapping (best effort, quick)
        let mut g = m.lock().await;
        if let Some(x) = g.mapping.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), g.mapper.unmap(&x)).await;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn registry_loop(
    control: Arc<Mutex<Control>>,
    id: Arc<Identity>,
    cfg: Config,
    info: JoinInfo,
    events: mpsc::Sender<Event>,
    refresh: Arc<AtomicBool>,
    all_connected: Arc<AtomicBool>,
    status: Arc<Status>,
    nat_state: Arc<std::sync::Mutex<NatInfo>>,
    register_now: Arc<AtomicBool>,
    rly: Arc<std::sync::Mutex<crate::engine::RlyShared>>,
    v6_ep: Arc<std::sync::Mutex<Option<String>>>,
) {
    let mut last_register = Instant::now();
    let mut last_members: Option<Instant> = None;
    let mut last_attached: Vec<[u8; 16]> = vec![];
    let mut routes_noted = false;
    loop {
        let attached = rly.lock().unwrap().attached.clone();
        if last_register.elapsed() >= Duration::from_secs(20) || register_now.swap(false, Ordering::Relaxed) || attached != last_attached {
            last_attached = attached.clone();
            let (eps, nat) = {
                let n = nat_state.lock().unwrap();
                let mut eps = endpoints_for(&cfg.advertise, &n);
                if let Some(v6) = v6_ep.lock().unwrap().clone() {
                    if !eps.contains(&v6) {
                        eps.push(v6);
                        eps.truncate(8);
                    }
                }
                (eps, n.description())
            };
            let res = control.lock().await.join(&id.node_id(), &id.pub_bytes, &eps, &cfg.name, nat.as_ref(), cfg.relay_offer, &attached).await;
            match res {
                Ok(i) => {
                    last_register = Instant::now();
                    if i != info {
                        status.note(format!("the registry now assigns {}/{} (was {}): reconnect to use it", i.ip, i.prefix, info.ip));
                    }
                }
                Err(e) => {
                    tracing::warn!("registry: {e:#}");
                    status.update(|s| s.message = format!("registry: {e:#}"));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        let every = Duration::from_secs(if all_connected.load(Ordering::Relaxed) { 5 } else { 3 });
        if refresh.swap(false, Ordering::Relaxed) || last_members.map_or(true, |t| t.elapsed() >= every) {
            // bind the result first: a guard living in the `match` scrutinee would still be held when the arm locks again
            let res = control.lock().await.nodes((info.ip, info.prefix)).await;
            match res {
                Ok((m, routes)) => {
                    last_members = Some(Instant::now());
                    let relay = control.lock().await.base().to_string();
                    status.update(|s| {
                        s.relay_url = relay;
                        if s.message.starts_with("registry:") {
                            s.message.clear();
                        }
                    });
                    // networks behind a gateway member: used only when the user asked for it (accept_routes)
                    let accepted: Vec<Route> = if cfg.accept_routes { routes.clone() } else { Vec::new() };
                    let shown = route_infos(&accepted, &m);
                    let nets = route_nets(&accepted);
                    status.update(|s| {
                        s.routes = shown;
                        s.route_nets = nets;
                    });
                    if !cfg.accept_routes && !routes.is_empty() && !routes_noted {
                        routes_noted = true;
                        status.note(format!("the community announces {} route(s) ({}): not used, accept_routes is off", routes.len(), routes.iter().map(|r| r.cidr()).collect::<Vec<_>>().join(", ")));
                    }
                    if events.send(Event::Routes(accepted)).await.is_err() {
                        return;
                    }
                    if events.send(Event::Members(m)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!("registry: {e:#}");
                    status.update(|s| s.message = format!("registry: {e:#}"));
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Addresses published to the registry: the ones given by hand plus our public UDP address when the NAT allows others to use it.
fn endpoints_for(advertise: &[String], nat: &NatInfo) -> Vec<String> {
    let mut v: Vec<String> = advertise.to_vec();
    if let Some(p) = nat.public_endpoint() {
        // measured against a relay on this very machine (or on loopback) the "public" address is 127.x: useless to everybody else
        let usable = p.parse::<std::net::SocketAddr>().map_or(true, |a| !a.ip().is_loopback() && !a.ip().is_unspecified());
        if usable && !v.contains(&p) {
            v.push(p);
        }
    }
    v.truncate(8);
    v
}

/// STUN on the node's own socket: answers of the relay go to the prober, Binding requests (the relay's reachability test,
/// other nodes' connectivity checks) get the address we see them from, at most 20 per second.
fn answer_stun(udp: &UdpSocket, prober: &Prober, data: &[u8], from: std::net::SocketAddr, answers: &mut (u32, Instant), dual: bool) {
    let Some(m) = nat::parse(data) else { return };
    if m.mtype == nat::BINDING_SUCCESS {
        prober.feed(data, from);
    } else if m.mtype == nat::BINDING_REQUEST {
        if answers.1.elapsed() > Duration::from_secs(1) {
            *answers = (0, Instant::now());
        }
        if answers.0 < 20 {
            answers.0 += 1;
            let _ = udp.try_send_to(&nat::binding_response(&m.txid, from), nat::wire_addr(from, dual));
        }
    }
}

/// One UDP socket for IPv4 and IPv6 (IPV6_V6ONLY off) when `listen` is an unspecified IPv4 address and this host has IPv6; otherwise a
/// plain socket. -> (socket, dual-stack?)
async fn bind_udp(listen: &str, ipv6: bool) -> Result<(UdpSocket, bool)> {
    if ipv6 {
        if let Ok(a) = listen.parse::<std::net::SocketAddr>() {
            if a.ip().is_unspecified() && a.is_ipv4() {
                let dual = (|| -> std::io::Result<UdpSocket> {
                    let s = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
                    s.set_only_v6(false)?;
                    s.bind(&socket2::SockAddr::from(std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), a.port())))?;
                    s.set_nonblocking(true)?;
                    UdpSocket::from_std(s.into())
                })();
                match dual {
                    Ok(u) => return Ok((u, true)),
                    Err(e) => tracing::info!("no dual-stack UDP socket ({e}): IPv4 only"),
                }
            }
        }
    }
    Ok((UdpSocket::bind(listen).await?, false))
}

fn url_host(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next().unwrap_or(rest);
    match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h.trim_matches(|c| c == '[' || c == ']').to_string(),
        _ => hostport.to_string(),
    }
}

/// What the registry gets to see: the measured NAT, or "open" when a router mapping was verified from outside (the relay probed its
/// external address from a port we never contacted); flags for a second NAT and for a predictable symmetric NAT.
fn effective_nat(raw: &NatInfo, cgnat: bool, mapping: Option<&Mapping>, verified: bool, inbound: Option<bool>) -> NatInfo {
    let mut n = raw.clone();
    n.cgnat = cgnat;
    n.inbound = inbound;
    if let (Some(m), true, false) = (mapping, verified, cgnat) {
        if let Some(ip) = m.ext_ip {
            n.kind = "open".into();
            n.via = Some(m.method.to_string());
            n.mapped = Some(std::net::SocketAddr::new(ip, m.ext_port));
            n.delta = None;
        }
    }
    n
}

/// A global unicast IPv6 address: 2000::/3, not the documentation prefix 2001:db8::/32.
fn is_global_v6(ip: std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
}

/// The global IPv6 address this host would use towards the internet (the OS picks it; nothing is sent), as "[addr]:port".
fn local_v6_endpoint(port: u16) -> Option<String> {
    let s = std::net::UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:4860:4860::8888]:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(v6) if is_global_v6(v6) => Some(std::net::SocketAddr::new(std::net::IpAddr::V6(v6), port).to_string()),
        _ => None,
    }
}

/// The router mapping a node holds, with the means to renew and release it.
pub struct MapState {
    pub mapper: PortMapper,
    pub mapping: Option<Mapping>,
}

/// Measure the NAT with the relay's STUN service, keep it measured (a changed mapping is noticed and measured again), ask the router
/// for a port mapping (PCP, NAT-PMP, UPnP) unless a second NAT makes it useless, publish the result through the registry loop and ask
/// the relay to probe our public address (and the mapped one) from a port we never contacted.
#[allow(clippy::too_many_arguments)]
async fn nat_task(
    control: Arc<Mutex<Control>>,
    prober: Arc<Prober>,
    udp: Arc<UdpSocket>,
    state: Arc<std::sync::Mutex<NatInfo>>,
    status: Arc<Status>,
    register_now: Arc<AtomicBool>,
    ports: Option<(u16, u16, Option<u16>)>,
    advertise: Vec<String>,
    id: [u8; 16],
    maps: Option<Arc<Mutex<MapState>>>,
    v6_ep: Arc<std::sync::Mutex<Option<String>>>,
    v6_flag: Option<Arc<AtomicBool>>,
) {
    let Some((port, alt, change)) = ports else {
        status.note("the relay has no STUN service: NAT type unknown, only the relay path and listed addresses are used");
        return;
    };
    let mut last_full: Option<Instant> = None;
    let (mut raw, mut cgnat, mut verified, mut inbound) = (NatInfo::default(), false, false, None::<bool>);
    loop {
        let host = url_host(control.lock().await.base());
        let ip = tokio::net::lookup_host((host.as_str(), port)).await.ok().and_then(|mut it| it.find(|a| a.is_ipv4())).map(|a| a.ip());
        let Some(ip) = ip else {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };
        let (main, altaddr) = (std::net::SocketAddr::new(ip, port), std::net::SocketAddr::new(ip, alt));
        let third = change.map(|c| std::net::SocketAddr::new(ip, c));
        let full = last_full.map_or(true, |t| t.elapsed() >= Duration::from_secs(300)) || raw.mapped.is_none();
        if full {
            let local_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
            let local = nat::guess_local_ip(ip).map(|i| std::net::SocketAddr::new(i, local_port));
            let old = state.lock().unwrap().clone();
            raw = nat::classify(&*prober, main, altaddr, local, third).await;
            last_full = Some(Instant::now());
            if let Some(flag) = &v6_flag {
                let ep = local_v6_endpoint(local_port);
                if *v6_ep.lock().unwrap() != ep {
                    status.note(format!("IPv6 candidate: {}", ep.as_deref().unwrap_or("none")));
                    register_now.store(true, Ordering::Relaxed);
                }
                flag.store(ep.is_some(), Ordering::Relaxed);
                *v6_ep.lock().unwrap() = ep;
            }
            let publish = |n: &NatInfo| {
                *state.lock().unwrap() = n.clone();
                status.update(|s| {
                    s.nat_type = n.kind.clone();
                    s.nat_public = n.mapped.map(|m| m.to_string()).unwrap_or_default();
                });
            };
            // publish what was measured now; the router probing below takes seconds
            let held = match &maps {
                Some(m) => m.lock().await.mapping.clone(),
                None => None,
            };
            publish(&effective_nat(&raw, cgnat, held.as_ref(), verified, inbound));
            // the router: a mapping for our port, and its WAN address, which is how a second NAT is recognised
            if let (Some(m), Some(mapped)) = (&maps, raw.mapped) {
                if raw.kind != "open" && raw.kind != "blocked" {
                    let mut g = m.lock().await;
                    if g.mapping.is_none() {
                        g.mapping = g.mapper.map(local_port, None, 3600).await;
                    }
                    let router_wan = match g.mapping.as_ref().and_then(|x| x.ext_ip) {
                        Some(ip) => Some(ip),
                        None => g.mapper.router_external_ip().await,
                    };
                    cgnat = nat::double_nat(Some(mapped.ip()), router_wan);
                    if cgnat {
                        if let Some(x) = g.mapping.take() {
                            status.note(format!("second NAT in front of the router (router WAN address {}, seen by the relay {}): the router mapping is useless, released", router_wan.map(|a| a.to_string()).unwrap_or_default(), mapped.ip()));
                            g.mapper.unmap(&x).await;
                        }
                    }
                } else {
                    cgnat = nat::double_nat(Some(mapped.ip()), None);
                }
            } else {
                cgnat = raw.mapped.map_or(false, |m| nat::double_nat(Some(m.ip()), None));
            }
            verified = false;
            let held = match &maps {
                Some(m) => m.lock().await.mapping.clone(),
                None => None,
            };
            publish(&effective_nat(&raw, cgnat, held.as_ref(), verified, inbound));
            // inbound reachability of our public address, of the router mapping and of anything given with --advertise
            let public = raw.public_endpoint();
            let mapped_ep = held.as_ref().filter(|m| m.ext_ip.map_or(false, |i| i.is_ipv4())).and_then(|m| m.endpoint());
            let mut targets = advertise.clone();
            for extra in public.iter().chain(mapped_ep.iter()) {
                if !targets.contains(extra) {
                    targets.push(extra.clone());
                }
            }
            let mut new_inbound = None;
            for t in targets {
                let r = control.lock().await.nat_test(&id, &t).await;
                if public.as_deref() == Some(t.as_str()) {
                    new_inbound = r;
                } else if mapped_ep.as_deref() == Some(t.as_str()) {
                    verified = r == Some(true);
                    status.note(format!(
                        "router mapping {t} ({}): {}",
                        held.as_ref().map_or("?", |m| m.method),
                        if verified { "reachable from outside, published as an open address" } else { "not reachable from outside (the router's address is not public?)" }
                    ));
                } else if r == Some(false) && advertise.contains(&t) {
                    status.note(format!("advertised address {t} did not answer the relay's probe: wrong address, or a forward or firewall rule is missing"));
                }
            }
            if new_inbound != inbound {
                inbound = new_inbound;
                status.update(|s| s.nat_inbound = inbound);
                if let Some(v) = inbound {
                    status.note(format!(
                        "inbound UDP to {}: {}",
                        public.clone().unwrap_or_default(),
                        if v { "reachable from a port of the relay we never used" } else { "needs a punched hole (normal behind a restricted NAT)" }
                    ));
                }
            }
            let now_pub = effective_nat(&raw, cgnat, held.as_ref(), verified, inbound);
            publish(&now_pub);
            if (&old.kind, old.mapped, old.cgnat, old.delta, &old.via, old.inbound) != (&now_pub.kind, now_pub.mapped, now_pub.cgnat, now_pub.delta, &now_pub.via, now_pub.inbound) {
                status.note(format!(
                    "NAT: {}{}{}{}{}",
                    now_pub.kind,
                    now_pub.mapped.map(|m| format!(", public UDP address {m}")).unwrap_or_default(),
                    now_pub.delta.map(|d| format!(", ports allocated in steps of {d} (predictable)")).unwrap_or_default(),
                    now_pub.via.as_ref().map(|v| format!(", forwarded by the router ({v})")).unwrap_or_default(),
                    if now_pub.cgnat { ", a second NAT in front of the router (carrier-grade): direct UDP is not attempted" } else { "" }
                ));
                register_now.store(true, Ordering::Relaxed);
            }
        } else {
            let m = prober.transact(main, 0).await;
            // a predictable symmetric NAT published its newest mapping, not the one towards the main port: only the address must still match
            let same = match (m, raw.mapped) {
                (Some(a), Some(b)) => if raw.delta.is_some() { a.ip() == b.ip() } else { a == b },
                _ => false,
            };
            if !same {
                last_full = None; // the mapping changed or was lost: measure again
                continue;
            }
            if let Some(ms) = &maps {
                let mut g = ms.lock().await;
                let due = g.mapping.as_ref().map_or(false, |m| Instant::now() >= m.renew_at());
                if due {
                    let old = g.mapping.clone().unwrap();
                    match g.mapper.renew(&old).await {
                        Some(n) => {
                            if n.endpoint() != old.endpoint() {
                                verified = false;
                                last_full = None;
                            }
                            g.mapping = Some(n);
                        }
                        None => {
                            status.note(format!("port mapping ({}) could not be renewed", old.method));
                            g.mapping = None;
                            verified = false;
                            last_full = None;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(25)).await;
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[tokio::test]
    async fn a_dual_stack_socket_talks_to_ipv4_peers_with_plain_addresses() {
        let (sock, dual) = bind_udp("0.0.0.0:0", true).await.unwrap();
        if !dual {
            eprintln!("no IPv6 on this host: dual-stack not testable here");
            return;
        }
        let port = sock.local_addr().unwrap().port();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"hi", ("127.0.0.1", port)).await.unwrap();
        let mut b = [0u8; 16];
        let (n, from) = sock.recv_from(&mut b).await.unwrap();
        assert!(from.ip().is_ipv6(), "a dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d");
        let from = std::net::SocketAddr::new(from.ip().to_canonical(), from.port());
        assert_eq!((&b[..n], from), (&b"hi"[..], peer.local_addr().unwrap()));
        sock.send_to(b"yo", nat::wire_addr(from, true)).await.unwrap();
        let (n, back) = peer.recv_from(&mut b).await.unwrap();
        assert_eq!((&b[..n], back.port()), (&b"yo"[..], port));
        // IPv6 peers are addressed as they are, and IPv4-only sockets never get mapped addresses
        assert_eq!(nat::wire_addr("[2001:db8::1]:5".parse().unwrap(), true), "[2001:db8::1]:5".parse().unwrap());
        assert_eq!(nat::wire_addr("1.2.3.4:5".parse().unwrap(), false), "1.2.3.4:5".parse().unwrap());
        // an explicit bind address or --no-ipv6 keeps plain IPv4
        assert!(!bind_udp("127.0.0.1:0", true).await.unwrap().1);
        assert!(!bind_udp("0.0.0.0:0", false).await.unwrap().1);
    }

    #[test]
    fn global_ipv6_addresses_only() {
        for (a, want) in [("2a02:2f0e::1", true), ("2001:db8::1", false), ("fe80::1", false), ("fd00::1", false), ("::1", false), ("::", false)] {
            assert_eq!(is_global_v6(a.parse().unwrap()), want, "{a}");
        }
    }

    #[test]
    fn effective_nat_is_open_only_for_a_verified_mapping_without_a_second_nat() {
        let raw = NatInfo { kind: "port-restricted".into(), mapped: Some("203.0.113.5:40000".parse().unwrap()), ..Default::default() };
        let m = Mapping { method: "upnp", ext_ip: Some("203.0.113.5".parse().unwrap()), ext_port: 51820, internal_port: 51820, lifetime: 3600, gateway: "192.168.1.1".parse().unwrap(), created: Instant::now(), igd: None };
        assert_eq!(effective_nat(&raw, false, Some(&m), false, None).kind, "port-restricted", "an unverified mapping is not claimed");
        assert_eq!(effective_nat(&raw, true, Some(&m), true, None).kind, "port-restricted", "a second NAT: the mapping is useless");
        let n = effective_nat(&raw, false, Some(&m), true, Some(true));
        assert_eq!((n.kind.as_str(), n.via.as_deref(), n.mapped), ("open", Some("upnp"), Some("203.0.113.5:51820".parse().unwrap())));
        assert_eq!(n.description().unwrap()["via"], "upnp");
        let c = effective_nat(&raw, true, None, false, None);
        assert!(c.cgnat && c.description().unwrap()["cgnat"] == true);
    }

    #[test]
    fn a_loopback_public_address_is_not_published_but_hand_given_ones_and_real_ones_are() {
        let mut n = NatInfo::default();
        n.kind = "open".into();
        n.mapped = Some("127.0.0.1:5000".parse().unwrap());
        assert!(endpoints_for(&[], &n).is_empty());
        assert_eq!(endpoints_for(&["10.1.0.3:51820".into()], &n), vec!["10.1.0.3:51820".to_string()]);
        n.mapped = Some("203.0.113.9:6000".parse().unwrap());
        assert_eq!(endpoints_for(&["10.1.0.3:51820".into()], &n), vec!["10.1.0.3:51820".to_string(), "203.0.113.9:6000".to_string()]);
    }
}
