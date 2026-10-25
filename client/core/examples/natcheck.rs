//! `natcheck HOST:PORT` - measure the NAT in front of this machine with the STUN service of a oneqrelay, without joining anything
//! (the Rust twin of `oneqnode nat-check`; also built for Android to test a phone on mobile data).
//! Prints the type, the mapped address, the port step of a symmetric NAT and the router's WAN address when it answers NAT-PMP/UPnP.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use oneq_core::nat::{self, Prober, Transact};
use oneq_core::portmap::PortMapper;
use tokio::net::UdpSocket;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arg = std::env::args().nth(1).expect("usage: natcheck HOST:PORT [--no-router]");
    let no_router = std::env::args().any(|a| a == "--no-router");
    let (host, port) = arg.rsplit_once(':').expect("HOST:PORT");
    let port: u16 = port.parse().expect("port");
    let ip: IpAddr = tokio::net::lookup_host((host, port)).await.expect("resolve").find(|a| a.is_ipv4()).expect("an IPv4 address").ip();
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("bind"));
    let local_port = udp.local_addr().unwrap().port();
    let prober = Arc::new(Prober::new(udp.clone()));
    let (p2, u2) = (prober.clone(), udp.clone());
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = u2.recv_from(&mut b).await {
            p2.feed(&b[..n], from);
        }
    });
    let local = nat::guess_local_ip(ip).map(|i| SocketAddr::new(i, local_port));
    let at = |p: u16| SocketAddr::new(ip, p);
    let info = nat::classify(&*prober as &dyn Transact, at(port), at(port + 1), local, Some(at(port + 2))).await;
    let router = if !no_router && info.mapped.is_some() && info.kind != "open" {
        let mut pm = PortMapper::default();
        pm.methods = vec!["natpmp", "upnp"];
        pm.search_time = std::time::Duration::from_millis(1500);
        pm.router_external_ip().await
    } else {
        None
    };
    let second = nat::double_nat(info.mapped.map(|m| m.ip()), router);
    println!("relay      {host} {ip}:{port}");
    println!("local      {}", local.map(|l| l.to_string()).unwrap_or_default());
    println!("type       {}", info.kind);
    println!("mapped     {}", info.mapped.map(|m| m.to_string()).unwrap_or_else(|| "-".into()));
    println!("mapping    {}   filtering {}", info.mapping, info.filtering);
    println!("port step  {}", info.delta.map(|d| d.to_string()).unwrap_or_else(|| "none (not sequential, or not symmetric)".into()));
    println!("router WAN {}", router.map(|r| r.to_string()).unwrap_or_else(|| "-".into()));
    println!("second NAT {}", if second { "yes (carrier-grade range or a different router WAN address)" } else { "not detected" });
    if let Some(m) = info.mapped {
        println!("cgnat range {}", nat::is_cgnat_ip(m.ip()));
    }
}
