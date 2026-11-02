//! `oneqclient proxy`: the node without a TUN device. It joins the mesh like `oneqclient up`, runs a userspace TCP/IP stack on the mesh address
//! (netstack.rs) and offers a SOCKS5 proxy on 127.0.0.1 (socks.rs) plus a tiny read-only status page for the browser extension
//! (GET /status). No administrator rights, no driver; only programs that use the proxy reach the mesh.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};

use crate::netstack::Netstack;
use crate::socks::{self, Resolver, Subnet};
use crate::status::Status;
use crate::{Config, Prepared};

pub struct ProxyOpts {
    pub socks: SocketAddr,
    pub status: Option<SocketAddr>,
    /// Who may use the SOCKS5 port and the status page (browsers by default).
    pub gate: crate::peer::Gate,
}

fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Runs until `stop` is notified.
pub async fn run(cfg: Config, opts: ProxyOpts, status: Arc<Status>, stop: Arc<Notify>) -> Result<()> {
    let prepared: Prepared = crate::prepare(cfg, &status).await?;
    let info = prepared.info.clone();
    let (to_mesh_tx, to_mesh_rx) = mpsc::channel::<Vec<u8>>(512); // stack -> mesh
    let (from_mesh_tx, from_mesh_rx) = mpsc::channel::<Vec<u8>>(512); // mesh -> stack
    let stack = Netstack::start(info.ip, info.prefix, info.mtu as usize, from_mesh_rx, to_mesh_tx);
    let socks_listener = TcpListener::bind(opts.socks).await.with_context(|| format!("bind the SOCKS5 proxy on {}", opts.socks))?;
    status.note(format!("SOCKS5 proxy on {} for the mesh {}/{} (this node: {}); served: {}", opts.socks, network_of(info.ip, info.prefix), info.prefix, info.ip, opts.gate.describe()));
    let subnet = Subnet { ip: network_of(info.ip, info.prefix), prefix: info.prefix };
    let st = status.clone();
    let resolve: Resolver = Arc::new(move |name: &str| {
        st.snapshot().peers.iter().find(|p| p.name.eq_ignore_ascii_case(name)).and_then(|p| p.ip.parse().ok())
    });
    let mut tasks = vec![tokio::spawn(socks::serve(socks_listener, stack, subnet.clone(), resolve, opts.gate.clone()).map_err_log("socks"))];
    if let Some(addr) = opts.status {
        let l = TcpListener::bind(addr).await.with_context(|| format!("bind the status page on {addr}"))?;
        tasks.push(tokio::spawn(status_server(l, status.clone(), opts.socks, subnet, opts.gate.clone())));
    }
    let r = crate::run_port(prepared, to_mesh_rx, from_mesh_tx, status, stop, None).await;
    for t in tasks {
        t.abort();
    }
    r
}

trait MapErrLog {
    fn map_err_log(self, what: &'static str) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

impl<F: std::future::Future<Output = Result<()>> + Send + 'static> MapErrLog for F {
    fn map_err_log(self, what: &'static str) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            if let Err(e) = self.await {
                tracing::error!("{what}: {e:#}");
            }
        })
    }
}

/// GET /status -> the node's snapshot plus the proxy's own parameters. Loopback only, Host header checked (no DNS rebinding), no CORS:
/// the extension reads it with its host permission, web pages cannot.
async fn status_server(l: TcpListener, status: Arc<Status>, socks: SocketAddr, subnet: Subnet, gate: crate::peer::Gate) {
    let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
    loop {
        let Ok((mut s, peer)) = l.accept().await else { continue };
        if !peer.ip().is_loopback() {
            continue;
        }
        let (status, subnet, gate) = (status.clone(), subnet.clone(), gate.clone());
        tokio::spawn(async move {
            let Ok(local) = s.local_addr() else { return };
            if !gate.admits(peer, local).await {
                return;
            }
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let first = req.lines().next().unwrap_or("");
            let host_ok = req.lines().any(|l| {
                let l = l.to_ascii_lowercase();
                l == format!("host: 127.0.0.1:{port}") || l == format!("host: localhost:{port}")
            });
            let (code, body) = if !host_ok {
                (403, "forbidden host".to_string())
            } else if first.starts_with("GET /status ") {
                let v = json!({"proxy": {"socks": socks.to_string(), "subnet": format!("{}/{}", subnet.ip, subnet.prefix), "version": env!("CARGO_PKG_VERSION"), "restricted": gate.restricted()},
                               "snapshot": status.snapshot()});
                (200, v.to_string())
            } else {
                (404, "not found".to_string())
            };
            let head = format!("HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(body.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

