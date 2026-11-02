//! SOCKS5 (RFC 1928, no authentication, CONNECT only) in front of the userspace stack: a browser or any program that speaks SOCKS5 reaches the
//! mesh addresses through `oneqclient proxy` without a TUN device. Only destinations inside the mesh subnet are served; a host name must be the
//! name of a member (`alice-laptop` or `alice-laptop.oneq`), there is no other DNS. The listener is meant for 127.0.0.1.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::netstack::{ConnectError, Netstack};

pub type Resolver = Arc<dyn Fn(&str) -> Option<Ipv4Addr> + Send + Sync>;

#[derive(Clone)]
pub struct Subnet {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix.min(32)) };
        (u32::from(a) & mask) == (u32::from(self.ip) & mask)
    }
}

pub async fn serve(listener: TcpListener, stack: Netstack, subnet: Subnet, resolve: Resolver, gate: crate::peer::Gate) -> Result<()> {
    loop {
        let (s, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue; // only this machine
        }
        let (stack, subnet, resolve, gate) = (stack.clone(), subnet.clone(), resolve.clone(), gate.clone());
        tokio::spawn(async move {
            // the owner of the connection is looked up per connection, off the accept loop; a program that is not a browser gets a closed socket
            let Ok(local) = s.local_addr() else { return };
            if !gate.admits(peer, local).await {
                return;
            }
            let _ = handle(s, stack, subnet, resolve).await;
        });
    }
}

async fn reply(s: &mut TcpStream, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn handle(mut s: TcpStream, stack: Netstack, subnet: Subnet, resolve: Resolver) -> Result<()> {
    let hs = async {
        // greeting: VER NMETHODS METHODS...
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await?;
        if h[0] != 5 {
            anyhow::bail!("not SOCKS5");
        }
        let mut methods = vec![0u8; h[1] as usize];
        s.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            s.write_all(&[5, 0xff]).await?;
            anyhow::bail!("no acceptable method");
        }
        s.write_all(&[5, 0]).await?;
        // request: VER CMD RSV ATYP ADDR PORT
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await?;
        if r[0] != 5 {
            anyhow::bail!("bad request");
        }
        let dst = match r[3] {
            1 => {
                let mut a = [0u8; 4];
                s.read_exact(&mut a).await?;
                Some(Ipv4Addr::from(a))
            }
            3 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                let mut n = vec![0u8; l[0] as usize];
                s.read_exact(&mut n).await?;
                let name = String::from_utf8_lossy(&n).to_ascii_lowercase();
                let name = name.strip_suffix(".oneq").unwrap_or(&name).to_string();
                match name.parse::<Ipv4Addr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => resolve(&name),
                }
            }
            4 => {
                let mut a = [0u8; 16];
                s.read_exact(&mut a).await?;
                reply(&mut s, 8).await?; // address type not supported
                anyhow::bail!("ipv6");
            }
            _ => {
                reply(&mut s, 8).await?;
                anyhow::bail!("bad address type");
            }
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await?;
        let port = u16::from_be_bytes(p);
        if r[1] != 1 {
            reply(&mut s, 7).await?; // command not supported
            anyhow::bail!("only CONNECT");
        }
        let Some(dst) = dst else {
            reply(&mut s, 4).await?; // host unreachable: unknown name
            anyhow::bail!("unknown name");
        };
        if !subnet.contains(dst) {
            reply(&mut s, 2).await?; // not allowed: outside the mesh
            anyhow::bail!("outside the mesh");
        }
        anyhow::Ok(SocketAddrV4::new(dst, port))
    };
    let dst = tokio::time::timeout(Duration::from_secs(15), hs).await??;
    let conn = match stack.connect(dst).await {
        Ok(c) => c,
        Err(e) => {
            reply(&mut s, match e {
                ConnectError::Refused => 5,
                ConnectError::Timeout => 4,
                ConnectError::Unreachable => 3,
            })
            .await?;
            return Ok(());
        }
    };
    reply(&mut s, 0).await?;
    let (mut rd, mut wr) = s.into_split();
    let (mut rx, tx) = (conn.rx, conn.tx);
    let up = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
        // dropping tx closes our side of the mesh connection
    };
    let down = async move {
        while let Some(d) = rx.recv().await {
            if wr.write_all(&d).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    async fn socks_connect(proxy: SocketAddr, atyp_name: Option<&str>, ip: Ipv4Addr, port: u16) -> (TcpStream, u8) {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        let mut req = vec![5, 1, 0];
        match atyp_name {
            Some(n) => {
                req.push(3);
                req.push(n.len() as u8);
                req.extend_from_slice(n.as_bytes());
            }
            None => {
                req.push(1);
                req.extend_from_slice(&ip.octets());
            }
        }
        req.extend_from_slice(&port.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        (c, rep[1])
    }

    #[tokio::test]
    async fn socks5_connects_to_a_mesh_service_by_address_and_by_member_name_and_refuses_the_rest() {
        let (a_out_tx, mut a_out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (b_out_tx, mut b_out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(256);
        tokio::spawn(async move {
            while let Some(p) = a_out_rx.recv().await {
                let _ = b_in_tx.send(p).await;
            }
        });
        tokio::spawn(async move {
            while let Some(p) = b_out_rx.recv().await {
                let _ = a_in_tx.send(p).await;
            }
        });
        let a = Netstack::start(Ipv4Addr::new(10, 7, 0, 1), 24, 1380, a_in_rx, a_out_tx);
        let b = Netstack::start(Ipv4Addr::new(10, 7, 0, 2), 24, 1380, b_in_rx, b_out_tx);
        let mut accepted = b.listen(80).await;
        tokio::spawn(async move {
            while let Some(mut c) = accepted.recv().await {
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    while !req.ends_with(b"\r\n\r\n") {
                        match c.rx.recv().await {
                            Some(d) => req.extend(d),
                            None => return,
                        }
                    }
                    let _ = c.tx.send(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
                });
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let resolve: Resolver = Arc::new(|n: &str| (n == "web").then_some(Ipv4Addr::new(10, 7, 0, 2)));
        tokio::spawn(serve(l, a, Subnet { ip: Ipv4Addr::new(10, 7, 0, 0), prefix: 24 }, resolve, crate::peer::Gate::any()));

        for name in [None, Some("web"), Some("WEB.oneq")] {
            let (mut c, code) = socks_connect(addr, name, Ipv4Addr::new(10, 7, 0, 2), 80).await;
            assert_eq!(code, 0, "{name:?}");
            c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            let mut out = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await.expect("response in time").unwrap();
            assert!(out.ends_with(b"ok"), "{name:?}: {}", String::from_utf8_lossy(&out));
        }
        assert_eq!(socks_connect(addr, None, Ipv4Addr::new(10, 7, 0, 2), 9).await.1, 5, "refused by the peer");
        assert_eq!(socks_connect(addr, None, Ipv4Addr::new(8, 8, 8, 8), 80).await.1, 2, "outside the mesh");
        assert_eq!(socks_connect(addr, Some("nobody"), Ipv4Addr::UNSPECIFIED, 80).await.1, 4, "unknown member name");
    }

    #[test]
    fn subnet_membership() {
        let s = Subnet { ip: Ipv4Addr::new(10, 78, 0, 0), prefix: 24 };
        assert!(s.contains(Ipv4Addr::new(10, 78, 0, 5)));
        assert!(!s.contains(Ipv4Addr::new(10, 78, 1, 5)));
        assert!(Subnet { ip: Ipv4Addr::new(10, 0, 0, 0), prefix: 8 }.contains(Ipv4Addr::new(10, 255, 1, 1)));
    }
}
