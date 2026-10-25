//! A small userspace TCP/IP stack (smoltcp) on top of the mesh's IP packets, so that a program can open TCP connections to mesh addresses (and
//! accept them) without a TUN device, administrator rights or a driver: `oneqclient proxy` serves them to browsers as a SOCKS5 proxy.
//!
//! The stack owns the mesh address of the node. IP packets from the mesh arrive on `from_mesh`, packets to the mesh leave on `to_mesh`
//! (the engine does the rest: ARP-less L3 over the L2 mesh, see l3.rs). Every connection is a pair of channels ([`Conn`]).
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::sync::{mpsc, oneshot};

const BUF: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// One TCP connection: bytes from the peer arrive on `rx` (it ends when the peer closed its side), bytes sent on `tx` go to the peer
/// (dropping `tx` closes our side after everything was sent).
pub struct Conn {
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectError {
    Refused,
    Timeout,
    Unreachable,
}

enum Cmd {
    Connect(SocketAddrV4, oneshot::Sender<Result<Conn, ConnectError>>),
    Listen(u16, mpsc::Sender<Conn>),
}

#[derive(Clone)]
pub struct Netstack {
    cmds: mpsc::Sender<Cmd>,
}

impl Netstack {
    /// Starts the stack task. `ip/prefix` is the node's mesh address; `mtu` the community MTU.
    pub fn start(ip: Ipv4Addr, prefix: u8, mtu: usize, from_mesh: mpsc::Receiver<Vec<u8>>, to_mesh: mpsc::Sender<Vec<u8>>) -> Netstack {
        let (cmds, cmd_rx) = mpsc::channel(64);
        tokio::spawn(stack_task(ip, prefix, mtu, from_mesh, to_mesh, cmd_rx));
        Netstack { cmds }
    }

    pub async fn connect(&self, dst: SocketAddrV4) -> Result<Conn, ConnectError> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::Connect(dst, tx)).await.map_err(|_| ConnectError::Unreachable)?;
        rx.await.unwrap_or(Err(ConnectError::Unreachable))
    }

    /// Accepts connections to `port` of the mesh address.
    pub async fn listen(&self, port: u16) -> mpsc::Receiver<Conn> {
        let (tx, rx) = mpsc::channel(16);
        let _ = self.cmds.send(Cmd::Listen(port, tx)).await;
        rx
    }
}

// ------------------------------------------------------------------------------------------------ smoltcp device
struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> TxToken for Tx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// ------------------------------------------------------------------------------------------------ the task
struct Entry {
    h: SocketHandle,
    /// toward the user (None once the peer closed its side)
    rx_out: Option<mpsc::Sender<Vec<u8>>>,
    /// from the user
    tx_in: mpsc::Receiver<Vec<u8>>,
    tx_done: bool,
    pending: Vec<u8>,
    off: usize,
    /// still connecting: the answer and the halves for the user
    reply: Option<(oneshot::Sender<Result<Conn, ConnectError>>, Conn)>,
    started: Instant,
}

struct Listener {
    port: u16,
    accept: mpsc::Sender<Conn>,
    h: SocketHandle,
}

fn new_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; BUF]), tcp::SocketBuffer::new(vec![0u8; BUF]))
}

fn pair() -> (Conn, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
    let (rx_tx, rx_rx) = mpsc::channel::<Vec<u8>>(32);
    let (tx_tx, tx_rx) = mpsc::channel::<Vec<u8>>(32);
    (Conn { rx: rx_rx, tx: tx_tx }, rx_tx, tx_rx)
}

async fn stack_task(
    ip: Ipv4Addr,
    prefix: u8,
    mtu: usize,
    mut from_mesh: mpsc::Receiver<Vec<u8>>,
    to_mesh: mpsc::Sender<Vec<u8>>,
    mut cmds: mpsc::Receiver<Cmd>,
) {
    let start = Instant::now();
    let now = || SmolInstant::from_millis(start.elapsed().as_millis() as i64);
    let mut dev = Dev { rx: VecDeque::new(), tx: Vec::new(), mtu };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(ip)), prefix));
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut entries: Vec<Entry> = Vec::new();
    let mut listeners: Vec<Listener> = Vec::new();
    let mut next_port: u16 = 49152 + (rand_u16() % 8000);

    loop {
        let busy = !entries.is_empty();
        tokio::select! {
            p = from_mesh.recv() => {
                match p {
                    Some(p) => dev.rx.push_back(p),
                    None => return,
                }
                while let Ok(p) = from_mesh.try_recv() {
                    dev.rx.push_back(p);
                    if dev.rx.len() > 512 {
                        break;
                    }
                }
            }
            c = cmds.recv() => {
                match c {
                    None => return,
                    Some(Cmd::Connect(dst, reply)) => {
                        let mut s = new_socket();
                        next_port = if next_port >= 60999 { 49152 } else { next_port + 1 };
                        let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(*dst.ip())), dst.port());
                        if s.connect(iface.context(), remote, next_port).is_err() {
                            let _ = reply.send(Err(ConnectError::Unreachable));
                        } else {
                            let h = sockets.add(s);
                            let (conn, rx_out, tx_in) = pair();
                            entries.push(Entry { h, rx_out: Some(rx_out), tx_in, tx_done: false, pending: vec![], off: 0, reply: Some((reply, conn)), started: Instant::now() });
                        }
                    }
                    Some(Cmd::Listen(port, accept)) => {
                        let mut s = new_socket();
                        if s.listen(port).is_ok() {
                            let h = sockets.add(s);
                            listeners.push(Listener { port, accept, h });
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(if busy { 2 } else { 40 })) => {}
        }

        iface.poll(now(), &mut dev, &mut sockets);

        // new connections on listening sockets
        for i in 0..listeners.len() {
            let h = listeners[i].h;
            if sockets.get::<tcp::Socket>(h).state() == tcp::State::Established {
                let (conn, rx_out, tx_in) = pair();
                if listeners[i].accept.try_send(conn).is_ok() {
                    entries.push(Entry { h, rx_out: Some(rx_out), tx_in, tx_done: false, pending: vec![], off: 0, reply: None, started: Instant::now() });
                } else {
                    sockets.get_mut::<tcp::Socket>(h).abort();
                }
                let mut s = new_socket();
                let _ = s.listen(listeners[i].port);
                listeners[i].h = sockets.add(s);
            }
        }

        // service the connections
        let mut done: Vec<usize> = Vec::new();
        for (i, e) in entries.iter_mut().enumerate() {
            let sock = sockets.get_mut::<tcp::Socket>(e.h);
            if let Some((reply, conn)) = e.reply.take() {
                match sock.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        let _ = reply.send(Ok(conn));
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let _ = reply.send(Err(ConnectError::Refused));
                        done.push(i);
                        continue;
                    }
                    _ if e.started.elapsed() > CONNECT_TIMEOUT => {
                        sock.abort();
                        let _ = reply.send(Err(ConnectError::Timeout));
                        done.push(i);
                        continue;
                    }
                    _ => {
                        e.reply = Some((reply, conn));
                        continue;
                    }
                }
            }
            // peer -> user
            while sock.can_recv() {
                let Some(out) = e.rx_out.as_ref() else { break };
                if out.is_closed() {
                    // nobody reads any more: discard, so that the peer's close can complete
                    let _ = sock.recv(|b| (b.len(), ()));
                    continue;
                }
                let Ok(permit) = out.try_reserve() else { break };
                let data = sock.recv(|b| {
                    let n = b.len().min(CHUNK);
                    (n, b[..n].to_vec())
                });
                match data {
                    Ok(d) if !d.is_empty() => permit.send(d),
                    _ => break,
                }
            }
            if !sock.may_recv() && !sock.can_recv() {
                e.rx_out = None; // the peer closed its side: the user's rx ends
            }
            // user -> peer
            loop {
                if e.off >= e.pending.len() {
                    e.pending.clear();
                    e.off = 0;
                    match e.tx_in.try_recv() {
                        Ok(v) => e.pending = v,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            e.tx_done = true;
                            break;
                        }
                    }
                }
                if !sock.can_send() {
                    break;
                }
                match sock.send_slice(&e.pending[e.off..]) {
                    Ok(n) => e.off += n,
                    Err(_) => break,
                }
                if e.off < e.pending.len() {
                    break;
                }
            }
            if e.tx_done && e.off >= e.pending.len() && sock.may_send() {
                sock.close(); // FIN after everything was sent
            }
            if e.rx_out.as_ref().map_or(true, |o| o.is_closed()) && e.tx_done && !sock.is_active() {
                done.push(i);
            } else if sock.state() == tcp::State::Closed && e.rx_out.is_none() {
                done.push(i);
            }
        }
        for i in done.into_iter().rev() {
            let e = entries.swap_remove(i);
            sockets.remove(e.h);
        }

        iface.poll(now(), &mut dev, &mut sockets);
        for p in dev.tx.drain(..) {
            let _ = to_mesh.try_send(p);
        }
    }
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = aws_lc_rs::rand::fill(&mut b);
    u16::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two stacks wired back to back (a "mesh" of two nodes): a connection, data both ways, an orderly close, a refused connection.
    #[tokio::test]
    async fn two_stacks_talk_tcp() {
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

        let mut accepted = b.listen(7).await;
        tokio::spawn(async move {
            while let Some(mut c) = accepted.recv().await {
                tokio::spawn(async move {
                    while let Some(d) = c.rx.recv().await {
                        let up: Vec<u8> = d.iter().map(|x| x.to_ascii_uppercase()).collect();
                        if c.tx.send(up).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let mut c = a.connect(SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 7)).await.expect("connect");
        c.tx.send(b"hello mesh".to_vec()).await.unwrap();
        let mut got = Vec::new();
        while got.len() < 10 {
            got.extend(tokio::time::timeout(Duration::from_secs(5), c.rx.recv()).await.expect("echo in time").expect("echo"));
        }
        assert_eq!(got, b"HELLO MESH");

        // 300 kB each way: flow control and segmentation
        let big: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let sender = c.tx.clone();
        let payload = big.clone();
        tokio::spawn(async move {
            for ch in payload.chunks(8000) {
                if sender.send(ch.to_vec()).await.is_err() {
                    break;
                }
            }
        });
        let mut back = Vec::new();
        while back.len() < big.len() {
            back.extend(tokio::time::timeout(Duration::from_secs(10), c.rx.recv()).await.expect("bulk in time").expect("bulk"));
        }
        assert_eq!(back, big.iter().map(|x| x.to_ascii_uppercase()).collect::<Vec<u8>>());

        // orderly close: dropping our tx ends the echo task, which closes its side, which ends our rx
        drop(c.tx);
        let end = tokio::time::timeout(Duration::from_secs(5), c.rx.recv()).await.expect("close in time");
        assert!(end.is_none());

        // nobody listens on 9: refused
        let r = a.connect(SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 9)).await;
        assert_eq!(r.err(), Some(ConnectError::Refused));
    }
}
