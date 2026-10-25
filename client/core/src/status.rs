//! Shared, serializable state that user interfaces (CLI, Flutter) poll.
use std::sync::Mutex;

use serde::Serialize;

#[derive(Clone, Default, Serialize, Debug)]
pub struct PeerInfo {
    pub name: String,
    pub ip: String,
    pub online: bool,
    pub session: bool,
    /// "direct", "relay" or "-" when there is no session
    pub path: String,
}

/// A network routed through a gateway member (accepted with `accept_routes`).
#[derive(Clone, Default, Serialize, Debug)]
pub struct RouteInfo {
    /// "192.168.16.0/24"
    pub net: String,
    /// the preferred gateway's mesh address (the operating-system route points at it; the engine picks the live one itself)
    pub via: String,
    pub gateway: String,
    /// the other gateways of the same network, by priority
    pub backups: Vec<String>,
}

#[derive(Clone, Default, Serialize, Debug)]
pub struct Snapshot {
    /// NAT measured with the relay's STUN service: open, cone, port-restricted, symmetric, blocked, unknown
    pub nat_type: String,
    pub nat_public: String,
    pub nat_inbound: Option<bool>,
    /// "idle", "connecting", "connected", "error", "stopped"
    pub state: String,
    pub message: String,
    pub ip: String,
    pub mac: String,
    pub prefix: u8,
    pub mtu: u16,
    pub community: String,
    pub relay_url: String,
    pub relay_connected: bool,
    pub peers: Vec<PeerInfo>,
    pub routes: Vec<RouteInfo>,
    /// every accepted routed network ("192.168.16.0/24"), also those whose gateway is not known yet: Android adds them to the VPN interface
    pub route_nets: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub log: Vec<String>,
}

#[derive(Default)]
pub struct Status {
    inner: Mutex<Snapshot>,
}

const LOG_LINES: usize = 200;

impl Status {
    pub fn new() -> Self {
        let s = Status::default();
        s.update(|x| x.state = "idle".into());
        s
    }

    pub fn snapshot(&self) -> Snapshot {
        self.inner.lock().unwrap().clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        f(&mut self.inner.lock().unwrap());
    }

    pub fn set_state(&self, state: &str, message: &str) {
        self.update(|s| {
            s.state = state.into();
            s.message = message.into();
        });
    }

    /// Log line for the user (also goes to `tracing`).
    pub fn note(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!("{msg}");
        self.update(|s| {
            s.log.push(msg);
            if s.log.len() > LOG_LINES {
                let cut = s.log.len() - LOG_LINES;
                s.log.drain(..cut);
            }
        });
    }
}
