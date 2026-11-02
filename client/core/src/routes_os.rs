//! Routes announced for the community (a private network behind a gateway member), installed in the operating system on the TUN interface so
//! that the programs of this computer reach the network without knowing about the mesh. The engine (l3.rs) sends the packets to the gateway's
//! MAC address; this module only makes the operating system hand them to the TUN device. Windows: `netsh`, Linux: `ip`, macOS: `route`.
//! The routes are removed again when they are withdrawn and when the node stops. Android routes are added by the VpnService (not done here).
//!
//! Exit-node routing: two /1 routes (0.0.0.0/1 and 128.0.0.0/1) through the TUN cover all of the internet without masking the mesh subnet
//! (/8 or finer). Before those routes are installed, the relay host addresses get a /32 route via the original default gateway so that the
//! control plane keeps working. `ExitKeeper` owns those /32 exception routes.
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::status::Status;

/// All non-loopback IPv4 addresses currently assigned to local interfaces. Used to skip announced routes whose
/// network the node is already on: installing such a route would shadow the direct LAN path and could cause loops.
pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut out = Vec::new();
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return out;
            }
            let mut p = ifap;
            while !p.is_null() {
                let ifa = &*p;
                if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                    let sin = ifa.ifa_addr as *const libc::sockaddr_in;
                    let ip = Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                    if !ip.is_loopback() {
                        out.push(ip);
                    }
                }
                p = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
        out
    }
    #[cfg(windows)]
    {
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'}).IPAddress"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines()
                .filter_map(|l| l.trim().parse::<Ipv4Addr>().ok())
                .collect())
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    { Vec::new() }
}

/// Returns true when at least one local interface address falls inside `cidr` ("net/prefix").
/// Used to skip OS route installation for networks the node can already reach directly.
///
/// Prefixes of 0 or 1 are never "local": they only occur as the exit-node's pair of /1 routes, which are
/// meant to cover (almost) all of the address space on purpose. Almost every machine has a local address
/// on each side of that split (e.g. 10.x and 172.x/192.168.x both exist locally at once), so applying this
/// loop guard to them would always classify the exit routes as local and silently drop the whole feature.
fn is_local_route(cidr: &str, local_addrs: &[Ipv4Addr]) -> bool {
    let Some((net_s, prefix_s)) = cidr.split_once('/') else { return false };
    let (Ok(net), Ok(prefix)) = (net_s.parse::<Ipv4Addr>(), prefix_s.parse::<u8>()) else { return false };
    if prefix > 32 || prefix <= 1 { return false; }
    let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix as u32) };
    let net_int = u32::from(net) & mask;
    local_addrs.iter().any(|a| u32::from(*a) & mask == net_int)
}

/// A route as the operating system needs it: network "a.b.c.d/p" and the gateway's mesh address.
pub type Wanted = (String, String);

#[derive(Default)]
pub struct Keeper {
    installed: Mutex<Vec<Wanted>>,
}

/// (program, arguments) that add (`add == true`) or delete a route.
pub fn command(add: bool, ifname: &str, net: &str, via: &str) -> Option<(String, Vec<String>)> {
    let s = |x: &str| x.to_string();
    if cfg!(windows) {
        let verb = if add { "add" } else { "delete" };
        let mut a: Vec<String> = vec![s("interface"), s("ipv4"), s(verb), s("route"), format!("prefix={net}"), format!("interface={ifname}"), format!("nexthop={via}")];
        if add {
            a.push(s("store=active"));
        }
        Some((s("netsh"), a))
    } else if cfg!(target_os = "linux") {
        let verb = if add { "replace" } else { "del" };
        Some((s("ip"), vec![s("route"), s(verb), s(net), s("via"), s(via), s("dev"), s(ifname)]))
    } else if cfg!(target_os = "macos") {
        Some((s("route"), vec![s("-n"), s(if add { "add" } else { "delete" }), s("-net"), s(net), s(via)]))
    } else {
        None
    }
}

fn run(cmd: (String, Vec<String>)) -> Result<(), String> {
    let mut c = std::process::Command::new(&cmd.0);
    c.args(&cmd.1);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: the service has no console
    }
    let o = c.output().map_err(|e| format!("{}: {e}", cmd.0))?;
    if o.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(if o.stderr.is_empty() { &o.stdout } else { &o.stderr }).trim().replace('\n', " ");
        Err(format!("{} {}: {text}", cmd.0, cmd.1.join(" ")))
    }
}

impl Keeper {
    pub fn new() -> Arc<Self> {
        Arc::new(Keeper::default())
    }

    /// Make the installed routes equal to `want`: delete the withdrawn ones, add the new ones. Returns the notes for the user.
    pub fn sync(&self, ifname: &str, want: &[Wanted]) -> Vec<String> {
        let mut notes = Vec::new();
        let mut inst = self.installed.lock().unwrap();
        for old in inst.clone() {
            if !want.contains(&old) {
                match command(false, ifname, &old.0, &old.1).map(run) {
                    Some(Err(e)) => notes.push(format!("route {} could not be removed: {e}", old.0)),
                    _ => notes.push(format!("route {} via {} removed", old.0, old.1)),
                }
                inst.retain(|x| *x != old);
            }
        }
        for new in want {
            if inst.contains(new) {
                continue;
            }
            match command(true, ifname, &new.0, &new.1).map(run) {
                None => notes.push(format!("route {}: not supported on this system", new.0)),
                Some(Err(e)) => notes.push(format!("route {} via {} could not be installed: {e}", new.0, new.1)),
                Some(Ok(())) => {
                    notes.push(format!("route {} via {} installed on {ifname}", new.0, new.1));
                    inst.push(new.clone());
                }
            }
        }
        notes
    }

    /// Remove everything that was installed (the node stops).
    pub fn clear(&self, ifname: &str) {
        self.sync(ifname, &[]);
    }

    /// Follow `status.routes` until the task is aborted. Routes whose network the node is already on (a local interface
    /// address falls inside the announced CIDR) are skipped: installing them would shadow the direct path and risk loops.
    pub async fn follow(self: Arc<Self>, ifname: String, status: Arc<Status>) {
        loop {
            let local = local_ipv4_addrs();
            let want: Vec<Wanted> = status.snapshot().routes.iter()
                .filter(|r| {
                    if is_local_route(&r.net, &local) {
                        tracing::debug!("route {} skipped: node is already on this network", r.net);
                        false
                    } else {
                        true
                    }
                })
                .map(|r| (r.net.clone(), r.via.clone()))
                .collect();
            let (k, i) = (self.clone(), ifname.clone());
            if let Ok(notes) = tokio::task::spawn_blocking(move || k.sync(&i, &want)).await {
                for n in notes {
                    status.note(n);
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

/// Read the current default IPv4 gateway from the operating system. Used once when an exit node is activated,
/// to install /32 exception routes for the relay hosts so the control plane survives.
pub fn default_gateway() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip").args(["route", "show", "default"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // "default via 192.168.1.1 dev eth0 ..."
        for token in text.split_whitespace().collect::<Vec<_>>().windows(2) {
            if token[0] == "via" {
                return Some(token[1].to_string());
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("gateway:") {
                return Some(rest.trim().to_string());
            }
        }
        None
    }
    #[cfg(windows)]
    {
        // PowerShell: (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort RouteMetric | Select -First 1).NextHop
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).NextHop"])
            .output().ok()?;
        let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if gw.is_empty() || gw == "0.0.0.0" { None } else { Some(gw) }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    { None }
}

/// Windows only: the interface index the default route currently goes through. `netsh interface ipv4 add|delete
/// route` requires a real interface (name or index) — unlike `ip route` or BSD `route`, it has no "any interface"
/// wildcard, so this must be looked up and passed in for every `/32` exception route. `None` elsewhere: the other
/// platforms' `gateway_command` ignores it.
pub fn default_interface() -> Option<String> {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).InterfaceIndex"])
            .output().ok()?;
        let idx = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if idx.is_empty() { None } else { Some(idx) }
    }
    #[cfg(not(windows))]
    { None }
}

/// The IPv4 addresses (with prefix length) of the local network interfaces, excluding loopback. Used to detect
/// when this node is already on a network that would be routed through the mesh, preventing a routing loop.
pub fn local_interface_nets() -> Vec<(std::net::Ipv4Addr, u8)> {
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        let o = std::process::Command::new("ip").args(["addr", "show"]).output().ok();
        if let Some(o) = o {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("inet ") {
                    let cidr = rest.split_whitespace().next().unwrap_or("");
                    if let Some((ip_s, pfx_s)) = cidr.split_once('/') {
                        if let (Ok(ip), Ok(pfx)) = (ip_s.parse::<std::net::Ipv4Addr>(), pfx_s.parse::<u8>()) {
                            if !ip.is_loopback() { out.push((ip, pfx)); }
                        }
                    }
                }
            }
        }
        out
    }
    #[cfg(target_os = "macos")]
    {
        let mut out = Vec::new();
        let o = std::process::Command::new("ifconfig").output().ok();
        if let Some(o) = o {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("inet ") {
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    if let Some(ip_s) = parts.first() {
                        if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_loopback() {
                                // "netmask 0xffffff00" -> leading ones
                                let pfx = parts.windows(2)
                                    .find(|w| w[0] == "netmask")
                                    .and_then(|w| u32::from_str_radix(w[1].trim_start_matches("0x"), 16).ok())
                                    .map(|m| m.leading_ones() as u8)
                                    .unwrap_or(32);
                                out.push((ip, pfx));
                            }
                        }
                    }
                }
            }
        }
        out
    }
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        use std::os::windows::process::CommandExt;
        let o = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses"])
            .creation_flags(0x0800_0000)
            .output().ok();
        if let Some(o) = o {
            let mut ip: Option<std::net::Ipv4Addr> = None;
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("IP Address:") {
                    ip = rest.trim().parse().ok();
                } else if let Some(rest) = line.strip_prefix("Subnet Prefix:") {
                    // "10.10.0.105/24 (mask 255.255.255.0)"
                    let cidr = rest.trim().split_whitespace().next().unwrap_or("");
                    if let Some((_, pfx_s)) = cidr.split_once('/') {
                        if let (Some(i), Ok(pfx)) = (ip.take(), pfx_s.parse::<u8>()) {
                            if !i.is_loopback() { out.push((i, pfx)); }
                        }
                    }
                }
            }
        }
        out
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    { Vec::new() }
}

/// (program, arguments) that add or delete a host route (`/32`) via an explicit gateway on the real WAN interface
/// (not through the TUN device). Used to keep the relay addresses reachable when an exit node is active.
/// `iface` is required on Windows (`netsh interface ipv4 ... route` has no "any interface" wildcard, unlike
/// `ip route` or BSD `route`): without the real interface name/index, the command is rejected outright.
pub fn gateway_command(add: bool, host_ip: &str, gw: &str, iface: Option<&str>) -> Option<(String, Vec<String>)> {
    let s = |x: &str| x.to_string();
    let net = format!("{host_ip}/32");
    if cfg!(windows) {
        let iface = iface?;
        let verb = if add { "add" } else { "delete" };
        let mut a = vec![s("interface"), s("ipv4"), s(verb), s("route"), format!("prefix={net}"), format!("interface={iface}"), format!("nexthop={gw}")];
        if add {
            a.push(s("store=active"));
        }
        Some((s("netsh"), a))
    } else if cfg!(target_os = "linux") {
        let verb = if add { "replace" } else { "del" };
        Some((s("ip"), vec![s("route"), s(verb), net, s("via"), s(gw)]))
    } else if cfg!(target_os = "macos") {
        Some((s("route"), vec![s("-n"), s(if add { "add" } else { "delete" }), s("-host"), s(host_ip), s(gw)]))
    } else {
        None
    }
}

/// Manages the /32 exception routes for relay host IPs that must stay reachable when exit-node routing is active.
#[derive(Default)]
pub struct ExitKeeper {
    installed: Mutex<Vec<(String, String, Option<String>)>>,  // (host_ip, gateway, interface)
}

impl ExitKeeper {
    pub fn new() -> Arc<Self> {
        Arc::new(ExitKeeper::default())
    }

    /// Install /32 routes for `hosts` via `gw` (over `iface`, required on Windows); remove any previously
    /// installed routes not in the new set.
    pub fn sync(&self, hosts: &[String], gw: &str, iface: Option<&str>) -> Vec<String> {
        let mut notes = Vec::new();
        let want: Vec<(String, String, Option<String>)> = hosts.iter().map(|h| (h.clone(), gw.to_string(), iface.map(String::from))).collect();
        let mut inst = self.installed.lock().unwrap();
        for old in inst.clone() {
            if !want.contains(&old) {
                match gateway_command(false, &old.0, &old.1, old.2.as_deref()).map(run) {
                    Some(Err(e)) => notes.push(format!("exit exception {} could not be removed: {e}", old.0)),
                    _ => { inst.retain(|x| *x != old); }
                }
            }
        }
        for new in &want {
            if inst.contains(new) {
                continue;
            }
            match gateway_command(true, &new.0, &new.1, new.2.as_deref()).map(run) {
                None => notes.push(format!("exit exception {}: not supported on this system", new.0)),
                Some(Err(e)) => notes.push(format!("exit exception {} via {} could not be installed: {e}", new.0, new.1)),
                Some(Ok(())) => { inst.push(new.clone()); }
            }
        }
        notes
    }

    pub fn clear(&self) {
        let mut inst = self.installed.lock().unwrap();
        for (host, gw, iface) in inst.drain(..).collect::<Vec<_>>() {
            let _ = gateway_command(false, &host, &gw, iface.as_deref()).map(run);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_route_filter_skips_networks_the_node_is_on() {
        let local: Vec<Ipv4Addr> = ["192.168.1.42", "10.10.0.105"].iter().map(|s| s.parse().unwrap()).collect();
        assert!(is_local_route("192.168.1.0/24", &local), "node has 192.168.1.42 in this /24");
        assert!(is_local_route("192.168.1.0/16", &local), "node has 192.168.1.42 in this /16");
        assert!(!is_local_route("192.168.2.0/24", &local), "different subnet");
        assert!(is_local_route("10.10.0.0/16", &local), "node's mesh IP is in this /16");
        assert!(!is_local_route("10.20.0.0/24", &local), "unrelated private network");
        assert!(!is_local_route("", &local), "malformed CIDR");
        assert!(!is_local_route("bad/cidr", &local), "bad network");
        assert!(!is_local_route("192.168.1.0/24", &[]), "no local addrs");
    }

    #[test]
    fn exit_node_default_routes_are_never_local() {
        // 10.x falls in 0.0.0.0/1, 192.168.x falls in 128.0.0.0/1: a typical machine has a local address
        // on each side, which must not make the exit-node's two /1 routes look "local" and get skipped.
        let local: Vec<Ipv4Addr> = ["10.0.0.123", "192.168.1.42"].iter().map(|s| s.parse().unwrap()).collect();
        assert!(!is_local_route("0.0.0.0/1", &local));
        assert!(!is_local_route("128.0.0.0/1", &local));
        assert!(!is_local_route("0.0.0.0/0", &local));
    }

    #[test]
    fn commands_have_the_network_the_gateway_and_the_interface() {
        let (prog, args) = command(true, "oneq", "192.168.16.0/24", "10.78.0.189").unwrap_or_default();
        let line = format!("{prog} {}", args.join(" "));
        assert!(line.contains("192.168.16.0/24") && line.contains("10.78.0.189"), "{line}");
        let (_, del) = command(false, "oneq", "192.168.16.0/24", "10.78.0.189").unwrap_or_default();
        assert_ne!(args, del);
        if cfg!(windows) {
            assert_eq!(prog, "netsh");
            assert!(line.contains("interface=oneq") && line.contains("prefix=192.168.16.0/24") && line.ends_with("store=active"), "{line}");
        }
    }

    #[test]
    fn gateway_command_needs_a_real_interface_on_windows() {
        // regression: netsh has no "any interface" wildcard, unlike `ip route`/`route`; passing one made every
        // exit-node relay exception fail outright (silently, since client.rs discards gateway_command's errors).
        if cfg!(windows) {
            assert!(gateway_command(true, "1.2.3.4", "10.0.0.1", None).is_none(), "no interface: must refuse rather than pass interface=*");
            let (prog, args) = gateway_command(true, "1.2.3.4", "10.0.0.1", Some("16")).unwrap();
            let line = format!("{prog} {}", args.join(" "));
            assert!(line.contains("interface=16") && line.contains("prefix=1.2.3.4/32") && line.contains("nexthop=10.0.0.1"), "{line}");
        } else {
            let (_, args) = gateway_command(true, "1.2.3.4", "10.0.0.1", None).unwrap();
            assert!(args.iter().any(|a| a.contains("1.2.3.4")));
        }
    }
}
