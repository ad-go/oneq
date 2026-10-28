//! Routes announced for the community (a private network behind a gateway member), installed in the operating system on the TUN interface so
//! that the programs of this computer reach the network without knowing about the mesh. The engine (l3.rs) sends the packets to the gateway's
//! MAC address; this module only makes the operating system hand them to the TUN device. Windows: `netsh`, Linux: `ip`, macOS: `route`.
//! The routes are removed again when they are withdrawn and when the node stops. Android routes are added by the VpnService (not done here).
//!
//! Exit-node routing: two /1 routes (0.0.0.0/1 and 128.0.0.0/1) through the TUN cover all of the internet without masking the mesh subnet
//! (/8 or finer). Before those routes are installed, the relay host addresses get a /32 route via the original default gateway so that the
//! control plane keeps working. `ExitKeeper` owns those /32 exception routes.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::status::Status;

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

    /// Follow `status.routes` until the task is aborted.
    pub async fn follow(self: Arc<Self>, ifname: String, status: Arc<Status>) {
        loop {
            let want: Vec<Wanted> = status.snapshot().routes.iter().map(|r| (r.net.clone(), r.via.clone())).collect();
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

/// (program, arguments) that add or delete a host route (`/32`) via an explicit gateway on the real WAN interface
/// (not through the TUN device). Used to keep the relay addresses reachable when an exit node is active.
pub fn gateway_command(add: bool, host_ip: &str, gw: &str) -> Option<(String, Vec<String>)> {
    let s = |x: &str| x.to_string();
    let net = format!("{host_ip}/32");
    if cfg!(windows) {
        let verb = if add { "add" } else { "delete" };
        let mut a = vec![s("interface"), s("ipv4"), s(verb), s("route"), format!("prefix={net}"), s("interface=*"), format!("nexthop={gw}")];
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
    installed: Mutex<Vec<(String, String)>>,  // (host_ip, gateway)
}

impl ExitKeeper {
    pub fn new() -> Arc<Self> {
        Arc::new(ExitKeeper::default())
    }

    /// Install /32 routes for `hosts` via `gw`; remove any previously installed routes not in the new set.
    pub fn sync(&self, hosts: &[String], gw: &str) -> Vec<String> {
        let mut notes = Vec::new();
        let want: Vec<(String, String)> = hosts.iter().map(|h| (h.clone(), gw.to_string())).collect();
        let mut inst = self.installed.lock().unwrap();
        for old in inst.clone() {
            if !want.contains(&old) {
                match gateway_command(false, &old.0, &old.1).map(run) {
                    Some(Err(e)) => notes.push(format!("exit exception {} could not be removed: {e}", old.0)),
                    _ => { inst.retain(|x| *x != old); }
                }
            }
        }
        for new in &want {
            if inst.contains(new) {
                continue;
            }
            match gateway_command(true, &new.0, &new.1).map(run) {
                None => notes.push(format!("exit exception {}: not supported on this system", new.0)),
                Some(Err(e)) => notes.push(format!("exit exception {} via {} could not be installed: {e}", new.0, new.1)),
                Some(Ok(())) => { inst.push(new.clone()); }
            }
        }
        notes
    }

    pub fn clear(&self) {
        let mut inst = self.installed.lock().unwrap();
        for (host, gw) in inst.drain(..).collect::<Vec<_>>() {
            let _ = gateway_command(false, &host, &gw).map(run);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
