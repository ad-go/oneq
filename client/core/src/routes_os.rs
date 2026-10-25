//! Routes announced for the community (a private network behind a gateway member), installed in the operating system on the TUN interface so
//! that the programs of this computer reach the network without knowing about the mesh. The engine (l3.rs) sends the packets to the gateway's
//! MAC address; this module only makes the operating system hand them to the TUN device. Windows: `netsh`, Linux: `ip`, macOS: `route`.
//! The routes are removed again when they are withdrawn and when the node stops. Android routes are added by the VpnService (not done here).
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
