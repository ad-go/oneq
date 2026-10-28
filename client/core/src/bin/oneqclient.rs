//! Command-line client: `oneqclient up --relay https://r1.example.org --community lan --user alice`
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use oneq_core::{Config, Status};
use tokio::sync::Notify;

const HELP: &str = "oneqclient - client of the oneq post-quantum mesh (Windows, macOS, Linux)

usage:
  oneqclient up --relay URL [--relay URL ...] --community C --user U [options]
  oneqclient service install|uninstall|start|stop|restart|status [options]   run the node in the background from boot
  oneqclient proxy --relay URL ... [--socks 127.0.0.1:1080] [--status 127.0.0.1:1081]   no TUN, no administrator: SOCKS5 proxy into the mesh (browser extension),
                                                                                              served to browsers only; --allow-process NAME adds a program, --allow-any-local opens it to every local program
  oneqclient relay init|install|uninstall|start|stop|restart|status|run|admin|selftest [options]   the oneq relay (registry + relay + STUN) of this machine
  oneqclient native-host install|uninstall                                   the extension's connection manager (see: oneqclient native-host help)
  oneqclient ui [--port N] [--no-open]                                       local web interface (settings, status, export/import)
  oneqclient menubar [--open]                                                (macOS) status icon in the menu bar; --open also opens the settings page
  oneqclient update check [--json] | download [--dir DIR] [--json]          look for a newer release / download and SHA-256-verify its installer
  oneqclient genkey [--key-file FILE]          create the node key and print the node id
  oneqclient help

options for `up`:
  --relay URL           oneqrelay (repeat for failover), e.g. https://r1.example.org
  --community C, --user U
  --password-file FILE  or the ONEQ_PASSWORD environment variable (never on the command line)
  --name TEXT           name shown in the member list (default: host name)
  --key-file FILE       node key (default: <config dir>/oneq/client.key, created on first use)
  --cafile FILE         private CA / self-signed relay certificate (PEM); default: public web roots
  --listen IP:PORT      UDP bind address (default 0.0.0.0:0)
  --advertise IP:PORT   address other nodes can reach us on directly (repeat); leave out behind NAT
  --relay-offer         offer to forward datagrams for the other members (takes effect once an administrator delegates this node)
  --no-delegates        do not use the delegated relay nodes of the community
  --no-port-mapping     do not ask the router (PCP, NAT-PMP, UPnP) to forward our UDP port
  --no-ipv6             IPv4 only (no dual-stack socket, no IPv6 candidates)
  --accept-routes       use the private networks the administrator routed through a gateway member (routes are installed on the TUN interface; off by default)
  --exit-node NAME      route all internet traffic through the named node (the administrator must have marked it as an exit node)
  --no-update-check     do not check GitHub for a newer release (default: check at start and every 24 h; nothing is installed automatically)
  --force-relay         send everything through the relay
  --no-relay            direct UDP only
  --no-autostart        (service install) do not start at boot; start it with `service start`
  --relay-after SEC     seconds without a direct session before the relay is also used for the handshake (10)
  --ifname NAME         network interface name (default oneq)
  --wintun FILE         path of wintun.dll (Windows; default: next to the executable)
  -v                    verbose logging

`service install` takes the same options as `up` (password from --password-file or ONEQ_PASSWORD): it writes the
configuration, the password file (administrators/SYSTEM only) and the CA into the service directory
(Windows: %ProgramData%\\oneq, macOS: /Library/Application Support/oneq), copies the interactive key if there is one
(same address as before) and registers the service (Windows service oneq / launchd daemon ro.example.oneq).

Needs administrator/root rights to create the network interface.
";

fn default_key_file() -> String {
    let base = std::env::var("APPDATA")
        .or_else(|_| std::env::var("XDG_CONFIG_HOME"))
        .unwrap_or_else(|_| format!("{}/.config", std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    format!("{base}/oneq/client.key")
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "oneq-client".into())
}

struct Args {
    cfg: Config,
    ifname: String,
    wintun: Option<String>,
    verbose: bool,
    autostart: bool,
    socks: String,
    status_addr: String,
    allow: Vec<String>,
    allow_any: bool,
    exit_with_pid: Option<u32>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args> {
    let mut cfg = Config { key_file: default_key_file(), name: hostname(), relay_after_s: 10.0, ..Default::default() };
    let (mut ifname, mut wintun, mut verbose, mut pwfile, mut autostart) = ("oneq".to_string(), None, false, None::<String>, true);
    let (mut socks, mut status_addr) = ("127.0.0.1:1080".to_string(), "127.0.0.1:1081".to_string());
    let (mut allow, mut allow_any) = (Vec::<String>::new(), false);
    let mut exit_with_pid = None::<u32>;
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().with_context(|| format!("{name} needs a value"));
        match a.as_str() {
            "--relay" => cfg.relays.push(val("--relay")?),
            "--community" => cfg.community = val("--community")?,
            "--user" => cfg.user = val("--user")?,
            "--password-file" => pwfile = Some(val("--password-file")?),
            "--name" => cfg.name = val("--name")?,
            "--key-file" => cfg.key_file = val("--key-file")?,
            "--cafile" => cfg.ca_pem = Some(std::fs::read(val("--cafile")?).context("read the CA file")?),
            "--listen" => cfg.listen = val("--listen")?,
            "--advertise" => cfg.advertise.push(val("--advertise")?),
            "--force-relay" => cfg.force_relay = true,
            "--no-autostart" => autostart = false,
            "--no-relay" => cfg.no_relay = true,
            "--relay-offer" => cfg.relay_offer = true,
            "--no-delegates" => cfg.no_delegates = true,
            "--no-port-mapping" => cfg.no_port_mapping = true,
            "--no-ipv6" => cfg.no_ipv6 = true,
            "--accept-routes" => cfg.accept_routes = true,
            "--exit-node" => cfg.exit_node = Some(val("--exit-node")?),
            "--no-update-check" => cfg.no_update_check = true,
            "--relay-after" => cfg.relay_after_s = val("--relay-after")?.parse()?,
            "--ifname" => ifname = val("--ifname")?,
            "--wintun" => wintun = Some(val("--wintun")?),
            "--socks" => socks = val("--socks")?,
            "--status" => status_addr = val("--status")?,
            "--allow-process" => allow.push(val("--allow-process")?),
            "--allow-any-local" => allow_any = true,
            "--exit-with-pid" => exit_with_pid = Some(val("--exit-with-pid")?.parse().context("--exit-with-pid needs a process id")?),
            "-v" => verbose = true,
            other => bail!("unknown option {other}"),
        }
    }
    cfg.password = match pwfile {
        Some(f) => std::fs::read_to_string(&f).with_context(|| format!("read {f}"))?.trim().to_string(),
        None => std::env::var("ONEQ_PASSWORD").unwrap_or_default(),
    };
    if cfg.relays.is_empty() || cfg.community.is_empty() || cfg.user.is_empty() || cfg.password.is_empty() {
        bail!("--relay, --community, --user and a password (--password-file or ONEQ_PASSWORD) are required");
    }
    Ok(Args { cfg, ifname, wintun, verbose, autostart, socks, status_addr, allow, allow_any, exit_with_pid })
}

/// `proxy` takes the options of `up`; its node key is separate (`proxy.key`): it is a different node from the TUN client of the same user.
fn parse_proxy(it: impl Iterator<Item = String>) -> Result<Args> {
    let mut a = parse(it)?;
    if a.cfg.key_file == default_key_file() {
        a.cfg.key_file = default_key_file().replace("client.key", "proxy.key");
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    // started by a browser as its native messaging host (the extension's connection manager): no command, the browser's own arguments
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if oneq_core::nativehost::is_launch(&argv) {
        return oneq_core::nativehost::run(oneq_core::svc::user_dir(), std::io::stdin().lock(), std::io::stdout().lock());
    }
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "version" | "--version" | "-V" => {
            println!("oneqclient {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "genkey" => {
            let mut key = default_key_file();
            while let Some(a) = args.next() {
                if a == "--key-file" {
                    key = args.next().context("--key-file needs a value")?;
                }
            }
            let id = oneq_core::load_or_create_identity(&key)?;
            println!("key file {key}\nnode_id {}", hex::encode(id.node_id()));
            Ok(())
        }
        "up" => {
            let a = parse(args)?;
            tracing_subscriber::fmt()
                .with_env_filter(if a.verbose { "oneq_core=debug,oneqclient=debug" } else { "oneq_core=info,oneqclient=info" })
                .init();
            let status = Arc::new(Status::new());
            if !a.cfg.no_update_check {
                tokio::spawn(oneq_core::update::background(|| true));
            }
            let prepared = oneq_core::prepare(a.cfg.clone(), &status).await?;
            let wintun = a.wintun.clone().or_else(|| {
                std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("wintun.dll").to_string_lossy().into_owned()))
            });
            let tun = Arc::new(oneq_core::create_tun(&a.ifname, &prepared.info, wintun.as_deref())?);
            let stop = Arc::new(Notify::new());
            let s2 = stop.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                s2.notify_one();
            });
            oneq_core::run(prepared, tun, status, stop).await
        }
        "proxy" => {
            let mut a = parse_proxy(args)?;
            tracing_subscriber::fmt()
                .with_env_filter(if a.verbose { "oneq_core=debug,oneqclient=debug" } else { "oneq_core=info,oneqclient=info" })
                .init();
            let status = Arc::new(Status::new());
            let stop = Arc::new(Notify::new());
            let s2 = stop.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                s2.notify_one();
            });
            let socks: std::net::SocketAddr = a.socks.parse().context("--socks must be IP:PORT")?;
            if !socks.ip().is_loopback() {
                bail!("--socks must be a loopback address (127.0.0.1): the proxy has no authentication");
            }
            let status_addr: Option<std::net::SocketAddr> = if a.status_addr.is_empty() { None } else { Some(a.status_addr.parse().context("--status must be IP:PORT")?) };
            if status_addr.map_or(false, |s| !s.ip().is_loopback()) {
                bail!("--status must be a loopback address");
            }
            if a.cfg.name == hostname() {
                a.cfg.name = format!("{}-proxy", a.cfg.name);
            }
            if let Some(pid) = a.exit_with_pid {
                // started by the browser's native host: end together with it (the SOCKS5 port lives as long as the browser session)
                let s3 = stop.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        if !oneq_core::nativehost::pid_alive(pid) {
                            s3.notify_one();
                            break;
                        }
                    }
                });
            }
            let gate = if a.allow_any { oneq_core::peer::Gate::any() } else { oneq_core::peer::Gate::browsers(&a.allow) };
            oneq_core::proxy::run(a.cfg, oneq_core::proxy::ProxyOpts { socks, status: status_addr, gate }, status, stop).await
        }
        "update" => update_cmd(args).await,
        "ui" => ui_cmd(args).await,
        "native-host" => native_host_cmd(args),
        "menubar" => {
            #[cfg(target_os = "macos")]
            {
                let open = args.any(|a| a == "--open");
                oneq_core::menubar::run(open)
            }
            #[cfg(not(target_os = "macos"))]
            bail!("the menu-bar icon exists on macOS only (Windows: the oneq app's tray icon)")
        }
        "service" => service_cmd(args).await,
        "relay" => relay_cmd(args),
        _ => {
            print!("{HELP}");
            Ok(())
        }
    }
}

const RELAY_HELP: &str = "oneqclient relay: the oneq relay (federated registry, relay and STUN service) runs on this machine from the bundled Python.
  relay init --name HOST [--ip ADDR ...] [--port 8443] [--id NAME] [--no-admin]    one-time setup in the data directory: private CA and
                                                                                   certificate, secrets, admin password + authenticator, relay.conf
  relay install [--no-autostart] [--no-start] [--no-firewall]    register the background service (Windows service oneqrelay / launchd ro.example.oneqrelay)
                                                                 and open TCP PORT and UDP PORT..PORT+2 in the firewall (Windows)
  relay start|stop|restart|status|uninstall                      control the service (uninstall also closes the firewall ports; data is kept)
  --user                                                         macOS: no administrator rights: a LaunchAgent of this user (runs while logged in), data in ~/.config/oneq/relay
  relay run                                                      run the relay in this terminal (no service)
  relay admin community-add|user-add|user-passwd|user-disable|user-enable|user-del|node-del|list ...    manage communities and users
  relay selftest [HOST [PORT]]                                   TLS, STUN and admin-login check of the running relay
options: --home DIR (bundle: python/, site-packages/, relay/; default next to oneqclient), --data DIR (default: <service dir>/relay)
Administrator rights are required for init/install/start/stop/uninstall.
";

const NATIVE_HELP: &str = "oneqclient native-host: the connection manager of the browser extension (Chrome, Brave, Edge, Firefox).
  native-host install [--extension-id ID]... [--only chrome,brave,edge,chromium,firefox]    register it for the browsers of this user
  native-host uninstall                                                                     remove the registration (the settings are kept)
  native-host configure --relay URL... --community C --user U [--name N] [--cafile F] [--password-file F]   fill in the settings (what the extension's form does)
  native-host set-password                                                                  read the password from stdin (one line) and store it for this user only
  native-host                                                                               run the host on stdin/stdout (what a browser does)
The extension asks the host to start `oneqclient proxy` with the settings typed in the extension; the proxy ends when the browser does.
--extension-id adds the id of a store-installed Chromium extension (the unpacked/pack builds are already allowed).
";

fn native_host_cmd(mut args: impl Iterator<Item = String>) -> Result<()> {
    use oneq_core::nativehost as nh;
    let dir = oneq_core::svc::user_dir();
    match args.next().as_deref() {
        None => nh::run(dir, std::io::stdin().lock(), std::io::stdout().lock()),
        Some("install") => {
            let (mut ids, mut only) = (Vec::<String>::new(), Vec::<String>::new());
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--extension-id" => ids.push(args.next().context("--extension-id needs a value")?),
                    "--only" => only.extend(args.next().context("--only needs a value")?.split(',').map(|s| s.trim().to_string())),
                    other => bail!("unknown option {other}"),
                }
            }
            if let Some(bad) = ids.iter().find(|i| i.len() != 32 || !i.chars().all(|c| ('a'..='p').contains(&c))) {
                bail!("{bad:?} is not a Chromium extension id (32 letters a-p)");
            }
            for l in nh::install(&dir, &ids, &only)? {
                println!("{l}");
            }
            println!("registered; the extension can now connect (Firefox: {}, Chromium builds: {})", nh::GECKO_ID, nh::DEV_EXTENSION_ID);
            Ok(())
        }
        Some("configure") => {
            let (mut relays, mut community, mut user, mut name, mut ca, mut pwfile) = (Vec::<String>::new(), String::new(), String::new(), String::new(), String::new(), None::<String>);
            while let Some(a) = args.next() {
                let mut val = |n: &str| args.next().with_context(|| format!("{n} needs a value"));
                match a.as_str() {
                    "--relay" => relays.push(val("--relay")?),
                    "--community" => community = val("--community")?,
                    "--user" => user = val("--user")?,
                    "--name" => name = val("--name")?,
                    "--cafile" => ca = std::fs::read_to_string(val("--cafile")?).context("read the CA file")?,
                    "--password-file" => pwfile = Some(val("--password-file")?),
                    other => bail!("unknown option {other}"),
                }
            }
            let password = match pwfile {
                Some(f) => Some(std::fs::read_to_string(&f).with_context(|| format!("read {f}"))?.trim().to_string()),
                None => None,
            };
            let mut cfg = serde_json::json!({"relays": relays, "community": community, "user": user, "name": name});
            if !ca.is_empty() {
                cfg["ca_pem"] = serde_json::Value::String(ca);
            }
            let mut host = nh::Host::new(dir)?;
            let r = host.configure(cfg, password)?;
            println!("settings saved; password {}; {}", if r["has_password"] == true { "stored" } else { "not set yet (oneqclient native-host set-password, or type it in the extension)" },
                     if r["complete"] == true { "complete" } else { "incomplete" });
            Ok(())
        }
        Some("set-password") => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let pw = line.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
            if pw.is_empty() {
                bail!("no password on stdin");
            }
            let mut host = nh::Host::new(dir)?;
            let cfg = host.config();
            host.configure(serde_json::json!({"relays": cfg.relays, "community": cfg.community, "user": cfg.user, "name": cfg.name}), Some(pw))?;
            println!("password stored for this user only");
            Ok(())
        }
        Some("uninstall") => {
            for l in nh::uninstall(&dir) {
                println!("{l}");
            }
            Ok(())
        }
        _ => {
            print!("{NATIVE_HELP}");
            Ok(())
        }
    }
}

fn relay_cmd(args: impl Iterator<Item = String>) -> Result<()> {
    use oneq_core::relaysvc as r;
    let mut home = None;
    let mut data = None;
    let mut rest: Vec<String> = Vec::new();
    let mut it = args;
    let sub = it.next().unwrap_or_else(|| "help".into());
    let (mut autostart, mut start, mut fw) = (true, true, true);
    let mut user = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--home" => home = Some(std::path::PathBuf::from(it.next().context("--home needs a value")?)),
            "--data" => data = Some(std::path::PathBuf::from(it.next().context("--data needs a value")?)),
            "--no-autostart" => autostart = false,
            "--no-start" => start = false,
            "--no-firewall" => fw = false,
            "--user" => user = true,
            _ => rest.push(a),
        }
    }
    // --user: no administrator rights (macOS: a LaunchAgent of this user, data in the user's configuration directory)
    let data = data.or_else(|| user.then(|| oneq_core::svc::user_dir().join("relay")));
    let l = r::Layout::new(home, data)?;
    #[cfg(not(target_os = "macos"))]
    let _ = user;
    match sub.as_str() {
        "init" => r::init(&l, &rest),
        "run" => {
            l.check_home()?;
            let mut cmd = l.command::<std::ffi::OsString>(&["run".into(), "--config".into(), l.conf().into_os_string()]);
            // Unix: become the relay (no wrapper left behind: a SIGTERM to this process must stop the relay itself, not orphan it)
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let e = cmd.exec();
                bail!("cannot start the relay: {e}");
            }
            #[cfg(not(unix))]
            {
                let st = cmd.status()?;
                if !st.success() {
                    bail!("oneqrelay exited with {st}");
                }
                Ok(())
            }
        }
        "admin" => r::passthrough(&l, "admin", &rest),
        "selftest" => {
            l.check_home()?;
            let t = l.home.join("relay").join("relay-selftest.py");
            let st = std::process::Command::new(l.python())
                .arg("-s").arg(t).arg(&l.data).args(&rest)
                .env("PYTHONPATH", l.site_packages()).env("PYTHONDONTWRITEBYTECODE", "1").env_remove("PYTHONHOME").status()?;
            if !st.success() {
                bail!("self-test failed");
            }
            Ok(())
        }
        #[cfg(windows)]
        "run-service" => {
            // called by the service control manager
            oneq_core::relaysvc::winsvc::dispatch(l)
        }
        "install" => {
            l.check_home()?;
            if !l.conf().exists() {
                bail!("{} not found: run `oneqclient relay init --name HOST` first", l.conf().display());
            }
            let exe = std::env::current_exe()?;
            #[cfg(windows)]
            {
                if fw {
                    r::firewall(l.port(), true)?;
                }
                r::winsvc::install(&exe, &l, autostart)?;
                if start {
                    r::winsvc::start()?;
                }
            }
            #[cfg(target_os = "macos")]
            {
                let _ = (&exe, fw, start);
                r::launchd::install(&l, autostart, user)?;
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                let _ = (&exe, autostart, start, fw);
                bail!("no service integration on this OS: use the Debian package (oneqrelay) or `oneqclient relay run`");
            }
            println!("relay service installed; data in {}", l.data.display());
            Ok(())
        }
        "uninstall" | "start" | "stop" | "restart" | "status" => {
            #[cfg(windows)]
            {
                use oneq_core::relaysvc::winsvc as w;
                match sub.as_str() {
                    "uninstall" => {
                        w::uninstall()?;
                        r::firewall(l.port(), false)?;
                    }
                    "start" => w::start()?,
                    "stop" => w::stop()?,
                    "restart" => {
                        w::stop()?;
                        w::start()?;
                    }
                    _ => {}
                }
                if sub != "uninstall" {
                    println!("service oneqrelay: {:?}", w::state()?);
                }
            }
            #[cfg(target_os = "macos")]
            {
                use oneq_core::relaysvc::launchd as m;
                if sub == "uninstall" {
                    m::uninstall(user)?;
                } else {
                    print!("{}", m::control(&sub, user)?);
                }
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            bail!("not supported on this OS");
            #[allow(unreachable_code)]
            Ok(())
        }
        _ => {
            print!("{RELAY_HELP}");
            Ok(())
        }
    }
}

async fn update_cmd(mut args: impl Iterator<Item = String>) -> Result<()> {
    use oneq_core::update;
    let sub = args.next().unwrap_or_default();
    let (mut json, mut dir) = (false, None::<String>);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json = true,
            "--dir" if sub == "download" => dir = Some(args.next().context("--dir needs a value")?),
            other => bail!("unknown option {other}"),
        }
    }
    match sub.as_str() {
        "check" => {
            let r = update::check_cached(true).await;
            if json {
                println!("{}", serde_json::to_string(&r)?);
            } else {
                match r.status.as_str() {
                    "newer" => {
                        println!("Version {} is available (you have {}).
Release notes: {}", r.latest, r.current, r.url);
                        match &r.asset {
                            Some(a) => println!("Installer for this system: {} ({} bytes). Download it with `oneqclient update download`.", a.name, a.size),
                            None => println!("This system has no installer in the release: see the release notes."),
                        }
                    }
                    "current" => println!("You have the latest version ({}).", r.current),
                    "error" => bail!("update check failed: {}", r.error.unwrap_or_default()),
                    _ => println!("Cannot compare the versions (you have {}, the release is {:?}).", r.current, r.latest),
                }
            }
            Ok(())
        }
        "download" => {
            let dir = dir.map(std::path::PathBuf::from).unwrap_or_else(update::downloads_dir);
            update::check_cached(true).await;
            let v = update::download_latest(&dir).await;
            if json {
                println!("{v}");
            } else if v["ok"] == true {
                println!("Downloaded and verified: {} ({} bytes, sha256 {}). Install it when you are ready.", v["path"].as_str().unwrap_or(""), v["size"], v["sha256"].as_str().unwrap_or(""));
            } else {
                bail!("download failed: {}", v["error"].as_str().unwrap_or("unknown error"));
            }
            if v["ok"] != true {
                std::process::exit(1);
            }
            Ok(())
        }
        _ => bail!("usage: oneqclient update check [--json] | update download [--dir DIR] [--json]"),
    }
}

async fn service_cmd(mut args: impl Iterator<Item = String>) -> Result<()> {
    use oneq_core::svc;
    let sub = args.next().unwrap_or_default();
    match sub.as_str() {
        "run" => {
            let mut config = svc::default_config_path();
            while let Some(a) = args.next() {
                if a == "--config" {
                    config = args.next().context("--config needs a value")?.into();
                }
            }
            #[cfg(windows)]
            {
                // called by the service control manager; blocks until the service stops
                return tokio::task::spawn_blocking(move || oneq_core::winsvc::dispatch(&config)).await?;
            }
            #[cfg(not(windows))]
            {
                svc::init_file_logging(&svc::service_dir().join("client.log"));
                let cfg = svc::ServiceConfig::load(&config)?;
                let stop = Arc::new(Notify::new());
                let s2 = stop.clone();
                tokio::spawn(async move {
                    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
                    }
                    s2.notify_one();
                });
                svc::supervise(cfg, Arc::new(Status::new()), stop).await;
                return Ok(());
            }
        }
        "install" => {
            let a = parse(args)?;
            let cfg_path = svc::write_install_files(&a.cfg, &a.ifname, a.wintun.clone())?;
            let exe = std::env::current_exe()?;
            #[cfg(windows)]
            {
                oneq_core::winsvc::install(&exe, &cfg_path, a.autostart)?;
                oneq_core::winsvc::start()?;
            }
            #[cfg(target_os = "macos")]
            svc::launchd::install(&exe, &cfg_path, a.autostart)?;
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                let _ = exe;
                println!("no service manager integration on this OS; run `oneqclient service run --config {}` from your init system", cfg_path.display());
            }
            println!("service installed; configuration in {}", cfg_path.display());
            Ok(())
        }
        "uninstall" | "start" | "stop" | "restart" | "status" => {
            #[cfg(windows)]
            {
                use oneq_core::winsvc as w;
                match sub.as_str() {
                    "uninstall" => w::uninstall()?,
                    "start" => w::start()?,
                    "stop" => w::stop()?,
                    "restart" => {
                        w::stop()?;
                        w::start()?;
                    }
                    _ => {}
                }
                println!("service oneq: {:?}", w::state()?);
            }
            #[cfg(target_os = "macos")]
            {
                if sub == "uninstall" {
                    svc::launchd::uninstall()?;
                } else {
                    print!("{}", svc::launchd::control(&sub)?);
                }
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            bail!("not supported on this OS");
            #[allow(unreachable_code)]
            Ok(())
        }
        _ => bail!("usage: oneqclient service install|uninstall|start|stop|restart|status|run"),
    }
}

async fn ui_cmd(mut args: impl Iterator<Item = String>) -> Result<()> {
    use oneq_core::ui;
    let (mut port, mut open) = (0u16, true);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().context("--port needs a value")?.parse()?,
            "--no-open" => open = false,
            other => bail!("unknown option {other}"),
        }
    }
    let cfg = Arc::new(ui::UiConfig::system()?);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let token = ui::new_token();
    let url = format!("http://127.0.0.1:{}/{}/", listener.local_addr()?.port(), token);
    // the URL is a secret (it carries the token): keep it readable by this user only
    std::fs::create_dir_all(&cfg.user_dir)?;
    let urlfile = cfg.user_dir.join("ui.url");
    std::fs::write(&urlfile, &url)?;
    oneq_core::svc::restrict(&urlfile).ok();
    println!("{url}");
    if open {
        ui::open_browser(&url);
    }
    ui::serve(listener, token, cfg).await
}
