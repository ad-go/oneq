//! Running the node as a background service: configuration file, supervisor with reconnection, and the per-OS
//! installers (Windows service in `winsvc.rs`, launchd daemon here for macOS).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::{Config, Status};

/// What the service reads at start. Secrets are never inline: the password is a file (readable by the service
/// account and administrators only), the CA a PEM file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ServiceConfig {
    pub relays: Vec<String>,
    pub community: String,
    pub user: String,
    pub password_file: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub cafile: Option<String>,
    pub key_file: String,
    #[serde(default = "default_ifname")]
    pub ifname: String,
    #[serde(default)]
    pub wintun: Option<String>,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub advertise: Vec<String>,
    #[serde(default)]
    pub force_relay: bool,
    #[serde(default)]
    pub no_relay: bool,
    #[serde(default)]
    pub relay_offer: bool,
    #[serde(default)]
    pub no_delegates: bool,
    #[serde(default)]
    pub no_port_mapping: bool,
    #[serde(default)]
    pub no_ipv6: bool,
    #[serde(default)]
    pub accept_routes: bool,
}

fn default_ifname() -> String {
    "oneq".into()
}

/// Directory of the service's files (config, key, password, log).
pub fn service_dir() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("oneq")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/oneq")
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        PathBuf::from("/etc/oneq-client")
    }
}

pub fn default_config_path() -> PathBuf {
    service_dir().join("client.json")
}

impl ServiceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let txt = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let c: ServiceConfig = serde_json::from_str(&txt).with_context(|| format!("parse {}", path.display()))?;
        if c.relays.is_empty() || c.community.is_empty() || c.user.is_empty() || c.password_file.is_empty() {
            bail!("{}: relays, community, user and password_file are required", path.display());
        }
        Ok(c)
    }

    pub fn to_config(&self) -> Result<Config> {
        let password = std::fs::read_to_string(&self.password_file)
            .with_context(|| format!("read the password file {}", self.password_file))?
            .trim()
            .to_string();
        let ca_pem = match &self.cafile {
            Some(f) if !f.is_empty() => Some(std::fs::read(f).with_context(|| format!("read the CA file {f}"))?),
            _ => None,
        };
        Ok(Config {
            relays: self.relays.clone(),
            community: self.community.clone(),
            user: self.user.clone(),
            password,
            name: if self.name.is_empty() { hostname() } else { self.name.clone() },
            ca_pem,
            key_file: self.key_file.clone(),
            listen: self.listen.clone(),
            advertise: self.advertise.clone(),
            force_relay: self.force_relay,
            no_relay: self.no_relay,
            relay_after_s: 10.0,
            relay_offer: self.relay_offer,
            no_delegates: self.no_delegates,
            no_port_mapping: self.no_port_mapping,
            no_ipv6: self.no_ipv6,
            accept_routes: self.accept_routes,
        })
    }
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "oneq-node".into())
}

/// Keep the node connected until `stop` is notified: (re)login, create the interface, run, and start over after any
/// failure (relay unreachable at boot, wrong password fixed later, TUN device lost, ...).
pub async fn supervise(cfg: ServiceConfig, status: Arc<Status>, stop: Arc<Notify>) {
    // a small status file for the local UI and the macOS menu-bar helper (the service has no other IPC)
    let st = status.clone();
    let writer = tokio::spawn(async move {
        loop {
            write_status(&st);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    supervise_inner(cfg, status.clone(), stop).await;
    writer.abort();
    status.set_state("stopped", "");
    write_status(&status);
}

/// `status.json` in the service directory: `{"updated": unix seconds, "snapshot": {...}}`, no secrets.
pub fn write_status(st: &Status) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let v = serde_json::json!({"updated": now, "snapshot": st.snapshot()});
    let p = service_dir().join("status.json");
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// Per-user directory of the UI settings and the interactive node key.
pub fn user_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .or_else(|_| std::env::var("XDG_CONFIG_HOME"))
        .unwrap_or_else(|_| format!("{}/.config", std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    PathBuf::from(base).join("oneq")
}

async fn supervise_inner(cfg: ServiceConfig, status: Arc<Status>, stop: Arc<Notify>) {
    let mut wait = 5u64;
    loop {
        let attempt: Result<()> = async {
            let c = cfg.to_config()?;
            let prepared = crate::prepare(c, &status).await?;
            let tun = Arc::new(crate::create_tun(&cfg.ifname, &prepared.info, cfg.wintun.as_deref())?);
            wait = 5;
            let inner_stop = Arc::new(Notify::new());
            let run = tokio::spawn(crate::run(prepared, tun, status.clone(), inner_stop.clone()));
            tokio::pin!(run);
            loop {
                tokio::select! {
                    _ = stop.notified() => {
                        inner_stop.notify_one();
                        let _ = (&mut run).await;
                        return Ok(());
                    }
                    r = &mut run => { r??; bail!("the engine stopped unexpectedly"); }
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {
                        if status.snapshot().state == "error" {
                            inner_stop.notify_one();
                            let _ = (&mut run).await;
                            bail!("{}", status.snapshot().message);
                        }
                    }
                }
            }
        }
        .await;
        match attempt {
            Ok(()) => return, // asked to stop
            Err(e) => {
                tracing::warn!("node down: {e:#}; retrying in {wait}s");
                status.set_state("error", &format!("{e:#}"));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
            _ = stop.notified() => return,
        }
        wait = (wait * 2).min(60);
    }
}

/// Log to a file (a service has no console). Truncates it when it is over 5 MB.
pub fn init_file_logging(path: &Path) {
    if std::fs::metadata(path).map_or(false, |m| m.len() > 5 * 1024 * 1024) {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("oneq_core=info,oneqclient=info")
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .try_init();
    }
}

/// Write the config, key location and secret files for a service install. Returns the config path.
pub fn write_install_files(c: &Config, ifname: &str, wintun: Option<String>) -> Result<PathBuf> {
    let dir = service_dir();
    std::fs::create_dir_all(&dir)?;
    let pass = dir.join("client.pass");
    std::fs::write(&pass, &c.password)?;
    restrict(&pass)?;
    let cafile = match &c.ca_pem {
        Some(pem) => {
            let p = dir.join("ca.pem");
            std::fs::write(&p, pem)?;
            Some(p.to_string_lossy().into_owned())
        }
        None => None,
    };
    let key = dir.join("client.key");
    // the key of the interactive user (CLI, imported settings) is the node's identity: same address as before
    if Path::new(&c.key_file).exists() && Path::new(&c.key_file) != key.as_path() {
        std::fs::copy(&c.key_file, &key)?;
    }
    if key.exists() {
        restrict(&key)?;
    }
    let sc = ServiceConfig {
        relays: c.relays.clone(),
        community: c.community.clone(),
        user: c.user.clone(),
        password_file: pass.to_string_lossy().into_owned(),
        name: c.name.clone(),
        cafile,
        key_file: key.to_string_lossy().into_owned(),
        ifname: ifname.into(),
        wintun,
        listen: c.listen.clone(),
        advertise: c.advertise.clone(),
        force_relay: c.force_relay,
        no_relay: c.no_relay,
        relay_offer: c.relay_offer,
        no_delegates: c.no_delegates,
        no_port_mapping: c.no_port_mapping,
        no_ipv6: c.no_ipv6,
        accept_routes: c.accept_routes,
    };
    let path = default_config_path();
    std::fs::write(&path, serde_json::to_string_pretty(&sc)?)?;
    Ok(path)
}

/// Owner (and, on Windows, SYSTEM and Administrators) only.
pub fn restrict(p: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let st = std::process::Command::new("icacls")
            .arg(p)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]) // SYSTEM, Administrators
            .output()?;
        if !st.status.success() {
            bail!("icacls failed on {}: {}", p.display(), String::from_utf8_lossy(&st.stdout));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ------------------------------------------------------------------ macOS (launchd), not tested: no Mac available
#[cfg(target_os = "macos")]
pub mod launchd {
    use super::*;

    pub const LABEL: &str = "ro.1q.oneq";
    const PLIST: &str = "/Library/LaunchDaemons/ro.1q.oneq.plist";

    pub fn install(exe: &Path, config: &Path, autostart: bool) -> Result<()> {
        let log = service_dir().join("client.log");
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>service</string><string>run</string><string>--config</string><string>{cfg}</string></array>
  <key>RunAtLoad</key><{auto}/>
  <key>KeepAlive</key><{auto}/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
            exe = exe.display(),
            cfg = config.display(),
            log = log.display(),
            auto = if autostart { "true" } else { "false" }
        );
        std::fs::write(PLIST, plist)?;
        restrict(Path::new(PLIST)).ok();
        let _ = std::process::Command::new("launchctl").args(["bootout", "system", PLIST]).output();
        let out = std::process::Command::new("launchctl").args(["bootstrap", "system", PLIST]).output()?;
        if !out.status.success() {
            bail!("launchctl bootstrap: {}", String::from_utf8_lossy(&out.stderr));
        }
        // without RunAtLoad the daemon is only loaded: start it now
        let _ = std::process::Command::new("launchctl").args(["kickstart", &format!("system/{LABEL}")]).output();
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let _ = std::process::Command::new("launchctl").args(["bootout", "system", PLIST]).output();
        let _ = std::fs::remove_file(PLIST);
        Ok(())
    }

    pub fn control(action: &str) -> Result<String> {
        let target = format!("system/{LABEL}");
        let args: Vec<&str> = match action {
            "start" => vec!["kickstart", &target],
            "stop" => vec!["kill", "TERM", &target],
            "restart" => vec!["kickstart", "-k", &target],
            _ => vec!["print", &target],
        };
        let out = std::process::Command::new("launchctl").args(&args).output()?;
        Ok(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oneq-svc-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn config_is_loaded_with_password_and_ca_from_files() {
        let d = tmp("ok");
        std::fs::write(d.join("pw"), "s3cret\r\n").unwrap();
        std::fs::write(d.join("ca.pem"), "PEM").unwrap();
        let json = format!(
            r#"{{"relays":["https://r1"],"community":"c","user":"u","password_file":{:?},"cafile":{:?},"key_file":"k"}}"#,
            d.join("pw").to_string_lossy(),
            d.join("ca.pem").to_string_lossy()
        );
        std::fs::write(d.join("c.json"), json).unwrap();
        let sc = ServiceConfig::load(&d.join("c.json")).unwrap();
        assert_eq!(sc.ifname, "oneq");
        let c = sc.to_config().unwrap();
        assert_eq!((c.password.as_str(), c.ca_pem.as_deref()), ("s3cret", Some(&b"PEM"[..])));
        assert!(!c.name.is_empty());
    }

    #[test]
    fn incomplete_or_dangling_config_is_refused() {
        let d = tmp("bad");
        std::fs::write(d.join("a.json"), r#"{"relays":[],"community":"c","user":"u","password_file":"p","key_file":"k"}"#).unwrap();
        assert!(ServiceConfig::load(&d.join("a.json")).is_err());
        std::fs::write(d.join("b.json"), r#"{"relays":["https://r"],"community":"c","user":"u","password_file":"/nonexistent/pw","key_file":"k"}"#).unwrap();
        let sc = ServiceConfig::load(&d.join("b.json")).unwrap();
        assert!(sc.to_config().is_err()); // the service retries instead of crashing
        assert!(ServiceConfig::load(&d.join("missing.json")).is_err());
    }
}
