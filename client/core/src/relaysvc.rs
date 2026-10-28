//! The oneq relay as an optional part of the desktop clients (Windows, macOS): the Python `oneqrelay` runs from a bundled interpreter
//! (python-build-standalone, OpenSSL >= 3.5 as the post-quantum TLS needs) and is installed as a background service, like the node:
//! Windows service `oneqrelay` (LocalSystem, restarted by the service manager) and launchd daemon `ro.example.oneqrelay`.
//!
//! Layout: `<home>` (read-only program files, default `<dir of oneqclient>/relay`) holds `python/`, `site-packages/` and `relay/` (the
//! relay's .py files); `<data>` (default `<service dir>/relay`) holds relay.conf, the certificates, secrets and the database, restricted
//! to the service account. `oneqclient relay init` fills `<data>` through `oneqrelay.py init`.
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Result};

use crate::svc;

pub struct Layout {
    pub home: PathBuf,
    pub data: PathBuf,
}

impl Layout {
    pub fn new(home: Option<PathBuf>, data: Option<PathBuf>) -> Result<Layout> {
        let home = match home {
            Some(h) => h,
            None => {
                let exe = std::env::current_exe()?;
                let exe = exe.canonicalize().unwrap_or(exe);
                exe.parent().ok_or_else(|| anyhow!("no directory for the executable"))?.join("relay")
            }
        };
        Ok(Layout { home, data: data.unwrap_or_else(|| svc::service_dir().join("relay")) })
    }

    pub fn python(&self) -> PathBuf {
        if cfg!(windows) { self.home.join("python").join("python.exe") } else { self.home.join("python").join("bin").join("python3") }
    }

    pub fn script(&self) -> PathBuf {
        self.home.join("relay").join("oneqrelay.py")
    }

    pub fn site_packages(&self) -> PathBuf {
        self.home.join("site-packages")
    }

    pub fn conf(&self) -> PathBuf {
        self.data.join("relay.conf")
    }

    pub fn log(&self) -> PathBuf {
        self.data.join("relay.log")
    }

    /// The bundled interpreter and the relay code must be there (`<home>` is created by the relay bundle of the release).
    pub fn check_home(&self) -> Result<()> {
        for p in [self.python(), self.script()] {
            if !p.exists() {
                bail!("{} not found: the relay is not part of this installation (install the package with the relay, or pass --home DIR)", p.display());
            }
        }
        Ok(())
    }

    /// `python -s oneqrelay.py ARGS` with the bundled site-packages; `-s`: no user site, the script directory is the relay's own.
    pub fn command<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Command {
        let mut c = Command::new(self.python());
        c.arg("-s").arg(self.script()).args(args);
        c.env("PYTHONPATH", self.site_packages()).env("PYTHONDONTWRITEBYTECODE", "1").env("PYTHONUTF8", "1");
        c.env_remove("PYTHONHOME").env_remove("OPENSSL_CONF");
        c
    }

    /// TCP port of the relay (the STUN service uses it and the next two UDP ports): `listen` of relay.conf, default 8443.
    pub fn port(&self) -> u16 {
        let text = std::fs::read_to_string(self.conf()).unwrap_or_default();
        for l in text.lines() {
            let l = l.trim();
            if let Some(v) = l.strip_prefix("listen") {
                if let Some(v) = v.trim_start().strip_prefix('=') {
                    if let Some(p) = v.trim().rsplit(':').next().and_then(|p| p.parse().ok()) {
                        return p;
                    }
                }
            }
        }
        8443
    }
}

/// `oneqrelay.py init ...` (creates the certificates, secrets and relay.conf in <data>).
pub fn init(l: &Layout, rest: &[String]) -> Result<()> {
    l.check_home()?;
    let st = l.command::<OsString>(&["init".into(), "--dir".into(), l.data.clone().into_os_string()]).args(rest).status()?;
    if !st.success() {
        bail!("oneqrelay init failed");
    }
    Ok(())
}

/// Anything else of the relay's own CLI (`admin ...` against the running database, `gen-secret`...): config = <data>/relay.conf.
pub fn passthrough(l: &Layout, sub: &str, rest: &[String]) -> Result<()> {
    l.check_home()?;
    let st = l.command::<OsString>(&[sub.into(), "--config".into(), l.conf().into_os_string()]).args(rest).status()?;
    if !st.success() {
        bail!("oneqrelay {sub} failed");
    }
    Ok(())
}

/// Opens (or closes) the relay's ports in the host firewall: TCP port, UDP port..port+2 (STUN).
pub fn firewall(port: u16, open: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let run = |args: &[&str]| std::process::Command::new("netsh").args(args).output();
        for (name, proto, ports) in [("oneq relay (TCP)", "TCP", port.to_string()), ("oneq relay (UDP, STUN)", "UDP", format!("{}-{}", port, port + 2))] {
            let _ = run(&["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]);
            if open {
                let o = run(&["advfirewall", "firewall", "add", "rule", &format!("name={name}"), "dir=in", "action=allow", &format!("protocol={proto}"), &format!("localport={ports}")])?;
                if !o.status.success() {
                    bail!("netsh: {}", String::from_utf8_lossy(&o.stdout));
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (port, open); // macOS: the application firewall is handled in launchd::install; nothing else filters inbound traffic by default
    }
    Ok(())
}

// ------------------------------------------------------------------ Windows service

#[cfg(windows)]
pub mod winsvc {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const NAME: &str = "oneqrelay";
    const TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    static LAYOUT: OnceLock<Layout> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Entry of `oneqclient relay run-service`: hands the process to the service control manager.
    pub fn dispatch(l: Layout) -> Result<()> {
        let _ = LAYOUT.set(l);
        service_dispatcher::start(NAME, ffi_service_main).map_err(|e| anyhow!("not started by the service manager: {e}"))
    }

    fn report(h: &service_control_handler::ServiceStatusHandle, state: ServiceState, code: u32) {
        let accepted = if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() };
        let _ = h.set_service_status(ServiceStatus {
            service_type: TYPE,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: if state == ServiceState::StopPending { Duration::from_secs(10) } else { Duration::default() },
            process_id: None,
        });
    }

    fn service_main(_args: Vec<OsString>) {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handler = match service_control_handler::register(NAME, move |ev| match ev {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                s.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(h) => h,
            Err(_) => return,
        };
        report(&handler, ServiceState::StartPending, 0);
        let code = match LAYOUT.get().ok_or_else(|| anyhow!("no layout")).and_then(|l| l.check_home().map(|_| l)) {
            Ok(l) => {
                report(&handler, ServiceState::Running, 0);
                supervise(l, &stop);
                0
            }
            Err(e) => {
                eprintln!("{e:#}");
                1
            }
        };
        report(&handler, ServiceState::Stopped, code);
    }

    /// Runs `oneqrelay.py run --config relay.conf` and restarts it 5 s after it dies, until the service is stopped.
    fn supervise(l: &Layout, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            let log = std::fs::OpenOptions::new().create(true).append(true).open(l.log());
            let mut cmd = l.command::<OsString>(&["run".into(), "--config".into(), l.conf().into_os_string()]);
            cmd.creation_flags(CREATE_NO_WINDOW).current_dir(&l.data);
            if let Ok(f) = log {
                if let Ok(f2) = f.try_clone() {
                    cmd.stdout(f).stderr(f2);
                }
            }
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(_) => {
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            loop {
                if stop.load(Ordering::SeqCst) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(300)),
                }
            }
            for _ in 0..50 {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access).map_err(|e| anyhow!("service manager: {e} (administrator rights are required)"))
    }

    pub fn install(exe: &Path, l: &Layout, autostart: bool) -> Result<()> {
        let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "oneq relay (post-quantum mesh registry and relay)".into(),
            service_type: TYPE,
            start_type: if autostart { ServiceStartType::AutoStart } else { ServiceStartType::OnDemand },
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.to_path_buf(),
            launch_arguments: vec![
                "relay".into(),
                "run-service".into(),
                "--home".into(),
                l.home.clone().into_os_string(),
                "--data".into(),
                l.data.clone().into_os_string(),
            ],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let s = m
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .map_err(|e| anyhow!("create service: {e} (already installed? run `relay uninstall` first)"))?;
        s.set_description("Federated registry and relay of the oneq post-quantum mesh (oneqrelay).").map_err(|e| anyhow!("{e}"))?;
        s.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(10) }; 3]),
        })
        .map_err(|e| anyhow!("failure actions: {e}"))?;
        Ok(())
    }

    fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
        let m = manager(ServiceManagerAccess::CONNECT)?;
        m.open_service(NAME, access).map_err(|e| anyhow!("service '{NAME}' not found or not accessible: {e}"))
    }

    pub fn state() -> Result<ServiceState> {
        Ok(open(ServiceAccess::QUERY_STATUS)?.query_status().map_err(|e| anyhow!("{e}"))?.current_state)
    }

    pub fn start() -> Result<()> {
        open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?.start::<&str>(&[]).map_err(|e| anyhow!("start: {e}"))
    }

    fn wait_stopped(s: &windows_service::service::Service) -> Result<()> {
        for _ in 0..40 {
            if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state == ServiceState::Stopped {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(anyhow!("the service did not stop within 20 s"))
    }

    pub fn stop() -> Result<()> {
        let s = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state != ServiceState::Stopped {
            let _ = s.stop();
        }
        wait_stopped(&s)
    }

    pub fn uninstall() -> Result<()> {
        let s = open(ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state != ServiceState::Stopped {
            let _ = s.stop();
            let _ = wait_stopped(&s);
        }
        s.delete().map_err(|e| anyhow!("delete: {e}"))
    }
}

// ------------------------------------------------------------------ macOS (launchd), not tested: no Mac available

#[cfg(target_os = "macos")]
pub mod launchd {
    use super::*;

    pub const LABEL: &str = "ro.example.oneqrelay";

    fn uid() -> String {
        std::process::Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(|_| "501".into())
    }

    /// `user`: a LaunchAgent of the logged-in user (no administrator rights; runs while the user is logged in) instead of a system LaunchDaemon.
    fn plist_path(user: bool) -> PathBuf {
        if user {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("Library/LaunchAgents/ro.example.oneqrelay.plist")
        } else {
            PathBuf::from("/Library/LaunchDaemons/ro.example.oneqrelay.plist")
        }
    }

    fn domain(user: bool) -> String {
        if user { format!("gui/{}", uid()) } else { "system".into() }
    }

    pub fn install(l: &Layout, autostart: bool, user: bool) -> Result<()> {
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{py}</string><string>-s</string><string>{script}</string><string>run</string><string>--config</string><string>{conf}</string></array>
  <key>EnvironmentVariables</key><dict><key>PYTHONPATH</key><string>{site}</string><key>PYTHONDONTWRITEBYTECODE</key><string>1</string><key>PYTHONUTF8</key><string>1</string></dict>
  <key>WorkingDirectory</key><string>{data}</string>
  <key>RunAtLoad</key><{auto}/>
  <key>KeepAlive</key><{auto}/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
            py = l.python().display(),
            script = l.script().display(),
            conf = l.conf().display(),
            site = l.site_packages().display(),
            data = l.data.display(),
            log = l.log().display(),
            auto = if autostart { "true" } else { "false" }
        );
        let path = plist_path(user);
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&path, plist)?;
        let dom = domain(user);
        let _ = std::process::Command::new("launchctl").arg("bootout").arg(&dom).arg(&path).output();
        let out = std::process::Command::new("launchctl").arg("bootstrap").arg(&dom).arg(&path).output()?;
        if !out.status.success() {
            bail!("launchctl bootstrap: {}", String::from_utf8_lossy(&out.stderr));
        }
        if !user {
            // the application firewall asks about incoming connections of an unsigned interpreter: allow it up front (best effort, needs root)
            let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
            let py = l.python().canonicalize().unwrap_or_else(|_| l.python());
            let _ = std::process::Command::new(fw).arg("--add").arg(&py).output();
            let _ = std::process::Command::new(fw).arg("--unblockapp").arg(&py).output();
        }
        let _ = std::process::Command::new("launchctl").args(["kickstart", &format!("{dom}/{LABEL}")]).output();
        Ok(())
    }

    pub fn uninstall(user: bool) -> Result<()> {
        let path = plist_path(user);
        let _ = std::process::Command::new("launchctl").arg("bootout").arg(domain(user)).arg(&path).output();
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    pub fn control(action: &str, user: bool) -> Result<String> {
        let target = format!("{}/{LABEL}", domain(user));
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

    #[test]
    fn port_comes_from_the_listen_line() {
        let d = std::env::temp_dir().join(format!("oneq-relaysvc-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("relay.conf"), "[relay]\nid = a\nlisten = 0.0.0.0:9443\nlisten_x = 1\n").unwrap();
        let l = Layout::new(Some(d.clone()), Some(d.clone())).unwrap();
        assert_eq!(l.port(), 9443);
        std::fs::write(d.join("relay.conf"), "[relay]\n").unwrap();
        assert_eq!(l.port(), 8443);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_bundle_is_reported() {
        let l = Layout::new(Some(PathBuf::from("/nonexistent-oneq")), Some(PathBuf::from("/nonexistent-oneq-data"))).unwrap();
        assert!(l.check_home().unwrap_err().to_string().contains("not part of this installation"));
    }
}
