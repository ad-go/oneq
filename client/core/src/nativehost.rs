//! Native messaging host of the browser extension (`oneqclient native-host`): lets the extension alone set up and run the connection to the mesh.
//!
//! The browser starts this program when the extension calls `connectNative("ro.1q.oneq")` and talks to it over stdin/stdout (4-byte little-endian length, then JSON).
//! The host keeps the connection settings of the extension (relays, community, user, device name, CA, password), starts `oneqclient proxy` as a child process with
//! them and stops it when the browser goes away: the SOCKS5 port exists only while the browser session does. Only the extensions named in the host manifest
//! (`allowed_origins` / `allowed_extensions`) can start it, which is enforced by the browser.
//!
//! The password is received once, written to a file that only this user can read, and never sent back, logged or put on a command line.
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const HOST_NAME: &str = "ro.1q.oneq";
pub const GECKO_ID: &str = "k@1q.ro";
/// Extension id of the builds that carry the development `key` in their manifest (the install packs, the unpacked folder).
pub const DEV_EXTENSION_ID: &str = "bgmdbjhjoieanbojmbkjpcdmkmofikoo";
const MAX_IN: usize = 1 << 20;

/// The browsers start the host with the caller's origin (`chrome-extension://ID/`, Chromium) or with the manifest path and the add-on id (Firefox).
pub fn is_launch(args: &[String]) -> bool {
    match args.first() {
        Some(a) if a.starts_with("chrome-extension://") => true,
        Some(a) if a.ends_with(".json") && args.get(1).map_or(false, |b| b.contains('@')) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------- framing
pub fn read_msg(r: &mut impl Read) -> io::Result<Option<Value>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_IN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write_msg(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(v)?;
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

// ---------------------------------------------------------------------------------------------------------------------------------- settings
#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct BrowserConfig {
    pub relays: Vec<String>,
    pub community: String,
    pub user: String,
    pub name: String,
    pub ca_pem: String,
}

impl BrowserConfig {
    pub fn complete(&self) -> bool {
        !self.relays.is_empty() && !self.community.is_empty() && !self.user.is_empty()
    }
}

fn clean_name(s: &str) -> bool {
    s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validates what the extension sent; the values end up in a command line, so they are strict.
pub fn validate(v: &Value) -> Result<BrowserConfig> {
    let text = |k: &str| -> Result<String> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.trim().to_string()),
            _ => bail!("\"{k}\" must be text"),
        }
    };
    let mut relays = Vec::new();
    match v.get("relays") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for r in a {
                let s = r.as_str().map(str::trim).unwrap_or("");
                if !s.is_empty() {
                    relays.push(s.to_string());
                }
            }
        }
        _ => bail!("\"relays\" must be a list"),
    }
    if relays.len() > 8 {
        bail!("at most 8 relays");
    }
    for r in &relays {
        if !r.starts_with("https://") || r.len() < 9 || r.len() > 200 || r.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"') {
            bail!("a relay must be an https:// URL without spaces: {r:?}");
        }
    }
    let c = BrowserConfig { relays, community: text("community")?, user: text("user")?, name: text("name")?, ca_pem: text("ca_pem")? };
    for (what, s) in [("community", &c.community), ("user", &c.user)] {
        if s.len() > 100 || s.chars().any(|ch| ch.is_control() || ch == '"') {
            bail!("\"{what}\" has characters that are not allowed");
        }
    }
    if !c.name.is_empty() && !clean_name(&c.name) {
        bail!("the device name may use letters, digits, '-', '_' and '.' (at most 63)");
    }
    if !c.ca_pem.is_empty() && (!c.ca_pem.contains("BEGIN CERTIFICATE") || c.ca_pem.len() > 20_000) {
        bail!("\"ca_pem\" is not a PEM certificate");
    }
    Ok(c)
}

// ---------------------------------------------------------------------------------------------------------------------------------- the host
pub struct Host {
    dir: PathBuf,
    exe: PathBuf,
    child: Option<Child>,
    pid: u32,
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(path);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        // the user's profile directory is only readable by this user (and administrators)
        std::fs::write(path, data)
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            for n in it.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl Host {
    pub fn new(dir: PathBuf) -> Result<Host> {
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Host { dir, exe: std::env::current_exe()?, child: None, pid: std::process::id() })
    }

    fn cfg_path(&self) -> PathBuf {
        self.dir.join("browser.json")
    }
    fn pass_path(&self) -> PathBuf {
        self.dir.join("browser.pass")
    }
    fn ca_path(&self) -> PathBuf {
        self.dir.join("browser-ca.pem")
    }
    fn log_path(&self) -> PathBuf {
        self.dir.join("browser-proxy.log")
    }

    pub fn config(&self) -> BrowserConfig {
        std::fs::read_to_string(self.cfg_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    fn has_password(&self) -> bool {
        std::fs::metadata(self.pass_path()).map(|m| m.len() > 0).unwrap_or(false)
    }

    fn running(&mut self) -> bool {
        match self.child.as_mut().map(|c| c.try_wait()) {
            Some(Ok(None)) => true,
            Some(_) => {
                self.child = None;
                false
            }
            None => false,
        }
    }

    fn log_tail(&self) -> String {
        let t = std::fs::read_to_string(self.log_path()).unwrap_or_default();
        let lines: Vec<String> = t.lines().map(strip_ansi).filter(|l| !l.trim().is_empty()).collect();
        let tail = lines[lines.len().saturating_sub(6)..].join("\n");
        tail.chars().rev().take(900).collect::<Vec<_>>().into_iter().rev().collect()
    }

    fn state(&mut self) -> Value {
        let c = self.config();
        let running = self.running();
        json!({"ok": true, "config": {"relays": c.relays, "community": c.community, "user": c.user, "name": c.name, "ca_set": !c.ca_pem.is_empty()},
               "has_password": self.has_password(), "complete": c.complete() && self.has_password(), "running": running, "log": self.log_tail()})
    }

    fn set(&mut self, req: &Value) -> Result<Value> {
        let mut c = validate(req.get("config").ok_or_else(|| anyhow!("\"config\" is missing"))?)?;
        let old = self.config();
        if req["config"].get("ca_pem").is_none() || req["config"]["ca_pem"].is_null() {
            c.ca_pem = old.ca_pem; // not sent: keep the stored CA
        }
        self.stop();
        match req.get("password") {
            Some(Value::String(p)) if !p.is_empty() => {
                if p.len() > 256 || p.contains('\n') || p.contains('\r') {
                    bail!("the password is too long or has line breaks");
                }
                write_private(&self.pass_path(), p.as_bytes())?;
            }
            _ => {
                if req.get("clear_password") == Some(&Value::Bool(true)) {
                    let _ = std::fs::remove_file(self.pass_path());
                }
            }
        }
        std::fs::write(self.cfg_path(), serde_json::to_string_pretty(&c)?)?;
        Ok(self.state())
    }

    /// For installers and scripts: the same as the extension's "set" (settings, optionally a password), without a browser.
    pub fn configure(&mut self, config: Value, password: Option<String>) -> Result<Value> {
        let mut req = json!({"cmd": "set", "config": config});
        if let Some(p) = password {
            req["password"] = Value::String(p);
        }
        self.set(&req)
    }

    pub fn start(&mut self) -> Result<Value> {
        if self.running() {
            return Ok(self.state());
        }
        let c = self.config();
        if !c.complete() {
            bail!("the connection is not set up (relays, community and user are needed)");
        }
        if !self.has_password() {
            bail!("the password is not set");
        }
        let mut cmd = Command::new(&self.exe);
        cmd.arg("proxy");
        for r in &c.relays {
            cmd.args(["--relay", r]);
        }
        cmd.args(["--community", &c.community, "--user", &c.user]).arg("--password-file").arg(self.pass_path());
        if !c.ca_pem.is_empty() {
            write_private(&self.ca_path(), c.ca_pem.as_bytes())?;
            cmd.arg("--cafile").arg(self.ca_path());
        }
        if !c.name.is_empty() {
            cmd.args(["--name", &c.name]);
        }
        cmd.arg("--key-file").arg(self.dir.join("proxy.key"));
        cmd.args(["--exit-with-pid", &self.pid.to_string()]);
        let log = std::fs::File::create(self.log_path())?;
        cmd.stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log); // never the host's own stdout: that is the protocol
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        self.child = Some(cmd.spawn().with_context(|| format!("start {}", self.exe.display()))?);
        std::thread::sleep(std::time::Duration::from_millis(400));
        Ok(self.state())
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn handle(&mut self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let r: Result<Value> = match req.get("cmd").and_then(Value::as_str) {
            Some("hello") => Ok(json!({"ok": true, "host": HOST_NAME, "version": env!("CARGO_PKG_VERSION"), "os": std::env::consts::OS})),
            Some("get") | Some("status") => Ok(self.state()),
            Some("set") => self.set(req),
            Some("start") => self.start(),
            Some("stop") => {
                self.stop();
                Ok(self.state())
            }
            other => Err(anyhow!("unknown command {:?}", other)),
        };
        let mut v = r.unwrap_or_else(|e| {
            let mut s = self.state();
            s["ok"] = Value::Bool(false);
            s["error"] = Value::String(format!("{e:#}"));
            s
        });
        v["id"] = id;
        v
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The message loop; returns when the browser closes the pipe (and then stops the proxy it started).
pub fn run(dir: PathBuf, mut input: impl Read, mut output: impl Write) -> Result<()> {
    let mut host = Host::new(dir)?;
    loop {
        match read_msg(&mut input) {
            Ok(Some(req)) => {
                let reply = host.handle(&req);
                if write_msg(&mut output, &reply).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = write_msg(&mut output, &json!({"ok": false, "error": format!("bad message: {e}")}));
                break;
            }
        }
    }
    host.stop();
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------------------- is a process alive
/// Used by `proxy --exit-with-pid`: the proxy started by the host ends when the host (and with it the browser session) is gone.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};
        // SAFETY: plain handle calls; the handle is closed
        unsafe {
            let h = OpenProcess(0x0010_0000 /* SYNCHRONIZE */, 0, pid);
            if h.is_null() {
                return false;
            }
            let r = WaitForSingleObject(h, 0);
            CloseHandle(h);
            r != 0 // WAIT_OBJECT_0: the process has ended
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the process exists
        let r = unsafe { libc::kill(pid as i32, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) // EPERM: it exists, it is just not ours
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        true
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------- registration
pub struct Target {
    pub name: &'static str,
    pub firefox: bool,
    /// Windows registry key (HKCU) of the browser's NativeMessagingHosts.
    #[allow(dead_code)]
    pub reg: &'static str,
    /// Directories of the browser on macOS and Linux; the host is registered only when the browser's own directory (the parent) exists.
    #[allow(dead_code)]
    pub mac: &'static str,
    #[allow(dead_code)]
    pub linux: &'static str,
}

pub const TARGETS: &[Target] = &[
    Target { name: "chrome", firefox: false, reg: r"Software\Google\Chrome\NativeMessagingHosts", mac: "Google/Chrome", linux: ".config/google-chrome" },
    Target { name: "brave", firefox: false, reg: r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts", mac: "BraveSoftware/Brave-Browser", linux: ".config/BraveSoftware/Brave-Browser" },
    Target { name: "edge", firefox: false, reg: r"Software\Microsoft\Edge\NativeMessagingHosts", mac: "Microsoft Edge", linux: ".config/microsoft-edge" },
    Target { name: "chromium", firefox: false, reg: r"Software\Chromium\NativeMessagingHosts", mac: "Chromium", linux: ".config/chromium" },
    Target { name: "firefox", firefox: true, reg: r"Software\Mozilla\NativeMessagingHosts", mac: "Mozilla", linux: ".mozilla" },
];

pub fn manifest(exe: &Path, firefox: bool, extension_ids: &[String]) -> Value {
    let mut m = json!({"name": HOST_NAME, "description": "oneq mesh: connection of the browser extension", "path": exe.to_string_lossy(), "type": "stdio"});
    if firefox {
        m["allowed_extensions"] = json!([GECKO_ID]);
    } else {
        m["allowed_origins"] = json!(extension_ids.iter().map(|i| format!("chrome-extension://{i}/")).collect::<Vec<_>>());
    }
    m
}

fn clean_exe(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy().to_string();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

/// Registers the host for the given browsers (all when `only` is empty). Returns one line per browser that was handled.
pub fn install(dir: &Path, extension_ids: &[String], only: &[String]) -> Result<Vec<String>> {
    let exe = clean_exe(std::env::current_exe()?.canonicalize()?);
    let ids: Vec<String> = if extension_ids.is_empty() { vec![DEV_EXTENSION_ID.to_string()] } else { extension_ids.to_vec() };
    let nm = dir.join("native-host");
    std::fs::create_dir_all(&nm)?;
    let mut out = Vec::new();
    for t in TARGETS {
        if !only.is_empty() && !only.iter().any(|o| o == t.name) {
            continue;
        }
        let file = nm.join(format!("{HOST_NAME}.{}.json", if t.firefox { "firefox" } else { "chromium" }));
        std::fs::write(&file, serde_json::to_string_pretty(&manifest(&exe, t.firefox, &ids))?)?;
        out.push(register(t, &file)?);
    }
    Ok(out)
}

#[cfg(windows)]
fn register(t: &Target, file: &Path) -> Result<String> {
    let key = format!(r"HKCU\{}\{HOST_NAME}", t.reg);
    let r = Command::new("reg").args(["add", &key, "/ve", "/t", "REG_SZ", "/d"]).arg(file).arg("/f").output().context("run reg.exe")?;
    if !r.status.success() {
        bail!("reg add {key}: {}", String::from_utf8_lossy(&r.stderr).trim());
    }
    Ok(format!("{}: {key} -> {}", t.name, file.display()))
}

#[cfg(unix)]
fn register(t: &Target, file: &Path) -> Result<String> {
    let home = PathBuf::from(std::env::var("HOME").context("HOME is not set")?);
    let base = if cfg!(target_os = "macos") { home.join("Library/Application Support").join(t.mac) } else { home.join(t.linux) };
    if !base.exists() {
        return Ok(format!("{}: not installed here (no {}), skipped", t.name, base.display()));
    }
    let dest = if cfg!(target_os = "macos") || !t.firefox && cfg!(target_os = "linux") {
        base.join("NativeMessagingHosts")
    } else {
        base.join("native-messaging-hosts")
    };
    std::fs::create_dir_all(&dest)?;
    let target = dest.join(format!("{HOST_NAME}.json"));
    std::fs::copy(file, &target)?;
    Ok(format!("{}: {}", t.name, target.display()))
}

#[cfg(not(any(windows, unix)))]
fn register(t: &Target, _file: &Path) -> Result<String> {
    Ok(format!("{}: not supported on this system", t.name))
}

pub fn uninstall(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for t in TARGETS {
        #[cfg(windows)]
        {
            let key = format!(r"HKCU\{}\{HOST_NAME}", t.reg);
            let r = Command::new("reg").args(["delete", &key, "/f"]).output();
            out.push(format!("{}: {}", t.name, if r.map(|o| o.status.success()).unwrap_or(false) { "removed" } else { "was not registered" }));
        }
        #[cfg(unix)]
        {
            let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
            let base = if cfg!(target_os = "macos") { home.join("Library/Application Support").join(t.mac) } else { home.join(t.linux) };
            let mut gone = false;
            for d in ["NativeMessagingHosts", "native-messaging-hosts"] {
                gone |= std::fs::remove_file(base.join(d).join(format!("{HOST_NAME}.json"))).is_ok();
            }
            out.push(format!("{}: {}", t.name, if gone { "removed" } else { "was not registered" }));
        }
    }
    let _ = std::fs::remove_dir_all(dir.join("native-host"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: &Value) -> Value {
        let mut buf = Vec::new();
        write_msg(&mut buf, v).unwrap();
        assert_eq!(u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize, buf.len() - 4);
        read_msg(&mut io::Cursor::new(buf)).unwrap().unwrap()
    }

    #[test]
    fn messages_have_a_little_endian_length_prefix_and_survive_a_round_trip() {
        let v = json!({"cmd": "set", "config": {"name": "ünï-€"}});
        assert_eq!(roundtrip(&v), v);
        assert!(read_msg(&mut io::Cursor::new(Vec::<u8>::new())).unwrap().is_none(), "EOF is a clean end");
        let mut big = (MAX_IN as u32 + 1).to_le_bytes().to_vec();
        big.extend([0u8; 8]);
        assert!(read_msg(&mut io::Cursor::new(big)).is_err(), "an oversized message is refused");
        let mut bad = 3u32.to_le_bytes().to_vec();
        bad.extend(b"{x}");
        assert!(read_msg(&mut io::Cursor::new(bad)).is_err());
    }

    #[test]
    fn the_browsers_launch_arguments_are_recognised() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_launch(&a(&["chrome-extension://abc/"])));
        assert!(is_launch(&a(&["chrome-extension://abc/", "--parent-window=123"])));
        assert!(is_launch(&a(&["C:\\x\\ro.1q.oneq.firefox.json", "k@1q.ro"])));
        for no in [vec![], vec!["proxy"], vec!["ui", "--no-open"], vec!["native-host"], vec!["x.json"]] {
            assert!(!is_launch(&a(&no)), "{no:?}");
        }
    }

    #[test]
    fn settings_are_validated_strictly() {
        let ok = validate(&json!({"relays": ["https://r1.example.org:8443", " https://r2.example.org "], "community": "lan", "user": "alice", "name": "my-laptop"})).unwrap();
        assert_eq!(ok.relays, vec!["https://r1.example.org:8443", "https://r2.example.org"]);
        assert!(ok.complete());
        for bad in [
            json!({"relays": ["http://plain.example.org"]}),
            json!({"relays": ["https://a b.example.org"]}),
            json!({"relays": ["https://x\".example.org"]}),
            json!({"relays": "https://x.example.org"}),
            json!({"relays": ["https://x.example.org"], "user": "a\"b"}),
            json!({"relays": ["https://x.example.org"], "name": "no spaces"}),
            json!({"relays": ["https://x.example.org"], "name": "semi;colon"}),
            json!({"relays": ["https://x.example.org"], "ca_pem": "not a certificate"}),
            json!({"relays": ["https://x.example.org"], "community": 5}),
        ] {
            assert!(validate(&bad).is_err(), "{bad}");
        }
        assert!(!validate(&json!({})).unwrap().complete());
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oneq-nh-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_password_is_stored_but_never_returned_logged_or_put_in_a_command_line() {
        let d = tmp("pw");
        let mut h = Host::new(d.clone()).unwrap();
        let secret = "s3cr3t-Pa55word!";
        let r = h.handle(&json!({"id": 7, "cmd": "set", "config": {"relays": ["https://r.example.org:8443"], "community": "lan", "user": "alice"}, "password": secret}));
        assert_eq!(r["ok"], true);
        assert_eq!(r["id"], 7);
        assert_eq!(r["has_password"], true);
        assert_eq!(r["complete"], true);
        assert!(!r.to_string().contains(secret), "the password must not come back");
        assert_eq!(std::fs::read_to_string(d.join("browser.pass")).unwrap(), secret);
        assert!(!std::fs::read_to_string(d.join("browser.json")).unwrap().contains(secret), "not in the settings file either");
        // keeping the stored password when none is sent, clearing it on request
        let r = h.handle(&json!({"id": 8, "cmd": "set", "config": {"relays": ["https://r.example.org:8443"], "community": "lan", "user": "bob"}}));
        assert_eq!(r["has_password"], true);
        assert_eq!(h.config().user, "bob");
        let r = h.handle(&json!({"id": 9, "cmd": "set", "config": {"relays": ["https://r.example.org:8443"], "community": "lan", "user": "bob"}, "clear_password": true}));
        assert_eq!(r["has_password"], false);
        assert_eq!(r["complete"], false);
        // a start without a password is refused with a message
        let r = h.handle(&json!({"id": 10, "cmd": "start"}));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("password"));
        // wrong input does not touch the stored settings
        let before = h.config();
        let r = h.handle(&json!({"id": 11, "cmd": "set", "config": {"relays": ["http://insecure"], "user": "mallory"}}));
        assert_eq!(r["ok"], false);
        assert_eq!(h.config(), before);
        assert_eq!(h.handle(&json!({"id": 12, "cmd": "nope"}))["ok"], false);
        drop(h);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_host_manifests_name_only_the_allowed_extensions() {
        let exe = Path::new("/opt/oneq/oneqclient");
        let c = manifest(exe, false, &["abcdefghijklmnopabcdefghijklmnop".into()]);
        assert_eq!(c["name"], "ro.1q.oneq");
        assert_eq!(c["type"], "stdio");
        assert_eq!(c["allowed_origins"], json!(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]));
        assert!(c.get("allowed_extensions").is_none());
        let f = manifest(exe, true, &[]);
        assert_eq!(f["allowed_extensions"], json!(["k@1q.ro"]));
        assert!(f.get("allowed_origins").is_none());
        assert!(!DEV_EXTENSION_ID.is_empty() && DEV_EXTENSION_ID.len() == 32 && DEV_EXTENSION_ID.chars().all(|c| ('a'..='p').contains(&c)));
    }

    #[test]
    fn a_process_that_is_gone_is_not_alive_and_this_one_is() {
        assert!(pid_alive(std::process::id()));
        let mut c = if cfg!(windows) { Command::new("cmd").args(["/C", "exit 0"]).spawn().unwrap() } else { Command::new("true").spawn().unwrap() };
        let pid = c.id();
        c.wait().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!pid_alive(pid));
    }
}
