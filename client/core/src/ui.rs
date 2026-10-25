//! `oneqclient ui`: a local web interface (settings, status, export/import, service control) that needs no GUI toolkit,
//! so it works the same on macOS, Windows and Linux. It only listens on 127.0.0.1, every URL carries a random token,
//! and the Host header is checked (DNS rebinding). The node itself runs as the background service; this program
//! only edits its configuration and starts/stops it, asking for administrator rights when needed.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::rand;
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::svc;

const PAGE: &str = include_str!("ui.html");
const MAX_BODY: usize = 1024 * 1024;

pub struct UiConfig {
    /// per-user directory: ui.json (settings) and client.key (node key of the interactive user)
    pub user_dir: PathBuf,
    /// service directory (status.json)
    pub service_dir: PathBuf,
    /// the program started with administrator rights for `service ...` commands
    pub exe: PathBuf,
}

impl UiConfig {
    pub fn system() -> Result<Self> {
        Ok(UiConfig { user_dir: svc::user_dir(), service_dir: svc::service_dir(), exe: std::env::current_exe()? })
    }
    fn settings_file(&self) -> PathBuf {
        self.user_dir.join("ui.json")
    }
    pub fn key_file(&self) -> PathBuf {
        self.user_dir.join("client.key")
    }
}

pub fn new_token() -> String {
    let mut b = [0u8; 24];
    let _ = rand::fill(&mut b);
    hex::encode(b)
}

// ---------------------------------------------------------------------------------------------------- settings
const EMPTY_SETTINGS: &str = r#"{"relays":[],"community":"","user":"","name":"","ca_pem":"","force_relay":false,"accept_routes":false,"auto_start":false,"start_hidden":false}"#;

fn load_settings(c: &UiConfig) -> Value {
    std::fs::read_to_string(c.settings_file()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_else(|| serde_json::from_str(EMPTY_SETTINGS).unwrap())
}

/// Validates the `settings` object of an exported/typed form and returns the cleaned version.
pub fn validate_settings(v: &Value) -> Result<Value> {
    let relays = v["relays"].as_array().filter(|a| !a.is_empty()).ok_or_else(|| anyhow!("\"relays\" must be a list of https:// URLs"))?;
    let mut rl = Vec::new();
    for r in relays {
        let s = r.as_str().map(str::trim).filter(|s| s.starts_with("https://") && s.len() > 8).ok_or_else(|| anyhow!("\"relays\" must be a list of https:// URLs"))?;
        rl.push(s.to_string());
    }
    let text = |k: &str, required: bool| -> Result<String> {
        match v.get(k) {
            None | Some(Value::Null) if !required => Ok(String::new()),
            Some(Value::String(s)) if !required || !s.trim().is_empty() => Ok(s.trim().to_string()),
            _ => bail!("\"{k}\" is missing or not text"),
        }
    };
    let ca = match v.get("ca_pem") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        _ => bail!("\"ca_pem\" is not text"),
    };
    if !ca.trim().is_empty() && !ca.contains("BEGIN CERTIFICATE") {
        bail!("\"ca_pem\" is not a PEM certificate");
    }
    Ok(json!({
        "relays": rl,
        "community": text("community", true)?,
        "user": text("user", true)?,
        "name": text("name", false)?,
        "ca_pem": ca,
        "force_relay": v["force_relay"] == true,
        "accept_routes": v["accept_routes"] == true,
        "auto_start": v["auto_start"] == true,
        "start_hidden": v["start_hidden"] == true,
    }))
}

fn save_settings(c: &UiConfig, s: &Value) -> Result<()> {
    std::fs::create_dir_all(&c.user_dir)?;
    std::fs::write(c.settings_file(), serde_json::to_string_pretty(s)?)?;
    Ok(())
}

fn export(c: &UiConfig, settings: &Value, password: Option<&str>, with_key: bool) -> Result<String> {
    let mut m = json!({"format": "oneq-settings", "version": 1, "settings": settings});
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        m["password"] = json!(p);
    }
    if with_key {
        let k = std::fs::read_to_string(c.key_file()).map_err(|_| anyhow!("this device has no node key of its own yet (the service keeps its key where only administrators can read it)"))?;
        m["node_key"] = json!(k.trim());
    }
    Ok(serde_json::to_string_pretty(&m)?)
}

/// Returns (message, settings, password).
fn import(c: &UiConfig, text: &str) -> Result<(String, Value, Option<String>)> {
    let m: Value = serde_json::from_str(text).map_err(|_| anyhow!("Not a JSON file."))?;
    if m["format"] != "oneq-settings" {
        bail!("Not a oneq settings file.");
    }
    if m["version"] != 1 {
        bail!("Unsupported settings version {}.", m["version"]);
    }
    let s = validate_settings(&m["settings"])?;
    let mut parts = vec!["settings".to_string()];
    let password = m["password"].as_str().filter(|p| !p.is_empty()).map(String::from);
    if password.is_some() {
        parts.push("password (kept in the form only)".into());
    }
    let mut new_key = None;
    if let Some(k) = m["node_key"].as_str().filter(|k| !k.is_empty()) {
        let raw = base64::engine::general_purpose::STANDARD.decode(k.trim()).map_err(|_| anyhow!("The node key in the file is damaged."))?;
        if raw.len() != 32 + 2400 {
            bail!("The node key in the file is damaged.");
        }
        new_key = Some(k.trim().to_string());
    }
    // everything validated: now change things
    if let Some(k) = new_key {
        std::fs::create_dir_all(&c.user_dir)?;
        let f = c.key_file();
        if f.exists() {
            std::fs::rename(&f, f.with_extension("key.bak"))?;
        }
        std::fs::write(&f, format!("{k}\n"))?;
        parts.push("node key (the old one was kept as client.key.bak; reconnect to apply it)".into());
    }
    save_settings(c, &s)?;
    Ok((format!("Imported: {}.", parts.join(", ")), s, password))
}

// ---------------------------------------------------------------------------------------------------- service
fn installed() -> bool {
    #[cfg(windows)]
    {
        crate::winsvc::state().is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/LaunchDaemons/ro.1q.oneq.plist").exists()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        svc::default_config_path().exists()
    }
}

fn status_json(c: &UiConfig) -> Value {
    let (mut fresh, mut snapshot) = (false, Value::Null);
    if let Ok(t) = std::fs::read_to_string(c.service_dir.join("status.json")) {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            fresh = now.saturating_sub(v["updated"].as_u64().unwrap_or(0)) <= 10;
            snapshot = v["snapshot"].clone();
            if snapshot["state"] == "stopped" {
                fresh = false; // the supervisor writes one last file when it stops
            }
        }
    }
    json!({
        "installed": installed(),
        "running": fresh,
        "snapshot": snapshot,
        "settings": load_settings(c),
        "os": std::env::consts::OS,
        "has_key": c.key_file().exists(),
    })
}

fn is_privileged() -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("net").arg("session").output().map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(unix)]
    {
        std::process::Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false)
    }
}

#[cfg(not(windows))]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Runs `exe args...` for each command, as administrator/root. `(args, ignore_failure)`. One password prompt for all.
fn run_elevated(exe: &Path, cmds: &[(Vec<String>, bool)]) -> Result<String> {
    if is_privileged() {
        let mut out = String::new();
        for (args, ignore) in cmds {
            let o = std::process::Command::new(exe).args(args).output()?;
            out.push_str(&String::from_utf8_lossy(&o.stdout));
            if !o.status.success() && !ignore {
                bail!("{}", format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim());
            }
        }
        return Ok(out.trim().to_string());
    }
    #[cfg(windows)]
    {
        bail!("Administrator rights are required: start `oneqclient ui` from an elevated prompt.");
    }
    #[cfg(not(windows))]
    {
        let line = cmds
            .iter()
            .map(|(args, ignore)| {
                let c = std::iter::once(sh_quote(&exe.to_string_lossy())).chain(args.iter().map(|a| sh_quote(a))).collect::<Vec<_>>().join(" ");
                if *ignore { format!("{c} || true") } else { c }
            })
            .collect::<Vec<_>>()
            .join(" && ");
        let o = if cfg!(target_os = "macos") {
            let esc = line.replace('\\', "\\\\").replace('"', "\\\"");
            std::process::Command::new("osascript").args(["-e", &format!("do shell script \"{esc}\" with administrator privileges")]).output()?
        } else {
            std::process::Command::new("pkexec").args(["sh", "-c", &line]).output()?
        };
        if !o.status.success() {
            let e = String::from_utf8_lossy(&o.stderr);
            if e.contains("-128") {
                bail!("Cancelled.");
            }
            bail!("{}", e.trim());
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
}

fn private_temp(prefix: &str, content: &str) -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!("{prefix}-{}", new_token()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?.write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&p, content)?;
    Ok(p)
}

fn connect(c: &UiConfig, body: &Value) -> Result<String> {
    let s = validate_settings(&body["settings"])?;
    let password = body["password"].as_str().filter(|p| !p.is_empty()).ok_or_else(|| anyhow!("Enter the password."))?;
    save_settings(c, &s)?;
    let pw = private_temp("oneq-pw", password)?;
    let ca = match s["ca_pem"].as_str().filter(|p| !p.trim().is_empty()) {
        Some(pem) => Some(private_temp("oneq-ca", pem)?),
        None => None,
    };
    let mut args: Vec<String> = vec!["service".into(), "install".into()];
    for r in s["relays"].as_array().unwrap() {
        args.extend(["--relay".into(), r.as_str().unwrap().into()]);
    }
    args.extend(["--community".into(), s["community"].as_str().unwrap().into(), "--user".into(), s["user"].as_str().unwrap().into()]);
    args.extend(["--password-file".into(), pw.to_string_lossy().into_owned(), "--key-file".into(), c.key_file().to_string_lossy().into_owned()]);
    if let Some(n) = s["name"].as_str().filter(|n| !n.is_empty()) {
        args.extend(["--name".into(), n.into()]);
    }
    if let Some(ca) = &ca {
        args.extend(["--cafile".into(), ca.to_string_lossy().into_owned()]);
    }
    if s["force_relay"] == true {
        args.push("--force-relay".into());
    }
    if s["accept_routes"] == true {
        args.push("--accept-routes".into());
    }
    if s["auto_start"] != true {
        args.push("--no-autostart".into());
    }
    let r = run_elevated(&c.exe, &[(vec!["service".into(), "uninstall".into()], true), (args, false)]);
    let _ = std::fs::remove_file(&pw);
    if let Some(ca) = ca {
        let _ = std::fs::remove_file(ca);
    }
    r.map(|_| "Service installed and started.".to_string())
}

fn service_action(c: &UiConfig, what: &str) -> Result<String> {
    if !["start", "stop", "restart", "uninstall"].contains(&what) {
        bail!("unknown action");
    }
    run_elevated(&c.exe, &[(vec!["service".into(), what.into()], false)]).map(|_| format!("Service: {what} done."))
}

// ---------------------------------------------------------------------------------------------------- HTTP
struct Req {
    method: String,
    path: String,
    host: String,
    body: Vec<u8>,
}

async fn read_req(s: &mut TcpStream) -> Result<Req> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 16 * 1024 {
            bail!("headers too large");
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("closed");
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut rl = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (rl.next().unwrap_or("").to_string(), rl.next().unwrap_or("").to_string());
    let (mut host, mut len) = (String::new(), 0usize);
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "host" => host = v.trim().to_string(),
                "content-length" => len = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    if len > MAX_BODY {
        bail!("body too large");
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("closed");
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok(Req { method, path, host, body })
}

async fn respond(s: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(body).await;
    let _ = s.shutdown().await;
}

async fn json_reply(s: &mut TcpStream, r: Result<Value>) {
    match r {
        Ok(v) => respond(s, 200, "application/json", v.to_string().as_bytes()).await,
        Err(e) => respond(s, 400, "application/json", json!({"error": format!("{e:#}")}).to_string().as_bytes()).await,
    }
}

async fn handle(mut s: TcpStream, token: Arc<String>, cfg: Arc<UiConfig>, port: u16) {
    let req = match tokio::time::timeout(Duration::from_secs(10), read_req(&mut s)).await {
        Ok(Ok(r)) => r,
        _ => return respond(&mut s, 400, "text/plain", b"bad request").await,
    };
    if req.host != format!("127.0.0.1:{port}") && req.host != format!("localhost:{port}") {
        return respond(&mut s, 403, "text/plain", b"forbidden host").await;
    }
    let path = req.path.split('?').next().unwrap_or("");
    let prefix = format!("/{}/", token);
    let Some(rest) = path.strip_prefix(prefix.as_str()).or_else(|| (path == format!("/{token}")).then_some("")) else {
        return respond(&mut s, 404, "text/plain", b"not found").await;
    };
    let body: Value = if req.body.is_empty() { Value::Null } else { serde_json::from_slice(&req.body).unwrap_or(Value::Null) };
    match (req.method.as_str(), rest) {
        ("GET", "") => respond(&mut s, 200, "text/html; charset=utf-8", PAGE.as_bytes()).await,
        ("GET", "api/status") => {
            let c = cfg.clone();
            let v = tokio::task::spawn_blocking(move || status_json(&c)).await.unwrap_or(Value::Null);
            json_reply(&mut s, Ok(v)).await
        }
        ("POST", "api/settings") => {
            let r = validate_settings(&body).and_then(|v| save_settings(&cfg, &v).map(|_| json!({"ok": true})));
            json_reply(&mut s, r).await
        }
        ("POST", "api/connect") => {
            let c = cfg.clone();
            let r = tokio::task::spawn_blocking(move || connect(&c, &body)).await.unwrap_or_else(|e| Err(anyhow!("{e}")));
            json_reply(&mut s, r.map(|m| json!({"message": m}))).await
        }
        ("POST", "api/service") => {
            let c = cfg.clone();
            let what = body["action"].as_str().unwrap_or("").to_string();
            let r = tokio::task::spawn_blocking(move || service_action(&c, &what)).await.unwrap_or_else(|e| Err(anyhow!("{e}")));
            json_reply(&mut s, r.map(|m| json!({"message": m}))).await
        }
        ("POST", "api/export") => {
            let r = validate_settings(&body["settings"])
                .and_then(|st| export(&cfg, &st, body["password"].as_str().filter(|_| body["with_password"] == true), body["with_key"] == true));
            json_reply(&mut s, r.map(|t| json!({"text": t}))).await
        }
        ("POST", "api/import") => {
            let r = import(&cfg, body["text"].as_str().unwrap_or(""));
            json_reply(&mut s, r.map(|(m, st, pw)| json!({"message": m, "settings": st, "password": pw}))).await
        }
        _ => respond(&mut s, 404, "text/plain", b"not found").await,
    }
}

/// Serve until the process ends.
pub async fn serve(listener: TcpListener, token: String, cfg: Arc<UiConfig>) -> Result<()> {
    let port = listener.local_addr().context("local address")?.port();
    let token = Arc::new(token);
    loop {
        let (s, _) = listener.accept().await?;
        tokio::spawn(handle(s, token.clone(), cfg.clone(), port));
    }
}

pub fn open_browser(url: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn cfg(name: &str) -> Arc<UiConfig> {
        let d = std::env::temp_dir().join(format!("oneq-ui-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("svc")).unwrap();
        Arc::new(UiConfig { user_dir: d.join("user"), service_dir: d.join("svc"), exe: PathBuf::from("oneqclient") })
    }

    fn good() -> Value {
        json!({"relays": ["https://r1.example.org:8443", " https://r2.example.org "], "community": "lan", "user": "alice", "name": "mac", "ca_pem": CA, "force_relay": true, "auto_start": true})
    }

    async fn http(port: u16, host: &str, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let t = String::from_utf8_lossy(&out).into_owned();
        let code = t.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, t.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
    }

    async fn start(c: Arc<UiConfig>) -> (u16, String) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let token = new_token();
        tokio::spawn(serve(l, token.clone(), c));
        (port, token)
    }

    #[test]
    fn settings_are_validated_and_cleaned() {
        let v = validate_settings(&good()).unwrap();
        assert_eq!((v["auto_start"].clone(), v["start_hidden"].clone()), (json!(true), json!(false))); // same fields as the apps
        assert_eq!(v["relays"], json!(["https://r1.example.org:8443", "https://r2.example.org"]));
        for (k, bad) in [("relays", json!(["http://plain"])), ("relays", json!([])), ("community", json!("")), ("user", json!(7)), ("ca_pem", json!("junk"))] {
            let mut g = good();
            g[k] = bad;
            assert!(validate_settings(&g).is_err(), "{k}");
        }
    }

    #[test]
    fn export_import_roundtrip_with_secrets_only_on_request() {
        let a = cfg("a");
        let key = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 32 + 2400]);
        std::fs::create_dir_all(&a.user_dir).unwrap();
        std::fs::write(a.key_file(), format!("{key}\n")).unwrap();
        let s = validate_settings(&good()).unwrap();
        let plain = export(&a, &s, None, false).unwrap();
        assert!(!plain.contains("password") && !plain.contains("node_key"));
        let full = export(&a, &s, Some("pw!"), true).unwrap();
        let b = cfg("b");
        std::fs::create_dir_all(&b.user_dir).unwrap();
        std::fs::write(b.key_file(), "old\n").unwrap();
        let (msg, st, pw) = import(&b, &full).unwrap();
        assert!(msg.contains("node key") && msg.contains("password"));
        assert_eq!((st, pw.as_deref()), (s.clone(), Some("pw!")));
        assert_eq!(std::fs::read_to_string(b.key_file()).unwrap().trim(), key);
        assert_eq!(std::fs::read_to_string(b.user_dir.join("client.key.bak")).unwrap().trim(), "old");
        assert_eq!(load_settings(&b), s); // persisted
        // bad files change nothing
        let c = cfg("c");
        for t in ["nope", r#"{"format":"x"}"#, r#"{"format":"oneq-settings","version":2}"#] {
            assert!(import(&c, t).is_err());
        }
        let mut m: Value = serde_json::from_str(&full).unwrap();
        m["node_key"] = json!("AAAA");
        assert!(import(&c, &m.to_string()).is_err());
        assert!(!c.settings_file().exists() && !c.key_file().exists());
    }

    #[tokio::test]
    async fn only_the_right_host_and_token_get_in() {
        let c = cfg("http");
        let (port, token) = start(c.clone()).await;
        let h = format!("127.0.0.1:{port}");
        assert_eq!(http(port, &h, "GET", &format!("/{token}/"), "").await.0, 200);
        assert_eq!(http(port, &format!("localhost:{port}"), "GET", &format!("/{token}/"), "").await.0, 200);
        assert_eq!(http(port, "evil.example.org", "GET", &format!("/{token}/"), "").await.0, 403); // DNS rebinding
        assert_eq!(http(port, &h, "GET", "/", "").await.0, 404);
        assert_eq!(http(port, &h, "GET", "/wrong/api/status", "").await.0, 404);
        assert_eq!(http(port, &h, "GET", &format!("/{token}/../x"), "").await.0, 404);
        let (code, body) = http(port, &h, "GET", &format!("/{token}/api/status"), "").await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((code, v["running"].clone(), v["settings"]["relays"].clone()), (200, json!(false), json!([])));
        // settings roundtrip through the API
        assert_eq!(http(port, &h, "POST", &format!("/{token}/api/settings"), &good().to_string()).await.0, 200);
        assert_eq!(http(port, &h, "POST", &format!("/{token}/api/settings"), r#"{"relays":["http://x"]}"#).await.0, 400);
        let (_, body) = http(port, &h, "GET", &format!("/{token}/api/status"), "").await;
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["settings"]["community"], "lan");
        // connecting without a password is refused before anything privileged happens
        let (code, body) = http(port, &h, "POST", &format!("/{token}/api/connect"), &json!({"settings": good()}).to_string()).await;
        assert_eq!(code, 400);
        assert!(body.contains("password"));
    }

    #[test]
    fn fresh_status_file_means_running() {
        let c = cfg("st");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        std::fs::write(c.service_dir.join("status.json"), json!({"updated": now, "snapshot": {"state": "connected", "ip": "10.0.0.2"}}).to_string()).unwrap();
        let v = status_json(&c);
        assert_eq!((v["running"].clone(), v["snapshot"]["ip"].clone()), (json!(true), json!("10.0.0.2")));
        std::fs::write(c.service_dir.join("status.json"), json!({"updated": now - 60, "snapshot": {}}).to_string()).unwrap();
        assert_eq!(status_json(&c)["running"], json!(false)); // stale: the service stopped
        std::fs::write(c.service_dir.join("status.json"), json!({"updated": now, "snapshot": {"state": "stopped"}}).to_string()).unwrap();
        assert_eq!(status_json(&c)["running"], json!(false)); // the final file of a clean stop is fresh but not running
    }
}
