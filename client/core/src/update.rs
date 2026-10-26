//! Update check: asks GitHub whether a newer oneq release exists and, on request, downloads the installer for this platform
//! and verifies its SHA-256 against the release's `SHA256SUMS`. Nothing is ever installed or executed.
//!
//! Network policy (shared specification of all oneq components): HTTPS only (plain `http://127.0.0.1` only when the test override
//! `ONEQ_UPDATE_URL` is set), at most 5 redirects, every hop on an allowlisted GitHub host, 10 s connect / 30 s per read,
//! API answer <= 1 MB, SHA256SUMS <= 64 KB, download <= 200 MB. This is classical TLS to a public web server with the Mozilla
//! roots; it deliberately does not use the post-quantum-only configuration of `tls.rs` (that one is for the oneq relays).
use std::cmp::Ordering;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::{digest, rand};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const API_URL: &str = "https://api.github.com/repos/ad-go/oneq/releases/latest";
const MAX_API: u64 = 1024 * 1024;
const MAX_SUMS: u64 = 64 * 1024;
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
const ERROR_TTL: Duration = Duration::from_secs(300);
const MIN_FORCE: Duration = Duration::from_secs(60);
const AUTO_EVERY: Duration = Duration::from_secs(24 * 3600);
const NOTES_MAX: usize = 600;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub download_url: String,
}

/// The shared result object (same JSON everywhere): `status` is newer|current|unknown|error.
#[derive(Clone, Debug, Serialize, Default, PartialEq)]
pub struct UpdateResult {
    pub current: String,
    pub latest: String,
    pub update_available: bool,
    pub status: String,
    pub url: String,
    pub notes: String,
    pub asset: Option<Asset>,
    pub checked_at: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub api_url: String,
    /// plain http to 127.0.0.1 is allowed (tests only, via ONEQ_UPDATE_URL)
    pub loopback_http: bool,
    /// the installer of this platform; `None` (Linux): newer versions are still reported
    pub asset_name: Option<String>,
    pub max_download: u64,
}

impl Opts {
    pub fn from_env() -> Self {
        let over = std::env::var("ONEQ_UPDATE_URL").ok().filter(|u| !u.trim().is_empty());
        Opts {
            loopback_http: over.is_some(),
            api_url: over.unwrap_or_else(|| API_URL.into()),
            asset_name: platform_asset().map(String::from),
            max_download: MAX_DOWNLOAD,
        }
    }
}

/// Installer offered by this build: Windows msi, macOS tar.gz of the CPU architecture, Android apk, nothing on Linux.
pub fn platform_asset() -> Option<&'static str> {
    if cfg!(target_os = "windows") {
        Some("oneq-node-windows-x64.msi")
    } else if cfg!(target_os = "macos") {
        Some(if cfg!(target_arch = "aarch64") { "oneq-node-macos-arm64.tar.gz" } else { "oneq-node-macos-x64.tar.gz" })
    } else if cfg!(target_os = "android") {
        Some("oneq-android.apk")
    } else {
        None
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ------------------------------------------------------------------------------------------------ versions, release JSON
/// "v0.0.2-rc1+x" -> [0, 0, 2]; `None` when a component is not a number.
pub fn parse_version(s: &str) -> Option<Vec<u64>> {
    let s = s.trim();
    let s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
    let core = s.split(['-', '+']).next()?;
    if core.is_empty() {
        return None;
    }
    core.split('.').map(|p| if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) { None } else { p.parse().ok() }).collect()
}

/// `None` when either side does not parse (never "newer" then).
pub fn compare_versions(remote: &str, local: &str) -> Option<Ordering> {
    let (mut a, mut b) = (parse_version(remote)?, parse_version(local)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}

/// `<hex>  <name>`, `<hex> *<name>`, names with `./` or a directory prefix: keyed by the base name, hex lower-cased.
pub fn parse_sums(text: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((hash, rest)) = line.split_once(char::is_whitespace) else { continue };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let name = rest.trim_start().trim_start_matches('*').trim();
        let base = name.rsplit(['/', '\\']).next().unwrap_or("");
        if !base.is_empty() {
            m.insert(base.to_string(), hash.to_ascii_lowercase());
        }
    }
    m
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 200 && n != "." && n != ".." && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn clean_notes(s: &str) -> String {
    let t: String = s.chars().filter(|c| *c == '\n' || *c == '\t' || !c.is_control()).collect();
    let t = t.replace("\r", "");
    let t = t.trim();
    if t.chars().count() <= NOTES_MAX {
        t.to_string()
    } else {
        let mut x: String = t.chars().take(NOTES_MAX - 1).collect();
        x.push('…');
        x
    }
}

fn base_result(current: &str) -> UpdateResult {
    UpdateResult { current: current.into(), status: "unknown".into(), checked_at: now(), ..Default::default() }
}

fn error_result(current: &str, e: impl std::fmt::Display) -> UpdateResult {
    let mut t = e.to_string();
    t.truncate(200);
    UpdateResult { status: "error".into(), error: Some(t), ..base_result(current) }
}

/// Turns the GitHub "latest release" JSON into the result object. `wanted`: asset name of this platform.
pub fn parse_release(body: &[u8], current: &str, wanted: Option<&str>) -> UpdateResult {
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return error_result(current, "bad JSON from the update server") };
    let Some(tag) = v["tag_name"].as_str() else { return error_result(current, "no tag_name in the release") };
    let latest = tag.trim().trim_start_matches(['v', 'V']).to_string();
    let mut r = base_result(current);
    r.latest = latest.clone();
    r.url = v["html_url"].as_str().filter(|u| u.starts_with("https://")).unwrap_or("").to_string();
    r.notes = clean_notes(v["body"].as_str().unwrap_or(""));
    if v["draft"] == true || v["prerelease"] == true {
        r.status = "current".into();
        r.latest = current.into();
        return r;
    }
    match compare_versions(&latest, current) {
        Some(Ordering::Greater) => {
            r.status = "newer".into();
            r.update_available = true;
        }
        Some(_) => r.status = "current".into(),
        None => r.status = "unknown".into(),
    }
    if let (Some(w), Some(list)) = (wanted, v["assets"].as_array()) {
        r.asset = list
            .iter()
            .find(|a| a["name"].as_str() == Some(w))
            .and_then(|a| {
                let url = a["download_url"].as_str().or_else(|| a["browser_download_url"].as_str())?;
                (valid_name(w) && url.starts_with("http")).then(|| Asset { name: w.into(), size: a["size"].as_u64().unwrap_or(0), download_url: url.into() })
            });
    }
    r
}

// ------------------------------------------------------------------------------------------------ URLs
#[derive(Debug, Clone)]
struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> Result<Url> {
    if u.bytes().any(|b| b <= b' ' || b == 0x7f) {
        bail!("bad URL");
    }
    let (https, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("unsupported URL scheme");
    };
    let rest = rest.split('#').next().unwrap_or("");
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if auth.is_empty() || auth.contains('@') || auth.contains('[') {
        bail!("bad URL host");
    }
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| anyhow!("bad URL port"))?),
        None => (auth, if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        bail!("bad URL host");
    }
    Ok(Url { https, host: host.to_ascii_lowercase(), port, path })
}

fn host_allowed(h: &str) -> bool {
    matches!(h, "api.github.com" | "github.com" | "objects.githubusercontent.com" | "release-assets.githubusercontent.com") || h.ends_with(".githubusercontent.com")
}

fn url_ok(u: &Url, opts: &Opts) -> bool {
    if u.https {
        host_allowed(&u.host)
    } else {
        opts.loopback_http && (u.host == "127.0.0.1" || u.host == "localhost")
    }
}

fn resolve(base: &Url, loc: &str) -> Result<String> {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        Ok(loc.to_string())
    } else if loc.starts_with('/') && !loc.starts_with("//") {
        Ok(format!("{}://{}:{}{}", if base.https { "https" } else { "http" }, base.host, base.port, loc))
    } else {
        bail!("unusable redirect target")
    }
}

// ------------------------------------------------------------------------------------------------ HTTP/1.1 client
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

fn tls_config() -> Result<Arc<ClientConfig>> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(c) = C.get() {
        return Ok(c.clone());
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(C.get_or_init(|| Arc::new(cfg)).clone())
}

async fn tmo<T>(f: impl Future<Output = std::io::Result<T>>) -> Result<T> {
    match tokio::time::timeout(READ_TIMEOUT, f).await {
        Ok(r) => r.map_err(|e| anyhow!("network error: {e}")),
        Err(_) => bail!("network timeout"),
    }
}

async fn connect(u: &Url) -> Result<Box<dyn Stream>> {
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((u.host.as_str(), u.port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => bail!("cannot connect to {}: {e}", u.host),
        Err(_) => bail!("connect to {} timed out", u.host),
    };
    let _ = tcp.set_nodelay(true);
    if !u.https {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(u.host.clone()).map_err(|_| anyhow!("bad host name"))?;
    let conn = tokio_rustls::TlsConnector::from(tls_config()?);
    match tokio::time::timeout(CONNECT_TIMEOUT, conn.connect(name, tcp)).await {
        Ok(Ok(s)) => Ok(Box::new(s)),
        Ok(Err(e)) => bail!("TLS error with {}: {e}", u.host),
        Err(_) => bail!("TLS handshake with {} timed out", u.host),
    }
}

async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, total: &mut usize) -> Result<String> {
    const HEAD_MAX: usize = 16 * 1024;
    let left = (HEAD_MAX.saturating_sub(*total) + 1) as u64;
    let mut buf = Vec::new();
    let n = tmo(AsyncBufReadExt::read_until(&mut (&mut *r).take(left), b'\n', &mut buf)).await?;
    if n == 0 {
        bail!("connection closed");
    }
    if buf.last() != Some(&b'\n') {
        bail!("header too long");
    }
    *total += n;
    Ok(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string())
}

async fn read_head<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<(u16, Vec<(String, String)>)> {
    let mut total = 0;
    let status = read_line(r, &mut total).await?;
    let mut it = status.split_whitespace();
    if !it.next().map_or(false, |v| v.starts_with("HTTP/1.")) {
        bail!("not an HTTP response");
    }
    let code: u16 = it.next().and_then(|c| c.parse().ok()).ok_or_else(|| anyhow!("bad HTTP status"))?;
    let mut headers = Vec::new();
    loop {
        let l = read_line(r, &mut total).await?;
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Ok((code, headers))
}

fn header<'a>(h: &'a [(String, String)], k: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

type Sink<'a> = &'a mut (dyn FnMut(&[u8]) -> Result<()> + Send);

async fn copy_n<R: AsyncBufRead + Unpin>(r: &mut R, mut n: u64, sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send)) -> Result<()> {
    while n > 0 {
        let k = {
            let buf = tmo(r.fill_buf()).await?;
            if buf.is_empty() {
                bail!("connection closed early");
            }
            let k = (buf.len() as u64).min(n) as usize;
            sink(&buf[..k])?;
            k
        };
        r.consume(k);
        n -= k as u64;
    }
    Ok(())
}

/// Body per Transfer-Encoding: chunked / Content-Length / until close; never more than `max` bytes.
async fn read_body<R: AsyncBufRead + Unpin>(r: &mut R, h: &[(String, String)], max: u64, sink: Sink<'_>) -> Result<()> {
    if header(h, "transfer-encoding").map_or(false, |v| v.to_ascii_lowercase().contains("chunked")) {
        let (mut total, mut head) = (0u64, 0usize);
        loop {
            let line = read_line(r, &mut head).await?;
            let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| anyhow!("bad chunk size"))?;
            if size == 0 {
                loop {
                    if read_line(r, &mut head).await?.is_empty() {
                        return Ok(()); // end of the trailers
                    }
                }
            }
            total = total.saturating_add(size);
            if total > max {
                bail!("response too large");
            }
            copy_n(r, size, &mut *sink).await?;
            if !read_line(r, &mut head).await?.is_empty() {
                bail!("bad chunk framing");
            }
            head = 0;
        }
    } else if let Some(n) = header(h, "content-length") {
        let n: u64 = n.trim().parse().map_err(|_| anyhow!("bad Content-Length"))?;
        if n > max {
            bail!("response too large");
        }
        copy_n(r, n, sink).await
    } else {
        let mut total = 0u64;
        loop {
            let k = {
                let buf = tmo(r.fill_buf()).await?;
                if buf.is_empty() {
                    return Ok(());
                }
                total += buf.len() as u64;
                if total > max {
                    bail!("response too large");
                }
                sink(buf)?;
                buf.len()
            };
            r.consume(k);
        }
    }
}

/// GET with redirects (<= 5, each hop checked against the policy); the body of the final 200 answer goes to `sink`.
async fn http_get(url: &str, opts: &Opts, accept: &str, max: u64, sink: Sink<'_>) -> Result<()> {
    let mut cur = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let u = parse_url(&cur)?;
        if !url_ok(&u, opts) {
            bail!("refusing to contact {}: not an allowed https host", u.host);
        }
        let mut br = BufReader::new(connect(&u).await?);
        let host = if (u.https && u.port == 443) || (!u.https && u.port == 80) { u.host.clone() } else { format!("{}:{}", u.host, u.port) };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: oneq/{VERSION}\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            u.path
        );
        tmo(br.get_mut().write_all(req.as_bytes())).await?;
        let (status, headers) = read_head(&mut br).await?;
        match status {
            301 | 302 | 303 | 307 | 308 => {
                let loc = header(&headers, "location").ok_or_else(|| anyhow!("redirect without Location"))?;
                cur = resolve(&u, loc)?;
            }
            200 => return read_body(&mut br, &headers, max, sink).await,
            403 | 429 => bail!("the update server refused the request (HTTP {status}, rate limit?)"),
            s => bail!("the update server answered HTTP {s}"),
        }
    }
    bail!("too many redirects")
}

// ------------------------------------------------------------------------------------------------ check
pub async fn check(current: &str, opts: &Opts) -> UpdateResult {
    let mut body = Vec::new();
    let r = http_get(&opts.api_url, opts, "application/vnd.github+json", MAX_API, &mut |b: &[u8]| {
        body.extend_from_slice(b);
        Ok(())
    })
    .await;
    match r {
        Ok(()) => parse_release(&body, current, opts.asset_name.as_deref()),
        Err(e) => error_result(current, e),
    }
}

#[derive(Default)]
struct State {
    last: Option<UpdateResult>,
    fetched: Option<Instant>,
    auto: Option<Instant>,
}

static STATE: Mutex<State> = Mutex::new(State { last: None, fetched: None, auto: None });

/// The last result of this process, `None` until a check ran.
pub fn last() -> Option<UpdateResult> {
    STATE.lock().ok().and_then(|s| s.last.clone())
}

/// Cached for 6 h (errors 5 min); `force` bypasses the cache but not more than once per 60 s.
pub async fn check_cached(force: bool) -> UpdateResult {
    check_cached_with(force, &Opts::from_env()).await
}

pub async fn check_cached_with(force: bool, opts: &Opts) -> UpdateResult {
    {
        let s = STATE.lock().unwrap();
        if let (Some(r), Some(t)) = (&s.last, s.fetched) {
            let age = t.elapsed();
            let ttl = if r.status == "error" { ERROR_TTL } else { CACHE_TTL };
            if (!force && age < ttl) || (force && age < MIN_FORCE) {
                return r.clone();
            }
        }
    }
    let r = check(VERSION, opts).await;
    if r.status == "error" {
        tracing::debug!("update check failed: {}", r.error.as_deref().unwrap_or(""));
    }
    let mut s = STATE.lock().unwrap();
    s.last = Some(r.clone());
    s.fetched = Some(Instant::now());
    r
}

/// Automatic checks: 30-120 s after start, then every 24 h while `enabled()` says yes (asked again every 10 min, so a
/// setting changed in the UI takes effect without a restart).
pub async fn background<F: Fn() -> bool + Send + 'static>(enabled: F) {
    let mut b = [0u8; 2];
    let _ = rand::fill(&mut b);
    tokio::time::sleep(Duration::from_secs(30 + (u16::from_le_bytes(b) % 91) as u64)).await;
    loop {
        let due = STATE.lock().unwrap().auto.map_or(true, |t| t.elapsed() >= AUTO_EVERY);
        if due && enabled() {
            STATE.lock().unwrap().auto = Some(Instant::now());
            let r = check_cached(false).await;
            tracing::info!("update check: {} ({})", r.status, r.latest);
        }
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

/// Blocking check for FFI/JNI callers (own small runtime). Never panics.
pub fn check_blocking(force: bool) -> UpdateResult {
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(check_cached(force)),
        Err(e) => error_result(VERSION, e),
    }
}

// ------------------------------------------------------------------------------------------------ download
#[derive(Debug, Clone, PartialEq)]
pub struct Downloaded {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

pub fn downloads_dir() -> PathBuf {
    let home = if cfg!(windows) { std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) } else { std::env::var("HOME") };
    PathBuf::from(home.unwrap_or_else(|_| ".".into())).join("Downloads")
}

fn file_sha256(p: &Path) -> Result<(String, u64)> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let (mut buf, mut n) = (vec![0u8; 64 * 1024], 0u64);
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        ctx.update(&buf[..k]);
        n += k as u64;
    }
    Ok((hex::encode(ctx.finish()), n))
}

/// Downloads `res.asset` into `dir` (`<name>.part`, hashed while streaming) and keeps it only when it matches the SHA256SUMS
/// entry of the same release.
pub async fn download(res: &UpdateResult, dir: &Path, opts: &Opts) -> Result<Downloaded> {
    let a = res.asset.as_ref().ok_or_else(|| anyhow!("this platform has no installer in the release: see the release notes"))?;
    if !valid_name(&a.name) {
        bail!("unsafe file name in the release");
    }
    let (base, _) = a.download_url.rsplit_once('/').ok_or_else(|| anyhow!("bad download URL"))?;
    let sums_url = format!("{base}/SHA256SUMS");
    let mut sums = Vec::new();
    http_get(&sums_url, opts, "text/plain, application/octet-stream", MAX_SUMS, &mut |b: &[u8]| {
        sums.extend_from_slice(b);
        Ok(())
    })
    .await
    .context("cannot fetch SHA256SUMS")?;
    let want = parse_sums(&String::from_utf8_lossy(&sums)).remove(&a.name).ok_or_else(|| anyhow!("{} is not listed in SHA256SUMS", a.name))?;

    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let dest = dir.join(&a.name);
    if dest.is_file() {
        if let Ok((h, n)) = file_sha256(&dest) {
            if h == want {
                return Ok(Downloaded { path: dest, name: a.name.clone(), size: n, sha256: h });
            }
        }
    }
    let part = dir.join(format!("{}.part", a.name));
    let result: Result<(String, u64)> = async {
        let mut f = std::fs::File::create(&part).with_context(|| format!("cannot write {}", part.display()))?;
        let mut ctx = digest::Context::new(&digest::SHA256);
        let (mut n, cap) = (0u64, opts.max_download);
        {
            use std::io::Write;
            http_get(&a.download_url, opts, "application/octet-stream", cap, &mut |b: &[u8]| {
                n += b.len() as u64;
                if n > cap {
                    bail!("download too large");
                }
                ctx.update(b);
                f.write_all(b)?;
                Ok(())
            })
            .await?;
            f.flush()?;
        }
        Ok((hex::encode(ctx.finish()), n))
    }
    .await;
    let (got, size) = match result {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
    if got != want {
        let _ = std::fs::remove_file(&part);
        bail!("SHA-256 mismatch: the file was deleted");
    }
    if dest.exists() {
        let _ = std::fs::remove_file(&dest); // Windows cannot rename over a file; the new one is verified
    }
    if let Err(e) = std::fs::rename(&part, &dest) {
        let _ = std::fs::remove_file(&part);
        bail!("cannot move the download into place: {e}");
    }
    Ok(Downloaded { path: dest, name: a.name.clone(), size, sha256: got })
}

pub fn download_json(r: Result<Downloaded>) -> Value {
    match r {
        Ok(d) => json!({"ok": true, "path": d.path.to_string_lossy(), "name": d.name, "size": d.size, "sha256": d.sha256}),
        Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
    }
}

/// Downloads the installer of the latest known check (checks first when nothing is known yet).
pub async fn download_latest(dir: &Path) -> Value {
    let opts = Opts::from_env();
    let res = match last() {
        Some(r) if r.update_available => r,
        _ => check_cached_with(false, &opts).await,
    };
    if !res.update_available {
        return download_json(Err(anyhow!(res.error.clone().unwrap_or_else(|| "there is no newer version".into()))));
    }
    download_json(download(&res, dir, &opts).await)
}

pub fn download_blocking(dir: &Path) -> Value {
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(download_latest(dir)),
        Err(e) => download_json(Err(anyhow!("{e}"))),
    }
}

// ------------------------------------------------------------------------------------------------ tests
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    /// path -> complete raw HTTP response
    pub async fn mock(build: impl FnOnce(u16) -> HashMap<String, Vec<u8>>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let routes = Arc::new(build(port));
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let resp = routes.get(&path).cloned().unwrap_or_else(|| ok(404, "text/plain", b"nope"));
                    let _ = s.write_all(&resp).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        port
    }

    pub fn ok(code: u16, ctype: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!("HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        v.extend_from_slice(body);
        v
    }

    pub fn sha(b: &[u8]) -> String {
        hex::encode(digest::digest(&digest::SHA256, b))
    }

    /// a release "9.9.9" with the msi and SHA256SUMS served by the mock itself
    pub fn release_routes(port: u16, file: &[u8], sums_hash: &str) -> HashMap<String, Vec<u8>> {
        let rel = json!({"tag_name": "v9.9.9", "html_url": "https://github.com/ad-go/oneq/releases/tag/v9.9.9", "name": "x", "body": "notes <b>here</b>",
            "assets": [{"name": "oneq-node-windows-x64.msi", "size": file.len(), "browser_download_url": format!("http://127.0.0.1:{port}/dl/oneq-node-windows-x64.msi")},
                       {"name": "SHA256SUMS", "size": 10, "browser_download_url": format!("http://127.0.0.1:{port}/dl/SHA256SUMS")}]});
        let mut m = HashMap::new();
        m.insert("/api".to_string(), ok(200, "application/json", rel.to_string().as_bytes()));
        m.insert("/dl/oneq-node-windows-x64.msi".to_string(), ok(200, "application/octet-stream", file));
        m.insert("/dl/SHA256SUMS".to_string(), ok(200, "text/plain", format!("{sums_hash} *oneq-node-windows-x64.msi\n").as_bytes()));
        m
    }

    pub fn opts(port: u16) -> Opts {
        Opts { api_url: format!("http://127.0.0.1:{port}/api"), loopback_http: true, asset_name: Some("oneq-node-windows-x64.msi".into()), max_download: MAX_DOWNLOAD }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oneq-upd-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn versions_compare_numerically() {
        use Ordering::*;
        assert_eq!(compare_versions("v0.0.2", "0.0.1"), Some(Greater));
        assert_eq!(compare_versions("0.0.1", "0.0.1"), Some(Equal));
        assert_eq!(compare_versions("0.10.0", "0.9.9"), Some(Greater)); // not a string compare
        assert_eq!(compare_versions("1", "1.0.0"), Some(Equal)); // missing = 0
        assert_eq!(compare_versions("0.0.1", "0.0.2"), Some(Less));
        assert_eq!(compare_versions("1.2.3-rc1+b5", "1.2.2"), Some(Greater)); // suffix ignored
        assert_eq!(compare_versions("garbage", "0.0.1"), None);
        assert_eq!(compare_versions("1.x", "0.0.1"), None);
        assert_eq!(compare_versions("", "0.0.1"), None);
        assert_eq!(parse_version("v1.2.3-beta"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn sha256sums_formats() {
        let h1 = "a".repeat(64);
        let h2 = "B".repeat(64);
        let h3 = "c".repeat(64);
        let t = format!("{h1} *one.msi\n{h2}  ./two.deb\n{h3}  dist/sub/three.apk\r\nnot a line\n{} bad.txt\n\n", "d".repeat(63));
        let m = parse_sums(&t);
        assert_eq!(m.get("one.msi"), Some(&h1));
        assert_eq!(m.get("two.deb"), Some(&"b".repeat(64))); // lower-cased
        assert_eq!(m.get("three.apk"), Some(&h3));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn release_json_and_asset_selection() {
        let rel = |tag: &str, extra: Value| {
            let mut v = json!({"tag_name": tag, "html_url": "https://github.com/ad-go/oneq/releases/tag/x", "body": "n".repeat(900),
                "assets": [{"name": "oneq-node-windows-x64.msi", "size": 5, "browser_download_url": "https://github.com/ad-go/oneq/releases/download/x/oneq-node-windows-x64.msi"},
                           {"name": "oneq-android.apk", "size": 7, "browser_download_url": "https://github.com/a/b/c/oneq-android.apk"}]});
            for (k, x) in extra.as_object().cloned().unwrap_or_default() {
                v[k] = x;
            }
            serde_json::to_vec(&v).unwrap()
        };
        let r = parse_release(&rel("v0.0.2", json!({})), "0.0.1", Some("oneq-node-windows-x64.msi"));
        assert_eq!((r.status.as_str(), r.update_available, r.latest.as_str()), ("newer", true, "0.0.2"));
        assert_eq!(r.asset.as_ref().unwrap().size, 5);
        assert_eq!(r.notes.chars().count(), 600);
        let r = parse_release(&rel("v0.0.2", json!({})), "0.0.1", Some("oneq-android.apk"));
        assert_eq!(r.asset.unwrap().name, "oneq-android.apk");
        // Linux: no asset, still newer
        let r = parse_release(&rel("v0.0.2", json!({})), "0.0.1", None);
        assert!(r.update_available && r.asset.is_none());
        assert_eq!(parse_release(&rel("v0.0.1", json!({})), "0.0.1", None).status, "current");
        assert_eq!(parse_release(&rel("v0.0.2", json!({"prerelease": true})), "0.0.1", None).update_available, false);
        assert_eq!(parse_release(&rel("v0.0.2", json!({"draft": true})), "0.0.1", None).update_available, false);
        let r = parse_release(&rel("nightly", json!({})), "0.0.1", None);
        assert_eq!((r.status.as_str(), r.update_available), ("unknown", false));
        assert_eq!(parse_release(b"<html>", "0.0.1", None).status, "error");
        // the JSON shape of the specification
        let v = serde_json::to_value(parse_release(&rel("v0.0.2", json!({})), "0.0.1", Some("oneq-node-windows-x64.msi"))).unwrap();
        for k in ["current", "latest", "update_available", "status", "url", "notes", "asset", "checked_at", "error"] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert!(v["error"].is_null());
        assert_eq!(platform_asset().is_some(), cfg!(any(windows, target_os = "macos", target_os = "android")));
    }

    #[test]
    fn hosts_and_urls_follow_the_policy() {
        let strict = Opts { api_url: API_URL.into(), loopback_http: false, asset_name: None, max_download: 1 };
        let ok = |u: &str, o: &Opts| url_ok(&parse_url(u).unwrap(), o);
        assert!(ok("https://api.github.com/repos/x", &strict));
        assert!(ok("https://github.com/a/b", &strict));
        assert!(ok("https://objects.githubusercontent.com/x", &strict));
        assert!(ok("https://release-assets.githubusercontent.com/x", &strict));
        assert!(ok("https://foo.githubusercontent.com/x", &strict));
        assert!(!ok("https://evilgithubusercontent.com/x", &strict));
        assert!(!ok("https://github.com.evil.org/x", &strict));
        assert!(!ok("https://example.org/", &strict));
        assert!(!ok("http://github.com/x", &strict)); // plain http never
        assert!(!ok("http://127.0.0.1:1/x", &strict)); // loopback only with the override
        let lo = Opts { loopback_http: true, ..strict.clone() };
        assert!(ok("http://127.0.0.1:1/x", &lo));
        assert!(!ok("http://example.org/x", &lo));
        assert!(parse_url("https://user@github.com/").is_err());
        assert!(parse_url("ftp://github.com/").is_err());
        assert!(parse_url("https://github.com/a b").is_err());
        assert!(valid_name("oneq-node-windows-x64.msi") && !valid_name("../x") && !valid_name("a/b") && !valid_name("a b") && !valid_name(".."));
    }

    #[tokio::test]
    async fn chunked_and_plain_bodies_are_decoded() {
        let json_body = br#"{"tag_name":"v9.9.9","html_url":"https://github.com/x","assets":[]}"#;
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in json_body.chunks(7) {
            chunked.extend_from_slice(format!("{:x};ext=1\r\n", part.len()).as_bytes());
            chunked.extend_from_slice(part);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\nX-Trailer: 1\r\n\r\n");
        let until_close = [&b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"[..], &json_body[..]].concat();
        let port = mock(|_| HashMap::from([("/chunked".to_string(), chunked), ("/close".to_string(), until_close)])).await;
        for p in ["chunked", "close"] {
            let mut o = opts(port);
            o.api_url = format!("http://127.0.0.1:{port}/{p}");
            let r = check("0.0.1", &o).await;
            assert_eq!((r.status.as_str(), r.latest.as_str()), ("newer", "9.9.9"), "{p}: {:?}", r.error);
        }
    }

    #[tokio::test]
    async fn redirects_are_limited_and_checked() {
        let port = mock(|port| {
            let redirect = |to: String| format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n").into_bytes();
            let mut m = HashMap::new();
            m.insert("/evil".to_string(), redirect("https://evil.example.org/x".into()));
            m.insert("/plain".to_string(), redirect("http://example.org/x".into()));
            m.insert("/loop".to_string(), redirect(format!("http://127.0.0.1:{port}/loop")));
            m.insert("/rel".to_string(), redirect("/final".into()));
            m.insert("/final".to_string(), ok(200, "application/json", br#"{"tag_name":"v1.0.0"}"#));
            m
        })
        .await;
        let at = |p: &str| Opts { api_url: format!("http://127.0.0.1:{port}/{p}"), ..opts(port) };
        let e = check("0.0.1", &at("evil")).await;
        assert!(e.error.unwrap().contains("not an allowed"), "evil");
        assert_eq!(check("0.0.1", &at("plain")).await.status, "error");
        let e = check("0.0.1", &at("loop")).await;
        assert!(e.error.unwrap().contains("too many redirects"));
        assert_eq!(check("0.0.1", &at("rel")).await.latest, "1.0.0"); // relative redirect on the same host
    }

    #[tokio::test]
    async fn response_size_caps() {
        let big = vec![b'x'; 2 * 1024 * 1024];
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..3 {
            chunked.extend_from_slice(format!("{:x}\r\n", 400_000).as_bytes());
            chunked.extend_from_slice(&vec![b'y'; 400_000]);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        let port = mock(|_| HashMap::from([("/big".to_string(), ok(200, "application/json", &big)), ("/chunks".to_string(), chunked)])).await;
        for p in ["big", "chunks"] {
            let mut o = opts(port);
            o.api_url = format!("http://127.0.0.1:{port}/{p}");
            let r = check("0.0.1", &o).await;
            assert!(r.error.as_deref().unwrap_or("").contains("too large"), "{p}: {:?}", r);
        }
        // HTTP errors
        let mut o = opts(port);
        o.api_url = format!("http://127.0.0.1:{port}/missing");
        assert_eq!(check("0.0.1", &o).await.status, "error");
    }

    #[tokio::test]
    async fn download_succeeds_verifies_and_reuses() {
        let file = b"fake installer bytes".repeat(1000);
        let port = mock(|p| release_routes(p, &file, &sha(&file))).await;
        let o = opts(port);
        let res = check("0.0.1", &o).await;
        assert!(res.update_available, "{:?}", res.error);
        assert!(res.notes.contains("<b>")); // text only: the UIs show it with textContent
        let dir = tmpdir("ok").join("Downloads");
        let d = download(&res, &dir, &o).await.unwrap();
        assert_eq!((d.name.as_str(), d.size, d.sha256.clone()), ("oneq-node-windows-x64.msi", file.len() as u64, sha(&file)));
        assert_eq!(std::fs::read(&d.path).unwrap(), file);
        assert!(!dir.join("oneq-node-windows-x64.msi.part").exists());
        // same file again: reported, not downloaded (the server has no file any more)
        let port2 = mock(|p| {
            let mut m = release_routes(p, &file, &sha(&file));
            m.remove("/dl/oneq-node-windows-x64.msi");
            m
        })
        .await;
        let o2 = opts(port2);
        let res2 = check("0.0.1", &o2).await;
        assert_eq!(download(&res2, &dir, &o2).await.unwrap().sha256, sha(&file));
        // a different file with that name is replaced only after the new one verified
        std::fs::write(dir.join("oneq-node-windows-x64.msi"), b"old").unwrap();
        assert_eq!(download(&res, &dir, &o).await.unwrap().size, file.len() as u64);
        assert_eq!(std::fs::read(dir.join("oneq-node-windows-x64.msi")).unwrap(), file);
        // the JSON of the specification
        let j = download_json(Ok(d));
        assert_eq!((j["ok"].clone(), j["name"].clone()), (json!(true), json!("oneq-node-windows-x64.msi")));
        assert_eq!(download_json(Err(anyhow!("boom")))["error"], json!("boom"));
    }

    #[tokio::test]
    async fn hash_mismatch_and_missing_sums_delete_the_file() {
        let file = b"payload".repeat(100);
        let dir = tmpdir("bad");
        // wrong hash: the partial file and the target are gone
        let port = mock(|p| release_routes(p, &file, &"0".repeat(64))).await;
        let o = opts(port);
        let res = check("0.0.1", &o).await;
        std::fs::write(dir.join("oneq-node-windows-x64.msi"), b"old").unwrap();
        let e = download(&res, &dir, &o).await.unwrap_err().to_string();
        assert!(e.contains("mismatch"), "{e}");
        assert!(!dir.join("oneq-node-windows-x64.msi.part").exists());
        assert_eq!(std::fs::read(dir.join("oneq-node-windows-x64.msi")).unwrap(), b"old"); // the old file is untouched
        // no SHA256SUMS at all
        let port = mock(|p| {
            let mut m = release_routes(p, &file, &sha(&file));
            m.remove("/dl/SHA256SUMS");
            m
        })
        .await;
        let o = opts(port);
        let res = check("0.0.1", &o).await;
        let dir2 = tmpdir("nosums");
        assert!(download(&res, &dir2, &o).await.is_err());
        assert!(std::fs::read_dir(&dir2).unwrap().next().is_none());
        // listed under another name only
        let port = mock(|p| {
            let mut m = release_routes(p, &file, &sha(&file));
            m.insert("/dl/SHA256SUMS".into(), ok(200, "text/plain", format!("{}  other.msi\n", sha(&file)).as_bytes()));
            m
        })
        .await;
        let o = opts(port);
        let res = check("0.0.1", &o).await;
        assert!(download(&res, &dir2, &o).await.unwrap_err().to_string().contains("not listed"));
        // size cap: stops and deletes
        let port = mock(|p| release_routes(p, &file, &sha(&file))).await;
        let mut o = opts(port);
        let res = check("0.0.1", &o).await;
        o.max_download = 100;
        assert!(download(&res, &dir2, &o).await.unwrap_err().to_string().contains("too large"));
        assert!(std::fs::read_dir(&dir2).unwrap().next().is_none());
        // no asset for the platform / unsafe name
        let mut none = res.clone();
        none.asset = None;
        assert!(download(&none, &dir2, &o).await.is_err());
        let mut evil = res.clone();
        evil.asset.as_mut().unwrap().name = "../evil.msi".into();
        assert!(download(&evil, &dir2, &o).await.is_err());
    }
}
