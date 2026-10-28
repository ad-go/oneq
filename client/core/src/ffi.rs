//! C ABI used by the Flutter apps through dart:ffi (Windows DLL, Android .so, macOS dylib).
//!
//! Sequence: `oneq_prepare(config_json)` (login + join, gives address and MTU), then `oneq_run(ifname, wintun, fd)`
//! (desktop: fd = -1, the TUN device is created here; Android: fd from `VpnService.Builder.establish()`), then poll
//! `oneq_status_json()`, finally `oneq_stop()`. Strings returned by this module are freed with `oneq_free_string`.
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::{Arc, Mutex, OnceLock};

use serde::Deserialize;
use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::{Config, Prepared, Status};

#[derive(Deserialize)]
struct FfiConfig {
    relays: Vec<String>,
    community: String,
    user: String,
    password: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ca_pem: Option<String>,
    key_file: String,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    advertise: Vec<String>,
    #[serde(default)]
    force_relay: bool,
    #[serde(default)]
    no_relay: bool,
    #[serde(default)]
    relay_offer: bool,
    #[serde(default)]
    no_delegates: bool,
    #[serde(default)]
    no_port_mapping: bool,
    #[serde(default)]
    no_ipv6: bool,
    #[serde(default)]
    accept_routes: bool,
    #[serde(default)]
    exit_node: Option<String>,
    /// check GitHub for new releases (default true)
    #[serde(default = "yes")]
    update_check: bool,
}

fn yes() -> bool {
    true
}

struct Session {
    rt: Runtime,
    status: Arc<Status>,
    prepared: Option<Prepared>,
    stop: Arc<Notify>,
    running: bool,
}

fn state() -> &'static Mutex<Option<Session>> {
    static S: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

fn last_error() -> &'static Mutex<String> {
    static E: OnceLock<Mutex<String>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(String::new()))
}

fn fail(e: impl std::fmt::Display) -> c_int {
    *last_error().lock().unwrap() = e.to_string();
    -1
}

fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(p) }.to_str().ok().map(String::from)
    }
}

fn to_c(s: String) -> *mut c_char {
    CString::new(s.replace('\0', " ")).unwrap().into_raw()
}

/// Log in and join. Returns 0, or -1 (see `oneq_last_error`).
#[no_mangle]
pub extern "C" fn oneq_prepare(config_json: *const c_char) -> c_int {
    let Some(txt) = cstr(config_json) else { return fail("null config") };
    let c: FfiConfig = match serde_json::from_str(&txt) {
        Ok(c) => c,
        Err(e) => return fail(format!("bad config: {e}")),
    };
    let mut guard = state().lock().unwrap();
    if guard.as_ref().map_or(false, |s| s.running) {
        return fail("already running");
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let cfg = Config {
        relays: c.relays,
        community: c.community,
        user: c.user,
        password: c.password,
        name: c.name,
        ca_pem: c.ca_pem.filter(|s| !s.trim().is_empty()).map(String::into_bytes),
        key_file: c.key_file,
        listen: c.listen,
        advertise: c.advertise,
        force_relay: c.force_relay,
        no_relay: c.no_relay,
        relay_after_s: 10.0,
        relay_offer: c.relay_offer,
        no_delegates: c.no_delegates,
        no_port_mapping: c.no_port_mapping,
        no_ipv6: c.no_ipv6,
        accept_routes: c.accept_routes,
        exit_node: c.exit_node.clone(),
        no_update_check: !c.update_check,
    };
    let update_check = c.update_check;
    let status = Arc::new(Status::new());
    match rt.block_on(crate::prepare(cfg, &status)) {
        Ok(p) => {
            if update_check {
                rt.spawn(crate::update::background(|| true));
            }
            *guard = Some(Session { rt, status, prepared: Some(p), stop: Arc::new(Notify::new()), running: false });
            0
        }
        Err(e) => fail(format!("{e:#}")),
    }
}

/// Start the engine in the background. `fd >= 0`: use that TUN file descriptor (Android); otherwise create the
/// interface `ifname` (Windows/macOS/Linux; `wintun` = path of wintun.dll or null).
#[no_mangle]
pub extern "C" fn oneq_run(ifname: *const c_char, wintun: *const c_char, fd: c_int) -> c_int {
    let mut guard = state().lock().unwrap();
    let Some(s) = guard.as_mut() else { return fail("call oneq_prepare first") };
    let Some(p) = s.prepared.take() else { return fail("already running or not prepared") };
    let tun = {
        let _enter = s.rt.enter(); // the device registers with the runtime's reactor
        if fd >= 0 {
            #[cfg(unix)]
            {
                unsafe { tun_rs::AsyncDevice::from_fd(fd) }.map_err(|e| anyhow::anyhow!("cannot use the TUN descriptor: {e}"))
            }
            #[cfg(not(unix))]
            {
                Err(anyhow::anyhow!("TUN descriptors are only supported on Unix"))
            }
        } else {
            crate::create_tun(&cstr(ifname).unwrap_or_else(|| "oneq".into()), &p.info, cstr(wintun).as_deref())
        }
    };
    let tun = match tun {
        Ok(t) => Arc::new(t),
        Err(e) => {
            s.status.set_state("error", &format!("{e:#}"));
            return fail(format!("{e:#}"));
        }
    };
    let (status, stop) = (s.status.clone(), s.stop.clone());
    s.running = true;
    s.rt.spawn(async move {
        if let Err(e) = crate::run(p, tun, status.clone(), stop).await {
            status.set_state("error", &format!("{e:#}"));
        }
    });
    0
}

/// Stop and release everything (idempotent).
#[no_mangle]
pub extern "C" fn oneq_stop() {
    if let Some(s) = state().lock().unwrap().take() {
        s.stop.notify_waiters();
        s.stop.notify_one();
        s.status.set_state("stopped", "");
        s.rt.shutdown_timeout(std::time::Duration::from_secs(2));
    }
}

/// JSON of the current [`crate::Snapshot`] (`{"state":"idle"}` when nothing was started).
#[no_mangle]
pub extern "C" fn oneq_status_json() -> *mut c_char {
    let g = state().lock().unwrap();
    to_c(match g.as_ref() {
        Some(s) => serde_json::to_string(&s.status.snapshot()).unwrap_or_default(),
        None => r#"{"state":"idle"}"#.into(),
    })
}

/// Update check (blocking; call it from a background isolate/thread). Returns the JSON result object
/// `{"current","latest","update_available","status","url","notes","asset","checked_at","error"}`; the cached result is returned unless
/// `force != 0` (then at most one request per 60 s). Free the string with `oneq_free_string`.
#[no_mangle]
pub extern "C" fn oneq_update_check_json(force: c_int) -> *mut c_char {
    let s = std::panic::catch_unwind(|| serde_json::to_string(&crate::update::check_blocking(force != 0)).unwrap_or_default())
        .unwrap_or_else(|_| r#"{"status":"error","update_available":false,"error":"internal error"}"#.into());
    to_c(s)
}

/// Downloads the installer of the latest update check into `dir` and verifies its SHA-256 (blocking). Returns
/// `{"ok":true,"path","name","size","sha256"}` or `{"ok":false,"error"}`. Nothing is installed or run. Free with `oneq_free_string`.
#[no_mangle]
pub extern "C" fn oneq_update_download_json(dir: *const c_char) -> *mut c_char {
    let Some(d) = cstr(dir).filter(|d| !d.trim().is_empty()) else { return to_c(r#"{"ok":false,"error":"no download directory"}"#.into()) };
    let s = std::panic::catch_unwind(|| crate::update::download_blocking(std::path::Path::new(&d)).to_string())
        .unwrap_or_else(|_| r#"{"ok":false,"error":"internal error"}"#.into());
    to_c(s)
}

/// Text of the last failure of `oneq_prepare`/`oneq_run`.
#[no_mangle]
pub extern "C" fn oneq_last_error() -> *mut c_char {
    to_c(last_error().lock().unwrap().clone())
}

#[no_mangle]
pub extern "C" fn oneq_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}

/// JNI entry points of `ro.u1q.oneq.oneq_app.NativeCore`: the Android foreground service drives the core directly so the
/// node keeps running (and can start at boot) without the Flutter engine.
#[cfg(target_os = "android")]
mod jni_api {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jstring};
    use jni::JNIEnv;

    fn take(p: *mut c_char) -> String {
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        oneq_free_string(p);
        s
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_prepare(mut env: JNIEnv, _c: JClass, cfg: JString) -> jint {
        let Ok(s) = env.get_string(&cfg) else { return -1 };
        let Ok(c) = CString::new(String::from(s)) else { return -1 };
        oneq_prepare(c.as_ptr())
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_run(_env: JNIEnv, _c: JClass, fd: jint) -> jint {
        oneq_run(std::ptr::null(), std::ptr::null(), fd)
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_stop(_env: JNIEnv, _c: JClass) {
        oneq_stop()
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_status(env: JNIEnv, _c: JClass) -> jstring {
        let s = take(oneq_status_json());
        env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_updateCheck(env: JNIEnv, _c: JClass, force: jint) -> jstring {
        let s = take(oneq_update_check_json(force));
        env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_updateDownload(mut env: JNIEnv, _c: JClass, dir: JString) -> jstring {
        let d = env.get_string(&dir).map(String::from).unwrap_or_default();
        let s = match CString::new(d) {
            Ok(c) => take(oneq_update_download_json(c.as_ptr())),
            Err(_) => r#"{"ok":false,"error":"bad directory"}"#.to_string(),
        };
        env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
    }

    #[no_mangle]
    pub extern "system" fn Java_ro_u1q_oneq_oneq_1app_NativeCore_lastError(env: JNIEnv, _c: JClass) -> jstring {
        let s = take(oneq_last_error());
        env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
    }
}
