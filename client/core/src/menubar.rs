//! Status icon in the macOS menu bar (`oneqclient menubar`): the same three tray icons as the Windows/macOS app (client/app/assets/tray_*.png),
//! a status line, "Open oneq…" (starts `oneqclient ui --no-open` and opens the page it prints) and "Quit".
//! Needs neither Swift nor the macOS SDK at build time: AppKit is reached through the Objective-C runtime, loaded with dlopen, so the
//! binary can be cross-compiled from Windows/Linux.
#![cfg(target_os = "macos")]

use anyhow::{anyhow, bail, Result};
use std::ffi::{c_char, c_void, CString};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

type Id = *mut c_void;
type Sel = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct NSSize {
    w: f64,
    h: f64,
}

#[derive(Clone, Copy)]
struct Rt {
    get_class: unsafe extern "C" fn(*const c_char) -> Id,
    reg_sel: unsafe extern "C" fn(*const c_char) -> Sel,
    msg: *mut c_void,
    alloc_pair: unsafe extern "C" fn(Id, *const c_char, usize) -> Id,
    add_method: unsafe extern "C" fn(Id, Sel, *mut c_void, *const c_char) -> bool,
    register: unsafe extern "C" fn(Id),
}
unsafe impl Send for Rt {}
unsafe impl Sync for Rt {}

struct Ui {
    status_line: Id,
    update_item: Id,
    item: Id,
    icons: [Id; 3],
}
unsafe impl Send for Ui {}
unsafe impl Sync for Ui {}

static RT: OnceLock<Rt> = OnceLock::new();
static UI: OnceLock<Ui> = OnceLock::new();
static STATE: AtomicU8 = AtomicU8::new(0); // 0 off, 1 connecting, 2 connected
static SHOWN: AtomicU8 = AtomicU8::new(255);
static TEXT: Mutex<String> = Mutex::new(String::new());
/// (latest version, release URL) when a newer release is known
static UPDATE: Mutex<Option<(String, String)>> = Mutex::new(None);
static UI_CHILD: Mutex<Option<(Child, Option<String>)>> = Mutex::new(None);

const ICONS: [&[u8]; 3] = [
    include_bytes!("../../app/assets/tray_off.png"),
    include_bytes!("../../app/assets/tray_connecting.png"),
    include_bytes!("../../app/assets/tray_connected.png"),
];

fn rt() -> &'static Rt {
    RT.get().expect("runtime loaded")
}

fn sel(name: &str) -> Sel {
    let c = CString::new(name).unwrap();
    unsafe { (rt().reg_sel)(c.as_ptr()) }
}

fn class(name: &str) -> Id {
    let c = CString::new(name).unwrap();
    unsafe { (rt().get_class)(c.as_ptr()) }
}

/// objc_msgSend with the exact C signature of the call (it is variadic in the headers, so it has to be cast per call).
macro_rules! send {
    ($obj:expr, $sel:expr => $ret:ty $(, $t:ty : $a:expr)*) => {{
        let f: unsafe extern "C" fn(Id, Sel $(, $t)*) -> $ret = std::mem::transmute(rt().msg);
        f($obj, sel($sel) $(, $a)*)
    }};
}

unsafe fn nsstring(s: &str) -> Id {
    let c = CString::new(s.replace('\0', "")).unwrap();
    send!(class("NSString"), "stringWithUTF8String:" => Id, *const c_char: c.as_ptr())
}

unsafe fn load() -> Result<Rt> {
    let open = |p: &str| -> Result<*mut c_void> {
        let c = CString::new(p).unwrap();
        let h = libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if h.is_null() {
            bail!("cannot load {p}");
        }
        Ok(h)
    };
    let objc = open("/usr/lib/libobjc.A.dylib")?;
    open("/System/Library/Frameworks/AppKit.framework/AppKit")?;
    let sym = |n: &str| -> Result<*mut c_void> {
        let c = CString::new(n).unwrap();
        let p = libc::dlsym(objc, c.as_ptr());
        if p.is_null() {
            bail!("missing symbol {n}");
        }
        Ok(p)
    };
    Ok(Rt {
        get_class: std::mem::transmute(sym("objc_getClass")?),
        reg_sel: std::mem::transmute(sym("sel_registerName")?),
        msg: sym("objc_msgSend")?,
        alloc_pair: std::mem::transmute(sym("objc_allocateClassPair")?),
        add_method: std::mem::transmute(sym("class_addMethod")?),
        register: std::mem::transmute(sym("objc_registerClassPair")?),
    })
}

/// Same reading of the service's status file as the Swift helper: (state, text).
fn read_status() -> (u8, String) {
    let off = (0u8, "oneq: not running".to_string());
    let Ok(data) = std::fs::read(crate::svc::service_dir().join("status.json")) else { return off };
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&data) else { return off };
    let (Some(updated), Some(snap)) = (root["updated"].as_f64(), root.get("snapshot")) else { return off };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    if now - updated > 10.0 {
        return off;
    }
    let state = snap["state"].as_str().unwrap_or("");
    if state == "stopped" {
        return (0, "oneq: stopped".into());
    }
    let ip = snap["ip"].as_str().unwrap_or("");
    let up = snap["peers"].as_array().map_or(0, |p| p.iter().filter(|x| x["session"].as_bool() == Some(true)).count());
    if state == "connected" && up > 0 {
        return (2, format!("oneq: {ip} · {up} peer{} connected", if up == 1 { "" } else { "s" }));
    }
    if state == "error" {
        return (1, format!("oneq: {}", snap["message"].as_str().unwrap_or("error")));
    }
    (1, "oneq: connecting…".into())
}

/// Main thread: put the current state into the icon, the tooltip and the first menu line.
extern "C" fn refresh(_this: Id, _cmd: Sel, _arg: Id) {
    let Some(ui) = UI.get() else { return };
    let st = STATE.load(Ordering::SeqCst);
    let text = TEXT.lock().map(|t| t.clone()).unwrap_or_default();
    unsafe {
        let button = send!(ui.item, "button" => Id);
        if SHOWN.swap(st, Ordering::SeqCst) != st {
            send!(button, "setImage:" => (), Id: ui.icons[st as usize % 3]);
        }
        let s = nsstring(&text);
        send!(ui.status_line, "setTitle:" => (), Id: s);
        send!(button, "setToolTip:" => (), Id: s);
        match UPDATE.lock().ok().and_then(|u| u.clone()) {
            Some((latest, _)) => {
                send!(ui.update_item, "setTitle:" => (), Id: nsstring(&format!("Update available: {latest}…")));
                send!(ui.update_item, "setHidden:" => (), bool: false);
            }
            None => send!(ui.update_item, "setHidden:" => (), bool: true),
        }
    }
}

fn open_url(url: &str) {
    let _ = Command::new("/usr/bin/open").arg(url).status();
}

/// Start `oneqclient ui --no-open` (or reuse the running one) and open the page; never blocks the UI thread.
fn open_ui() {
    std::thread::spawn(|| {
        let mut g = UI_CHILD.lock().unwrap();
        if let Some((c, url)) = g.as_mut() {
            if c.try_wait().ok().flatten().is_none() {
                if let Some(u) = url {
                    open_url(u);
                    return;
                }
            }
        }
        let Ok(exe) = std::env::current_exe() else { return };
        let Ok(mut child) = Command::new(exe).args(["ui", "--no-open"]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else { return };
        let out = child.stdout.take();
        *g = Some((child, None));
        drop(g);
        // the first line printed by `oneqclient ui` is the URL (it carries a secret token)
        let Some(out) = out else { return };
        let mut line = String::new();
        if BufReader::new(out).read_line(&mut line).is_ok() && line.starts_with("http") {
            let url = line.trim().to_string();
            if let Some((_, u)) = UI_CHILD.lock().unwrap().as_mut() {
                *u = Some(url.clone());
            }
            open_url(&url);
        }
    });
}

extern "C" fn on_open(_this: Id, _cmd: Sel, _sender: Id) {
    open_ui();
}

/// "Update available: x…": opens the release page in the browser (nothing is downloaded or installed here).
extern "C" fn on_update(_this: Id, _cmd: Sel, _sender: Id) {
    if let Some((_, url)) = UPDATE.lock().ok().and_then(|u| u.clone()) {
        if url.starts_with("https://") {
            open_url(&url);
        }
    }
}

/// "Check for updates": a forced check in a thread; the menu item appears on the next status refresh.
extern "C" fn on_check(_this: Id, _cmd: Sel, _sender: Id) {
    std::thread::spawn(|| {
        let r = crate::update::check_blocking(true);
        set_update(&r);
    });
}

fn set_update(r: &crate::update::UpdateResult) {
    if let Ok(mut u) = UPDATE.lock() {
        *u = if r.update_available { Some((r.latest.clone(), r.url.clone())) } else { None };
    }
}

extern "C" fn on_quit(_this: Id, _cmd: Sel, _sender: Id) {
    if let Some((c, _)) = UI_CHILD.lock().unwrap().as_mut() {
        let _ = c.kill();
    }
    unsafe {
        let app = send!(class("NSApplication"), "sharedApplication" => Id);
        send!(app, "terminate:" => (), Id: std::ptr::null_mut());
    }
}

pub fn run(open_on_start: bool) -> Result<()> {
    // one icon per user
    std::fs::create_dir_all(crate::svc::user_dir())?;
    let lock = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(crate::svc::user_dir().join("menubar.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        eprintln!("the oneq menu-bar icon is already running");
        return Ok(());
    }
    unsafe {
        let r = load().map_err(|e| anyhow!("{e}"))?;
        let _ = RT.set(r);
        let pool = send!(send!(class("NSAutoreleasePool"), "alloc" => Id), "init" => Id);
        let _ = pool;
        let app = send!(class("NSApplication"), "sharedApplication" => Id);
        send!(app, "setActivationPolicy:" => bool, isize: 1); // accessory: no Dock icon

        // the delegate class with the three actions
        let cls = (r.alloc_pair)(class("NSObject"), c"OneqMenuDelegate".as_ptr(), 0);
        if cls.is_null() {
            bail!("cannot create the delegate class");
        }
        let imp = |f: extern "C" fn(Id, Sel, Id)| f as usize as *mut c_void;
        (r.add_method)(cls, sel("openUI:"), imp(on_open), c"v@:@".as_ptr());
        (r.add_method)(cls, sel("updateAvailable:"), imp(on_update), c"v@:@".as_ptr());
        (r.add_method)(cls, sel("checkUpdate:"), imp(on_check), c"v@:@".as_ptr());
        (r.add_method)(cls, sel("quitApp:"), imp(on_quit), c"v@:@".as_ptr());
        (r.add_method)(cls, sel("refresh:"), imp(refresh), c"v@:@".as_ptr());
        (r.register)(cls);
        let delegate = send!(send!(cls, "alloc" => Id), "init" => Id);

        // icons: the PNGs of the app, shown 20 points high
        let mut icons = [std::ptr::null_mut(); 3];
        for (i, png) in ICONS.iter().enumerate() {
            let data = send!(class("NSData"), "dataWithBytes:length:" => Id, *const c_void: png.as_ptr() as *const c_void, usize: png.len());
            let img = send!(send!(class("NSImage"), "alloc" => Id), "initWithData:" => Id, Id: data);
            send!(img, "setSize:" => (), NSSize: NSSize { w: 20.0, h: 20.0 });
            icons[i] = img;
        }

        let bar = send!(class("NSStatusBar"), "systemStatusBar" => Id);
        let item = send!(bar, "statusItemWithLength:" => Id, f64: -2.0); // NSSquareStatusItemLength
        send!(item, "retain" => Id);
        let menu = send!(send!(class("NSMenu"), "alloc" => Id), "init" => Id);
        let mk = |title: &str, action: Option<&str>, key: &str| -> Id {
            let it = send!(send!(class("NSMenuItem"), "alloc" => Id), "initWithTitle:action:keyEquivalent:" => Id,
                Id: nsstring(title), Sel: action.map_or(std::ptr::null_mut(), sel), Id: nsstring(key));
            if action.is_some() {
                send!(it, "setTarget:" => (), Id: delegate);
            }
            it
        };
        let status_line = mk("oneq: …", None, "");
        send!(menu, "addItem:" => (), Id: status_line);
        send!(menu, "addItem:" => (), Id: send!(class("NSMenuItem"), "separatorItem" => Id));
        let update_item = mk("Update available", Some("updateAvailable:"), "");
        send!(update_item, "setHidden:" => (), bool: true);
        send!(menu, "addItem:" => (), Id: update_item);
        send!(menu, "addItem:" => (), Id: mk("Open oneq…", Some("openUI:"), "o"));
        send!(menu, "addItem:" => (), Id: mk("Check for updates", Some("checkUpdate:"), ""));
        send!(menu, "addItem:" => (), Id: mk("Quit menu bar icon", Some("quitApp:"), "q"));
        send!(item, "setMenu:" => (), Id: menu);
        let _ = UI.set(Ui { status_line, update_item, item, icons });

        // automatic update check (while enabled in the settings of this user); the service's own result is read with the status
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(crate::update::background(crate::ui::update_check_enabled));
        }

        // status polling: every 3 s in a thread, applied on the main thread
        let d = delegate as usize;
        std::thread::spawn(move || loop {
            let (st, text) = read_status();
            STATE.store(st, Ordering::SeqCst);
            // newest knowledge wins: this process's own check, else the one the service published in status.json
            match crate::update::last() {
                Some(r) => set_update(&r),
                None => {
                    let from_service = std::fs::read(crate::svc::service_dir().join("status.json")).ok().and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok()).and_then(|v| {
                        let u = &v["snapshot"]["update"];
                        (u["update_available"] == true).then(|| (u["latest"].as_str().unwrap_or("").to_string(), u["url"].as_str().unwrap_or("").to_string()))
                    });
                    if let Ok(mut u) = UPDATE.lock() {
                        *u = from_service;
                    }
                }
            }
            if let Ok(mut t) = TEXT.lock() {
                *t = text;
            }
            unsafe {
                send!(d as Id, "performSelectorOnMainThread:withObject:waitUntilDone:" => (), Sel: sel("refresh:"), Id: std::ptr::null_mut(), bool: false);
            }
            std::thread::sleep(Duration::from_secs(3));
        });
        if open_on_start {
            open_ui();
        }
        send!(app, "run" => ());
    }
    drop(lock);
    Ok(())
}
