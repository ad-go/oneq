//! Who is on the other end of a loopback connection? `oneqclient proxy` serves SOCKS5 and its status page on 127.0.0.1 without authentication
//! (Chrome cannot send SOCKS credentials), so any program of the computer could use the mesh. The gate asks the operating system which process owns the
//! client side of every accepted connection and admits only browsers (or the names given with `--allow-process`).
//!
//! The process is found by the connection itself, never by anything the client says: Windows `GetExtendedTcpTable`, Linux `/proc/net/tcp` + `/proc/*/fd`,
//! macOS `lsof`. If the owner cannot be determined (another user's process on Linux, a failed lookup) the connection is refused.
//! Limit: the name of an executable is not an identity. A program of the same user can be called `chrome`; this keeps out other users' programs, scripts and
//! tools that merely know the port, not a hostile program of the same account (it could read the node key anyway).
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Substrings (lower case) of the executable names of the supported browsers; Chromium's network process is the browser's own executable
/// (macOS: "<Browser> Helper").
pub const BROWSERS: &[&str] = &["chrome", "chromium", "brave", "msedge", "microsoft edge", "firefox", "librewolf", "waterfox", "vivaldi", "opera", "tor browser"];

#[derive(Clone)]
pub struct Gate {
    allow: Option<Arc<Vec<String>>>,
}

impl Gate {
    /// Any program on this computer (the old behaviour; `--allow-any-local`).
    pub fn any() -> Gate {
        Gate { allow: None }
    }

    /// Browsers plus `extra` executable-name fragments.
    pub fn browsers(extra: &[String]) -> Gate {
        let mut v: Vec<String> = BROWSERS.iter().map(|s| s.to_string()).collect();
        v.extend(extra.iter().map(|s| s.to_ascii_lowercase()));
        Gate { allow: Some(Arc::new(v)) }
    }

    pub fn restricted(&self) -> bool {
        self.allow.is_some()
    }

    pub fn describe(&self) -> String {
        match &self.allow {
            None => "any program of this computer".into(),
            Some(v) => format!("browsers only ({})", v.join(", ")),
        }
    }

    /// `peer` is the client's address, `local` the address it connected to.
    pub async fn admits(&self, peer: SocketAddr, local: SocketAddr) -> bool {
        let Some(allow) = &self.allow else { return true };
        if !peer.ip().is_loopback() {
            return false;
        }
        let found = tokio::task::spawn_blocking(move || owner(peer, local)).await.ok().flatten();
        match found {
            Some(name) if name_matches(&name, allow) => true,
            other => {
                refused(other.as_deref());
                false
            }
        }
    }
}

static LAST_LOG: AtomicU64 = AtomicU64::new(0);

/// One line per 10 seconds: a program that hammers the port must not flood the log.
fn refused(name: Option<&str>) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if now >= LAST_LOG.load(Ordering::Relaxed) + 10 {
        LAST_LOG.store(now, Ordering::Relaxed);
        tracing::warn!(
            "refused a local connection to the proxy from {} (only browsers are served; --allow-process NAME or --allow-any-local changes that)",
            name.map(|n| format!("the program {n:?}")).unwrap_or_else(|| "a program that could not be identified".into())
        );
    }
}

pub fn name_matches(name: &str, allow: &[String]) -> bool {
    let l = name.to_ascii_lowercase();
    let l = l.strip_suffix(".exe").unwrap_or(&l);
    !l.is_empty() && allow.iter().any(|a| !a.is_empty() && l.contains(a.as_str()))
}

/// Name of the executable that owns the client end (`peer` -> `local`) of a loopback TCP connection.
pub fn owner(peer: SocketAddr, local: SocketAddr) -> Option<String> {
    let (SocketAddr::V4(p), SocketAddr::V4(l)) = (peer, local) else { return None };
    owner_v4(p.port(), l.port())
}

// ---------------------------------------------------------------------------------------------------------------------------------- Windows
#[cfg(windows)]
fn owner_v4(src: u16, dst: u16) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut size: u32 = 64 * 1024;
    let mut buf: Vec<u8>;
    loop {
        buf = vec![0u8; size as usize];
        // SAFETY: the buffer is `size` bytes long; the call writes at most that many and updates `size`
        let r = unsafe { GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, 2 /* AF_INET */, TCP_TABLE_OWNER_PID_ALL, 0) };
        match r {
            0 => break,
            122 => continue, // ERROR_INSUFFICIENT_BUFFER: `size` now holds the needed length
            _ => return None,
        }
    }
    let pid = pid_in_table(&buf, src, dst)?;
    // SAFETY: plain handle use; the handle is closed below
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut name = vec![0u16; 1024];
        let mut len = name.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, name.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&name[..len as usize]);
        Some(path.rsplit(['\\', '/']).next().unwrap_or("").to_string())
    }
}

/// `MIB_TCPTABLE_OWNER_PID`: u32 count, then rows of six u32 (state, local addr, local port, remote addr, remote port, pid); addresses and ports are in
/// network byte order. The client's row is the one whose local side is 127.0.0.1:`src` and whose remote port is `dst`.
#[cfg(any(windows, test))]
fn pid_in_table(buf: &[u8], src: u16, dst: u16) -> Option<u32> {
    let n = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    for i in 0..n {
        let o = 4 + i * 24;
        let row = buf.get(o..o + 24)?;
        let (laddr, lport) = (&row[4..8], u16::from_be_bytes([row[8], row[9]]));
        let (raddr, rport) = (&row[12..16], u16::from_be_bytes([row[16], row[17]]));
        if laddr == [127, 0, 0, 1] && raddr == [127, 0, 0, 1] && lport == src && rport == dst {
            return Some(u32::from_le_bytes(row[20..24].try_into().ok()?));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------------------------- Linux
#[cfg(target_os = "linux")]
fn owner_v4(src: u16, dst: u16) -> Option<String> {
    let tcp = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let inode = inode_in_proc_tcp(&tcp, src, dst)?;
    let want = format!("socket:[{inode}]");
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue }; // other users' processes: not readable, skipped
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).map(|l| l.to_string_lossy() == want).unwrap_or(false) {
                let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
                return exe.or_else(|| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()));
            }
        }
    }
    None
}

/// `/proc/net/tcp`: `sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...`, addresses as `0100007F:C350` (little-endian IPv4, hex port).
#[cfg(any(target_os = "linux", test))]
fn inode_in_proc_tcp(text: &str, src: u16, dst: u16) -> Option<u64> {
    let (local, remote) = (format!("0100007F:{src:04X}"), format!("0100007F:{dst:04X}"));
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 9 && f[1].eq_ignore_ascii_case(&local) && f[2].eq_ignore_ascii_case(&remote) {
            f[9].parse().ok()
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------------------------------------------------------------- macOS
#[cfg(target_os = "macos")]
fn owner_v4(src: u16, dst: u16) -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/lsof").args(["-nP", "+c", "0", &format!("-iTCP:{src}"), "-Fpcn"]).output().ok()?;
    command_in_lsof(&String::from_utf8_lossy(&out.stdout), src, dst)
}

/// `lsof -F` output: `p<pid>`, `c<command>`, then `n<local>-><remote>` per socket. The client's socket is `127.0.0.1:src->127.0.0.1:dst`.
#[cfg(any(target_os = "macos", test))]
fn command_in_lsof(out: &str, src: u16, dst: u16) -> Option<String> {
    let want = format!("127.0.0.1:{src}->127.0.0.1:{dst}");
    let mut cmd = String::new();
    for l in out.lines() {
        match l.split_at_checked(1) {
            Some(("p", _)) => cmd.clear(),
            Some(("c", v)) => cmd = v.to_string(),
            Some(("n", v)) if v == want && !cmd.is_empty() => return Some(cmd),
            _ => {}
        }
    }
    None
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn owner_v4(_src: u16, _dst: u16) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Vec<String> {
        BROWSERS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn browser_names_are_matched_and_other_programs_are_not() {
        for n in ["chrome.exe", "Chrome.EXE", "brave.exe", "msedge.exe", "firefox", "Google Chrome Helper", "Brave Browser Helper", "Microsoft Edge Helper (Renderer)", "chromium"] {
            assert!(name_matches(n, &allow()), "{n}");
        }
        for n in ["curl.exe", "python3", "node", "powershell.exe", "ssh", "", "oneqclient", "Safari"] {
            assert!(!name_matches(n, &allow()), "{n}");
        }
        assert!(name_matches("MyBrowser.exe", &["mybrowser".to_string()]));
        assert!(!name_matches("anything", &["".to_string()]), "an empty fragment must not match everything");
    }

    #[test]
    fn windows_table_row_of_the_client_is_found_not_the_server_row() {
        let row = |laddr: [u8; 4], lport: u16, raddr: [u8; 4], rport: u16, pid: u32| {
            let mut r = Vec::new();
            r.extend(5u32.to_le_bytes());
            r.extend(laddr);
            r.extend([lport.to_be_bytes()[0], lport.to_be_bytes()[1], 0, 0]);
            r.extend(raddr);
            r.extend([rport.to_be_bytes()[0], rport.to_be_bytes()[1], 0, 0]);
            r.extend(pid.to_le_bytes());
            r
        };
        let mut t = 3u32.to_le_bytes().to_vec();
        t.extend(row([127, 0, 0, 1], 1080, [127, 0, 0, 1], 50000, 111)); // the proxy's side of the connection
        t.extend(row([127, 0, 0, 1], 50000, [127, 0, 0, 1], 1080, 222)); // the client's side
        t.extend(row([10, 0, 0, 5], 50000, [127, 0, 0, 1], 1080, 333));
        assert_eq!(pid_in_table(&t, 50000, 1080), Some(222));
        assert_eq!(pid_in_table(&t, 50001, 1080), None);
        assert_eq!(pid_in_table(&t[..10], 50000, 1080), None, "a truncated table is not an answer");
    }

    #[test]
    fn linux_proc_net_tcp_line_gives_the_inode_of_the_client_socket() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 0: 0100007F:0438 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 0 0 0\n\
                 1: 0100007F:C350 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0 0 0 0\n";
        assert_eq!(inode_in_proc_tcp(t, 0xC350, 0x0438), Some(22222));
        assert_eq!(inode_in_proc_tcp(t, 0x0438, 0xC350), Some(11111));
        assert_eq!(inode_in_proc_tcp(t, 1, 2), None);
    }

    #[test]
    fn macos_lsof_output_gives_the_command_of_the_client_socket() {
        let out = "p100\nconeqclient\nn127.0.0.1:1080->127.0.0.1:50000\np200\ncBrave Browser Helper\nn127.0.0.1:50000->127.0.0.1:1080\n";
        assert_eq!(command_in_lsof(out, 50000, 1080).as_deref(), Some("Brave Browser Helper"));
        assert_eq!(command_in_lsof(out, 50001, 1080), None);
    }

    /// The real thing, on every operating system: this test process connects to a loopback listener and the lookup must name this very program.
    #[tokio::test]
    async fn the_operating_system_names_the_process_at_the_other_end() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = l.local_addr().unwrap();
        let c = tokio::net::TcpStream::connect(local).await.unwrap();
        let (_s, peer) = l.accept().await.unwrap();
        assert_eq!(c.local_addr().unwrap(), peer);
        let me = std::env::current_exe().unwrap().file_stem().unwrap().to_string_lossy().to_lowercase();
        let found = tokio::task::spawn_blocking(move || owner(peer, local)).await.unwrap();
        let found = found.expect("the owner of the connection could not be determined");
        let found = found.to_lowercase();
        let found = found.strip_suffix(".exe").unwrap_or(&found);
        // Linux truncates nothing in /proc/PID/exe; lsof +c 0 gives the full command name
        assert!(me.starts_with(found) || found.starts_with(&me), "{found} vs {me}");
        // and the gate: this test binary is not a browser, a gate that allows its name admits it, the default gate refuses it
        assert!(!Gate::browsers(&[]).admits(peer, local).await);
        assert!(Gate::browsers(&[me.clone()]).admits(peer, local).await);
        assert!(Gate::any().admits(peer, local).await);
    }
}
