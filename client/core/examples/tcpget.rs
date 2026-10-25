//! `tcpget IP:PORT [PATH]` - open a TCP connection, send a minimal HTTP/1.0 request and print the first line of the answer
//! (a tool for testing TCP through the mesh from a device without `nc`/`curl`, e.g. an Android shell).
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn main() {
    let mut a = std::env::args().skip(1);
    let dst = a.next().expect("usage: tcpget IP:PORT [PATH]");
    let path = a.next().unwrap_or_else(|| "/".into());
    let t = Instant::now();
    let addr = dst.parse().expect("IP:PORT");
    let mut s = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            println!("{dst}: connect failed after {} ms: {e}", t.elapsed().as_millis());
            std::process::exit(1);
        }
    };
    println!("{dst}: connected in {} ms from {}", t.elapsed().as_millis(), s.local_addr().unwrap());
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ = s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {}\r\n\r\n", addr.ip()).as_bytes());
    let mut buf = [0u8; 512];
    match s.read(&mut buf) {
        Ok(0) => println!("{dst}: closed by the peer without data"),
        Ok(n) => println!("{dst}: {n} bytes, first line: {:?}", String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("")),
        Err(e) => println!("{dst}: read: {e}"),
    }
}
