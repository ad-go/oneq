//! `udpsend IP:PORT TEXT` - send one UDP datagram from a fresh port (a tool for testing port mappings from another network).
fn main() {
    let mut a = std::env::args().skip(1);
    let (dst, text) = (a.next().expect("usage: udpsend IP:PORT TEXT"), a.next().unwrap_or_else(|| "hello".into()));
    let s = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
    for _ in 0..3 {
        s.send_to(text.as_bytes(), &dst).expect("send");
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    println!("sent 3x {text:?} to {dst} from {}", s.local_addr().unwrap());
}
