```rust
pub async fn run(tun: Tun, conn: Connection) {
    let mut framed = tun.into_framed();

    loop {
        select! {
            Some(ip_pkt) = framed.next() => {
                let ip_pkt = ip_pkt.unwrap();
                let _ = conn.send_datagram(ip_pkt);
            }
            dgram = conn.read_datagram() => {
                let dgram = dgram.unwrap();
                let _ = framed.send(dgram);
            }
        }
    }
}
```
