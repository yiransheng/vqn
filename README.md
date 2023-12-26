```rust
pub async fn run(tun: AsyncDevice, conn: Connection) {
    let mut framed = tun.into_framed();

    loop {
        select! {
            Some(ip_pkt) = framed.next() => {
                let ip_pkt = ip_pkt.unwrap();
                let _ = conn.send_datagram(ip_pkt.into_bytes());
            }
            dgram = conn.read_datagram() => {
                let dgram = dgram.unwrap();
                let _ = framed.send(TunPacket::new(dgram.to_vec()));
            }
        }
    }
}
```
