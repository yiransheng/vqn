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

## Perf

Direct:
```
Connecting to host www.vqn.org, port 10086
[  5] local 192.168.10.6 port 57380 connected to 192.0.2.1 port 10086
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-20.00  sec  30.0 MBytes  12.6 Mbits/sec   11    588 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-20.00  sec  30.0 MBytes  12.6 Mbits/sec   11             sender
[  5]   0.00-20.31  sec  27.3 MBytes  11.3 Mbits/sec                  receiver

iperf Done.
```

vqn:
```
Connecting to host 10.10.0.1, port 1024
[  5] local 10.10.0.3 port 53802 connected to 10.10.0.1 port 1024
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-20.00  sec  36.8 MBytes  15.4 Mbits/sec   39    607 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-20.00  sec  36.8 MBytes  15.4 Mbits/sec   39             sender
[  5]   0.00-20.30  sec  36.1 MBytes  14.9 Mbits/sec                  receiver

iperf Done.
```
