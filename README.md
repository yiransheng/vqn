# VQN

An incredibly simple VPN based on the QUIC protocol.

## Key Features

**QUIC Protocol Foundation**: VQN is built on QUIC, which means we get innovative features and performance enhancements of QUIC for free: such as [CUBIC congestion controller](https://www.rfc-editor.org/rfc/rfc8312.html) support, [packet pacing](https://www.rfc-editor.org/rfc/rfc9002.html#name-pacing), [Generic Segmentation Offload](https://lwn.net/Articles/188489/) support.

**TLS/MTLS for Client Identity**: Client identity and access are securely managed using TLS/MTLS. This integration ensures that only authorized clients with the right certificate credentials can access the network, enhancing security and simplifying identity management.

**UDP Protocol** VQN doesn't really define a custom protocol per se, it relies on `quinn`'s QUIC extension for sending/receiving raw UDP datagrams instead of using streams. Compared to TCP-based VPN protocols, this ensures lower latency, better congestion control, and faster connection establishment.

**Comparison with WireGuard** While WireGuard is known for its simplicity and speed, VQN's QUIC basis offers even more security and confidentiality. For example, packet number in WireGuard protocol is transmitted in plain texts, but encrypted with header protection in QUIC. On the other hand, all peers in WireGuard are (mostly) symmetrical, whereas VQN requires separate client/server node roles inferior in terms of flexibilities offered for network topologies.

**Simplicity and Pure Rust implementation** VQN is ~1k LOC, and relies on [`quinn`](https://github.com/quinn-rs/quinn) and [`rustls`](https://github.com/rustls/rustls) for all the heavy lifting. The core logic can be digested in a few minutes. It is close to the simplest VPN implementation that could offer enough security and protection for usage over the public Internet (although it is not heavily tested nor audited).

## Usage

TODO


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
