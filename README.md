# VQN

An incredibly simple VPN based on the QUIC protocol.

## Key Features

**QUIC Protocol Foundation**: VQN is built on QUIC, which means we get innovative features and performance enhancements of QUIC for free: such as [CUBIC congestion controller](https://www.rfc-editor.org/rfc/rfc8312.html) support, [packet pacing](https://www.rfc-editor.org/rfc/rfc9002.html#name-pacing), [Generic Segmentation Offload](https://lwn.net/Articles/188489/) support.

**TLS/MTLS for Client Identity**: Client identity and access are securely managed using TLS/MTLS. This integration ensures that only authorized clients with the right certificate credentials can access the network, enhancing security and simplifying identity management.

**UDP Protocol** VQN doesn't really define a custom protocol per se, it relies on `quinn`'s QUIC extension for sending/receiving raw UDP datagrams instead of using streams. Compared to TCP-based VPN protocols, this ensures lower latency, better congestion control, and faster connection establishment.

**Comparison with WireGuard** While WireGuard is known for its simplicity and speed, VQN's QUIC basis offers even more security and confidentiality. For example, packet number in WireGuard protocol is transmitted in plain texts, but encrypted with header protection in QUIC. On the other hand, all peers in WireGuard are (mostly) symmetrical, whereas VQN requires separate client/server node roles inferior in terms of flexibilities offered for network topologies.

**Simplicity and Pure Rust implementation** VQN is ~1k LOC, and relies on [`quinn`](https://github.com/quinn-rs/quinn) and [`rustls`](https://github.com/rustls/rustls) for all the heavy lifting. The core logic can be digested in a few minutes. It is close to the simplest VPN implementation that could offer enough security and protection for usage over the public Internet (although it is not heavily tested nor audited).

Developed and tested only on Linux.

## Usage

Running:

```bash
vqn --config server.toml
```

```bash
vqn --config client.toml
```

Example configuration files: [server.toml.example](./set_me_up/server.toml.example) and [client.toml.example](./set_me_up/client.toml.example).

See also: 

* [nat.sh](./set_me_up/nat.sh) for an example NAT wrapper
* [tests/ping.sh](./tests/ping.sh) for running client in a Linux netns (testing `VQN` on a single machine)

Required TLS certs and keys:
|                 | Required by server | Required by client | Note                                                                        |
|-----------------|--------------------|--------------------|-----------------------------------------------------------------------------|
| ca-cert.pem     | Yes                | Yes                | Certification authority cert.                                               |
| server-key.pem  | Yes                | No                 | Server private key.                                                         |
| server-cert.pem | Yes                | No                 | Server cert, signed by the same CA,                                         |
| client-key.pem  | No                 | Yes                | Client private key.                                                         |
| client-cert.pem | Yes                | Yes                | Client cert, signed by the same CA. Required on server for identification.  |

Run `make` in the `set_me_up` directory to generate these files.

## Perf

Performed with `iperf3 -i 0 -c 10.9.0.1 -C cubic -t 20` on a pair of EC2 `t2.micro` instances over vpc. With the same `mtu` 1420 (WireGuard default). 

WireGuard

```
Connecting to host 10.9.0.1, port 10088
[  5] local 10.9.0.3 port 53142 connected to 10.9.0.1 port 10088
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-20.00  sec   579 MBytes   243 Mbits/sec    0   1001 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-20.00  sec   579 MBytes   243 Mbits/sec    0             sender
[  5]   0.00-20.04  sec   577 MBytes   242 Mbits/sec                  receiver
```

VQN	
```
Connecting to host 10.10.0.1, port 10088
[  5] local 10.10.0.3 port 53882 connected to 10.10.0.1 port 10088
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-20.00  sec   474 MBytes   199 Mbits/sec  1128    221 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-20.00  sec   474 MBytes   199 Mbits/sec  1128             sender
[  5]   0.00-20.05  sec   471 MBytes   197 Mbits/sec                  receiver
```

Direct connection

```
Connecting to host 172.30.2.167, port 10086
[  5] local 172.30.2.115 port 42210 connected to 172.30.2.167 port 10086
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-20.00  sec  2.28 GBytes   979 Mbits/sec  466    251 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-20.00  sec  2.28 GBytes   979 Mbits/sec  466             sender
[  5]   0.00-20.04  sec  2.28 GBytes   976 Mbits/sec
```

