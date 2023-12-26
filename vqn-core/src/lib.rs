use std::eprintln;
use std::{any::Any, net::IpAddr, str::FromStr, sync::Arc};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use packet::ip::Packet;
use quinn::{Connecting, Connection, Endpoint};
use rustls::Certificate;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};

mod allowed_ips;
mod async_tun;
mod router;

pub use async_tun::Iface;

use router::Router;

pub async fn server(cert: Vec<Certificate>, tun: Iface, endpoint: Endpoint) {
    let mut router = Router::default();
    router.add_peer(cert, [(IpAddr::from_str("10.10.0.3").unwrap(), 24)]);

    let (tx, rx) = mpsc::channel::<Bytes>(32);

    let router = Arc::new(router);
    let r = Arc::clone(&router);

    tokio::spawn(async move {
        tun_loop(tun, r, rx).await;
    });

    while let Some(conn) = endpoint.accept().await {
        let router = Arc::clone(&router);
        let tx = tx.clone();
        tokio::spawn(async move {
            let conn = conn.await.unwrap();
            let conn = router.connect(conn).await;
            conn_loop(conn, tx).await;
        });
    }
}

async fn tun_loop(tun: Iface, router: Arc<Router>, mut peer_packets: Receiver<Bytes>) {
    let mut framed = tun.into_framed(1460);

    loop {
        select! {
            Some(ip_pkt) = framed.next() => {
                let ip_pkt = ip_pkt.unwrap();
                let pkt = Packet::unchecked(&ip_pkt);
                let dst_ip: IpAddr = match pkt {
                    Packet::V4(p) => p.destination().into(),
                    Packet::V6(_) => continue,
                };
                eprintln!("--> conn: {dst_ip}");
                if let Some(conn) = router.lookup(dst_ip).await {
                    eprintln!("==> conn: {dst_ip}");
                    let _send_result = conn.send_datagram(ip_pkt);
                } else {
                    eprintln!("...no peer");
                }
            }
            dgram = peer_packets.recv() => {
                eprintln!("--> tunn: {}", dgram.is_some());
                if let Some(dgram) = dgram {
                    let _send_result = framed.send(dgram).await;
                }
            }
        }
    }
}

async fn conn_loop(conn: Arc<Connection>, tx: Sender<Bytes>) {
    while let Ok(dgram) = conn.read_datagram().await {
        eprintln!("conn --> {}", dgram.len());
        let _ = tx.send(dgram).await;
    }
}

pub async fn tunnel(tun: Iface, conn: Connection) {
    let mut framed = tun.into_framed(1500);

    loop {
        select! {
            Some(ip_pkt) = framed.next() => {
                let ip_pkt = ip_pkt.unwrap();
                let _send_result = conn.send_datagram(ip_pkt);
            }
            dgram = conn.read_datagram() => {
                if let Ok(dgram) = dgram {
                    eprintln!("dgram: {}", dgram.len());
                    let _send_result = framed.send(dgram).await;
                }
            }
        }
    }
}
