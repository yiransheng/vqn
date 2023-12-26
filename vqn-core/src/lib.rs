use std::io;
use std::{net::IpAddr, str::FromStr, sync::Arc};

use async_tun::TunPacketCodec;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use packet::ip::Packet;
use quinn::{Connection, ConnectionError, Endpoint, SendDatagramError};
use rustls::Certificate;
use thiserror::Error;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver};

mod allowed_ips;
mod async_tun;
mod router;

pub use async_tun::Iface;

use router::Router;
use tokio_util::codec::Framed;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error read/write from tun: {0}")]
    Tun(#[from] io::Error),

    #[error("error read/write from connection: {0}")]
    Conn(#[from] ConnectionError),
}

pub async fn server(cert: Vec<Certificate>, tun: Iface, endpoint: Endpoint) -> Result<(), Error> {
    let mut router = Router::default();
    router.add_peer(cert, [(IpAddr::from_str("10.10.0.3").unwrap(), 32)]);

    let (tx, rx) = mpsc::channel::<Bytes>(32);

    let router = Arc::new(router);
    let r = Arc::clone(&router);

    tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            let router = Arc::clone(&router);
            let tx = tx.clone();
            tokio::spawn(async move {
                let conn = conn.await.unwrap();
                let conn = router.connect(conn).await;

                while let Ok(dgram) = conn.read_datagram().await {
                    let _ = tx.send(dgram).await;
                }
            });
        }
    });

    let jh = tokio::spawn(async move { tun_loop(tun, r, rx).await });
    jh.await.unwrap()?;

    Ok(())
}

async fn tun_loop(
    tun: Iface,
    router: Arc<Router>,
    mut peer_packets: Receiver<Bytes>,
) -> Result<(), Error> {
    let mut framed = tun.into_framed(1460);

    loop {
        select! {
            Some(ip_pkt) = framed.next() => {
                let ip_pkt = ip_pkt?;
                let pkt = Packet::unchecked(&ip_pkt);
                let dst_ip: IpAddr = match pkt {
                    Packet::V4(p) => p.destination().into(),
                    Packet::V6(_) => {
                        tracing::warn!("ipv6 not supported");
                        continue;
                    },
                };


                if let Some(conn) = router.lookup(dst_ip).await {
                    tracing::trace!("sening {} to {dst_ip}", ip_pkt.len());

                    if let Err(SendDatagramError::ConnectionLost(err)) = conn.send_datagram(ip_pkt) {
                        return Err(err.into());
                    }
                } else {
                    tracing::trace!("dropping packet, no route for {dst_ip}");
                }
            }
            dgram = peer_packets.recv() => {
                if let Some(dgram) = dgram {
                    framed.send(dgram).await?;
                }
            }
        }
    }
}

pub struct Client {
    tun: Framed<Iface, TunPacketCodec>,
}

impl Client {
    pub fn new(tun: Iface, mtu: usize) -> Self {
        Self {
            tun: tun.into_framed(mtu),
        }
    }

    pub async fn run(&mut self, conn: Connection) -> Result<(), Error> {
        loop {
            select! {
                Some(ip_pkt) = self.tun.next() => {
                    let ip_pkt = ip_pkt.unwrap();
                    tracing::trace!("packet size ->: {}", ip_pkt.len());

                    if let Err(SendDatagramError::ConnectionLost(err)) = conn.send_datagram(ip_pkt) {
                        return Err(err.into());
                    }
                }
                dgram = conn.read_datagram() => {
                    let dgram = dgram?;
                    tracing::trace!("packet size <-: {}", dgram.len());

                    self.tun.send(dgram).await?;
                }
            }
        }
    }
}
