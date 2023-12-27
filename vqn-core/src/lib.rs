use std::io;
use std::{net::IpAddr, sync::Arc};

use async_tun::TunPacketCodec;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use quinn::{Connection, ConnectionError, Endpoint, SendDatagramError};
use rustls::Certificate;
use thiserror::Error;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver};

mod allowed_ips;
mod async_tun;
mod router;

pub use async_tun::Iface;
pub use tun;

use router::Router;
use tokio_util::codec::Framed;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error read/write from tun: {0}")]
    Tun(#[from] io::Error),

    #[error("error read/write from connection: {0}")]
    Conn(#[from] ConnectionError),
}

pub struct Server {
    tun: Iface,
    router: Router,
}

impl Server {
    pub fn new(tun: Iface) -> Self {
        Self {
            tun,
            router: Router::default(),
        }
    }

    pub fn add_peer(
        &mut self,
        cert_chain: Vec<Certificate>,
        allowed_ips: impl IntoIterator<Item = (IpAddr, u8)>,
    ) {
        self.router.add_peer(cert_chain, allowed_ips);
    }

    pub async fn run(self, endpoint: Endpoint) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel::<Bytes>(32);

        let Server { tun, router } = self;
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

                let dst_ip = match ip_dst_address(&ip_pkt) {
                    Some(addr) => addr,
                    _ => {
                        tracing::debug!("unknown ip packet");
                        continue;
                    }
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

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SIZE: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SIZE: usize = 16;

fn ip_dst_address(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV4_IP_SIZE] = packet
                [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SIZE]
                .try_into()
                .unwrap();
            Some(IpAddr::from(addr_bytes))
        }
        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV6_IP_SIZE] = packet
                [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SIZE]
                .try_into()
                .unwrap();
            Some(IpAddr::from(addr_bytes))
        }
        _ => None,
    }
}
