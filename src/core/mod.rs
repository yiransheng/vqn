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

pub mod rt;
pub use async_tun::Iface;
pub use tun;

use router::Router;
use tokio_util::codec::Framed;
use tun::Device;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error read/write from tun: {0}")]
    Tun(#[from] io::Error),

    #[error("error read/write from connection: {0}")]
    Conn(#[from] ConnectionError),
}

/// Represents a VPN server, often used as a NAT (Network Address Translation) device.
/// It supports multiple clients, with each client requiring upfront configuration.
/// The server uses one QUIC connection per client.
pub struct Server {
    tun: Iface,
    router: Router,
}

impl Server {
    /// Constructs a new Server instance with a specified tun [Iface].
    pub fn new(tun: Iface) -> Self {
        Self {
            tun,
            router: Router::default(),
        }
    }

    /// Configures a client, including their TLS certificate chain and permitted IP ranges.
    /// Client connections are identified identified by their TLS certificates.
    pub fn add_client(
        &mut self,
        cert_chain: Vec<Certificate>,
        allowed_ips: impl IntoIterator<Item = (IpAddr, u8)>,
    ) {
        self.router.add_peer(cert_chain, allowed_ips);
    }

    /// Asynchronously runs the server using a specified QUIC [Endpoint]
    /// The function handles incoming connections and routes traffic through the tun interface.
    pub async fn run(self, endpoint: Endpoint) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel::<Bytes>(32);

        let Server { tun, router } = self;
        let router = Arc::new(router);
        let r = Arc::clone(&router);

        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                tracing::info!("incoming connection: {}", conn.remote_address());

                let router = Arc::clone(&router);
                let tx = tx.clone();
                tokio::spawn(async move {
                    match conn.await {
                        Ok(conn) => {
                            let conn = router.connect(conn).await;

                            while let Ok(dgram) = conn.read_datagram().await {
                                let _ = tx.send(dgram).await;
                            }
                        }
                        Err(err) => {
                            tracing::trace!("Accept connection error: {err}");
                        }
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
            Some(dgram) = peer_packets.recv() => {
                framed.send(dgram).await?;
            }
        }
    }
}

/// Represents a VPN client that handles packet transmission between
/// a local interface and a VPN connection.
pub struct Client {
    tun: Framed<Iface, TunPacketCodec>,
}

impl Client {
    // Creates a new `Client` instance with a specified network interface ([Iface])
    ///
    /// - `tun`: The network interface to be used by the client.
    pub fn new(tun: Iface) -> tun::Result<Self> {
        let mtu = tun.mtu()?;

        Ok(Self {
            tun: tun.into_framed(mtu as usize),
        })
    }

    /// Asynchronously runs the client, managing the transmission of packets between the local tun interface and
    ///  the VPN connection.
    ///
    /// This method continuously listens for packets from both the local network interface and the VPN connection,
    /// forwarding them appropriately. It handles both incoming and outgoing traffic, wrapping and unwrapping packets
    /// as required.
    ///
    /// - `conn`: The VPN connection used for sending and receiving datagrams.
    /// - Returns: A result indicating success (`Ok`) or an error (`Err`).
    ///
    /// The method will run indefinitely until an error occurs or the connection is lost.
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
