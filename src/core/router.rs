use std::sync::{Arc, Weak};
use std::{collections::HashMap, net::IpAddr};

use super::allowed_ips::AllowedIps;
use quinn::Connection;
use rustls::Certificate;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct Router {
    // map cert_chain -> AllowedIps
    allowed_ips: HashMap<Vec<Certificate>, AllowedIps<()>>,
    // lookup Connection by IP
    connections: RwLock<AllowedIps<Weak<Connection>>>,
}

impl Router {
    pub fn add_peer(
        &mut self,
        key: Vec<Certificate>,
        iter: impl IntoIterator<Item = (IpAddr, u8)>,
    ) {
        self.allowed_ips
            .entry(key)
            .or_default()
            .extend(iter.into_iter().map(|(ip, cidr)| (ip, cidr, ())));
    }

    pub async fn connect(&self, conn: Connection) -> Arc<Connection> {
        let certs = conn
            .peer_identity()
            .and_then(|ident| ident.downcast::<Vec<Certificate>>().ok());

        let conn = Arc::new(conn);

        let Some(certs) = certs else {
            return conn;
        };

        let mut connections = self.connections.write().await;
        for (_, ip, cidr) in self
            .allowed_ips
            .get(&*certs)
            .into_iter()
            .flat_map(|ips| ips.iter())
        {
            let conn = Arc::downgrade(&conn);
            connections.insert(ip, cidr, conn);
        }

        conn
    }

    pub async fn lookup(&self, ip: IpAddr) -> Option<Arc<Connection>> {
        let connections = self.connections.read().await;

        connections.get(ip).and_then(|conn| conn.upgrade())
    }
}
