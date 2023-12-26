use std::collections::VecDeque;
use std::net::IpAddr;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// A trie of IP/cidr addresses
pub struct AllowedIps<D> {
    ips: IpNetworkTable<D>,
}

impl<T> Default for AllowedIps<T> {
    fn default() -> Self {
        AllowedIps {
            ips: IpNetworkTable::new(),
        }
    }
}

impl<D> AllowedIps<D> {
    pub fn insert(&mut self, key: IpAddr, cidr: u8, data: D) -> Option<D> {
        self.ips.insert(
            IpNetwork::new_truncate(key, cidr).expect("cidr is valid length"),
            data,
        )
    }

    pub fn get(&self, key: IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    pub fn iter(&self) -> Iter<D> {
        Iter(
            self.ips
                .iter()
                .map(|(ipa, d)| (d, ipa.network_address(), ipa.netmask()))
                .collect(),
        )
    }
}

pub struct Iter<'a, D: 'a>(VecDeque<(&'a D, IpAddr, u8)>);

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpAddr, u8);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

impl<T> Extend<(IpAddr, u8, T)> for AllowedIps<T> {
    fn extend<I: IntoIterator<Item = (IpAddr, u8, T)>>(&mut self, iter: I) {
        for (ip, cidr, value) in iter {
            self.insert(ip, cidr, value);
        }
    }
}
