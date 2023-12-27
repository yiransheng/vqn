use std::collections::VecDeque;
use std::net::IpAddr;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// Represents a collection of allowed IP addresses and their associated data.
///
/// This structure uses a trie (prefix tree) to efficiently store and query
/// IP addresses with associated CIDR (Classless Inter-Domain Routing) notation.
///
/// Each entry in the collection associates an IP address and its subnet mask
/// (in CIDR notation) with generic data of type `D`.
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
    /// Inserts a new IP address, its CIDR, and associated data into the collection.
    ///
    /// If the IP address (with its CIDR) already exists in the collection,
    /// the existing data is replaced with the new data and returned.
    ///
    /// # Arguments
    /// * `key` - An IP address to insert.
    /// * `cidr` - The CIDR notation indicating the subnet mask of the IP address.
    /// * `data` - The data to associate with the IP address.
    ///
    /// # Returns
    /// An `Option` containing the old data if the IP address was already present.
    ///
    /// # Panics
    /// Panics if the provided CIDR value is not a valid length.
    pub fn insert(&mut self, key: IpAddr, cidr: u8, data: D) -> Option<D> {
        self.ips.insert(
            IpNetwork::new_truncate(key, cidr).expect("cidr is valid length"),
            data,
        )
    }

    /// Retrieves the data associated with the longest matching IP address.
    ///
    /// # Arguments
    /// * `key` - The IP address to query.
    ///
    /// # Returns
    /// An `Option` containing a reference to the data, if a matching IP address is found.
    pub fn get(&self, key: IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    /// Provides an iterator over all IP addresses, their CIDR, and associated data in the collection.
    ///
    /// # Returns
    /// An iterator that yields tuples of a data reference, IP address, and CIDR notation
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
