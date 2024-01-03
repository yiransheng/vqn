use std::io;
use std::path::Path;
use std::str::FromStr;
use std::{net::IpAddr, path::PathBuf};

use anyhow::{self, Context};
use serde::{de, Deserialize, Deserializer};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Conf {
    pub network: Network,
    pub tls: Tls,
}

impl Conf {
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let conf = std::fs::read_to_string(path).with_context(|| "failed to read config file")?;
        let mut conf = Self::parse_from(&conf).with_context(|| "failed to parse config file")?;
        conf.tls.update_relative_paths(path)?;

        Ok(conf)
    }

    pub fn parse_from(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tls {
    pub key: PathBuf,
    pub cert: PathBuf,
    pub ca_cert: PathBuf,
}

impl Tls {
    fn update_relative_paths(&mut self, base: &Path) -> io::Result<()> {
        Self::update_relative_path(base, &mut self.key)?;
        Self::update_relative_path(base, &mut self.cert)?;
        Self::update_relative_path(base, &mut self.ca_cert)
    }

    fn update_relative_path(config: &Path, file: &mut PathBuf) -> io::Result<()> {
        if !file.is_absolute() {
            let mut base = if config.is_absolute() {
                config.to_path_buf()
            } else {
                // If 'dir' is a relative path, make it absolute.
                std::env::current_dir()?.join(config)
            };
            if base.is_file() {
                base.pop();
            }

            *file = base.join(&file);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "role")]
pub enum Network {
    #[serde(rename = "server")]
    Server {
        name: Option<String>,
        address: Cidr,
        mtu: Option<usize>,
        port: Option<u16>,
        client: Vec<ClientPeer>,
        fwmark: Option<u32>,
        dns: Option<String>,
    },

    #[serde(rename = "client")]
    Client {
        name: Option<String>,
        address: Cidr,
        mtu: Option<usize>,
        server: ServerPeer,
        fwmark: Option<u32>,
        dns: Option<String>,
    },
}

impl Network {
    pub fn address(&self) -> Cidr {
        match self {
            Network::Server { address, .. } => *address,
            Network::Client { address, .. } => *address,
        }
    }

    pub fn mtu(&self) -> Option<usize> {
        match self {
            Network::Server { mtu, .. } => *mtu,
            Network::Client { mtu, .. } => *mtu,
        }
    }

    pub fn fwmark(&self) -> Option<u32> {
        match self {
            Network::Server { fwmark, .. } => *fwmark,
            Network::Client { fwmark, .. } => *fwmark,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Network::Server { name, .. } => name.as_deref(),
            Network::Client { name, .. } => name.as_deref(),
        }
    }

    pub fn dns(&self) -> Option<&str> {
        match self {
            Network::Server { dns, .. } => dns.as_deref(),
            Network::Client { dns, .. } => dns.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientPeer {
    pub client_cert: PathBuf,

    pub allowed_ips: AllowedIps,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerPeer {
    pub url: Url,
    pub server_name: Option<String>,
    pub allowed_ips: AllowedIps,
}

#[derive(Debug, Copy, Clone)]
pub struct Cidr(pub IpAddr, pub u8);

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Cidr(ip, cidr) = self;

        write!(f, "{ip}/{cidr}")
    }
}

impl Cidr {
    pub fn ip(self) -> IpAddr {
        self.0
    }

    pub fn netmask(self) -> (u8, u8, u8, u8) {
        let mask = if self.1 >= 32 {
            return (255, 255, 255, 255);
        } else {
            ((1u64 << self.1) - 1) << (32 - self.1)
        };

        (
            ((mask >> 24) & 0xFF) as u8,
            ((mask >> 16) & 0xFF) as u8,
            ((mask >> 8) & 0xFF) as u8,
            (mask & 0xFF) as u8,
        )
    }
}

#[derive(Debug, Clone)]
pub struct AllowedIps {
    pub values: Vec<Cidr>,
}

impl AllowedIps {
    pub fn iter(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.values.iter().map(|cidr| (cidr.0, cidr.1))
    }
}

impl std::fmt::Display for AllowedIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for cidr in &self.values {
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
            write!(f, "{cidr}")?;
        }
        Ok(())
    }
}

pub struct ParseCidrError(String);

impl std::fmt::Display for ParseCidrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(cidr: &str) -> Result<Self, Self::Err> {
        let (ip_str, subnet_str) = cidr
            .split_once('/')
            .ok_or_else(|| ParseCidrError(format!("Invalid CIDR format: {cidr}")))?;

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|_| ParseCidrError(format!("Invalid IP address: {cidr}")))?;

        let subnet = subnet_str
            .parse::<u8>()
            .map_err(|_| ParseCidrError(format!("Invalid subnet mask: {cidr}")))?;

        if subnet > 32 {
            return Err(ParseCidrError(format!(
                "Subnet mask must be in the range 0-32: {cidr}"
            )));
        }

        Ok(Self(ip, subnet))
    }
}

impl FromStr for AllowedIps {
    type Err = ParseCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let values: Result<Vec<_>, _> = s
            .split(',')
            .filter_map(|allowed_ip| Some(allowed_ip.trim()).filter(|s| !s.is_empty()))
            .map(Cidr::from_str)
            .collect();

        Ok(AllowedIps { values: values? })
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for AllowedIps {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_server() {
        let input = r#"
[tls]
key = "./key.pem"
cert = "./cert.pem"
ca_cert = "./ca_cert.pem"

[network]
role = "server"
address = "10.10.0.3/24"
port = 10086

[[network.client]]
client_cert = "./client_cert.pem"
allowed_ips = "10.10.0.1/32"

[[network.client]]
client_cert = "./client_cert2.pem"
allowed_ips = "10.10.0.2/32"
"#;

        let conf: Result<Conf, _> = toml::from_str(input);
        assert!(conf.is_ok());
    }

    #[test]
    fn test_client() {
        let input = r#"
[tls]
key = "./key.pem"
cert = "./cert.pem"
ca_cert = "./ca_cert.pem"

[network]
role = "client"
address = "10.10.0.3/24"

[network.server]
url = "https://example.org"
allowed_ips = "0.0.0.0/0, ::/0"
"#;
        let conf: Result<Conf, _> = toml::from_str(input);

        assert!(conf.is_ok());
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(
            Cidr("0.0.0.0".parse().unwrap(), 32).netmask(),
            (255, 255, 255, 255)
        );
        assert_eq!(
            Cidr("0.0.0.0".parse().unwrap(), 24).netmask(),
            (255, 255, 255, 0)
        );
        assert_eq!(
            Cidr("0.0.0.0".parse().unwrap(), 16).netmask(),
            (255, 255, 0, 0)
        );
        assert_eq!(
            Cidr("0.0.0.0".parse().unwrap(), 8).netmask(),
            (255, 0, 0, 0)
        );
        assert_eq!(Cidr("0.0.0.0".parse().unwrap(), 0).netmask(), (0, 0, 0, 0));
    }
}
