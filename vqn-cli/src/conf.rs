use std::str::FromStr;
use std::{
    net::{IpAddr},
    path::PathBuf,
};

use serde::{de, Deserialize, Deserializer};
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Conf {
    pub network: Network,
    pub tls: Tls,
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub key: PathBuf,
    pub cert: PathBuf,
    pub ca_cert: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role")]
pub enum Network {
    #[serde(rename = "server")]
    Server {
        address: Cidr,
        client: Vec<ClientPeer>,
    },

    #[serde(rename = "client")]
    Client { address: Cidr, server: ServerPeer },
}

#[derive(Debug, Deserialize)]
pub struct ClientPeer {
    pub client_cert: PathBuf,

    pub allowed_ips: AllowedIps,
}

#[derive(Debug, Deserialize)]
pub struct ServerPeer {
    pub url: Url,
    pub allowed_ips: AllowedIps,
}

#[derive(Debug)]
pub struct Cidr(pub IpAddr, pub u8);

#[derive(Debug)]
pub struct AllowedIps {
    pub values: Vec<Cidr>,
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
}
