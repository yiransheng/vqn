use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use clap::Parser;
use quinn::TransportConfig;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot::{self, Sender};
use tracing::Level;

use core::Iface;

mod conf;
mod core;
mod firewall;

use conf::{ClientPeer, Conf, Network, ServerPeer};

#[derive(Debug, Parser)]
#[clap(name = "vqn", version)]
pub struct Args {
    #[arg(long)]
    config: PathBuf,

    #[arg(long)]
    log_level: Option<Level>,
}

const DEFAULT_LISTEN_PORT: u16 = 10086;
const DEFAULT_MTU: usize = 1344;
const DEFAULT_TUN_NAME: &str = "tun0";

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(args.log_level.unwrap_or(Level::INFO))
            .finish(),
    )
    .unwrap();

    let conf =
        std::fs::read_to_string(&args.config).with_context(|| "failed to read config file")?;
    let conf = Conf::parse_from(&conf).with_context(|| "failed to parse config file")?;

    let code = {
        if let Err(e) = run(&args.config, conf) {
            eprintln!("{e}");
            1
        } else {
            0
        }
    };

    std::process::exit(code);
}

#[tokio::main]
async fn run(config_path: &Path, conf: Conf) -> anyhow::Result<()> {
    let iface = create_tun(&conf.network)?;

    firewall::dev_up(&conf).context("failed start up firewall configuration sequence")?;

    let conf2 = conf.clone();
    let (tx, rx) = oneshot::channel::<()>();
    let jh = tokio::spawn(async move {
        handle_signals(tx, &conf2).await;
    });

    match &conf.network {
        Network::Server {
            client,
            port,
            fwmark,
            ..
        } => {
            tokio::select! {
                biased;
                _ = rx => (),
                _ = run_server(
                    config_path,
                    iface,
                    port.unwrap_or(DEFAULT_LISTEN_PORT),
                    *fwmark,
                    &conf.tls,
                    client,
                ) => ()
            }
        }
        Network::Client { server, fwmark, .. } => {
            tokio::select! {
                biased;
                _ = rx => (),
                _ = run_client(
                    config_path,
                    iface,
                    *fwmark,
                    &conf.tls,
                    server
                ) => ()
            }
        }
    }

    jh.await?;
    Ok(())
}

fn create_tun(network: &Network) -> anyhow::Result<Iface> {
    let mut config = core::tun::Configuration::default();
    config
        .name(network.name().unwrap_or(DEFAULT_TUN_NAME))
        .address(network.address().ip())
        .netmask(network.address().netmask())
        .mtu(network.mtu().unwrap_or(DEFAULT_MTU) as i32)
        .up();
    let iface = Iface::new(config).context("failed to create a tun interface")?;

    Ok(iface)
}

async fn run_server(
    config_path: &Path,
    iface: Iface,
    listen_port: u16,
    fwmark: Option<u32>,
    tls_config: &conf::Tls,
    clients: &[ClientPeer],
) -> anyhow::Result<()> {
    let server_key = key(config_path, &tls_config.key)?;
    let cert_chain = certs(config_path, &tls_config.cert)?;
    let roots = roots(config_path, tls_config)?;

    let client_cert_verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier.boxed())
        .with_single_cert(cert_chain, server_key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(120).try_into()?))
        .max_concurrent_uni_streams(0_u8.into());

    let listen = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let endpoint = core::rt::server_endpoint(server_config, listen, fwmark)?;
    tracing::info!("listening at {}", listen);

    let mut server = core::Server::new(iface);
    for client in clients {
        tracing::info!("adding a client with allowed ips: {}", &client.allowed_ips);
        server.add_client(
            certs(config_path, &client.client_cert)?,
            client.allowed_ips.iter(),
        )
    }

    server.run(endpoint).await?;

    Ok(())
}

async fn run_client(
    config_path: &Path,
    iface: Iface,
    fwmark: Option<u32>,
    tls_config: &conf::Tls,
    server: &ServerPeer,
) -> anyhow::Result<()> {
    let client_key = key(config_path, &tls_config.key)?;
    let cert_chain = certs(config_path, &tls_config.cert)?;
    let roots = roots(config_path, tls_config)?;

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, client_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(120).try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(15)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = core::rt::client_endpoint("[::]:0".parse().unwrap(), fwmark)?;
    endpoint.set_default_client_config(client_config);

    let url = &server.url;
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(443))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("no hostname specified"))?;
    tracing::info!("connecting to {host} at {remote}");

    let mut client = core::Client::new(iface)?;

    loop {
        let conn = endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;

        tracing::info!("connected to {host} at {remote}");

        if let Err(core::Error::Conn(_)) = client.run(conn).await {
            // reconnect
            continue;
        } else {
            break;
        }
    }

    Ok(())
}

fn roots(config_path: &Path, tls_config: &conf::Tls) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = certs(config_path, &tls_config.ca_cert)?;
    for cert in &ca_certs {
        roots.add(cert)?;
    }

    Ok(roots)
}

fn key(config_path: &Path, key_path: &Path) -> anyhow::Result<rustls::PrivateKey> {
    let key_path = resolve_path(config_path, key_path)?;
    let key = std::fs::read(&key_path)
        .with_context(|| format!("failed to read private key: {}", key_path.to_string_lossy()))?;
    let pkcs8 =
        rustls_pemfile::pkcs8_private_keys(&mut &*key).context("malformed PKCS #8 private key")?;
    let key = match pkcs8.into_iter().next() {
        Some(x) => rustls::PrivateKey(x),
        None => {
            let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                .context("malformed PKCS #1 private key")?;
            match rsa.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    anyhow::bail!("no private keys found");
                }
            }
        }
    };
    Ok(key)
}

fn certs(config_path: &Path, cert_path: &Path) -> anyhow::Result<Vec<rustls::Certificate>> {
    let cert_path = resolve_path(config_path, cert_path)?;
    let cert_chain = std::fs::read(&cert_path).with_context(|| {
        format!(
            "failed to certificate chain: {}",
            cert_path.to_string_lossy()
        )
    })?;
    let cert_chain: Vec<_> = rustls_pemfile::certs(&mut &*cert_chain)
        .context("invalid PEM-encoded certificate")?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    Ok(cert_chain)
}

async fn handle_signals(shutdown: Sender<()>, conf: &Conf) {
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
    let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");

    tokio::select! {
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT");
            firewall::dev_down(conf);
            let _ = shutdown.send(());
        },
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM");
            firewall::dev_down(conf);
            let _ = shutdown.send(());
        },
            _ = sighup.recv() => {
            tracing::info!("Received SIGHUP");
            firewall::dev_down(conf);
            let _ = shutdown.send(());
        },
    }
}

fn resolve_path(config: &Path, file: &Path) -> io::Result<PathBuf> {
    if file.is_absolute() {
        Ok(file.to_path_buf())
    } else {
        let mut base = if config.is_absolute() {
            config.to_path_buf()
        } else {
            // If 'dir' is a relative path, make it absolute.
            std::env::current_dir()?.join(config)
        };
        if base.is_file() {
            base.pop();
        }

        Ok(base.join(file))
    }
}
