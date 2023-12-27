use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use quinn::TransportConfig;
use tracing::Level;
use url::Url;

use vqn_core::Iface;

#[derive(Debug, Parser)]
#[clap(name = "vqn", version)]
pub struct App {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
struct GlobalOpts {
    #[clap(long = "ca-cert")]
    ca_cert: PathBuf,

    #[arg(long)]
    log_level: Option<Level>,
}

#[derive(Debug, Parser)]
struct ServerOpts {
    #[clap(long)]
    key: PathBuf,

    #[clap(long)]
    cert: PathBuf,

    #[clap(long, short)]
    listen: SocketAddr,
}

#[derive(Debug, Parser)]
struct ClientOpts {
    #[clap(long)]
    key: PathBuf,

    #[clap(long)]
    cert: PathBuf,

    #[clap(long)]
    url: Url,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server(ServerOpts),
    Client(ClientOpts),
}

fn main() {
    let args = App::parse();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(args.global_opts.log_level.unwrap_or(Level::INFO))
            .finish(),
    )
    .unwrap();
    let code = {
        if let Err(e) = run(args) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };

    std::process::exit(code);
}

#[tokio::main]
async fn run(args: App) -> anyhow::Result<()> {
    match args.command {
        Command::Server(ref opts) => run_server(&args.global_opts, opts).await?,
        Command::Client(ref opts) => run_client(&args.global_opts, opts).await?,
    }

    Ok(())
}

async fn run_server(global: &GlobalOpts, args: &ServerOpts) -> anyhow::Result<()> {
    let server_key = key(&args.key)?;
    let cert_chain = certs(&args.cert)?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = certs(&global.ca_cert)?;
    for cert in &ca_certs {
        roots.add(cert)?;
    }

    let client_cert_verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier.boxed())
        .with_single_cert(cert_chain, server_key)?;

    // server_crypto.alpn_protocols = quinn::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.initial_mtu(1360);

    let endpoint = quinn::Endpoint::server(server_config, args.listen)?;

    let mut config = vqn_core::tun::Configuration::default();
    config
        .name("tun0")
        .address((10, 10, 0, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1344)
        .up();
    let iface = Iface::new(config).context("failed to create a tun interface")?;

    let mut server = vqn_core::Server::new(iface);

    // TODO: for testing prototype only
    server.add_peer(certs(&args.cert)?, [("10.10.0.3".parse().unwrap(), 32)]);
    server.run(endpoint).await?;

    Ok(())
}

async fn run_client(global: &GlobalOpts, args: &ClientOpts) -> anyhow::Result<()> {
    let mut config = vqn_core::tun::Configuration::default();
    config
        .name("tun0")
        .address((10, 10, 0, 3))
        .netmask((255, 255, 255, 0))
        .mtu(1344)
        .up();
    let iface = Iface::new(config).context("failed to create a tun interface")?;

    let client_key = key(&args.key)?;
    let cert_chain = certs(&args.cert)?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = certs(&global.ca_cert)?;
    for cert in &ca_certs {
        roots.add(cert)?;
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, client_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config
        .initial_mtu(1360)
        .max_idle_timeout(Some(Duration::from_secs(120).try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(15)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let url = &args.url;
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("no hostname specified"))?;
    eprintln!("connecting to {host} at {remote}");

    let mut client = vqn_core::Client::new(iface, 1500);

    loop {
        let conn = endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;

        eprintln!("connected to {host} at {remote}");

        if let Err(vqn_core::Error::Conn(_)) = client.run(conn).await {
            // reconnect
            continue;
        } else {
            break;
        }
    }

    Ok(())
}

fn key(key_path: &Path) -> anyhow::Result<rustls::PrivateKey> {
    let key = std::fs::read(key_path).context("failed to read private key")?;
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

fn certs(cert_path: &Path) -> anyhow::Result<Vec<rustls::Certificate>> {
    let cert_chain = std::fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain: Vec<_> = rustls_pemfile::certs(&mut &*cert_chain)
        .context("invalid PEM-encoded certificate")?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    Ok(cert_chain)
}
