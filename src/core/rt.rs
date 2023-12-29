//! This module provides custom constructors for `quinn` [Endpoint]s,
//! exposing the option to set `fwmark` on all tunnel traffic managed by `vqn`. This
//! is the same trick employed by WireGuard to prevent routing loops.
use std::io;
use std::net::SocketAddr;

use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt;
use quinn::{default_runtime, Endpoint, ServerConfig};

// https://docs.rs/quinn/0.10.2/src/quinn/endpoint.rs.html#55-65
pub fn client_endpoint(addr: SocketAddr, fwmark: Option<u32>) -> io::Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    if let Some(fwmark) = fwmark {
        setsockopt(&socket, sockopt::Mark, &fwmark)?;
    }

    let runtime = default_runtime()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;

    Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
}

// https://docs.rs/quinn/0.10.2/src/quinn/endpoint.rs.html#74-84
pub fn server_endpoint(
    config: ServerConfig,
    addr: SocketAddr,
    fwmark: Option<u32>,
) -> io::Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    if let Some(fwmark) = fwmark {
        setsockopt(&socket, sockopt::Mark, &fwmark)?;
    }

    let runtime = default_runtime()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;

    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
}
