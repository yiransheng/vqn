use std::process::Command;

use crate::conf::{Cidr, Conf, Network};

pub fn dev_up(conf: &Conf) {
    let tun = conf.network.name().unwrap_or("tun0");
    let routing_table = "19988";
    let fwmark = conf.network.fwmark().unwrap_or(19988).to_string();

    match &conf.network {
        Network::Server { client, .. } => {
            for c in client {
                for ip in &c.allowed_ips.values {
                    route_allowed_ip("add", tun, *ip, routing_table);
                }
            }
        }
        Network::Client { server, .. } => {
            for ip in &server.allowed_ips.values {
                route_allowed_ip("add", tun, *ip, routing_table);
            }
        }
    }

    for ipv in ["-4", "-6"] {
        cmd(
            "ip",
            [
                ipv,
                "rule",
                "add",
                "not",
                "fwmark",
                &fwmark,
                "table",
                routing_table,
            ]
            .as_slice(),
        );
        cmd(
            "ip",
            [
                ipv,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ]
            .as_slice(),
        );
    }
    cmd("resolvectl", ["dns", tun, "1.1.1.1"].as_slice());
}

pub fn dev_down(conf: &Conf) {
    let routing_table = "19988";
    let fwmark = conf.network.fwmark().unwrap_or(19988).to_string();

    for ipv in ["-4", "-6"] {
        cmd(
            "ip",
            [
                ipv,
                "rule",
                "delete",
                "not",
                "fwmark",
                &fwmark,
                "table",
                routing_table,
            ]
            .as_slice(),
        );
        cmd(
            "ip",
            [
                ipv,
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ]
            .as_slice(),
        );
    }
    cmd("ip", ["rule", "delete", "table", routing_table].as_slice());
}

fn route_allowed_ip(action: &str, tun: &str, ip: Cidr, table: &str) {
    let ipv = match ip.ip() {
        std::net::IpAddr::V4(_) => "-4",
        std::net::IpAddr::V6(_) => "-6",
    };
    cmd(
        "ip",
        [
            ipv,
            "route",
            action,
            &ip.to_string(),
            "dev",
            tun,
            "table",
            table,
        ]
        .as_slice(),
    )
}

fn cmd(cmd: &str, args: &[&str]) {
    let exit_code = Command::new(cmd)
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    if !exit_code.success() {
        tracing::error!("Failed to execte {}, {:?}", cmd, args);
    }
}
