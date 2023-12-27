use std::net::IpAddr;

use cmd_lib::{run_cmd, CmdResult};

use crate::conf::{Cidr, Conf, Network};

pub fn dev_up(conf: &Conf) -> CmdResult {
    let tun = conf.network.name().unwrap_or("tun0");
    let routing_table = "19988";
    let fwmark = conf.network.fwmark().unwrap_or(19988).to_string();

    match &conf.network {
        Network::Server { client, .. } => {
            for c in client {
                for ip in &c.allowed_ips.values {
                    route_allowed_ip(tun, *ip, routing_table)?;
                }
            }
        }
        Network::Client { server, .. } => {
            for ip in &server.allowed_ips.values {
                route_allowed_ip(tun, *ip, routing_table)?;
            }
        }
    }
    run_cmd! {
        ip -4 rule add not fwmark $fwmark table $routing_table;
        ip -4 rule add table main suppress_prefixlength 0;
        ip -6 rule add not fwmark $fwmark table $routing_table;
        ip -6 rule add table main suppress_prefixlength 0;
        resolvectl dns tun0 1.1.1.1;
    }
}

pub fn dev_down(conf: &Conf) {
    let routing_table = "19988";
    let fwmark = conf.network.fwmark().unwrap_or(19988).to_string();

    let _ = run_cmd! {
        ip -4 rule delete not fwmark $fwmark table $routing_table;
        ip -4 rule delete table main suppress_prefixlength 0;

        ip -6 rule delete not fwmark $fwmark table $routing_table;
        ip -6 rule delete table main suppress_prefixlength 0;

        ip rule delete table $routing_table;
    };
}

fn route_allowed_ip(tun: &str, ip: Cidr, table: &str) -> CmdResult {
    let ip_ = ip.to_string();
    match ip.ip() {
        IpAddr::V4(_) => run_cmd! {
            ip -4 route add $ip_ dev $tun table $table;
        },
        IpAddr::V6(_) => run_cmd! {
            ip -6 route add $ip_ dev $tun table $table;
        },
    }
}
