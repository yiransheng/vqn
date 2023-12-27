#!/bin/bash

IP=10.10.0.3/24

setcap cap_net_admin=eip target/release/vqn-cli
target/release/vqn-cli "$@" &
pid=$!

set -x

ip addr add $IP dev tun0
ip link set up dev tun0
ip link set dev tun0 mtu 1344

ip -4 route add 20.27.0.0/16 dev tun0 table 19988
ip -4 rule add not fwmark 19988 table 19988
ip -4 rule add table main suppress_prefixlength 0
resolvectl dns tun0 1.1.1.1

cleanup() {
  kill $pid;
  ip -4 rule delete not fwmark 19988 table 19988
  ip -4 rule delete table 19988
  ip -4 rule delete table main suppress_prefixlength 0
  # iptables-restore -n
}

trap "cleanup" INT TERM
wait $pid
