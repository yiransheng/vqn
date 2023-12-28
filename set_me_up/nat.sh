#!/bin/bash

setcap cap_net_admin=eip vqn
./vqn --config server.toml --log-level debug &
pid=$!

iptables -A FORWARD -i tun0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE


cleanup() {
  iptables -D FORWARD -i tun0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
  ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
}

trap "cleanup" INT TERM
wait $pid
