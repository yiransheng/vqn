#!/bin/bash

cd "$(dirname "$0")"

set -x

VQN_BIN="../target/release/vqn"

# Create network namespace vqnc to run vqn client in
ip netns add vqnc

# Add necessary capacities
setcap 'cap_net_admin,cap_setfcap=eip' $VQN_BIN

# Create a pair of connected virtual ethernet devices
# VPN traffic over QUIC will be tunneled between veth0 <-> veth1
ip link add veth0 type veth peer name veth1
# Move veth1 into the network namespace vqnc
ip link set veth1 netns vqnc

# Assign ip address to veth0 in root netns
ip addr add 172.19.0.1/24 dev veth0
ip link set up dev veth0

# Assign ip address to veth1 in vqnc 
ip netns exec vqnc ip addr add 172.19.0.3/24 dev veth1
ip netns exec vqnc ip link set up dev veth1

# Start server
$VQN_BIN --config server.toml &
server_pid=$!

# Start client
$VQN_BIN --config client.toml --netns vqnc --log-level debug &
client_pid=$!

# Resources clean up
down() {
    kill -SIGINT $client_pid
    kill -SIGINT $server_pid
    
    ip netns exec vqnc ip link set down veth1
    ip link set down dev veth0

    ip netns delete vqnc
}

trap "down" INT TERM

# Ping client from root netns
ping -c 5 10.10.0.3 || exit 1

# Ping server from vqnc netns
ip netns exec vqnc ping -c 5 10.10.0.1 || exit 1

down
