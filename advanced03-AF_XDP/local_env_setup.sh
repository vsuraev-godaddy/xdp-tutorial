#!/bin/bash
# Create a distinct client network namespace
sudo ip netns add ns_client

# Create the veth pair
sudo ip link add veth_client type veth peer name veth_xdp

# Move veth_client inside the isolated namespace
sudo ip link set veth_client netns ns_client

sudo ip netns exec ns_client ip addr add 192.168.100.1/24 dev veth_client
sudo ip netns exec ns_client ip link set veth_client up

# Bring up loopback inside the namespace to satisfy tool defaults
sudo ip netns exec ns_client ip link set lo up

