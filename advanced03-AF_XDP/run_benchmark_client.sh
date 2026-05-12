#!/bin/bash
sudo ip netns exec ns_client ~/doggo benchmark ./dns_xdp_benchmark_config.json
