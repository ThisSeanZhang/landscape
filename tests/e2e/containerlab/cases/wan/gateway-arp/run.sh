#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
source "$lab_root/lib/capture.sh"
case_name=wan/gateway-arp
case_image_target=wan-arp

prepare_peers() {
    docker exec "$lan_peer" ip addr add 192.0.2.10/24 dev eth1
    docker exec "$lan_peer" ip route add default via 192.0.2.1
    docker exec "$wan" ip link add link eth1 name onlink address 02:00:00:00:00:77 type macvlan mode bridge
    docker exec "$wan" ip link set onlink arp off up
    docker exec "$wan" ip addr add 198.51.100.77/32 dev onlink
    start_capture "$wan" 'arp or (udp and dst portrange 42001-42005)'
}

case_diagnostics() {
    docker exec "$wan" tcpdump -nn -e -r /tmp/exchange.pcap
    docker exec "$router" ip -4 neigh show dev wan0
}

run_case() {
    python3 -I "$case_dir/check.py" "$router" "$lan_peer" "$wan" "$lab_root/lib/router-api.sh"
}

run_single_wan_lab
