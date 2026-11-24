#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
source "$lab_root/lib/capture.sh"
case_name=wan/gateway-ns
case_image_target=wan-ns

# Fixed delegated prefix for this case.
prefix=2001:db8:1000
prefix_len=56
lan_net=$prefix:1

prepare_peers() {
    docker exec "$lan_peer" ip addr add 192.0.2.10/24 dev eth1
    docker exec "$lan_peer" ip route add default via 192.0.2.1

    # LAN side of the delegated prefix; nodad keeps the addresses usable at once.
    docker exec "$router" ip -6 addr add "$lan_net::1/64" dev lan0 nodad
    docker exec "$lan_peer" ip -6 addr add "$lan_net::2/64" dev eth1 nodad
    docker exec "$lan_peer" ip -6 route add default via "$lan_net::1"

    start_capture "$wan" 'icmp6 or udp port 546 or udp port 547 or (ip6 and udp and dst portrange 42001-42005)'

    # The PD responder and NS gateway is the WAN link's own link-local address.
    local wan_ll
    wan_ll=$(docker exec "$wan" ip -6 -o addr show dev eth1 scope link | awk '{print $4}' | cut -d/ -f1)
    test -n "$wan_ll"
    docker cp "$case_dir/pd_server.py" "$wan:/tmp/pd_server.py"
    docker exec -d "$wan" sh -c \
        'exec python3 -u /tmp/pd_server.py eth1 "$1" "$2" "$3" "$(cat /sys/class/net/eth1/address)" >/tmp/pd_server.log 2>&1' \
        sh "$wan_ll" "$prefix::" "$prefix_len"
}

case_diagnostics() {
    docker exec "$wan" cat /tmp/pd_server.log || true
    docker exec "$wan" tcpdump -nn -e -r /tmp/exchange.pcap \
        '(udp port 546 or udp port 547 or icmp6)' || true
    docker exec "$router" ip -6 addr show dev wan0
    docker exec "$router" ip -6 neigh show dev wan0
    docker exec "$router" ip -6 route show
    docker exec "$router" ss -lunp || true
}

run_case() {
    python3 -I "$case_dir/check.py" "$router" "$lan_peer" "$wan" "$lab_root/lib/router-api.sh"
}

run_single_wan_lab
