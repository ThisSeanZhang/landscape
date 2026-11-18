#!/usr/bin/env bash
set -euo pipefail
case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
source "$lab_root/lib/capture.sh"
case_name=lan/dhcp-renew
case_image_target=dhcp-renew

case_diagnostics() {
    router_api services/lan_devices
    docker exec "$lan_peer" cat /tmp/udhcpc.log
    docker exec "$lan_peer" tcpdump -nnvr /tmp/exchange.pcap
}

run_case() {
    docker exec -d "$lan_peer" sh -ec 'exec udhcpc -f -n -i eth1 -p /tmp/udhcpc.pid >/tmp/udhcpc.log 2>&1'
    local before
    before=$(python3 -I "$case_dir/renew.py" "$lan_peer" "$router" "$lab_root/lib/router-api.sh")
    start_capture "$lan_peer" 'udp and (port 67 or port 68)'
    docker exec "$lan_peer" sh -ec 'kill -USR1 "$(cat /tmp/udhcpc.pid)"'
    python3 -I "$case_dir/renew.py" "$lan_peer" "$router" "$lab_root/lib/router-api.sh" "$before"
    bash "$lab_root/lib/check-forward.sh" "$lan_peer" "$wan"
}

run_single_wan_lab
