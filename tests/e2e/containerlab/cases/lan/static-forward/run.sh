#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
case_name=lan/static-forward

case_diagnostics() { :; }

run_case() {
    docker exec "$lan_peer" ip addr add 192.0.2.10/24 dev eth1
    docker exec "$lan_peer" ip route add default via 192.0.2.1
    bash "$lab_root/lib/check-forward.sh" "$lan_peer" "$wan"
}

run_single_wan_lab
