#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
case_name=lan/dhcp-acquire

case_diagnostics() {
    echo "LAN devices and DHCP leases"
    router_api services/lan_devices
    echo
}

run_case() {
    python3 -I "$case_dir/probe.py" "$lan_peer" "$router" "$work/landscape_init.toml" "$lab_root/lib/router-api.sh"
    bash "$lab_root/lib/check-forward.sh" "$lan_peer" "$wan"
}

run_single_wan_lab
