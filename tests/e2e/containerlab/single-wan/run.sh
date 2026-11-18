#!/usr/bin/env bash
# From the repo root: ./tests/e2e/containerlab/single-wan/run.sh [static|dhcp]
# Requires a native Linux build environment, Docker and Containerlab.
set -euo pipefail

client_mode=${1:-static}
if (( $# > 1 )) || [[ $client_mode != static && $client_mode != dhcp ]]; then
    echo "Usage: $0 [static|dhcp]" >&2
    exit 2
fi

scenario=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$scenario/../lib/lab.sh"
case_name="single-wan/$client_mode"

case_diagnostics() {
    if [[ $client_mode == dhcp ]]; then
        echo "LAN devices and DHCP leases"
        router_api services/lan_devices
        echo
    fi
}

run_case() {
    if [[ $client_mode == dhcp ]]; then
        python3 -I "$scenario/cases/dhcp-acquire.py" "$lan_peer" "$router" "$wan"
    else
        bash "$scenario/cases/static-forward.sh" "$lan_peer" "$wan"
    fi
}

run_lab "$scenario/single-wan.clab.yml" "$scenario/landscape_init.toml" client
