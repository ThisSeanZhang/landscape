#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
case_name=dns/negative-cache
case_image_target=dns

case_diagnostics() {
    docker exec "$wan" cat /tmp/upstream.log
}

run_case() {
    docker exec "$lan_peer" ip addr add 192.0.2.10/24 dev eth1
    docker cp "$case_dir/probe.py" "$wan:/tmp/probe.py"
    docker exec -d "$wan" sh -ec 'exec python3 -u /tmp/probe.py serve >/tmp/upstream.log 2>&1'
    docker exec -i "$lan_peer" python3 - check < "$case_dir/probe.py"

    # The middle LAN query is a cache hit. Only the first and last reach the WAN.
    docker exec "$wan" cat /tmp/upstream.log > "$work/queries"
    diff -u <(printf '%s\n' alias.cache.example.org. target.cache.example.org. alias.cache.example.org. target.cache.example.org.) "$work/queries"
}

run_single_wan_lab "$case_dir/dns.toml"
