#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/gateway.sh"
case_name=gateway/live-upstream-update

start_origin() {
    local name=$1 port=$2
    docker exec -d "$lan_peer" sh -ec '
        mkdir -p "/srv/$1"
        printf "%s\n" "$1-$3" > "/srv/$1/origin.txt"
        exec python3 -u -m http.server "$2" --bind 192.0.2.10 --directory "/srv/$1" > "/tmp/$1.log" 2>&1
    ' sh "$name" "$port" "$LANDSCAPE_LAB_NAME"
    docker exec "$router" curl --noproxy '*' -fsS --retry 10 --retry-all-errors --retry-delay 1 --max-time 2 \
        "http://192.0.2.10:$port/origin.txt" >/dev/null
}

run_case() {
    start_origin A 8081
    start_origin B 8082
    python3 -I "$case_dir/switch.py" "$router" "$wan" "$lan_peer" "$LANDSCAPE_LAB_NAME"
}

run_gateway_lab
