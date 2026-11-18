#!/usr/bin/env bash
set -euo pipefail
client=$1
wan=$2

docker exec "$client" ip addr add 192.0.2.10/24 dev eth1
docker exec "$client" ip route add default via 192.0.2.1
exec bash "$(dirname "$0")/../check-forward.sh" "$client" "$wan"
