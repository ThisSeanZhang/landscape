#!/usr/bin/env bash
# Both client modes must reach the WAN with the router's translated address.
set -euo pipefail
client=$1
wan=$2
request_id=${LANDSCAPE_LAB_NAME:?}

printf '%s\n' "$request_id" | docker exec -i "$wan" sh -ec 'cat > "/tmp/$1"' sh "$request_id"
response=$(docker exec "$client" curl -fsS --noproxy '*' --retry 8 --retry-all-errors --retry-delay 1 --max-time 3 \
    "http://198.51.100.1:8080/$request_id")
if [[ "$response" != "$request_id" ]]; then
    echo "Unexpected response from WAN for request $request_id" >&2
    exit 1
fi
if ! docker logs "$wan" 2>&1 | grep -F "198.51.100.2 - - " | grep -F "GET /$request_id HTTP/1.1\" 200"; then
    echo "WAN did not log HTTP 200 from 198.51.100.2 for $request_id" >&2
    exit 1
fi
echo "PASS: client reached the WAN server through Landscape TC and IPv4 NAT"
