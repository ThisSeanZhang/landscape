#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/gateway.sh"
case_name=gateway/https-path-rewrite

run_case() {
    local backend=$lan_peer
    wait_for_gateway_https
    # Only the backend holds the per-run response. Its access log records the raw URL.
    printf '%s\n' "$LANDSCAPE_LAB_NAME" | docker exec -i "$backend" sh -ec 'cat > /tmp/orders'
    docker exec -d "$backend" sh -ec 'exec python3 -u -m http.server 8080 --bind 192.0.2.10 --directory /tmp >/proc/1/fd/1 2>/proc/1/fd/2'
    docker exec "$router" curl --noproxy '*' -fsS --retry 10 --retry-all-errors --retry-delay 1 --max-time 2 \
        http://192.0.2.10:8080/orders >/dev/null

    install_gateway_certificate app.lab.test
    docker exec -i "$wan" python3 -I - app.lab.test /tmp/gateway.pem \
        --get '/api/orders?id=7' "$LANDSCAPE_LAB_NAME" < "$lab_root/lib/probe-https.py"

    if ! docker logs "$backend" 2>&1 | grep -F '"GET /orders?id=7 HTTP/1.1" 200'; then
        echo 'LAN backend did not log the rewritten path and original query with HTTP 200' >&2
        return 1
    fi
}

run_gateway_lab "$case_dir/rules.toml"
