#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/gateway.sh"
case_name=gateway/sni-passthrough

run_case() {
    local domain=passthrough.lab.test control=gateway.lab.test
    wait_for_gateway_https
    docker exec "$lan_peer" sh -ec '
        mkdir -p /srv/origin
        printf "%s\n" "$2" > /srv/origin/origin.txt
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 \
            -subj "/CN=$1" -addext "subjectAltName=DNS:$1" \
            -keyout /tmp/backend.key -out /tmp/backend.pem
    ' sh "$domain" "$LANDSCAPE_LAB_NAME"
    docker exec -d -w /srv/origin "$lan_peer" sh -ec '
        exec openssl s_server -accept 192.0.2.10:8443 -cert /tmp/backend.pem \
            -key /tmp/backend.key -WWW -quiet >/proc/1/fd/1 2>/proc/1/fd/2
    '
    docker exec "$lan_peer" curl --noproxy '*' -fsS --retry 10 --retry-all-errors --retry-delay 1 --max-time 2 \
        --cacert /tmp/backend.pem --resolve "$domain:8443:192.0.2.10" "https://$domain:8443/origin.txt" >/dev/null
    docker cp "$lan_peer:/tmp/backend.pem" "$work/backend.pem"
    docker cp "$work/backend.pem" "$wan:/tmp/backend.pem"

    # Both names are eligible for local TLS termination. Only one has an SNI rule.
    install_gateway_certificate "$domain" "$control"
    docker exec -i "$wan" python3 -I - "$control" /tmp/gateway.pem < "$lab_root/lib/probe-https.py"
    docker exec -i "$wan" python3 -I - "$domain" /tmp/backend.pem \
        --get /origin.txt "$LANDSCAPE_LAB_NAME" < "$lab_root/lib/probe-https.py"
}

run_gateway_lab "$case_dir/rules.toml"
