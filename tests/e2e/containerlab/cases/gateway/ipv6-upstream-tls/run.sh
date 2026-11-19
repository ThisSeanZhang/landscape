#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/gateway.sh"
case_name=gateway/ipv6-upstream-tls

prepare_peers() {
    docker exec -w /tmp "$lan_peer" sh -ec '
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 \
            -subj "/CN=Gateway IPv6 test CA" -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign" -keyout ca.key -out ca.pem
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
            -subj "/CN=backend" -addext "subjectAltName=IP:fe80::10" \
            -addext "extendedKeyUsage=serverAuth" -keyout backend.key -out backend.csr
        openssl x509 -req -in backend.csr -CA ca.pem -CAkey ca.key -days 1 \
            -copy_extensions copy -out backend.pem
    '
    # The gateway loads its trust roots when it starts. Install only the public CA in the lab router.
    docker exec "$lan_peer" cat /tmp/ca.pem |
        docker exec -i "$router" sh -ec 'cat >> /etc/ssl/certs/ca-certificates.crt'
}

run_case() {
    docker exec "$router" ip -6 addr add fe80::1/64 dev lan0 nodad
    docker exec "$lan_peer" ip -6 addr add fe80::10/64 dev eth1 nodad
    docker exec "$lan_peer" ip -6 addr add fe80::11/64 dev eth1 nodad
    docker exec "$lan_peer" sh -ec 'mkdir -p /srv/origin && echo "$1" > /srv/origin/origin.txt' sh "$LANDSCAPE_LAB_NAME"
    docker exec -d -w /srv/origin "$lan_peer" sh -ec '
        exec openssl s_server -6 -accept 8443 -cert /tmp/backend.pem -key /tmp/backend.key \
            -WWW -quiet >/proc/1/fd/1 2>/proc/1/fd/2
    '

    docker exec "$wan" sh -ec '
        body=$(curl --noproxy "*" -fsS --retry 10 --retry-all-errors --retry-delay 1 --max-time 3 \
            --resolve match.lab.test:80:198.51.100.2 http://match.lab.test/origin.txt)
        if [ "$body" != "$1" ]; then
            echo "Expected the marker from the IPv6 backend, got: $body" >&2
            exit 1
        fi
        echo "PASS: Gateway verified the fe80::10 certificate and returned the origin marker"

        status=$(curl --noproxy "*" -sS --max-time 5 -o /tmp/mismatch-body -w "%{http_code}" \
            --resolve mismatch.lab.test:80:198.51.100.2 http://mismatch.lab.test/origin.txt)
        if [ "$status" != 502 ] || ! grep -Fxq "Reason: upstream_tls_failed" /tmp/mismatch-body; then
            echo "Expected a TLS verification failure for fe80::11, got HTTP $status" >&2
            cat /tmp/mismatch-body >&2
            exit 1
        fi
        echo "PASS: Gateway rejected the same certificate for fe80::11 with HTTP 502"
    ' sh "$LANDSCAPE_LAB_NAME"
}

run_gateway_lab "$case_dir/rules.toml"
