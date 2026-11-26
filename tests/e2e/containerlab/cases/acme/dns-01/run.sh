#!/usr/bin/env bash
set -euo pipefail

case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/single-wan.sh"
case_name=acme/dns-01
case_cargo_args=(--features e2e-acme)
case_image_target=acme

case_diagnostics() {
    docker exec "$wan" tail -n 30 /var/lib/acme-lab/pebble.log /var/lib/acme-lab/dns.log
}

run_case() {
    local dir=/var/lib/acme-lab
    docker exec "$wan" mkdir -m 700 "$dir"
    docker cp "$case_dir/pebble.json" "$wan:$dir/"
    docker cp "$case_dir/dns_provider.py" "$wan:$dir/"
    docker exec -w "$dir" "$wan" sh -ec '
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 \
            -subj "/CN=Landscape lab transport CA" -keyout ca.key -out ca.pem
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
            -subj "/CN=Pebble" -keyout server.key -out server.csr
        printf "%s\n" "subjectAltName=IP:198.51.100.1" "extendedKeyUsage=serverAuth" > extensions
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -days 1 \
            -extfile extensions -out server.pem
    '
    docker exec "$wan" cat "$dir/ca.pem" | docker exec -i "$router" sh -ec 'cat >> /etc/ssl/certs/ca-certificates.crt'
    docker exec -d -w "$dir" -e LAB_DNS_TOKEN="$LANDSCAPE_LAB_NAME" "$wan" sh -ec \
        'exec python3 -u dns_provider.py >dns.log 2>&1'
    docker exec -d -w "$dir" -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 "$wan" sh -ec \
        'exec pebble -config pebble.json -dnsserver 127.0.0.1:8053 >pebble.log 2>&1'
    docker exec "$router" curl --noproxy '*' -fsS --retry 10 --retry-all-errors --retry-delay 1 \
        --max-time 3 https://198.51.100.1:14000/dir >/dev/null
    docker exec "$router" curl --noproxy '*' -fsS --retry 10 --retry-all-errors --retry-delay 1 \
        --max-time 3 -H "Authorization: Bearer $LANDSCAPE_LAB_NAME" \
        http://198.51.100.1:8055/client/v4/zones >/dev/null
    python3 -I "$case_dir/issue.py" "$router" "$wan" "$LANDSCAPE_LAB_NAME"
}

run_single_wan_lab
