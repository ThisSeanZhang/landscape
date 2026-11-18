#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

case_diagnostics() {
    router_api gateway/status
    echo
    docker exec "$wan" ip -br addr show dev eth1
}

wait_for_gateway_https() {
    local deadline=$((SECONDS + 30))
    until router_api gateway/status | python3 -c 'import json, sys; sys.exit(not json.load(sys.stdin)["data"]["https_ready"])'; do
        if (( SECONDS >= deadline )); then
            echo 'Gateway HTTPS listener did not become ready' >&2
            return 1
        fi
        sleep 1
    done
}

install_gateway_certificate() {
    python3 -c '
import json, sys
print(json.dumps({"name": "gateway-e2e", "domains": sys.argv[1:],
                  "cert_type": {"t": "generated", "validity_days": 1}, "for_gateway": True}))
' "$@" | router_api cert/certs --json @- |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["data"]["certificate"])' > "$work/gateway.pem"
    docker cp "$work/gateway.pem" "$wan:/tmp/gateway.pem"
}

run_gateway_lab() {
    local layout="$lab_root/topologies/gateway/wan-to-lan"
    run_lab "$layout/topology.clab.yml" "$layout/landscape_init.toml" backend "$@"
}
