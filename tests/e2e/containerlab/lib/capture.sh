#!/usr/bin/env bash
# Each case captures one exchange per node. Wait until the filter is attached.
start_capture() {
    local node=$1 filter=$2
    docker exec -d "$node" sh -ec 'exec tcpdump --immediate-mode -U -ni eth1 -w /tmp/exchange.pcap "$1" 2>/tmp/capture.log' sh "$filter"
    docker exec "$node" timeout 10 sh -ec 'until grep -q "listening on" /tmp/capture.log; do sleep 0.1; done'
}
