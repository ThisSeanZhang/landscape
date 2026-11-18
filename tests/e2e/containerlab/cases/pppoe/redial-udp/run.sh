#!/usr/bin/env bash
set -euo pipefail
case_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$case_dir/../../../lib/lab.sh"
source "$lab_root/lib/capture.sh"
case_name=pppoe/redial-udp
case_image_target=pppoe

prepare_peers() {
    start_capture "$wan" 'ether proto 0x8863'
    docker exec "$wan" sh -ec '
        test -c /dev/ppp
        printf "lab * lab *\n" > /etc/ppp/pap-secrets
        chmod 600 /etc/ppp/pap-secrets
        printf "%s\n" require-pap refuse-chap refuse-mschap refuse-mschap-v2 refuse-eap nobsdcomp nodeflate "logfile /tmp/pppd.log" > /tmp/ac-options
    '
    docker exec -d "$wan" sh -ec 'exec pppoe-server -F -I eth1 -L 198.51.100.1 -R 198.51.100.2 -N 4 -O /tmp/ac-options >/tmp/ac.log 2>&1'
    docker cp "$case_dir/echo.py" "$wan:/tmp/"
    docker exec -d "$wan" python3 /tmp/echo.py
}

case_diagnostics() {
    docker exec "$wan" cat /tmp/ac.log /tmp/pppd.log
    docker exec "$wan" tcpdump -nnr /tmp/exchange.pcap
    docker exec "$wan" ip -br address
}

run_case() {
    docker exec "$lan_peer" ip addr add 192.0.2.10/24 dev eth1
    docker exec "$lan_peer" ip route add default via 192.0.2.1
    docker cp "$case_dir/client.py" "$lan_peer:/tmp/"
    docker exec "$lan_peer" python3 /tmp/client.py &
    local probe=$!
    docker exec "$lan_peer" timeout 65 sh -ec 'until test -f /tmp/first-reply; do sleep 0.2; done'
    docker exec "$wan" sh -ec 'read -r pid < /run/ppp0.pid; kill -TERM "$pid"'
    wait "$probe"
    docker exec "$wan" tcpdump -nnr /tmp/exchange.pcap > "$work/discovery.log"
    python3 - "$work/discovery.log" <<'PY'
from pathlib import Path
import re
import sys

events = re.findall(r'PPPoE (PADS|PADT) \[ses (0x[0-9a-fA-F]+)\]', Path(sys.argv[1]).read_text())
for i, (kind, first) in enumerate(events):
    if kind == "PADT" and ("PADS", first) in events[:i]:
        if any(k == "PADS" and sid != first for k, sid in events[i + 1:]):
            print(f"PASS: PPPoE discovery confirmed session replacement: {events}")
            break
else:
    sys.exit(f"Missing initial PADS, matching PADT and new PADS: {events}")
PY
}

layout="$lab_root/topologies/pppoe/single-wan"
run_lab "$layout/topology.clab.yml" "$layout/landscape_init.toml" client
