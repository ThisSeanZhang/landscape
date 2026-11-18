#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/lab.sh"

run_single_wan_lab() {
    local layout="$lab_root/topologies/lan/single-wan"
    run_lab "$layout/topology.clab.yml" "$layout/landscape_init.toml" client
}
