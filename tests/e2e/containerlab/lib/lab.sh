#!/usr/bin/env bash
# Sourced by case launchers, which define run_case and case_diagnostics.
lab_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

router_api() {
    bash "$lab_root/lib/router-api.sh" "$router" "$@"
}

diagnostics() {
    echo "Lab $LANDSCAPE_LAB_NAME, case $case_name"
    echo "LAN peer addresses, routes and DNS"
    docker exec "$lan_peer" ip -br addr show dev eth1
    docker exec "$lan_peer" ip -4 route
    docker exec "$lan_peer" cat /etc/resolv.conf
    case_diagnostics
    echo "Router addresses, routes and TC filters"
    docker exec "$router" ip -br addr
    docker exec "$router" ip -4 route
    docker exec "$router" tc filter show dev lan0 ingress
    docker exec "$router" tc filter show dev wan0 ingress
    docker exec "$router" tc filter show dev wan0 egress
    echo "LAN peer, router and WAN logs"
    docker logs --tail 10 "$lan_peer"
    docker logs --tail 60 "$router"
    docker logs --tail 10 "$wan"
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ $deploy_started == true ]]; then
        if (( status != 0 )); then
            diagnostics >&2 || true
        fi
        if [[ ${E2E_KEEP_LAB:-0} == 1 ]]; then
            echo "E2E_KEEP_LAB=1: keeping lab $LANDSCAPE_LAB_NAME (destroy with: containerlab destroy -t $topology --cleanup)" >&2
            exit "$status"
        fi
        if ! containerlab destroy -t "$topology" --cleanup; then
            echo "Cleanup failed. Retry with LANDSCAPE_LAB_NAME=$LANDSCAPE_LAB_NAME containerlab destroy -t $topology --cleanup" >&2
            exit 1
        fi
    fi
    if docker image inspect "$image" >/dev/null 2>&1; then
        docker image rm "$image" >/dev/null || status=1
    fi
    rm -rf "$work"
    exit "$status"
}

ready() {
    router_api system/info/net_dev |
        python3 -c 'import json, sys; names = {i["iface_name"] for i in json.load(sys.stdin)["data"]}; sys.exit(not {"wan0", "lan0"} <= names)' || return 1
    # Kernel BPF program names are limited to 15 characters.
    docker exec "$router" tc filter show dev lan0 ingress | grep -q 'tc_lan_ingress_' || return 1
    docker exec "$router" tc filter show dev wan0 ingress | grep -q 'tc_wan_ingress_'
}

run_lab() {
    local source_topology=$1 init_config=$2 lan_node=$3
    local build_dir binary version deadline
    cd "$lab_root/../../.."
    work=$(mktemp -d)
    export LANDSCAPE_LAB_NAME="ld-e2e-$(cat /proc/sys/kernel/random/uuid)"
    image="landscape-e2e:$LANDSCAPE_LAB_NAME"
    router="clab-$LANDSCAPE_LAB_NAME-router"
    lan_peer="clab-$LANDSCAPE_LAB_NAME-$lan_node"
    wan="clab-$LANDSCAPE_LAB_NAME-wan"
    topology="$work/topology.clab.yml"
    deploy_started=false

    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Share compiled dependencies, but stage each run's feature-specific executable separately.
    build_dir=${CARGO_BUILD_BUILD_DIR:-${CARGO_TARGET_DIR:-target}}
    CARGO_BUILD_BUILD_DIR=$(realpath -m "$build_dir") cargo build --locked --profile fast \
        --target-dir "$work/artifacts" -p landscape-webserver --bin landscape-webserver "${case_cargo_args[@]}"
    binary="$work/artifacts/fast/landscape-webserver"
    cd "$work"
    mkdir build
    strip -o build/landscape-webserver "$binary"
    # Use the build host's resolver while fetching Debian packages. The lab nodes
    # themselves only have their point-to-point data links.
    docker build --target "${case_image_target:-lab}" --network host \
        --secret id=resolver,src=/etc/resolv.conf -t "$image" -f "$lab_root/Dockerfile" build
    cp "$source_topology" "$topology"
    deploy_started=true
    containerlab deploy -t "$topology"

    if declare -F prepare_peers >/dev/null; then
        prepare_peers
    fi

    # Use a private bpffs and container-local config/SQLite on each run.
    docker exec "$router" mount -t bpf bpf /sys/fs/bpf
    docker exec "$router" mkdir -p /var/lib/landscape
    version=$(docker exec "$router" landscape-webserver --version)
    printf 'version = "%s"\n' "${version##* }" > landscape_init.toml
    # A case can append its own tables after the topology's base configuration.
    cat "$init_config" "${@:4}" >> landscape_init.toml
    docker cp landscape_init.toml "$router:/var/lib/landscape/"
    docker exec -d -e LANDSCAPE_LOG_TERMINAL=true "$router" sh -ec 'exec landscape-webserver --config-dir /var/lib/landscape >/proc/1/fd/1 2>/proc/1/fd/2'

    deadline=$((SECONDS + 90))
    until ready 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            echo 'Timed out waiting for the management API and the LAN/WAN TC programs' >&2
            exit 1
        fi
        sleep 1
    done
    run_case
}
