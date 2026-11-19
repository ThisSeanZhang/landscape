set positional-arguments

# List available project tasks
default:
    @just --list

# Run pnpm with the repository's Corepack fallback
pnpm +args:
    bash -c 'source scripts/pnpm_cmd.sh && pnpm_cmd "$@"' -- "$@"

# Install workspace dependencies and generate the TypeScript client
init: (pnpm "install" "--frozen-lockfile") bindings

# Generate the TypeScript client from the backend OpenAPI schema
bindings *args:
    ./gen_ts_bindings.sh "$@"

# Build the Rust workspace
build *args:
    cargo build --workspace "$@"

# Run the Rust workspace tests
test *args:
    cargo test --workspace "$@"

# Run eBPF integration tests (requires root)
test-bpf *args:
    cargo test -p landscape-ebpf --features bpf-test "$@"

# Build the Web UI bundle
web: (pnpm "--filter" "landscape-webui" "build")

# Format sources or select checks with fmt.sh options
fmt *args:
    ./fmt.sh "$@"

# Run all Containerlab cases in sequence
e2e: e2e-lan e2e-gateway e2e-acme e2e-pppoe e2e-dns-negative-cache

# Run LAN forwarding, DHCP acquisition and renewal cases
e2e-lan: e2e-lan-static e2e-lan-dhcp e2e-lan-dhcp-renew

# Check IPv4 forwarding and NAT with a static client address
e2e-lan-static:
    ./tests/e2e/containerlab/cases/lan/static-forward/run.sh

# Acquire a DHCPv4 lease and reach the WAN
e2e-lan-dhcp:
    ./tests/e2e/containerlab/cases/lan/dhcp-acquire/run.sh

# Renew a DHCPv4 lease and verify that the client can still reach the WAN
e2e-lan-dhcp-renew:
    ./tests/e2e/containerlab/cases/lan/dhcp-renew/run.sh

# Verify CNAME-to-NODATA caching and recovery through the LAN DNS listener
e2e-dns-negative-cache:
    ./tests/e2e/containerlab/cases/dns/negative-cache/run.sh

# Run all PPPoE cases
e2e-pppoe: e2e-pppoe-redial-udp

# Verify an existing UDP socket recovers after a forced PPPoE redial
e2e-pppoe-redial-udp:
    ./tests/e2e/containerlab/cases/pppoe/redial-udp/run.sh

# Run all Gateway cases
e2e-gateway: e2e-gateway-rewrite e2e-gateway-sni e2e-gateway-update e2e-gateway-ipv6-tls

# Check HTTPS termination and path rewriting
e2e-gateway-rewrite:
    ./tests/e2e/containerlab/cases/gateway/https-path-rewrite/run.sh

# Verify TLS passthrough by SNI
e2e-gateway-sni:
    ./tests/e2e/containerlab/cases/gateway/sni-passthrough/run.sh

# Switch a running Gateway rule to a new upstream
e2e-gateway-update:
    ./tests/e2e/containerlab/cases/gateway/live-upstream-update/run.sh

# Verify the certificate of a link-local IPv6 upstream
e2e-gateway-ipv6-tls:
    ./tests/e2e/containerlab/cases/gateway/ipv6-upstream-tls/run.sh

# Run all ACME cases
e2e-acme: e2e-acme-dns01

# Issue a base-domain and wildcard certificate through DNS-01
e2e-acme-dns01:
    ./tests/e2e/containerlab/cases/acme/dns-01/run.sh
