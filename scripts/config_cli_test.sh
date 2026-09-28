#!/usr/bin/env bash
#
# End-to-end checks for the `config` subcommand.
#
# Usage:
#   scripts/config_cli_test.sh [PATH_TO_LANDSCAPE_WEBSERVER]
#
# The binary defaults to target/debug/landscape-webserver (overridable with the
# first argument or the BIN environment variable). The script only exercises the
# `config` subcommand, so it never touches the database, eBPF or the network.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN="${1:-${BIN:-$REPO_ROOT/target/debug/landscape-webserver}}"
if [[ "$BIN" != /* ]]; then
  BIN="$REPO_ROOT/$BIN"
fi

if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found or not executable: $BIN" >&2
  echo "build it first, e.g.: cargo build -p landscape-webserver" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/landscape-config-cli.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n      %s\n' "$1" "${2:-}"; }

assert_has() {
  local name="$1" out="$2"; shift 2
  local missing=""
  for needle in "$@"; do
    grep -qF -- "$needle" <<<"$out" || missing="$missing [$needle]"
  done
  if [[ -z "$missing" ]]; then ok "$name"; else bad "$name" "missing:$missing"; fi
}

assert_not_has() {
  local name="$1" out="$2"; shift 2
  local present=""
  for needle in "$@"; do
    grep -qF -- "$needle" <<<"$out" && present="$present [$needle]"
  done
  if [[ -z "$present" ]]; then ok "$name"; else bad "$name" "unexpected:$present"; fi
}

# run <name> <expected_exit> <args...>: stores combined output in OUT and the
# exit code in RC.
run() {
  local name="$1" expect="$2"; shift 2
  OUT="$("$BIN" config "$@" 2>&1)"; RC=$?
  if [[ "$RC" -eq "$expect" ]]; then
    ok "$name (exit=$RC)"
  else
    bad "$name" "exit=$RC expected=$expect :: $(head -n1 <<<"$OUT")"
  fi
}

echo "binary:  $BIN"
echo "workdir: $WORK"

echo "== help =="
run "help" 0 --help
assert_has "help lists flags" "$OUT" \
  "--wan-mode" "--lan-iface" "--pppoe-username" "--pppd-plugin" "--lan-dhcp-range" "--enable"

echo "== generation =="
run "dhcp" 0 --wan-iface eth0 --lan-iface br_lan --wan-mode dhcp --stdout
assert_has "dhcp: wan iface" "$OUT" 'name = "eth0"' 'zone_type = "wan"'
assert_has "dhcp: lan bridge" "$OUT" 'create_dev_type = "bridge"' 'zone_type = "lan"'
assert_has "dhcp: client model" "$OUT" 't = "dhcpclient"'
assert_has "dhcp: dhcp server" "$OUT" '[[dhcpv4_services]]' 'server_ip_addr = "192.168.5.1"'
assert_has "dhcp: base services" "$OUT" '[[nats]]' '[[route_wans]]' '[[route_lans]]'
assert_not_has "dhcp: no mss-clamp" "$OUT" '[[mss_clamps]]'

run "static" 0 --wan-iface eth0 --lan-iface br_lan --wan-mode static \
  --wan-ip 203.0.113.2/24 --wan-gateway 203.0.113.1 --wan-ipv6 2001:db8::2 --stdout
assert_has "static: model" "$OUT" \
  't = "static"' 'ipv4 = "203.0.113.2"' 'ipv4_mask = 24' 'default_router_ip = "203.0.113.1"'
assert_has "static: ipv6" "$OUT" 'ipv6 = "2001:db8::2"'
assert_not_has "static: no mss-clamp" "$OUT" '[[mss_clamps]]'

run "pppoe" 0 --wan-iface eth0 --lan-iface br_lan --wan-mode pppoe \
  --pppoe-username u --pppoe-password p --pppoe-ac-name ac --stdout
assert_has "pppoe: model" "$OUT" \
  't = "pppoe"' 'username = "u"' 'password = "p"' 'ac_name = "ac"' 'mtu = 1492'
assert_has "pppoe: mss-clamp on wan" "$OUT" '[[mss_clamps]]' 'clamp_size = 1492'
assert_not_has "pppoe: no pppd block" "$OUT" '[[pppds]]'

run "pppd" 0 --wan-iface eth0 --lan-iface br_lan --wan-mode pppd \
  --pppoe-username u --pppoe-password p --pppd-iface ppp9 --pppd-plugin pppoe --stdout
assert_has "pppd: service block" "$OUT" \
  '[[pppds]]' 'attach_iface_name = "eth0"' 'iface_name = "ppp9"' 'peer_id = "u"' 'plugin = "pppoe"'
assert_has "pppd: wan services bound to ppp iface" "$OUT" '[[mss_clamps]]' 'iface_name = "ppp9"'
assert_not_has "pppd: no ipconfigs" "$OUT" '[[ipconfigs]]'

run "none" 0 --wan-mode none --lan-iface br_lan --stdout
assert_not_has "none: no wan iface/services" "$OUT" \
  'zone_type = "wan"' '[[ipconfigs]]' '[[nats]]' '[[route_wans]]' '[[mss_clamps]]'
assert_has "none: route-lan kept" "$OUT" '[[route_lans]]'

echo "== auth =="
run "admin creds" 0 --wan-iface eth0 --lan-iface br_lan \
  --admin-user admin --admin-pass secret --stdout
assert_has "auth: written to config" "$OUT" 'admin_user = "admin"' 'admin_pass = "secret"'
run "admin pass only" 0 --wan-iface eth0 --lan-iface br_lan --admin-pass secret --stdout
assert_has "auth: partial allowed" "$OUT" 'admin_pass = "secret"'
assert_not_has "auth: user stays unset" "$OUT" 'admin_user'

echo "== wan-only =="
run "wan-only static" 0 --wan-iface eth0 --wan-mode static \
  --wan-ip 203.0.113.2/24 --wan-gateway 203.0.113.1 \
  --static-nat 22:22 --static-nat 6443:16443 --stdout
assert_has "wan-only: wan iface" "$OUT" 'name = "eth0"' 'zone_type = "wan"'
assert_has "wan-only: static model" "$OUT" 't = "static"' 'ipv4 = "203.0.113.2"'
assert_not_has "wan-only: no lan bridge" "$OUT" 'create_dev_type = "bridge"' 'zone_type = "lan"'
assert_not_has "wan-only: no lan services" "$OUT" '[[route_lans]]' '[[dhcpv4_services]]'
assert_has "wan-only: wan services" "$OUT" '[[nats]]' '[[route_wans]]'
assert_has "wan-only: static nat" "$OUT" \
  '[[static_nat_mappings_v4]]' 't = "local"' 'wan_port = 22' 'lan_port = 22' \
  'wan_port = 6443' 'lan_port = 16443'

run "wan-only dhcp" 0 --wan-iface eth0 --wan-mode dhcp --stdout
assert_has "wan-only dhcp: client model" "$OUT" 't = "dhcpclient"' 'name = "eth0"'
assert_not_has "wan-only dhcp: no lan" "$OUT" '[[route_lans]]' '[[dhcpv4_services]]' '[[static_nat_mappings_v4]]'

run "lan member" 0 --wan-iface eth0 --lan-iface br_lan --lan-member eth1 --lan-member eth2 --stdout
assert_has "lan member: controller" "$OUT" 'name = "eth1"' 'name = "eth2"' 'controller_name = "br_lan"'

run "dhcp explicit mss" 0 --wan-iface eth0 --lan-iface br_lan --enable mss-clamp --stdout
assert_has "dhcp explicit mss-clamp" "$OUT" '[[mss_clamps]]'

run "disable defaults" 0 --wan-iface eth0 --lan-iface br_lan --disable nat,route-wan,route-lan --stdout
assert_not_has "disable strips defaults" "$OUT" '[[nats]]' '[[route_wans]]' '[[route_lans]]'

run "firewall enable" 0 --wan-iface eth0 --lan-iface br_lan --enable firewall --stdout
assert_has "firewall enable" "$OUT" '[[firewalls]]'

run "custom dhcp range+lease" 0 --wan-iface eth0 --lan-iface br_lan --lan-ip 10.0.0.1/24 \
  --lan-dhcp-range 10.0.0.50-10.0.0.90 --lan-dhcp-lease 7200 --stdout
assert_has "custom dhcp" "$OUT" \
  'ip_range_start = "10.0.0.50"' 'ip_range_end = "10.0.0.90"' 'address_lease_time = 7200'

echo "== file output =="
run "write dir" 0 --wan-iface eth0 --lan-iface br_lan --dir "$WORK"
FILE="$WORK/landscape_init.toml"
if [[ -f "$FILE" ]]; then ok "file created"; else bad "file created" "missing $FILE"; fi

PERM="$(stat -c '%a' "$FILE" 2>/dev/null || echo '?')"
if [[ "$PERM" == "600" ]]; then
  ok "file perms 600"
else
  bad "file perms 600" "got $PERM"
fi

if command -v python3 >/dev/null 2>&1 && python3 -c 'import tomllib' >/dev/null 2>&1; then
  if python3 -c "import tomllib; tomllib.load(open('$FILE','rb'))" 2>/dev/null; then
    ok "file is valid TOML"
  else
    bad "file is valid TOML"
  fi
else
  echo "SKIP  file is valid TOML (python3 tomllib unavailable)"
fi

run "re-write without force" 1 --wan-iface eth0 --lan-iface br_lan --dir "$WORK"
assert_has "re-write error message" "$OUT" "already exists" "--force"
run "re-write with force" 0 --wan-iface eth0 --lan-iface br_lan --dir "$WORK" --force

echo "== validation errors =="
run "missing wan-iface" 1 --lan-iface br_lan
assert_has "missing wan-iface msg" "$OUT" "--wan-iface is required"
run "missing both ifaces" 1 --wan-mode none
assert_has "missing both ifaces msg" "$OUT" "at least one of --wan-iface or --lan-iface"
run "empty admin-user" 1 --wan-iface eth0 --lan-iface br_lan --admin-user ""
assert_has "empty admin-user msg" "$OUT" "must not be empty"
run "wan-only with lan-member" 1 --wan-iface eth0 --lan-member eth1
assert_has "wan-only with lan-member msg" "$OUT" "--lan-member requires --lan-iface"
run "wan-only with lan dhcp range" 1 --wan-iface eth0 --lan-dhcp-range 192.168.5.10
assert_has "wan-only with lan dhcp range msg" "$OUT" "--lan-dhcp-range requires --lan-iface"
run "lan service with wan-only" 1 --wan-iface eth0 --enable route-lan
assert_has "lan service with wan-only msg" "$OUT" "requires --lan-iface"
run "static-nat without wan" 1 --wan-mode none --lan-iface br_lan --static-nat 22:22
assert_has "static-nat without wan msg" "$OUT" "--static-nat requires --wan-mode"
run "invalid static-nat" 1 --wan-iface eth0 --static-nat 22
assert_has "invalid static-nat msg" "$OUT" "invalid static NAT mapping"
run "zero static-nat port" 1 --wan-iface eth0 --static-nat 0:22
assert_has "zero static-nat port msg" "$OUT" "invalid static NAT configuration"
run "static missing ip" 1 --wan-iface eth0 --lan-iface br_lan --wan-mode static
assert_has "static missing ip msg" "$OUT" "--wan-ip is required"
run "static missing gateway" 1 --wan-iface eth0 --lan-iface br_lan --wan-mode static --wan-ip 1.2.3.4/24
assert_has "static missing gw msg" "$OUT" "--wan-gateway is required"
run "pppoe missing creds" 1 --wan-iface eth0 --lan-iface br_lan --wan-mode pppoe
assert_has "pppoe creds msg" "$OUT" "--pppoe-username"
run "unknown service" 1 --wan-iface eth0 --lan-iface br_lan --enable dns
assert_has "unknown service msg" "$OUT" "unknown service 'dns'"
run "conflicting service" 1 --wan-iface eth0 --lan-iface br_lan --enable nat --disable nat
assert_has "conflicting service msg" "$OUT" "both --enable and --disable"
run "wan service with none" 1 --wan-mode none --lan-iface br_lan --enable route-wan
assert_has "wan service with none msg" "$OUT" "requires --wan-mode other than 'none'"
run "member equals wan" 1 --wan-iface eth0 --lan-iface br_lan --lan-member eth0
assert_has "member equals wan msg" "$OUT" "must differ from --wan-iface"
run "invalid cidr" 1 --wan-iface eth0 --lan-iface br_lan --wan-mode static --wan-ip 1.2.3.4 --wan-gateway 1.2.3.1
assert_has "invalid cidr msg" "$OUT" "invalid CIDR"
run "invalid dhcp range" 1 --wan-iface eth0 --lan-iface br_lan --lan-dhcp-range 192.168.5.200-192.168.5.10
assert_has "invalid dhcp range msg" "$OUT" "invalid DHCP configuration"
run "bad enum" 2 --wan-iface eth0 --lan-iface br_lan --wan-mode bogus
assert_has "bad enum msg" "$OUT" "invalid value"

echo
echo "TOTAL: PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
