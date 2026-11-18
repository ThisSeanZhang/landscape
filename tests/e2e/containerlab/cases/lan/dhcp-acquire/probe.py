"""Acquire a DHCPv4 lease and check the client configuration and router lease."""

import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib


client, router, init_config, router_api = sys.argv[1:]
with Path(init_config).open("rb") as config_file:
    (service,) = tomllib.load(config_file)["dhcpv4_services"]
config = service["config"]
gateway = config["server_ip_addr"]


def client_output(*args):
    return subprocess.check_output(["docker", "exec", client, *args], text=True)


if client_output("ip", "-4", "-o", "addr", "show", "dev", "eth1").strip():
    sys.exit("Expected no IPv4 address on eth1 before DHCP")
if client_output("ip", "-4", "route", "show", "default").strip():
    sys.exit("Expected no default IPv4 route before DHCP")
subprocess.run(
    ["docker", "exec", client, "udhcpc", "-f", "-q", "-n", "-t", "10", "-T", "2", "-i", "eth1"],
    check=True,
)

(interface,) = json.loads(client_output("ip", "-j", "addr", "show", "dev", "eth1"))
addresses = [addr for addr in interface["addr_info"] if addr["family"] == "inet"]
if len(addresses) != 1:
    sys.exit(f"Expected one DHCPv4 address on eth1, got {addresses}")
address = ipaddress.IPv4Address(addresses[0]["local"])
prefix = addresses[0]["prefixlen"]
start = ipaddress.IPv4Address(config["ip_range_start"])
end = ipaddress.IPv4Address(config["ip_range_end"])
if not (start <= address < end and prefix == config["network_mask"]):
    sys.exit(f"Client address {address}/{prefix} does not match the DHCP pool")

routes = json.loads(client_output("ip", "-j", "-4", "route", "show", "default"))
if [(r.get("gateway"), r["dev"]) for r in routes] != [(gateway, "eth1")]:
    sys.exit(f"Unexpected default route: {routes}")
resolver = client_output("cat", "/etc/resolv.conf").splitlines()
servers = [line.split()[1] for line in resolver if line.split()[:1] == ["nameserver"]]
if servers != [gateway]:
    sys.exit(f"Expected DNS server {gateway}, got {servers}")

mac = interface["address"]
# The directory consumes allocation events asynchronously.
deadline = time.monotonic() + 10
while True:
    snapshot = subprocess.run(
        ["bash", router_api, router, "services/lan_devices"],
        capture_output=True, text=True,
    )
    devices = json.loads(snapshot.stdout)["data"] if snapshot.returncode == 0 else []
    matches = [row for row in devices if (row.get("mac") or "").lower() == mac]
    if len(matches) == 1:
        device = matches[0]
        lease = device.get("dhcp_lease") or {}
        if (
            device["iface_name"] == service["iface_name"]
            and device["ipv4"] == {"ip": str(address), "source": "lease"}
            and lease.get("ip") == str(address)
        ):
            break
    if time.monotonic() >= deadline:
        sys.exit(f"Landscape has not recorded the expected lease for {mac}: {snapshot.stderr or matches}")
    time.sleep(0.5)
duration = (lease["expires"] - lease["last_request"]) / 1000
if duration != config["address_lease_time"] or lease["expires"] <= time.time() * 1000:
    sys.exit(f"Unexpected lease lifetime: {lease}")
print(f"PASS: DHCPv4 {mac} -> {address}/{prefix}, gateway/DNS {gateway}, lease {duration:g}s", flush=True)
