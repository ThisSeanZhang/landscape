"""Compare the active client address and the router's lease across a forced renewal."""
import json
import subprocess
import sys
import time

client, router, api, *baseline = sys.argv[1:]
before = json.loads(baseline[0]) if baseline else None
mac = subprocess.check_output(
    ["docker", "exec", client, "cat", "/sys/class/net/eth1/address"], text=True
).strip()
deadline = time.monotonic() + 25
while time.monotonic() < deadline:
    interface, = json.loads(subprocess.check_output(
        ["docker", "exec", client, "ip", "-j", "addr", "show", "dev", "eth1"]
    ))
    addresses = [a["local"] for a in interface["addr_info"] if a["family"] == "inet"]
    devices = json.loads(subprocess.check_output(["bash", api, router, "services/lan_devices"]))["data"]
    leases = [row["dhcp_lease"] for row in devices if row["iface_name"] == "lan0"
              and row.get("mac") == mac and row.get("dhcp_lease")]
    if len(leases) == 1 and addresses == [leases[0]["ip"]]:
        lease = leases[0]
        if before is None:
            print(json.dumps({"mac": mac, "ip": lease["ip"], "expires": lease["expires"]}))
            break
        if (mac, lease["ip"]) != (before["mac"], before["ip"]):
            sys.exit(f"Client identity changed: {before} -> {lease} ({mac})")
        if lease["expires"] > before["expires"]:
            capture = ["docker", "exec", client, "tcpdump", "-nnvr", "/tmp/exchange.pcap"]
            requests = subprocess.check_output(
                [*capture, f"src host {lease['ip']} and udp src port 68"], text=True
            )
            replies = subprocess.check_output([*capture, "udp src port 67"], text=True)
            if "DHCP-Message (53), length 1: Request" in requests and "DHCP-Message (53), length 1: ACK" in replies:
                print(f"PASS: {mac} renewed {lease['ip']}, expiry {before['expires']} -> {lease['expires']}")
                break
    time.sleep(0.5)
else:
    sys.exit(f"Timed out waiting for DHCP lease and exchange: baseline={before}, leases={leases}")
