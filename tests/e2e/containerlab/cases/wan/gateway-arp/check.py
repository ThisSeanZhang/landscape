"""Observe the production gateway ARP worker and forwarded frames in the single-WAN lab."""

from functools import cache
import json
import subprocess
import sys
import time

router, client, wan, api_script = sys.argv[1:]
wan_ip = "198.51.100.2"
gateway = "198.51.100.1"
onlink = "198.51.100.77"
offlink = "203.0.113.9"
new_mac = "02:00:00:00:00:22"
fallback_mac = "02:00:00:00:00:fe"
zero_mac = "00:00:00:00:00:00"
roots = "/sys/fs/bpf/landscape/default/tc_chain/tc_wan_egress_roots"


def command(*args, body=None):
    result = subprocess.run(args, input=body, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr.strip()} {result.stdout.strip()}")
    return result.stdout.strip()


def peer(node, *args):
    return command("docker", "exec", node, *args)


def api(path, update=None):
    args = ["bash", api_script, router, f"services/{path}"]
    if update is None:
        return json.loads(command(*args))["data"]
    return json.loads(command(*args, "-X", "PUT", "--json", "@-", body=json.dumps(update)))["data"]


def wait_for(description, predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Timed out waiting for {description}")
        time.sleep(0.5)


def bpf(*args):
    return json.loads(peer(router, "bpftool", "-j", *args))


def root_id(slot):
    key = [str(byte) for byte in slot.to_bytes(4, sys.byteorder)]
    value = bpf("map", "lookup", "pinned", roots, "key", *key)["value"]
    return int.from_bytes(bytes(int(v, 16) for v in value), sys.byteorder)


@cache
def bss_map(program):
    maps = bpf("prog", "show", "id", str(program))["map_ids"]
    bss, = [m for m in maps if bpf("map", "show", "id", str(m))["name"].endswith(".bss")]
    return str(bss)


def confirmed(program):
    entry = bpf("map", "lookup", "id", bss_map(program), "key", "0", "0", "0", "0")
    fields = entry["formatted"]["value"][".bss"]
    word, = [field["confirmed_gateway_mac"] for field in fields if "confirmed_gateway_mac" in field]
    return word.to_bytes(8, sys.byteorder)[:6].hex(":")


def frames(packet_filter):
    return peer(wan, "tcpdump", "-nn", "-e", "-r", "/tmp/exchange.pcap", packet_filter).splitlines()


def check_frame(destination, port, mac):
    peer(client, "python3", "-c",
         "import socket,sys; socket.socket(type=socket.SOCK_DGRAM).sendto(b'wan-arp', "
         "(sys.argv[1], int(sys.argv[2])))", destination, str(port))
    probe = f"udp and dst port {port} and dst host {destination}"
    wait_for(f"WAN frame for {destination}:{port}", lambda: frames(probe))
    expected = f"ether src {router_mac} and ether dst {mac} and src host {wan_ip}"
    wrong = frames(f"({probe}) and not ({expected})")
    if wrong:
        raise AssertionError(f"Expected {expected}, captured {wrong}")
    print(f"PASS {destination}:{port} left the WAN for {mac}", flush=True)


def set_ipv4(enabled):
    path = f"wan-links/{link['id']}"
    config = api(path)
    config["v4"]["enable"] = enabled
    api(path, config)


def has_wan_address():
    devices = json.loads(peer(router, "ip", "-j", "-4", "address", "show", "dev", "wan0"))
    return any(addr["local"] == wan_ip for dev in devices for addr in dev["addr_info"])


link, = api("wan-links")
slot = link["link_chain_id"]
router_mac = peer(router, "cat", "/sys/class/net/wan0/address")
gateway_mac = peer(wan, "cat", "/sys/class/net/eth1/address")
host_mac = peer(wan, "cat", "/sys/class/net/onlink/address")
assert len({router_mac, gateway_mac, new_mac, host_mac, fallback_mac}) == 5
request = f"arp[6:2] = 1 and ether src {router_mac} and arp src host {wan_ip} and arp dst host {gateway}"
reply = f"arp[6:2] = 2 and ether dst {router_mac} and arp src host {gateway} and arp dst host {wan_ip}"

# Give the ordinary neighbour path a distinguishable MAC even for the gateway.
# A frame using that fallback for an off-link destination must fail the capture check.
for ip, mac in ((gateway, fallback_mac), (onlink, host_mac)):
    peer(router, "ip", "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", "wan0")

wait_for("the gateway's initial ARP reply", lambda: frames(f"({reply}) and ether src {gateway_mac}"))
assert frames(request), "missing WAN ARP request for the gateway"
wait_for("the initial gateway confirmation", lambda: confirmed(root_id(slot)) == gateway_mac)
root = root_id(slot)
check_frame(offlink, 42001, gateway_mac)
check_frame(onlink, 42002, host_mac)

peer(wan, "ip", "link", "set", "dev", "eth1", "address", new_mac)
wait_for("a refresh reply from the new gateway MAC", lambda: frames(f"({reply}) and ether src {new_mac}"), 50)
assert root_id(slot) == root, "a MAC refresh replaced the TC egress root"
wait_for("the new MAC in the same root", lambda: confirmed(root) == new_mac)
check_frame(offlink, 42003, new_mac)

peer(wan, "ip", "addr", "del", f"{gateway}/24", "dev", "eth1")
requests, replies = len(frames(request)), len(frames(reply))
# Two more requests with no reply put at least one full probe timeout behind us.
wait_for("a refresh and an unanswered retry", lambda: len(frames(request)) >= requests + 2, 55)
assert len(frames(reply)) == replies, "the gateway answered during the silent interval"
assert root_id(slot) == root and confirmed(root) == new_mac, "timeout lost the confirmed MAC"
check_frame(offlink, 42004, new_mac)

set_ipv4(False)
wait_for("IPv4 teardown", lambda: not has_wan_address() and root_id(slot) != root)
disabled_root = root_id(slot)
assert confirmed(disabled_root) == zero_mac, "IPv4 disable left a MAC in the root"
# Rebind the same addresses while the gateway is silent. A retained confirmation
# would be written back into this root as soon as the binding returns.
set_ipv4(True)
wait_for("the original static IPv4 binding", lambda: has_wan_address() and root_id(slot) != disabled_root)
rebound = root_id(slot)
assert confirmed(rebound) == zero_mac, "IPv4 re-enable reused a MAC from before disable"
peer(wan, "ip", "addr", "add", f"{gateway}/24", "dev", "eth1")
wait_for("fresh confirmation after re-enable", lambda: confirmed(rebound) == new_mac, 45)
check_frame(offlink, 42005, new_mac)
print("PASS explicit IPv4 disable cleared the MAC and re-enable learned it again")
