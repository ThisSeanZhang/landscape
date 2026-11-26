"""Observe the IPv6 NS gateway probe and forwarded frames in the single-WAN lab."""

from functools import cache
import json
import subprocess
import sys
import time

router, client, wan, api_script = sys.argv[1:]
prefix = "2001:db8:1000"
offlink = "2001:db8:ffff::9"
pd_mac = "02:00:00:00:00:02"
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


def wait_for(description, predicate, timeout=20):
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
    word, = [field["confirmed_gateway_mac6"] for field in fields if "confirmed_gateway_mac6" in field]
    return word.to_bytes(8, sys.byteorder)[:6].hex(":")


def frames(packet_filter):
    return peer(wan, "tcpdump", "-nn", "-e", "-r", "/tmp/exchange.pcap", packet_filter).splitlines()


def set_pd(enabled):
    path = f"wan-links/{link['id']}"
    config = api(path)
    config["pd"] = {"enable": enabled, "mac": pd_mac, "expected_pd_len": 56}
    api(path, config)


def check_frame(destination, port, mac):
    peer(
        client,
        "python3",
        "-c",
        "import socket,sys; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto("
        "b'wan-ns', (sys.argv[1], int(sys.argv[2])))",
        destination,
        str(port),
    )
    probe = f"ip6 and udp and dst port {port} and dst host {destination}"
    wait_for(f"WAN frame for {destination}:{port}", lambda: frames(probe))
    expected = f"ether src {router_mac} and ether dst {mac} and dst host {destination}"
    wrong = frames(f"({probe}) and not ({expected})")
    if wrong:
        raise AssertionError(f"Expected {expected}, captured {wrong}")
    print(f"PASS {destination}:{port} left the WAN for {mac}", flush=True)


def linklocal(node, dev):
    fields = peer(node, "ip", "-6", "-o", "addr", "show", "dev", dev, "scope", "link").split()
    return fields[3].split("/")[0]


link, = api("wan-links")
slot = link["link_chain_id"]
router_mac = peer(router, "cat", "/sys/class/net/wan0/address")
gateway_mac = peer(wan, "cat", "/sys/class/net/eth1/address")
# The PD responder and NS gateway is the WAN link's link-local address.
gateway = linklocal(wan, "eth1")
# NS is sourced from the probing interface's link-local, like kernel NDP.
ns_source = linklocal(router, "wan0")
assert len({router_mac, gateway_mac, fallback_mac}) == 3
request = f"icmp6 and ip6[40] == 135 and ether src {router_mac} and src host {ns_source}"
reply = f"icmp6 and ip6[40] == 136 and ether dst {router_mac} and src host {gateway}"

# The lab starts with a static IPv4 WAN; enabling PD drives the IPv6 bind the
# NS worker probes.
set_pd(True)
wait_for("the gateway's initial NS reply", lambda: frames(reply), 40)
assert frames(request), "missing WAN NS request for the gateway"
wait_for("the initial gateway confirmation", lambda: confirmed(root_id(slot)) == gateway_mac, 40)
root = root_id(slot)

# A stale kernel neighbour entry for the gateway must not beat the probe result.
peer(router, "ip", "-6", "neigh", "replace", gateway, "lladdr", fallback_mac, "nud", "permanent", "dev", "wan0")
check_frame(offlink, 42001, gateway_mac)

# A silent gateway keeps the last confirmed MAC.
peer(wan, "ip", "-6", "addr", "del", f"{gateway}/64", "dev", "eth1")
requests, replies = len(frames(request)), len(frames(reply))
# Two more requests with no reply put at least one full probe timeout behind us.
wait_for("a refresh and an unanswered retry", lambda: len(frames(request)) >= requests + 2, 60)
assert len(frames(reply)) == replies, "the gateway answered during the silent interval"
assert root_id(slot) == root and confirmed(root) == gateway_mac, "timeout lost the confirmed MAC"
check_frame(offlink, 42002, gateway_mac)

# Disabling PD clears the v6 bind and the MAC in the new root.
set_pd(False)
wait_for("IPv6 teardown", lambda: root_id(slot) != root, 20)
disabled_root = root_id(slot)
assert confirmed(disabled_root) == zero_mac, "IPv6 disable left a MAC in the root"

# Rebind the same prefix while the gateway is reachable again.
peer(wan, "ip", "-6", "addr", "add", f"{gateway}/64", "dev", "eth1", "nodad")
set_pd(True)
wait_for("fresh confirmation after re-enable", lambda: confirmed(root_id(slot)) == gateway_mac, 60)
check_frame(offlink, 42003, gateway_mac)
print("PASS explicit IPv6 disable cleared the MAC and re-enable learned it again")
