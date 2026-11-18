"""Switch a running gateway's rule and observe both ends of fresh WAN connections."""

import json
from pathlib import Path
import re
import subprocess
import sys
import time


router, wan, backend, run_id = sys.argv[1:]
router_api = Path(__file__).resolve().parents[3] / "lib/router-api.sh"
domain = "switch.lab.test"
path = f"/origin.txt?run={run_id}"


def rules_api(rule=None):
    command = ["bash", router_api, router, "gateway/rules"]
    body = ""
    if rule is not None:
        command.extend(["--json", "@-"])
        body = json.dumps(rule)
    result = subprocess.check_output(command, input=body, text=True)
    return json.loads(result)["data"]


def check_origin(name):
    body = subprocess.check_output([
        "docker", "exec", wan, "curl", "--noproxy", "*", "-fsS", "--max-time", "5",
        "--resolve", f"{domain}:80:198.51.100.2", f"http://{domain}{path}",
    ], text=True)
    if body != f"{name}-{run_id}\n":
        sys.exit(f"Expected backend {name} from WAN, received {body[:200]!r}")
    subprocess.run([
        "docker", "exec", backend, "grep", "-F", f'"GET {path} HTTP/1.1" 200', f"/tmp/{name}.log",
    ], check=True)
    print(f"PASS: new WAN connection to {domain} reached backend {name}", flush=True)


def listener_inodes():
    sockets = subprocess.check_output(
        ["docker", "exec", router, "ss", "-Hlnte", "sport = :80"], text=True,
    )
    inodes = set(re.findall(r"\bino:(\d+)", sockets))
    return inodes


deadline = time.monotonic() + 30
while not (original_listeners := listener_inodes()):
    if time.monotonic() >= deadline:
        sys.exit("Gateway HTTP listener did not become ready")
    time.sleep(0.5)

rule = rules_api({
    "enable": True,
    "name": "switch-origin",
    "domains": [domain],
    "match_rule": {"t": "host"},
    "upstream": {"targets": [{"address": "192.0.2.10", "port": 8081}]},
})
check_origin("A")
original_id = rule["id"]

rule["upstream"]["targets"][0]["port"] = 8082
updated = rules_api(rule)
if updated["id"] != original_id:
    sys.exit(f"Rule ID changed from {original_id} to {updated['id']}")
check_origin("B")
if listener_inodes() != original_listeners:
    sys.exit("Gateway replaced the HTTP listening socket during the rule update")
stored = rules_api()
if len(stored) != 1 or stored[0]["id"] != original_id:
    sys.exit(f"Expected a single rule with ID {original_id}, got {stored!r}")
if stored[0]["upstream"]["targets"] != rule["upstream"]["targets"]:
    sys.exit(f"Expected stored upstream to point at backend B, got {stored[0]['upstream']!r}")
print(f"PASS: rule {original_id} switched A -> B on the same Gateway HTTP listener")
