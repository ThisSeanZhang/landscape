"""Drive Landscape's management API and verify the order with Pebble's issuing root."""

import json
from pathlib import Path
import subprocess
import sys
import time


router, wan, token = sys.argv[1:]
router_api = Path(__file__).resolve().parents[3] / "lib/router-api.sh"
domain = "app.lab.test"
lab = "/var/lib/acme-lab"


def api(path, body=None, post=False):
    command = ["bash", router_api, router, path]
    if body is not None:
        command.extend(["--json", "@-"])
    elif post:
        command.extend(["-X", "POST"])
    output = subprocess.check_output(command, text=True, input=json.dumps(body) if body is not None else "")
    return json.loads(output)["data"]


provider = {"e2e": {"api_url": "http://198.51.100.1:8055/client/v4", "api_token": token}}
api("dns/provider_profiles/validate", {"provider_config": provider})
profile = api("dns/provider_profiles", {"name": "lab-dns", "provider_config": provider})
account = api("cert/accounts", {
    "name": "lab-ca", "email": "tester@lab.test", "terms_agreed": True,
    "provider_config": {"e2e": {"directory_url": "https://198.51.100.1:14000/dir"}},
})
registered = api(f"cert/accounts/{account['id']}/register", post=True)
if registered["status"] != "registered":
    sys.exit(f"Account registration failed: {registered.get('status_message')}")

cert = api("cert/certs", {
    "name": "lab-dns-01", "domains": [domain, "*." + domain],
    "cert_type": {"t": "acme", "account_id": account["id"],
                  "challenge_type": {"dns": {"provider_profile_id": profile["id"]}}},
})
cert_path = f"cert/certs/{cert['id']}"
api(cert_path + "/issue", post=True)
deadline = time.monotonic() + 180
while True:
    cert = api(cert_path)
    if cert["status"] == "valid":
        break
    if cert["status"] != "processing" or time.monotonic() >= deadline:
        sys.exit(f"Order stopped at {cert['status']}: {cert.get('status_message')}")
    time.sleep(1)

# Only public certificates cross from the management API into the WAN fixture.
for field, filename in [("certificate", "leaf.pem"), ("certificate_chain", "chain.pem")]:
    subprocess.run(
        ["docker", "exec", "-i", "-w", lab, wan, "sh", "-ec", 'cat > "$1"', "sh", filename],
        input=cert[field], text=True, check=True,
    )
subprocess.run(["docker", "exec", "-w", lab, wan, "sh", "-ec", """
    curl --noproxy '*' --cacert ca.pem -fsS https://198.51.100.1:15000/roots/0 > issuing-ca.pem
    openssl x509 -in leaf.pem -noout -ext subjectAltName | grep -F 'DNS:*.app.lab.test'
    for host in app.lab.test www.app.lab.test; do
        openssl verify -purpose sslserver -verify_hostname "$host" \
            -CAfile issuing-ca.pem -untrusted chain.pem leaf.pem
    done
"""], check=True)
print("PASS: Pebble issued a trusted certificate for the base name and wildcard", flush=True)

owner = "_acme-challenge." + domain
subprocess.run(["docker", "exec", "-w", lab, wan, "grep", "-Fxq",
                f"TXT {owner}: 3 distinct values", "dns.log"], check=True)
subprocess.run(["docker", "exec", wan, "python3", "-c", """
import sys
from dnslib import DNSRecord
query = DNSRecord.question(sys.argv[1], "TXT")
answer = DNSRecord.parse(query.send("127.0.0.1", 8053, timeout=3))
if [rr.rdata.data for rr in answer.rr] != [[b"keep-me"]]:
    sys.exit(f"Unexpected TXT records after cleanup: {answer}")
""", owner], check=True)
print("PASS: Pebble queried both challenge values and cleanup preserved the pre-existing TXT")
