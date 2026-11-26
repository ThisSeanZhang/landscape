"""Lab DNS authority and the subset of the Cloudflare API used for DNS-01."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from dnslib import QTYPE, RCODE, RR, TXT
from dnslib.server import BaseResolver, DNSLogger, DNSServer


ZONE = "lab.test"
RECORDS_PATH = "/client/v4/zones/lab/dns_records"
# This unrelated TXT must survive both DNS-01 authorizations at the same name.
records = {"existing": ("_acme-challenge.app.lab.test", "keep-me", 60)}
lock = Lock()


class Authority(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply(ra=0)
        name = str(request.q.qname).rstrip(".").lower()
        if name != ZONE and not name.endswith("." + ZONE):
            reply.header.rcode = RCODE.REFUSED
        elif request.q.qtype == QTYPE.TXT:
            with lock:
                for owner, value, ttl in records.values():
                    if owner == name:
                        reply.add_answer(RR(name, QTYPE.TXT, ttl=ttl, rdata=TXT(value)))
                distinct = len({rr.rdata.data[0] for rr in reply.rr})
                print(f"TXT {name}: {distinct} distinct values", flush=True)
        return reply


class ProviderAPI(BaseHTTPRequestHandler):
    def respond(self, status, result=None, error=None):
        body = json.dumps({"success": error is None, "result": result,
                           "errors": [{"message": error}] if error else []}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if self.headers.get("Authorization") == "Bearer " + os.environ["LAB_DNS_TOKEN"]:
            return True
        self.respond(403, error="Invalid lab DNS token")
        return False

    def do_GET(self):
        if not self.authorized():
            return
        url = urlsplit(self.path)
        if url.path != "/client/v4/zones":
            return self.respond(404, error="Unknown path")
        zone = parse_qs(url.query).get("name", [ZONE])[0]
        self.respond(200, [{"id": "lab", "name": ZONE}] if zone == ZONE else [])

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != RECORDS_PATH:
            return self.respond(404, error="Unknown zone")
        try:
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            name, value, ttl = data["name"].rstrip(".").lower(), data["content"], data["ttl"]
            if (data["type"] != "TXT" or not name.endswith("." + ZONE)
                    or not isinstance(value, str) or not isinstance(ttl, int) or ttl < 1):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError):
            return self.respond(400, error="Expected a TXT record in the lab zone")
        record_id = str(uuid4())
        with lock:
            records[record_id] = (name, value, ttl)
        self.respond(200, {"id": record_id})

    def do_DELETE(self):
        if not self.authorized():
            return
        prefix, _, record_id = self.path.rpartition("/")
        with lock:
            removed = records.pop(record_id, None) if prefix == RECORDS_PATH else None
        if removed is None:
            return self.respond(404, error="Unknown record")
        self.respond(200, {"id": record_id})


if __name__ == "__main__":
    for tcp in (False, True):
        DNSServer(Authority(), address="127.0.0.1", port=8053, tcp=tcp,
                  logger=DNSLogger(log="error", prefix=False)).start_thread()
    HTTPServer(("198.51.100.1", 8055), ProviderAPI).serve_forever()
