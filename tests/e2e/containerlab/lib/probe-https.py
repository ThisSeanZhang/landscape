"""Verify the TLS peer from the WAN, optionally fetching a known backend response."""

import argparse
from hashlib import sha256
from http.client import HTTPResponse
from pathlib import Path
import socket
import ssl
import sys


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("domain")
parser.add_argument("certificate", type=Path)
parser.add_argument("--get", nargs=2, metavar=("PATH", "EXPECTED_BODY"))
args = parser.parse_args()

pem = args.certificate.read_text()
expected_fingerprint = sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
context = ssl.create_default_context(cadata=pem)

with socket.create_connection(("198.51.100.2", 443), timeout=5) as tcp:
    with context.wrap_socket(tcp, server_hostname=args.domain) as tls:
        fingerprint = sha256(tls.getpeercert(binary_form=True)).hexdigest()
        if fingerprint != expected_fingerprint:
            sys.exit(f"Expected {args.domain} certificate {expected_fingerprint}, got {fingerprint}")
        print(f"PASS: verified TLS for {args.domain}, SHA-256 {fingerprint}", flush=True)
        if args.get:
            path, expected_body = args.get
            request = f"GET {path} HTTP/1.1\r\nHost: {args.domain}\r\nConnection: close\r\n\r\n"
            tls.sendall(request.encode("ascii"))
            with HTTPResponse(tls) as response:
                response.begin()
                body = response.read()
                if response.status != 200 or body != (expected_body + "\n").encode():
                    sys.exit(f"Unexpected upstream response: HTTP {response.status}, body={body[:200]!r}")
                print(f"PASS: {path} returned HTTP 200 and the LAN backend response")
