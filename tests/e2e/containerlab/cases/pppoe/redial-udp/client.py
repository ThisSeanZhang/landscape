"""Keep sending from one socket to the same endpoint across the PPPoE redial."""
from pathlib import Path
import socket
import time

peer = ("198.51.100.1", 9080)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("192.0.2.10", 0))
    sock.settimeout(0.5)
    for expected in ("198.51.100.2", "198.51.100.3"):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            sequence = str(time.monotonic_ns()).encode()
            sock.sendto(sequence, peer)
            try:
                reply, sender = sock.recvfrom(128)
            except TimeoutError:
                continue
            if sender == peer and reply == sequence + b" " + expected.encode():
                print(f"PASS: UDP {sock.getsockname()} reached WAN as {expected}", flush=True)
                break
            time.sleep(0.1)
        else:
            raise SystemExit(f"No matching UDP echo with NAT source {expected}")
        if expected == "198.51.100.2":
            Path("/tmp/first-reply").touch()
