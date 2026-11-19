"""WAN DNS fixture and LAN client for the CNAME negative-cache case."""

import socket
import sys
import time

from dnslib import A, CNAME, DNSRecord, QTYPE, RCODE, RR


ALIAS = "alias.cache.example.org."
TARGET = "target.cache.example.org."
READY = "ready.cache.example.org."
ADDRESS = "198.51.100.19"
NEGATIVE_TTL = 5


def serve():
    target_exists = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("198.51.100.1", 8053))
        while True:
            data, peer = sock.recvfrom(4096)
            request = DNSRecord.parse(data)
            name = str(request.q.qname).lower()
            reply = request.reply()
            if request.q.qtype != QTYPE.A:
                reply.header.rcode = RCODE.REFUSED
            elif name == READY:
                reply.add_answer(RR(name, QTYPE.A, ttl=0, rdata=A(ADDRESS)))
            elif name == ALIAS:
                print(name, flush=True)
                reply.add_answer(RR(name, QTYPE.CNAME, ttl=40, rdata=CNAME(TARGET)))
            elif name == TARGET:
                print(name, flush=True)
                if target_exists:
                    reply.add_answer(RR(name, QTYPE.A, ttl=40, rdata=A(ADDRESS)))
                target_exists = True
            else:
                reply.header.rcode = RCODE.REFUSED
            sock.sendto(reply.pack(), peer)


def query(name):
    request = DNSRecord.question(name, "A")
    reply = DNSRecord.parse(request.send("192.0.2.1", 53, timeout=2))
    assert reply.header.id == request.header.id and reply.q == request.q, reply
    return reply


def check():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            ready = query(READY)
            if any(rr.rtype == QTYPE.A and str(rr.rdata) == ADDRESS for rr in ready.rr):
                break
        except OSError:
            pass
        time.sleep(0.25)
    else:
        raise RuntimeError("LAN DNS listener did not return the WAN readiness record")

    alias = (ALIAS, QTYPE.CNAME, TARGET)
    for cached in (False, True):
        reply = query(ALIAS)
        assert reply.header.rcode == RCODE.NOERROR and not reply.auth, reply
        assert [(str(rr.rname), rr.rtype, str(rr.rdata)) for rr in reply.rr] == [alias], reply
        if cached:
            assert 0 < reply.rr[0].ttl <= NEGATIVE_TTL, reply
            print(f"LAN cache hit: CNAME TTL {reply.rr[0].ttl}s")

    time.sleep(NEGATIVE_TTL)
    fresh = query(ALIAS)
    assert fresh.header.rcode == RCODE.NOERROR, fresh
    records = [(str(rr.rname), rr.rtype, str(rr.rdata)) for rr in fresh.rr]
    assert records == [alias, (TARGET, QTYPE.A, ADDRESS)], fresh
    print(f"LAN received {TARGET} A {ADDRESS} after negative cache expiry")


if __name__ == "__main__":
    {"serve": serve, "check": check}[sys.argv[1]]()
