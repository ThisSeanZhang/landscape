#!/usr/bin/env python3
"""Minimal DHCPv6-PD responder for the gateway-ns e2e case.

Replies to Solicit/Request/Renew/Rebind from a fixed source address so the
client installs it as the link's IPv6 gateway (and the NS probe targets it).
Scapy only encodes/decodes the DHCPv6 payload; transport is a plain UDP6
socket so the kernel handles the UDP checksum and neighbour resolution.
"""

import socket
import struct
import sys

from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Rebind,
    DHCP6_Release,
    DHCP6_Renew,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptElapsedTime,
    DHCP6OptIA_PD,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
)

iface, server_ip, prefix, prefix_len, server_mac = sys.argv[1:6]
prefix_len = int(prefix_len)
ifindex = socket.if_nametoindex(iface)
server_duid = b"\x00\x03\x00\x01" + bytes.fromhex(server_mac.replace(":", ""))

solicit, request, renew, rebind, release = 1, 3, 5, 6, 8
kinds = {
    solicit: (DHCP6_Solicit, DHCP6_Advertise),
    request: (DHCP6_Request, DHCP6_Reply),
    renew: (DHCP6_Renew, DHCP6_Reply),
    rebind: (DHCP6_Rebind, DHCP6_Reply),
    release: (DHCP6_Release, DHCP6_Reply),
}


def response(kind, request_msg, xid):
    iaid = request_msg[DHCP6OptIA_PD].iaid if DHCP6OptIA_PD in request_msg else 1
    client_id = bytes(request_msg[DHCP6OptClientId].duid)
    return (
        kind(trid=xid)
        / DHCP6OptClientId(duid=client_id)
        / DHCP6OptServerId(duid=server_duid)
        / DHCP6OptElapsedTime()
        / DHCP6OptIA_PD(
            iaid=iaid,
            T1=3600,
            T2=5400,
            iapdopt=[
                DHCP6OptIAPrefix(
                    preflft=7200, validlft=7200, plen=prefix_len, prefix=prefix
                )
            ],
        )
    )


listen = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listen.bind(("::", 547))
group = socket.inet_pton(socket.AF_INET6, "ff02::1:2")
listen.setsockopt(
    socket.IPPROTO_IPV6,
    socket.IPV6_JOIN_GROUP,
    group + struct.pack("@I", ifindex),
)

def reply_to(client_ip, payload):
    # struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
    pktinfo = socket.inet_pton(socket.AF_INET6, server_ip) + struct.pack("@I", ifindex)
    listen.sendmsg(
        [payload],
        [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, pktinfo)],
        0,
        (client_ip, 546, 0, ifindex),
    )


print(
    f"listening on {iface}: server={server_ip} prefix={prefix}/{prefix_len} mac={server_mac}",
    flush=True,
)
while True:
    data, addr = listen.recvfrom(2048)
    try:
        cls, reply_cls = kinds.get(data[0], (None, None))
        if cls is None:
            continue
        request_msg = cls(data)
        reply = response(reply_cls, request_msg, request_msg.trid)
        reply_to(addr[0], bytes(reply))
        name = "ADVERTISE" if reply_cls is DHCP6_Advertise else "REPLY"
        print(f"sent {name} to {addr[0]}", flush=True)
    except Exception as err:  # noqa: BLE001 - one bad frame must not stop the responder
        import traceback

        print(f"ignoring frame from {addr[0]}: {err}", flush=True)
        traceback.print_exc()
