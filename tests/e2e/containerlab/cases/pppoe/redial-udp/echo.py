"""Return each sequence number and the source address observed by the WAN."""
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("", 9080))
    while True:
        sequence, peer = sock.recvfrom(128)
        sock.sendto(sequence + b" " + peer[0].encode(), peer)
