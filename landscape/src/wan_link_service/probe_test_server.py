"""Local deterministic DNS/HTTP responder for the privileged Rust netns test."""
import selectors
import socket
import struct

selector = selectors.DefaultSelector()
for family, address in [(socket.AF_INET, "198.19.0.53"), (socket.AF_INET6, "fd53::53")]:
    for kind, port in [(socket.SOCK_DGRAM, 53), (socket.SOCK_STREAM, 18080)]:
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        if kind == socket.SOCK_STREAM:
            sock.listen()
        selector.register(sock, selectors.EVENT_READ, kind)
print("ready", flush=True)
while True:
    for key, _ in selector.select():
        sock = key.fileobj
        if key.data == socket.SOCK_STREAM:
            connection, _ = sock.accept()
            with connection:
                connection.settimeout(2)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            query, peer = sock.recvfrom(4096)
            record_type = struct.unpack("!H", query[-4:-2])[0]
            answer = socket.inet_pton(socket.AF_INET6 if record_type == 28 else socket.AF_INET,
                                      "fd53::53" if record_type == 28 else "198.19.0.53")
            reply = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:]
            reply += b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, 30, len(answer)) + answer
            sock.sendto(reply, peer)
