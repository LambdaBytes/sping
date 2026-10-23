#!/usr/bin/env python3
"""A STUN server for scripts/ip-bench.sh (`sping --ip --external`, 1.8).

It runs in the bench's `dst` namespace, answers Binding requests on
10.0.3.2 and fd00:3::2, port 3478, as the case asks, and logs every request
it receives (family, source address, source port) to a file the E2E test
`ip_bench` reads:

  answer   a response of another transaction ID with other values first,
           then the answer: mapped addresses from the documentation ranges,
           never the client's, so the test tells what the server said from
           what the client knows
  foreign  only responses of another transaction ID: ten for each request,
           50 ms apart
  silent   no answer

Usage: stun-bench-server.py MODE LOG READY (READY is created once it listens)
"""

import select
import socket
import struct
import sys
import threading
import time

COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
XOR_MAPPED_ADDRESS = 0x0020
LISTEN = {socket.AF_INET: "10.0.3.2", socket.AF_INET6: "fd00:3::2"}
PORT = 3478
MAPPED = {
    socket.AF_INET: ("198.51.100.77", 40312),
    socket.AF_INET6: ("2001:db8:77::5", 51022),
}
FOREIGN = {
    socket.AF_INET: ("203.0.113.9", 1111),
    socket.AF_INET6: ("2001:db8:99::9", 2222),
}


def response(family, txid, mapped):
    """A Binding success response for `txid` with XOR-MAPPED-ADDRESS `mapped`."""
    ip, port = mapped
    key = struct.pack("!I", COOKIE) + txid
    address = bytes(a ^ k for a, k in zip(socket.inet_pton(family, ip), key))
    code = 1 if family == socket.AF_INET else 2
    value = struct.pack("!BBH", 0, code, port ^ (COOKIE >> 16)) + address
    attrs = struct.pack("!HH", XOR_MAPPED_ADDRESS, len(value)) + value
    return struct.pack("!HHI", BINDING_SUCCESS, len(attrs), COOKIE) + txid + attrs


def other(txid):
    """Another transaction ID."""
    return bytes([txid[0] ^ 0xFF]) + txid[1:]


def flood(sock, txid, peer):
    for _ in range(10):
        sock.sendto(response(sock.family, other(txid), FOREIGN[sock.family]), peer)
        time.sleep(0.05)


def main():
    mode, log, ready = sys.argv[1:4]
    if mode not in ("answer", "foreign", "silent"):
        sys.exit(f"stun-bench-server: unknown mode {mode}")
    socks = []
    for family, host in LISTEN.items():
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((host, PORT))
        socks.append(sock)
    with open(ready, "w", encoding="ascii"):
        pass
    while True:
        readable, _, _ = select.select(socks, [], [])
        for sock in readable:
            data, peer = sock.recvfrom(1500)
            if (
                len(data) < 20
                or struct.unpack("!HHI", data[:8]) != (BINDING_REQUEST, 0, COOKIE)
            ):
                continue
            txid = data[8:20]
            family = "v4" if sock.family == socket.AF_INET else "v6"
            # Appended and closed each time: the test empties the file
            # between runs.
            with open(log, "a", encoding="ascii") as f:
                f.write(f"{family} {peer[0]} {peer[1]}\n")
            if mode == "answer":
                sock.sendto(response(sock.family, other(txid), FOREIGN[sock.family]), peer)
                sock.sendto(response(sock.family, txid, MAPPED[sock.family]), peer)
            elif mode == "foreign":
                threading.Thread(target=flood, args=(sock, txid, peer), daemon=True).start()


if __name__ == "__main__":
    main()
