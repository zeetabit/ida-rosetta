#!/usr/bin/env python3
"""Measure a GDB RSP stub (the Rosetta debugserver) packet by packet.

Useful when attach/stepping feels slow: it tells whether the stub or IDA is the
bottleneck. Starts nothing; either connect to a stub that is already attached to
a process, or pass --pid to attach an idle stub first.

Examples:
    # idle stub already running on 1239, attach to pid 1234
    ./rsp_probe.py --port 1239 --pid 1234

    # just the handshake of a stub that already owns its process
    ./rsp_probe.py --port 1239 --no-attach

    # machine-readable
    ./rsp_probe.py --port 1239 --pid 1234 --json
"""

import argparse
import json
import socket
import sys
import time


def checksum(data):
    return sum(data) & 0xFF


class Rsp:
    def __init__(self, port, host="127.0.0.1", timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def send(self, data, timeout=5.0):
        self.sock.settimeout(timeout)
        packet = b"$" + data + b"#" + ("%02x" % checksum(data)).encode()
        self.sock.sendall(packet)
        t0 = time.time()
        while True:
            c = self.sock.recv(1)
            if not c:
                return "EOF", time.time() - t0, b""
            if c in (b"+", b"-"):
                if c == b"-":
                    self.sock.sendall(b"+")
                continue
            if c in (b"$", b"%"):
                buf = b""
                while True:
                    ch = self.sock.recv(1)
                    if ch == b"#":
                        self.sock.recv(2)
                        break
                    buf += ch
                self.sock.sendall(b"+")
                return ("OK" if c == b"$" else "NOTIFY"), time.time() - t0, buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1239)
    ap.add_argument("--pid", type=int, default=None,
                    help="attach this pid before measuring")
    ap.add_argument("--no-attach", action="store_true",
                    help="do not send vAttach (stub already owns a process)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    try:
        rsp = Rsp(a.port, a.host, a.timeout)
    except OSError as exc:
        print("connect failed: %s" % exc, file=sys.stderr)
        return 2

    results = []

    def probe(name, packet, timeout=None):
        try:
            status, dt, reply = rsp.send(packet, timeout or a.timeout)
        except socket.timeout:
            status, dt, reply = "TIMEOUT", a.timeout, b""
        results.append({"packet": name, "status": status,
                        "seconds": round(dt, 4), "reply_len": len(reply),
                        "reply": reply[:60].decode("latin1", "replace")})
        if not a.json:
            print("%-22s %-9s %8.3fs  len=%-6d %r"
                  % (name, status, dt, len(reply), reply[:48]))

    probe("qSupported", b"qSupported:multiprocess+;xmlRegisters=i386")
    if a.pid is not None and not a.no_attach:
        probe("vAttach", ("vAttach;%x" % a.pid).encode())
    probe("?", b"?")
    probe("g (registers)", b"g")
    probe("p0", b"p0")
    for size in (0x40, 0x1000, 0x10000):
        probe("m %d bytes" % size, b"m100000000,%x" % size)
    probe("qXfer:features", b"qXfer:features:read:target.xml:0,400")
    probe("qXfer:libraries", b"qXfer:libraries:read::0,1000")
    probe("qMemoryRegionInfo", b"qMemoryRegionInfo:100000000")
    probe("qThreadExtraInfo", b"qThreadExtraInfo,1")
    probe("vCont?", b"vCont?")
    rsp.close()

    if a.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
