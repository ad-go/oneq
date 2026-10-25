#!/usr/bin/env python3
"""Tiny ICMP echo tool for hosts without `ping` (needs root: raw socket).
    sudo python3 oneqping.py DEST [COUNT] [PAYLOAD_BYTES]      -> one summary line: loss and min/avg/max RTT in ms
Used by the test procedures to check the oneq mesh (the interface routes the community subnet)."""
import os
import select
import socket
import struct
import sys
import time


def checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ping(dest: str, count: int = 5, size: int = 56, timeout: float = 2.0, dont_fragment: bool = True):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if dont_fragment:
        s.setsockopt(socket.IPPROTO_IP, 10, 2)          # IP_MTU_DISCOVER = IP_PMTUDISC_DO
    ident = os.getpid() & 0xFFFF
    rtts = []
    for seq in range(count):
        payload = struct.pack("!d", time.time()) + b"x" * max(0, size - 8)
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        pkt = struct.pack("!BBHHH", 8, 0, checksum(hdr + payload), ident, seq) + payload
        try:
            s.sendto(pkt, (dest, 0))
        except OSError as e:
            return {"sent": seq + 1, "received": 0, "error": str(e)}
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([s], [], [], max(0, end - time.time()))
            if not r:
                break
            data, _ = s.recvfrom(4096)
            ihl = (data[0] & 0x0F) * 4
            t, _, _, i, q = struct.unpack("!BBHHH", data[ihl:ihl + 8])
            if t == 0 and i == ident and q == seq:
                rtts.append((time.time() - struct.unpack("!d", data[ihl + 8:ihl + 16])[0]) * 1000)
                break
        time.sleep(0.2)
    return {"sent": count, "received": len(rtts), "rtts": rtts}


if __name__ == "__main__":
    dest = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 56
    r = ping(dest, count, size)
    if r.get("error"):
        print(f"{dest}: ERROR {r['error']}")
        sys.exit(1)
    rt = r["rtts"]
    loss = 100 * (r["sent"] - r["received"]) // r["sent"]
    print(f"{dest}: {r['received']}/{r['sent']} ok, loss {loss}%" + (f", rtt min/avg/max {min(rt):.1f}/{sum(rt)/len(rt):.1f}/{max(rt):.1f} ms" if rt else ""))
    sys.exit(0 if r["received"] else 1)
