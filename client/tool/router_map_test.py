"""Real test of the router port mapping (oneqportmap) against the home router:
   the phone (Wi-Fi off, mobile data) sends UDP datagrams to the router's public address before, during and after a mapping."""
import asyncio
import socket
import subprocess
import sys
import time

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import oneqportmap as pm

SERIAL = "HYF4C18B08001134"   # the phone used on 2026-10-24: change it (adb devices)
PORT = 47321
LOG = []


def say(*a):
    line = " ".join(str(x) for x in a)
    print(line, flush=True)
    LOG.append(line)


def adb(cmd, timeout=40):
    r = subprocess.run(["adb", "-s", SERIAL, "shell", cmd], capture_output=True, text=True, timeout=timeout)
    return (r.stdout + r.stderr).strip()


def phone_sends(ip, tag):
    # toybox nc, UDP, one datagram: "<tag>"
    return adb(f"/data/local/tmp/udpsend {ip}:{PORT} {tag}")


async def received(sock, tag, wait=2.5):
    loop = asyncio.get_running_loop()
    end = loop.time() + wait
    got = []
    while loop.time() < end:
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 100), max(0.05, end - loop.time()))
            got.append((data.decode(errors="replace").strip(), addr))
        except (asyncio.TimeoutError, BlockingIOError):
            break
    return [g for g in got if tag in g[0]]


async def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    sock.setblocking(False)
    say("listening on UDP", PORT)
    mapper = pm.PortMapper()
    gw = mapper._gw()
    say("gateway", gw, "router WAN (read-only)", await mapper.router_external_ip())
    wan = await mapper.router_external_ip()
    if not wan:
        say("the router does not report its WAN address: stop")
        return
    wan = str(wan)

    for lan in ("192.168.254.20", "192.168.254.100"):          # control: can the firewall of this PC receive on that port at all?
        say("phone nc:", phone_sends(lan, "LAN"))
        say("0. LAN control to", lan, "arrived:", bool(await received(sock, "LAN")))
    say("phone Wi-Fi off:", adb("svc wifi disable; sleep 8; ip -4 addr | grep -E 'rmnet|wlan' | grep inet"))
    ok = True
    try:
        # control 1: before the mapping, nothing must arrive
        say("phone nc:", phone_sends(wan, "BEFORE"))
        r = await received(sock, "BEFORE")
        say("1. before the mapping, datagram from the phone arrived:", bool(r), r)

        m = await mapper.map(PORT, PORT, 120)
        say("2. map() ->", m and (m.method, m.ext_ip, m.ext_port, m.internal_port, m.lifetime))
        if m is None:
            ok = False
        else:
            say("   endpoint", m.endpoint())
            await asyncio.sleep(1)
            say("phone nc:", phone_sends(str(m.ext_ip), "DURING"))
            r = await received(sock, "DURING")
            say("3. during the mapping, datagram from the phone arrived:", bool(r), r)
            n = await mapper.renew(m)
            say("4. renew() ->", n and (n.method, n.ext_ip, n.ext_port, n.lifetime))
            await mapper.unmap(m)
            say("5. unmap() done")
            await asyncio.sleep(1)
            say("phone nc:", phone_sends(str(m.ext_ip), "AFTER"))
            r = await received(sock, "AFTER")
            say("6. after the release, datagram from the phone arrived:", bool(r), r)
    finally:
        say("phone Wi-Fi on:", adb("svc wifi enable; sleep 10; settings get global wifi_on"))


asyncio.run(main())
