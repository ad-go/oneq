"""Automatic port mapping: ask the home router to forward a UDP port to this node, so that other nodes can reach it without
hole punching. Three protocols, tried in this order:

  1. PCP      (RFC 6887, UDP port 5351 of the default gateway)         MAP opcode
  2. NAT-PMP  (RFC 6886, UDP port 5351 of the default gateway)         external-address and map requests
  3. UPnP IGD (SSDP multicast discovery, then SOAP over HTTP)           WANIPConnection / WANPPPConnection

What the node does with it (see oneqnode.py): the mapped external address becomes one more candidate, the router's WAN address is used
to recognise a second NAT in front of the router (carrier-grade NAT: a mapping on the first router is then useless), the mapping is
renewed at half its lifetime and removed when the node stops.

Safety of the UPnP part: the SSDP answer is trusted only from a private (or link-local) address, its LOCATION and the control URL must
point at that same address (a forged answer must not make the node talk to a third host), and every download is size-limited.
Educational project, not independently audited.
"""
import asyncio
import ipaddress
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit

log = logging.getLogger("oneqnode")

PCP_VERSION, NATPMP_VERSION = 2, 0
PORT = 5351
PROTO_UDP = 17
SSDP_ADDR = ("239.255.255.250", 1900)
IGD_TARGETS = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2")
WAN_SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANPPPConnection:1")
MAX_BODY = 64 * 1024
UDP_RETRIES = (0.25, 0.5, 1.0)

PCP_RESULTS = {0: "success", 1: "unsupported version", 2: "not authorized", 3: "malformed request", 4: "unsupported opcode",
               5: "unsupported option", 6: "malformed option", 7: "network failure", 8: "no resources", 9: "unsupported protocol",
               10: "user quota exceeded", 11: "cannot provide external port", 12: "address mismatch", 13: "excessive remote peers"}
NATPMP_RESULTS = {0: "success", 1: "unsupported version", 2: "not authorized or refused", 3: "network failure", 4: "out of resources",
                  5: "unsupported opcode"}


@dataclass
class Mapping:
    method: str                      # "pcp" | "natpmp" | "upnp"
    ext_ip: Optional[str]            # the router's WAN address as the router reports it
    ext_port: int
    internal_port: int
    lifetime: int                    # seconds the router granted
    gateway: str
    created: float = field(default_factory=time.monotonic)
    extra: dict = field(default_factory=dict)

    def endpoint(self) -> Optional[str]:
        if not self.ext_ip:
            return None
        return f"[{self.ext_ip}]:{self.ext_port}" if ":" in self.ext_ip else f"{self.ext_ip}:{self.ext_port}"

    def renew_at(self) -> float:
        return self.created + max(30.0, self.lifetime / 2)


# ---------------------------------------------------------------- local network facts

def default_gateway_v4() -> Optional[str]:
    """The IPv4 default gateway of this machine (Linux /proc/net/route, macOS `route`, Windows `route print`)."""
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/net/route") as f:
                for line in list(f)[1:]:
                    p = line.split()
                    if len(p) >= 8 and p[1] == "00000000" and int(p[3], 16) & 2:
                        return socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
        elif sys.platform == "darwin":
            out = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"gateway:\s*([0-9.]+)", out)
            return m.group(1) if m else None
        elif sys.platform == "win32":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True, timeout=10).stdout
            best = None
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                    try:
                        ipaddress.IPv4Address(p[2])
                        metric = int(p[4])
                    except ValueError:
                        continue
                    if best is None or metric < best[0]:
                        best = (metric, p[2])
            return best[1] if best else None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def local_ip_towards(dst: str) -> Optional[str]:
    """The local address the OS would use to reach `dst` (no packet is sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def ip16(ip: str) -> bytes:
    """An address in the 16-byte form PCP uses (IPv4 as ::ffff:a.b.c.d)."""
    return socket.inet_pton(socket.AF_INET6, "::ffff:" + ip) if ":" not in ip else socket.inet_pton(socket.AF_INET6, ip)


def from_ip16(b: bytes) -> str:
    a = ipaddress.IPv6Address(b)
    return str(a.ipv4_mapped) if a.ipv4_mapped else str(a)


# ---------------------------------------------------------------- PCP (RFC 6887)

def pcp_map_request(client_ip: str, internal_port: int, ext_port: int, lifetime: int, nonce: bytes) -> bytes:
    hdr = struct.pack(">BBHI", PCP_VERSION, 1, 0, lifetime) + ip16(client_ip)
    body = nonce + struct.pack(">B3xHH", PROTO_UDP, internal_port, ext_port) + ip16("0.0.0.0")
    return hdr + body


def pcp_parse_map_response(data: bytes, nonce: bytes) -> Optional[dict]:
    """-> {"result", "lifetime", "ext_port", "ext_ip", "internal_port"} for a MAP response to our nonce, None for anything else."""
    if len(data) < 60 or data[0] != PCP_VERSION or data[1] != 0x81:
        return None
    result, lifetime = data[3], struct.unpack(">I", data[4:8])[0]
    if data[24:36] != nonce:
        return None
    internal_port, ext_port = struct.unpack(">HH", data[40:44])
    return {"result": result, "lifetime": lifetime, "ext_port": ext_port, "ext_ip": from_ip16(data[44:60]), "internal_port": internal_port}


# ---------------------------------------------------------------- NAT-PMP (RFC 6886)

def natpmp_addr_request() -> bytes:
    return struct.pack(">BB", NATPMP_VERSION, 0)


def natpmp_parse_addr_response(data: bytes) -> Optional[dict]:
    if len(data) != 12 or data[0] != 0 or data[1] != 128:
        return None
    return {"result": struct.unpack(">H", data[2:4])[0], "ext_ip": socket.inet_ntoa(data[8:12])}


def natpmp_map_request(internal_port: int, ext_port: int, lifetime: int) -> bytes:
    return struct.pack(">BBHHHI", NATPMP_VERSION, 1, 0, internal_port, ext_port, lifetime)


def natpmp_parse_map_response(data: bytes, internal_port: int) -> Optional[dict]:
    if len(data) != 16 or data[0] != 0 or data[1] != 129:
        return None
    result, _epoch, iport, eport, lifetime = struct.unpack(">HIHHI", data[2:16])
    if iport != internal_port:
        return None
    return {"result": result, "ext_port": eport, "lifetime": lifetime}


# ---------------------------------------------------------------- UPnP IGD

def ssdp_search(target: str) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + target + "\r\n\r\n").encode()


def ssdp_location(data: bytes) -> Optional[str]:
    try:
        head = data.decode("latin-1")
    except UnicodeDecodeError:
        return None
    if not head.startswith("HTTP/1.1 200"):
        return None
    for line in head.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "location":
            return v.strip()
    return None


def trusted_lan_host(host: str, responder: str, allow_loopback: bool = False) -> bool:
    """A UPnP URL is followed only if it names the very address that answered, and that address is on the local network."""
    try:
        a = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    if host.strip("[]") != responder:
        return False
    if a.is_loopback:
        return allow_loopback                  # Python calls 127.0.0.1 "private": a router is never there (tests only)
    return (a.is_private or a.is_link_local) and not (a.is_unspecified or a.is_multicast or a.is_reserved)


def parse_igd_description(xml: str) -> Optional[dict]:
    """-> {"service": serviceType, "control": controlURL} of the first WAN connection service (regex, not a full XML parser: the
    document comes from the LAN and is size-limited, but a billion-laughs document must not be able to hurt)."""
    for st in WAN_SERVICES:
        for m in re.finditer(r"<service>(.*?)</service>", xml, re.S | re.I):
            blk = m.group(1)
            t = re.search(r"<serviceType>\s*([^<\s]+)\s*</serviceType>", blk, re.I)
            c = re.search(r"<controlURL>\s*([^<\s]+)\s*</controlURL>", blk, re.I)
            if t and c and t.group(1) == st:
                return {"service": st, "control": c.group(1)}
    return None


def soap_envelope(service: str, action: str, args: list) -> bytes:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in args)
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{body}</u:{action}></s:Body></s:Envelope>').encode()


def soap_error(xml: str) -> Optional[int]:
    m = re.search(r"<errorCode>\s*(\d+)\s*</errorCode>", xml)
    return int(m.group(1)) if m else None


async def http_request(method: str, url: str, headers: Optional[dict] = None, body: bytes = b"", timeout: float = 4.0) -> tuple:
    """A tiny HTTP/1.1 client (no redirects, no TLS, size-limited): UPnP devices speak plain HTTP on the LAN. -> (status, text)."""
    u = urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        raise ValueError("only http URLs")
    port = u.port or 80
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    hdr = {"Host": f"{u.hostname}:{port}", "Connection": "close", "Content-Length": str(len(body))}
    hdr.update(headers or {})
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdr.items()) + "\r\n"
    r, w = await asyncio.wait_for(asyncio.open_connection(u.hostname, port), timeout)
    try:
        w.write(req.encode() + body)
        await w.drain()
        data = b""
        while len(data) < MAX_BODY:
            chunk = await asyncio.wait_for(r.read(4096), timeout)
            if not chunk:
                break
            data += chunk
    finally:
        w.close()
    head, _, rest = data.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    if b"transfer-encoding: chunked" in head.lower():
        out, i = b"", 0
        while i < len(rest):
            j = rest.find(b"\r\n", i)
            if j < 0:
                break
            try:
                n = int(rest[i:j].split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[j + 2:j + 2 + n]
            i = j + 2 + n + 2
        rest = out
    return status, rest.decode("utf-8", "replace")


# ---------------------------------------------------------------- the mapper

class _Exchange(asyncio.DatagramProtocol):
    def __init__(self, dst, check):
        self.dst, self.check = dst, check
        self.fut = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if addr[0] != self.dst[0] or self.fut.done():
            return
        r = self.check(data)
        if r is not None:
            self.fut.set_result(r)


async def udp_exchange(dst: tuple, payload: bytes, check, retries=UDP_RETRIES):
    """Send `payload` to `dst` from a fresh socket and wait for an answer that `check` accepts (retransmitting, as the RFCs do)."""
    loop = asyncio.get_running_loop()
    tr, proto = await loop.create_datagram_endpoint(lambda: _Exchange(dst, check), remote_addr=dst)
    try:
        for t in retries:
            tr.sendto(payload)
            try:
                return await asyncio.wait_for(asyncio.shield(proto.fut), t)
            except asyncio.TimeoutError:
                continue
        return None
    finally:
        tr.close()


class PortMapper:
    """`gateway`, `pcp_port`, `natpmp_port`, `ssdp_addr` and `allow_loopback` exist so that the protocols can be tested against simulated
    gateways on the loopback interface; a node leaves them at their defaults."""

    def __init__(self, gateway: Optional[str] = None, methods=("pcp", "natpmp", "upnp"), pcp_port: int = PORT, natpmp_port: int = PORT,
                 ssdp_addr: tuple = SSDP_ADDR, allow_loopback: bool = False, local_ip: Optional[str] = None, search_time: float = 2.0):
        self.gateway = gateway
        self.methods = methods
        self.pcp_port, self.natpmp_port, self.ssdp_addr = pcp_port, natpmp_port, ssdp_addr
        self.allow_loopback, self.local_ip, self.search_time = allow_loopback, local_ip, search_time
        self._igd = None                       # cached UPnP device: {"base", "service", "control", "host"}
        self.disabled = set()                  # methods that answered "unsupported": not tried again

    def _gw(self) -> Optional[str]:
        return self.gateway or default_gateway_v4()

    def _me(self, gw: str) -> Optional[str]:
        return self.local_ip or local_ip_towards(gw)

    # ---- PCP
    async def _pcp(self, gw: str, internal_port: int, want_port: int, lifetime: int) -> Optional[Mapping]:
        me = self._me(gw)
        if me is None:
            return None
        nonce = os.urandom(12)
        r = await udp_exchange((gw, self.pcp_port), pcp_map_request(me, internal_port, want_port, lifetime, nonce),
                               lambda d: pcp_parse_map_response(d, nonce) or ({"result": 1} if len(d) >= 4 and d[0] == 0 else None))
        if r is None:
            return None
        if r["result"] != 0:
            log.debug("PCP: %s", PCP_RESULTS.get(r["result"], r["result"]))
            if r["result"] == 1:
                self.disabled.add("pcp")
            return None
        return Mapping("pcp", r["ext_ip"], r["ext_port"], internal_port, r["lifetime"], gw)

    # ---- NAT-PMP
    async def _natpmp_ext_ip(self, gw: str) -> Optional[str]:
        r = await udp_exchange((gw, self.natpmp_port), natpmp_addr_request(), natpmp_parse_addr_response)
        return r["ext_ip"] if r and r["result"] == 0 else None

    async def _natpmp(self, gw: str, internal_port: int, want_port: int, lifetime: int) -> Optional[Mapping]:
        ext_ip = await self._natpmp_ext_ip(gw)
        if ext_ip is None:
            return None
        r = await udp_exchange((gw, self.natpmp_port), natpmp_map_request(internal_port, want_port, lifetime),
                               lambda d: natpmp_parse_map_response(d, internal_port))
        if r is None or r["result"] != 0:
            log.debug("NAT-PMP: %s", NATPMP_RESULTS.get((r or {}).get("result"), "no answer"))
            return None
        return Mapping("natpmp", ext_ip, r["ext_port"], internal_port, r["lifetime"], gw)

    # ---- UPnP
    async def _igd_discover(self, gw: Optional[str]) -> Optional[dict]:
        if self._igd is not None:
            return self._igd
        loop = asyncio.get_running_loop()
        found = loop.create_future()

        class P(asyncio.DatagramProtocol):
            def datagram_received(_s, data, addr):
                loc = ssdp_location(data)
                if loc and not found.done():
                    u = urlsplit(loc)
                    if u.scheme == "http" and u.hostname and trusted_lan_host(u.hostname, addr[0], self.allow_loopback):
                        found.set_result((loc, addr[0]))
        tr, _ = await loop.create_datagram_endpoint(P, local_addr=("0.0.0.0", 0), family=socket.AF_INET)
        try:
            tr.get_extra_info("socket").setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        try:
            for st in IGD_TARGETS:
                tr.sendto(ssdp_search(st), self.ssdp_addr)
            try:
                loc, host = await asyncio.wait_for(asyncio.shield(found), self.search_time)
            except asyncio.TimeoutError:
                return None
        finally:
            tr.close()
        try:
            status, xml = await http_request("GET", loc)
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            log.debug("UPnP description: %s", e)
            return None
        svc = parse_igd_description(xml) if status == 200 else None
        if not svc:
            return None
        control = urljoin(loc, svc["control"])
        cu = urlsplit(control)
        if cu.scheme != "http" or cu.hostname != urlsplit(loc).hostname:
            log.debug("UPnP: the control URL points elsewhere than the device: ignored")
            return None
        self._igd = {"service": svc["service"], "control": control, "host": host}
        return self._igd

    async def _soap(self, igd: dict, action: str, args: list) -> tuple:
        hdr = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{igd["service"]}#{action}"'}
        return await http_request("POST", igd["control"], hdr, soap_envelope(igd["service"], action, args))

    async def _upnp_ext_ip(self, igd: dict) -> Optional[str]:
        status, text = await self._soap(igd, "GetExternalIPAddress", [])
        m = re.search(r"<NewExternalIPAddress>\s*([^<\s]*)\s*</NewExternalIPAddress>", text)
        return m.group(1) if status == 200 and m else None

    async def _upnp(self, gw: Optional[str], internal_port: int, want_port: int, lifetime: int) -> Optional[Mapping]:
        igd = await self._igd_discover(gw)
        me = self._me(igd["host"]) if igd else None
        if igd is None or me is None:
            return None
        try:
            ext_ip = await self._upnp_ext_ip(igd)
            port, lease = want_port, lifetime
            for _ in range(4):
                args = [("NewRemoteHost", ""), ("NewExternalPort", port), ("NewProtocol", "UDP"), ("NewInternalPort", internal_port),
                        ("NewInternalClient", me), ("NewEnabled", 1), ("NewPortMappingDescription", "oneq"), ("NewLeaseDuration", lease)]
                status, text = await self._soap(igd, "AddPortMapping", args)
                if status == 200:
                    return Mapping("upnp", ext_ip, port, internal_port, lease or 7200, igd["host"], extra={"igd": igd})
                err = soap_error(text)
                if err == 725 and lease:                # OnlyPermanentLeasesSupported: ask for a permanent mapping (removed at exit)
                    lease = 0
                elif err in (718, 727):                 # the port is taken: another one
                    port = 20000 + int.from_bytes(os.urandom(2), "big") % 40000
                else:
                    log.debug("UPnP AddPortMapping: HTTP %s, error %s", status, err)
                    return None
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            log.debug("UPnP: %s", e)
        return None

    # ---- public API
    async def router_external_ip(self) -> Optional[str]:
        """The router's WAN address without creating a mapping (NAT-PMP, then UPnP), or None. Used to recognise a second NAT."""
        gw = self._gw()
        if gw and "natpmp" in self.methods and "natpmp" not in self.disabled:
            ip = await self._natpmp_ext_ip(gw)
            if ip:
                return ip
        if "upnp" in self.methods:
            try:
                igd = await self._igd_discover(gw)
                return await self._upnp_ext_ip(igd) if igd else None
            except (OSError, asyncio.TimeoutError, ValueError):
                return None
        return None

    async def map(self, internal_port: int, want_port: Optional[int] = None, lifetime: int = 3600) -> Optional[Mapping]:
        gw = self._gw()
        want = want_port or internal_port
        for m in self.methods:
            if m in self.disabled:
                continue
            try:
                if m == "pcp" and gw:
                    r = await self._pcp(gw, internal_port, want, lifetime)
                elif m == "natpmp" and gw:
                    r = await self._natpmp(gw, internal_port, want, lifetime)
                elif m == "upnp":
                    r = await self._upnp(gw, internal_port, want, lifetime)
                else:
                    r = None
            except (OSError, asyncio.TimeoutError) as e:
                log.debug("port mapping with %s: %s", m, e)
                r = None
            if r is not None:
                log.info("port mapping (%s): %s -> %s:%s lifetime %ss", r.method, internal_port, r.ext_ip, r.ext_port, r.lifetime)
                return r
        return None

    async def renew(self, m: Mapping) -> Optional[Mapping]:
        """The same request again (the protocols treat it as a renewal), asking for the port we already have."""
        gw = m.gateway
        try:
            if m.method == "pcp":
                return await self._pcp(gw, m.internal_port, m.ext_port, max(m.lifetime, 120))
            if m.method == "natpmp":
                return await self._natpmp(gw, m.internal_port, m.ext_port, max(m.lifetime, 120))
            igd = m.extra.get("igd") or self._igd
            self._igd = igd
            return await self._upnp(gw, m.internal_port, m.ext_port, m.lifetime)
        except (OSError, asyncio.TimeoutError):
            return None

    async def unmap(self, m: Mapping):
        """Release the mapping (best effort, quick): PCP and NAT-PMP with lifetime 0, UPnP DeletePortMapping."""
        try:
            if m.method == "pcp":
                me = self._me(m.gateway)
                nonce = os.urandom(12)
                if me:
                    await udp_exchange((m.gateway, self.pcp_port), pcp_map_request(me, m.internal_port, m.ext_port, 0, nonce),
                                       lambda d: pcp_parse_map_response(d, nonce), retries=(0.3,))
            elif m.method == "natpmp":
                await udp_exchange((m.gateway, self.natpmp_port), natpmp_map_request(m.internal_port, 0, 0),
                                   lambda d: natpmp_parse_map_response(d, m.internal_port), retries=(0.3,))
            else:
                igd = m.extra.get("igd") or self._igd
                if igd:
                    await self._soap(igd, "DeletePortMapping", [("NewRemoteHost", ""), ("NewExternalPort", m.ext_port), ("NewProtocol", "UDP")])
        except (OSError, asyncio.TimeoutError, ValueError):
            pass
