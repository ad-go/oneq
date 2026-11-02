#!/usr/bin/env python3
"""Tests of oneqportmap: the PCP / NAT-PMP / UPnP codecs against the RFC layouts, and the mapper against simulated gateways on loopback
(a PCP server, a NAT-PMP server, an UPnP IGD with SSDP answer, HTTP description and SOAP control), including hostile answers."""
import pqtls  # noqa: F401

import asyncio
import socket
import struct
import unittest

import oneqportmap as pm

EXT_IP = "203.0.113.7"


class UdpServer(asyncio.DatagramProtocol):
    def __init__(self, handler):
        self.handler, self.tr, self.seen = handler, None, []

    def connection_made(self, tr):
        self.tr = tr

    def datagram_received(self, data, addr):
        self.seen.append(data)
        out = self.handler(data)
        if out is not None:
            self.tr.sendto(out, addr)

    @property
    def port(self):
        return self.tr.get_extra_info("sockname")[1]


async def udp_server(handler):
    srv = UdpServer(handler)
    await asyncio.get_running_loop().create_datagram_endpoint(lambda: srv, local_addr=("127.0.0.1", 0))
    return srv


def pcp_gateway(result=0, ext_port=None, ext_ip=EXT_IP):
    """A PCP server: answers MAP requests (and records them)."""
    state = {"maps": []}

    def handler(data):
        if len(data) < 60 or data[0] != 2:
            return None
        lifetime = struct.unpack(">I", data[4:8])[0]
        nonce = data[24:36]
        iport, wport = struct.unpack(">HH", data[40:42] + data[42:44])
        state["maps"].append({"lifetime": lifetime, "internal": iport, "wanted": wport, "client": pm.from_ip16(data[8:24])})
        granted = ext_port or wport
        hdr = struct.pack(">BBBB", 2, 0x81, 0, result) + struct.pack(">I", lifetime) + struct.pack(">I", 1234) + b"\0" * 12
        body = nonce + struct.pack(">B3xHH", 17, iport, granted) + pm.ip16(ext_ip)
        return hdr + body
    return handler, state


def natpmp_gateway(map_result=0, ext_port=None):
    state = {"maps": []}

    def handler(data):
        if data[:2] == b"\x00\x00" and len(data) == 2:
            return struct.pack(">BBHI", 0, 128, 0, 99) + socket.inet_aton(EXT_IP)
        if len(data) == 12 and data[1] == 1:
            _v, _o, _r, iport, wport, lifetime = struct.unpack(">BBHHHI", data)
            state["maps"].append({"internal": iport, "wanted": wport, "lifetime": lifetime})
            return struct.pack(">BBHIHHI", 0, 129, map_result, 99, iport, ext_port or wport, lifetime)
        return None
    return handler, state


class FakeIgd:
    """An UPnP gateway: answers SSDP on a unicast UDP port, serves the device description and a WANIPConnection control URL."""

    def __init__(self, description=None, location_host=None, control_host=None, add_errors=None, status_ext=EXT_IP):
        self.maps, self.calls, self.add_errors = {}, [], list(add_errors or [])
        self.location_host, self.control_host, self.status_ext = location_host, control_host, status_ext
        self.description = description

    async def start(self):
        self.http = await asyncio.start_server(self._http, "127.0.0.1", 0)
        self.http_port = self.http.sockets[0].getsockname()[1]
        igd = self

        def ssdp(data):
            if b"M-SEARCH" in data:
                host = igd.location_host or "127.0.0.1"
                return f"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: http://{host}:{igd.http_port}/desc.xml\r\nST: x\r\n\r\n".encode()
        self.ssdp = await udp_server(ssdp)
        return self

    async def close(self):
        self.http.close()
        self.ssdp.tr.close()

    def desc_xml(self):
        host = self.control_host or f"127.0.0.1:{self.http_port}"
        ctl = f"http://{host}/ctl/ip" if self.control_host else "/ctl/ip"
        return self.description or ('<?xml version="1.0"?><root><device><deviceList><device><deviceList><device><serviceList>'
                                    '<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>'
                                    f'<controlURL>{ctl}</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>')

    async def _http(self, r, w):
        head = await r.readuntil(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode()
        n = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                n = int(line.split(b":")[1])
        body = (await r.readexactly(n)).decode() if n else ""
        if first.startswith("GET /desc.xml"):
            out, code = self.desc_xml(), 200
        elif first.startswith("POST /ctl/ip"):
            act = [l for l in head.decode().split("\r\n") if l.lower().startswith("soapaction")][0].split("#")[1].strip('"')
            self.calls.append((act, body))
            code, out = 200, "<ok/>"
            if act == "GetExternalIPAddress":
                out = f"<NewExternalIPAddress>{self.status_ext}</NewExternalIPAddress>"
            elif act == "AddPortMapping":
                import re
                port = int(re.search(r"<NewExternalPort>(\d+)<", body).group(1))
                lease = int(re.search(r"<NewLeaseDuration>(\d+)<", body).group(1))
                if self.add_errors:
                    e = self.add_errors.pop(0)
                    if e == 725 and lease == 0:
                        pass
                    else:
                        code, out = 500, f"<errorCode>{e}</errorCode>"
                if code == 200:
                    self.maps[port] = lease
            elif act == "DeletePortMapping":
                import re
                self.maps.pop(int(re.search(r"<NewExternalPort>(\d+)<", body).group(1)), None)
        else:
            out, code = "", 404
        data = out.encode()
        w.write(f"HTTP/1.1 {code} X\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        await w.drain()
        w.close()


class TestCodecs(unittest.TestCase):
    def test_pcp_map_request_has_the_rfc_layout(self):
        nonce = bytes(range(12))
        d = pm.pcp_map_request("192.168.1.10", 51820, 51820, 3600, nonce)
        self.assertEqual(len(d), 60)
        self.assertEqual(d[:4], bytes([2, 1, 0, 0]))                                   # version 2, opcode MAP, reserved
        self.assertEqual(struct.unpack(">I", d[4:8])[0], 3600)
        self.assertEqual(d[8:24], bytes(10) + b"\xff\xff" + bytes([192, 168, 1, 10]))  # the client address, IPv4-mapped
        self.assertEqual(d[24:36], nonce)
        self.assertEqual(d[36], 17)                                                    # UDP
        self.assertEqual(d[40:44], struct.pack(">HH", 51820, 51820))

    def test_pcp_response_is_checked_against_the_nonce(self):
        nonce = b"n" * 12
        good = struct.pack(">BBBBII", 2, 0x81, 0, 0, 120, 7) + b"\0" * 12 + nonce + struct.pack(">B3xHH", 17, 4000, 4001) + pm.ip16("198.51.100.4")
        r = pm.pcp_parse_map_response(good, nonce)
        self.assertEqual((r["result"], r["lifetime"], r["ext_port"], r["ext_ip"], r["internal_port"]), (0, 120, 4001, "198.51.100.4", 4000))
        self.assertIsNone(pm.pcp_parse_map_response(good, b"x" * 12), "somebody else's nonce")
        self.assertIsNone(pm.pcp_parse_map_response(good[:50], nonce))
        self.assertIsNone(pm.pcp_parse_map_response(bytes([0]) + good[1:], nonce), "wrong version")

    def test_natpmp_messages(self):
        self.assertEqual(pm.natpmp_addr_request(), b"\x00\x00")
        self.assertEqual(pm.natpmp_map_request(4000, 4001, 7200), struct.pack(">BBHHHI", 0, 1, 0, 4000, 4001, 7200))
        r = pm.natpmp_parse_addr_response(struct.pack(">BBHI", 0, 128, 0, 5) + bytes([198, 51, 100, 9]))
        self.assertEqual(r, {"result": 0, "ext_ip": "198.51.100.9"})
        self.assertIsNone(pm.natpmp_parse_addr_response(b"\x00\x80"))
        m = pm.natpmp_parse_map_response(struct.pack(">BBHIHHI", 0, 129, 0, 5, 4000, 4002, 3600), 4000)
        self.assertEqual((m["result"], m["ext_port"], m["lifetime"]), (0, 4002, 3600))
        self.assertIsNone(pm.natpmp_parse_map_response(struct.pack(">BBHIHHI", 0, 129, 0, 5, 4001, 4002, 3600), 4000), "another internal port")

    def test_upnp_description_and_trust_rules(self):
        xml = ('<root><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>'
               '<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/ip</controlURL></service></root>')
        self.assertEqual(pm.parse_igd_description(xml), {"service": "urn:schemas-upnp-org:service:WANIPConnection:1", "control": "/ctl/ip"})
        self.assertIsNone(pm.parse_igd_description("<root></root>"))
        self.assertTrue(pm.trusted_lan_host("192.168.1.1", "192.168.1.1"))
        self.assertFalse(pm.trusted_lan_host("192.168.1.1", "192.168.1.2"), "the URL must name the address that answered")
        self.assertFalse(pm.trusted_lan_host("8.8.8.8", "8.8.8.8"), "a public address is not a router on the LAN")
        self.assertFalse(pm.trusted_lan_host("127.0.0.1", "127.0.0.1"))
        self.assertTrue(pm.trusted_lan_host("127.0.0.1", "127.0.0.1", allow_loopback=True))
        self.assertTrue(pm.trusted_lan_host("169.254.1.1", "169.254.1.1"))
        self.assertEqual(pm.soap_error("<detail><errorCode>718</errorCode></detail>"), 718)
        self.assertIsNone(pm.ssdp_location(b"HTTP/1.1 404 Not Found\r\nLOCATION: http://x/\r\n\r\n"))
        self.assertEqual(pm.ssdp_location(b"HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1:5000/d.xml\r\n\r\n"), "http://192.168.1.1:5000/d.xml")

    def test_mapping_endpoint_formats(self):
        self.assertEqual(pm.Mapping("pcp", "198.51.100.4", 4001, 4000, 3600, "g").endpoint(), "198.51.100.4:4001")
        self.assertEqual(pm.Mapping("pcp", "2001:db8::1", 4001, 4000, 3600, "g").endpoint(), "[2001:db8::1]:4001")
        self.assertIsNone(pm.Mapping("upnp", None, 4001, 4000, 3600, "g").endpoint())
        m = pm.Mapping("pcp", "1.2.3.4", 1, 1, 3600, "g", created=100.0)
        self.assertEqual(m.renew_at(), 100.0 + 1800)


class TestGateways(unittest.IsolatedAsyncioTestCase):
    async def test_pcp_maps_renews_and_unmaps(self):
        handler, st = pcp_gateway()
        gw = await udp_server(handler)
        mp = pm.PortMapper(gateway="127.0.0.1", methods=("pcp",), pcp_port=gw.port, local_ip="192.168.1.10")
        m = await mp.map(51820)
        self.assertEqual((m.method, m.ext_ip, m.ext_port, m.internal_port), ("pcp", EXT_IP, 51820, 51820))
        self.assertEqual(st["maps"][0]["client"], "192.168.1.10")
        self.assertEqual(m.endpoint(), f"{EXT_IP}:51820")
        again = await mp.renew(m)
        self.assertEqual(again.ext_port, 51820)
        self.assertEqual(st["maps"][-1]["wanted"], 51820, "a renewal asks for the port we have")
        await mp.unmap(m)
        self.assertEqual(st["maps"][-1]["lifetime"], 0, "release = lifetime 0")
        gw.tr.close()

    async def test_pcp_refusal_and_an_unsupported_version_fall_through(self):
        handler, _ = pcp_gateway(result=2)
        gw = await udp_server(handler)
        mp = pm.PortMapper(gateway="127.0.0.1", methods=("pcp",), pcp_port=gw.port, local_ip="192.168.1.10")
        self.assertIsNone(await mp.map(51820))
        gw.tr.close()
        # an old NAT-PMP-only router answers the PCP request with a version-0 "unsupported version"
        h2, st2 = natpmp_gateway()

        def old_router(data):
            if data and data[0] == 2:
                return struct.pack(">BBHI", 0, 0x81, 1, 0)
            return h2(data)
        gw2 = await udp_server(old_router)
        mp2 = pm.PortMapper(gateway="127.0.0.1", methods=("pcp", "natpmp"), pcp_port=gw2.port, natpmp_port=gw2.port, local_ip="192.168.1.10")
        m = await mp2.map(51820)
        self.assertEqual(m.method, "natpmp")
        self.assertIn("pcp", mp2.disabled)
        gw2.tr.close()

    async def test_natpmp_maps_gives_another_port_when_asked_and_unmaps(self):
        handler, st = natpmp_gateway(ext_port=40001)
        gw = await udp_server(handler)
        mp = pm.PortMapper(gateway="127.0.0.1", methods=("natpmp",), natpmp_port=gw.port)
        self.assertEqual(await mp.router_external_ip(), EXT_IP)
        m = await mp.map(51820)
        self.assertEqual((m.method, m.ext_ip, m.ext_port), ("natpmp", EXT_IP, 40001), "the router may choose another external port")
        await mp.unmap(m)
        self.assertEqual((st["maps"][-1]["wanted"], st["maps"][-1]["lifetime"]), (0, 0))
        gw.tr.close()

    async def test_nothing_answers_means_no_mapping_quickly(self):
        dead = await udp_server(lambda d: None)
        mp = pm.PortMapper(gateway="127.0.0.1", methods=("pcp", "natpmp"), pcp_port=dead.port, natpmp_port=dead.port, local_ip="192.168.1.10")
        t0 = asyncio.get_running_loop().time()
        self.assertIsNone(await mp.map(51820))
        self.assertLess(asyncio.get_running_loop().time() - t0, 6.0)
        dead.tr.close()

    async def test_upnp_discovers_maps_and_deletes(self):
        igd = await FakeIgd().start()
        mp = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd.ssdp.port), allow_loopback=True, local_ip="192.168.1.10", search_time=1.0)
        self.assertEqual(await mp.router_external_ip(), EXT_IP)
        m = await mp.map(51820)
        self.assertEqual((m.method, m.ext_ip, m.ext_port), ("upnp", EXT_IP, 51820))
        self.assertIn(51820, igd.maps)
        add = [b for a, b in igd.calls if a == "AddPortMapping"][0]
        for needle in ("<NewProtocol>UDP<", "<NewInternalClient>192.168.1.10<", "<NewInternalPort>51820<", "<NewPortMappingDescription>oneq<"):
            self.assertIn(needle, add)
        await mp.unmap(m)
        self.assertNotIn(51820, igd.maps)
        await igd.close()

    async def test_upnp_retries_with_a_permanent_lease_and_another_port_on_conflict(self):
        igd = await FakeIgd(add_errors=[725]).start()
        mp = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd.ssdp.port), allow_loopback=True, local_ip="192.168.1.10", search_time=1.0)
        m = await mp.map(51820)
        self.assertEqual(igd.maps[51820], 0, "the router only takes permanent leases")
        self.assertEqual(m.ext_port, 51820)
        await igd.close()
        igd2 = await FakeIgd(add_errors=[718]).start()
        mp2 = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd2.ssdp.port), allow_loopback=True, local_ip="192.168.1.10", search_time=1.0)
        m2 = await mp2.map(51820)
        self.assertNotEqual(m2.ext_port, 51820, "conflict: another external port")
        self.assertIn(m2.ext_port, igd2.maps)
        await igd2.close()

    async def test_upnp_ignores_a_description_that_points_the_control_url_at_another_host(self):
        igd = await FakeIgd(control_host="192.0.2.99:80").start()
        mp = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd.ssdp.port), allow_loopback=True, local_ip="192.168.1.10", search_time=1.0)
        self.assertIsNone(await mp.map(51820))
        self.assertEqual(igd.calls, [], "nothing was sent to the foreign control URL or to the device")
        await igd.close()

    async def test_upnp_ignores_a_location_that_names_a_third_host(self):
        igd = await FakeIgd(location_host="192.0.2.50").start()      # the answer comes from 127.0.0.1 but says the device is elsewhere
        mp = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd.ssdp.port), allow_loopback=True, local_ip="192.168.1.10", search_time=0.6)
        self.assertIsNone(await mp.map(51820))
        await igd.close()

    async def test_upnp_without_loopback_permission_refuses_a_loopback_device(self):
        igd = await FakeIgd().start()
        mp = pm.PortMapper(methods=("upnp",), ssdp_addr=("127.0.0.1", igd.ssdp.port), allow_loopback=False, local_ip="192.168.1.10", search_time=0.6)
        self.assertIsNone(await mp.map(51820))
        await igd.close()

    async def test_methods_are_tried_in_order_and_the_first_success_wins(self):
        h, st = natpmp_gateway()
        gw = await udp_server(h)
        dead = await udp_server(lambda d: None)
        mp = pm.PortMapper(gateway="127.0.0.1", methods=("pcp", "natpmp"), pcp_port=dead.port, natpmp_port=gw.port, local_ip="192.168.1.10")
        m = await mp.map(51820)
        self.assertEqual(m.method, "natpmp")
        gw.tr.close()
        dead.tr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
