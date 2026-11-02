#!/usr/bin/env python3
"""Verifies deploy/nginx-rendezvous.conf for real: starts a private nginx (own prefix, high port,
no root) in front of rendezvous_server.py and checks that the PQ-only restriction holds.
Skipped if nginx is missing or built against OpenSSL < 3.5.  Run: python3 test_nginx_proxy.py
"""
import pqtls  # noqa: F401

import asyncio
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import aiohttp

import oneqtunel as t
from test_oneqtunel import OPENSSL, free_port, make_cert, openssl_has_mlkem, wait_port

HERE = os.path.dirname(os.path.abspath(__file__))
NGINX = shutil.which("nginx") or next((p for p in ("/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx")
                                       if os.path.exists(p)), None)


def nginx_has_mlkem():
    if not NGINX:
        return False
    out = subprocess.run([NGINX, "-V"], capture_output=True, text=True).stderr
    m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 5)


@unittest.skipUnless(NGINX and nginx_has_mlkem() and openssl_has_mlkem(), "needs nginx + openssl >= 3.5")
class TestNginxProxy(unittest.TestCase):
    conf_name = "nginx-rendezvous.conf"

    @classmethod
    def backend_cmd(cls):
        return [sys.executable, os.path.join(HERE, "rendezvous_server.py"), "run", "--listen",
                f"127.0.0.1:{cls.back}", "--insecure-http", "--trust-proxy", "--open"]

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="pqngx")
        cls.cert, cls.key = make_cert(cls.d)
        cls.back, cls.front = free_port(), free_port()
        cls.srv = subprocess.Popen(cls.backend_cmd(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_port(cls.back)
        conf = open(os.path.join(HERE, "deploy", cls.conf_name)).read()
        conf = conf.replace("listen 443 ssl;", f"listen 127.0.0.1:{cls.front} ssl;")
        conf = re.sub(r"ssl_certificate\s+[^;]+;", f"ssl_certificate {cls.cert};", conf)
        conf = re.sub(r"ssl_certificate_key\s+[^;]+;", f"ssl_certificate_key {cls.key};", conf)
        conf = conf.replace("127.0.0.1:8080", f"127.0.0.1:{cls.back}")
        site = os.path.join(cls.d, "site.conf")
        open(site, "w").write(conf)
        main = os.path.join(cls.d, "nginx.conf")
        open(main, "w").write(
            f"worker_processes 1;\npid {cls.d}/nginx.pid;\nerror_log {cls.d}/error.log;\n"
            f"events {{ worker_connections 64; }}\nhttp {{\n access_log off;\n"
            f" client_body_temp_path {cls.d}/b; proxy_temp_path {cls.d}/p; fastcgi_temp_path {cls.d}/f;\n"
            f" uwsgi_temp_path {cls.d}/u; scgi_temp_path {cls.d}/s;\n include {site};\n}}\n")
        r = subprocess.run([NGINX, "-p", cls.d, "-c", main, "-e", f"{cls.d}/error.log"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert wait_port(cls.front), open(f"{cls.d}/error.log").read()

    @classmethod
    def tearDownClass(cls):
        try:
            pid = int(open(f"{cls.d}/nginx.pid").read())
            os.kill(pid, 15)
        except Exception:
            pass
        cls.srv.terminate()
        cls.srv.wait(5)
        time.sleep(0.3)
        shutil.rmtree(cls.d, ignore_errors=True)

    def s_client(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{self.front}", "-CAfile", self.cert,
                            "-brief", *args], input=b"", capture_output=True, env=env, timeout=20)
        return r.returncode, (r.stdout + r.stderr).decode(errors="replace")

    def test_pq_group_accepted(self):
        rc, out = self.s_client("-tls1_3", "-groups", "X25519MLKEM768")
        self.assertEqual(rc, 0, out)
        self.assertIn("X25519MLKEM768", out)

    def test_classic_groups_refused(self):
        for g in ("X25519", "secp256r1", "secp384r1"):
            rc, out = self.s_client("-tls1_3", "-groups", g)
            self.assertNotEqual(rc, 0, (g, out))

    def test_tls12_refused(self):
        rc, _ = self.s_client("-tls1_2")
        self.assertNotEqual(rc, 0)

    def test_api_and_relay_through_proxy(self):
        a, b = t.Identity.generate(), t.Identity.generate()

        async def go():
            rv = t.Rendezvous(f"https://127.0.0.1:{self.front}", "tok", self.cert, a.pub)
            try:
                self.assertEqual((await rv.register(["127.0.0.1:1"]))["node_id"], a.node_id.hex())
            finally:
                await rv.close()
            ctx = pqtls.client_context(self.cert)
            hdr = {"Authorization": "Bearer tok"}
            async with aiohttp.ClientSession() as s:
                wa = await s.ws_connect(f"wss://127.0.0.1:{self.front}/v1/relay?node={a.node_id.hex()}",
                                        ssl=ctx, headers=hdr)
                wb = await s.ws_connect(f"wss://127.0.0.1:{self.front}/v1/relay?node={b.node_id.hex()}",
                                        ssl=ctx, headers=hdr)
                await wa.send_bytes(b.node_id + b"through-nginx")
                m = await asyncio.wait_for(wb.receive(), 5)
                self.assertEqual(m.data, a.node_id + b"through-nginx")
        asyncio.run(go())


@unittest.skipUnless(NGINX and nginx_has_mlkem() and openssl_has_mlkem(), "needs nginx + openssl >= 3.5")
class TestNginxOneqrelay(TestNginxProxy):
    """deploy/nginx-oneqrelay.conf in front of a real oneqrelay: PQ-only TLS, login, join, relay and federation paths."""
    conf_name = "nginx-oneqrelay.conf"

    @classmethod
    def backend_cmd(cls):
        import meshdb
        meshdb.SCRYPT_N = 2 ** 10
        cls.secret = os.path.join(cls.d, "fed.secret")
        open(cls.secret, "w").write(base64.b64encode(b"s" * 32).decode())
        os.chmod(cls.secret, 0o600)
        reg = meshdb.Registry(meshdb.Store(os.path.join(cls.d, "r1.db"), "r1"), b"s" * 32)
        reg.create_community("lan", "10.50.0.0/24")
        reg.add_user("lan", "alice", "alice-password", "admin", max_nodes=10)
        return [sys.executable, os.path.join(HERE, "oneqrelay.py"), "run", "--id", "r1", "--db",
                os.path.join(cls.d, "r1.db"), "--secret-file", cls.secret, "--listen", f"127.0.0.1:{cls.back}",
                "--insecure-http", "--trust-proxy"]

    def test_api_and_relay_through_proxy(self):
        a, b = t.Identity.generate(), t.Identity.generate()

        async def go():
            ctx = pqtls.client_context(self.cert)
            base = f"https://127.0.0.1:{self.front}"
            async with aiohttp.ClientSession() as s:
                r = await s.post(base + "/v1/login", ssl=ctx,
                                 json={"community": "lan", "user": "alice", "password": "alice-password"})
                self.assertEqual(r.status, 200)
                hdr = {"Authorization": "Bearer " + (await r.json())["token"]}
                for ident in (a, b):
                    r = await s.put(f"{base}/v1/c/lan/nodes/{ident.node_id.hex()}", ssl=ctx, headers=hdr,
                                    json={"pub": base64.b64encode(ident.pub).decode(), "endpoints": ["1.2.3.4:5"]})
                    self.assertEqual(r.status, 200)
                self.assertEqual(len((await (await s.get(f"{base}/v1/c/lan/nodes", ssl=ctx, headers=hdr)).json())["nodes"]), 2)
                wa = await s.ws_connect(f"{base.replace('https', 'wss')}/v1/relay?comm=lan&node={a.node_id.hex()}",
                                        ssl=ctx, headers=hdr)
                wb = await s.ws_connect(f"{base.replace('https', 'wss')}/v1/relay?comm=lan&node={b.node_id.hex()}",
                                        ssl=ctx, headers=hdr)
                await wa.send_bytes(b.node_id + b"through-nginx")
                m = await asyncio.wait_for(wb.receive(), 5)
                self.assertEqual(m.data, a.node_id + b"through-nginx")
                r = await s.post(base + "/fed/v1/sync", ssl=ctx, data=b"{}")        # federation needs its signature
                self.assertEqual(r.status, 401)
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main(verbosity=2)
