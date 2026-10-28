"""Tests of onequpdate: versions, SHA256SUMS, asset selection, network policy, verified download, TLS against a classical server."""
import pqtls  # noqa: F401  (first, as in the real processes: OPENSSL_CONF restricts the groups)

import asyncio
import hashlib
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import onequpdate as U

BIN = os.urandom(5000)
BIN_SHA = hashlib.sha256(BIN).hexdigest()


class Mock:
    """Loopback server (optionally TLS) serving a release, SHA256SUMS and a binary; behaviour is tweaked through attributes."""

    def __init__(self, tls=None):
        self.tag = "v0.0.2"
        self.draft = self.prerelease = False
        self.api_status = 200
        self.sums = None            # None = derived from BIN
        self.no_sums = False
        self.blob = BIN
        self.redirect = {}          # path -> location
        self.names = None
        self.hits = []
        m = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                m.hits.append(self.path)
                if self.path in m.redirect:
                    self.send_response(302)
                    self.send_header("Location", m.redirect[self.path])
                    self.end_headers()
                    return
                if self.path == "/rel":
                    if m.api_status != 200:
                        self.send_response(m.api_status)
                        self.end_headers()
                        return
                    v = m.tag.lstrip("v")
                    names = m.names or [f"oneqrelay_{v}_amd64.deb", f"oneqnode_{v}_amd64.deb", f"oneq-server_{v}_all.deb"]
                    assets = [{"name": n, "size": len(m.blob), "browser_download_url": f"{m.base}/blob/{n}"} for n in names]
                    if not m.no_sums:
                        assets.append({"name": "SHA256SUMS", "size": 100, "browser_download_url": f"{m.base}/sums"})
                    body = json.dumps({"tag_name": m.tag, "draft": m.draft, "prerelease": m.prerelease, "html_url": "https://github.com/ad-go/oneq/releases/tag/" + m.tag,
                                       "body": "Notes <b>x</b>" + "n" * 900, "assets": assets}).encode()
                    self.reply(body)
                elif self.path == "/sums":
                    v = m.tag.lstrip("v")
                    s = m.sums if m.sums is not None else f"{BIN_SHA} *oneqrelay_{v}_amd64.deb\n{BIN_SHA}  ./out/oneqnode_{v}_amd64.deb\n"
                    self.reply(s.encode())
                elif self.path.startswith("/blob/"):
                    self.reply(m.blob)
                else:
                    self.send_response(404)
                    self.end_headers()

            def reply(self, body):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.scheme = "http"
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            ctx.set_ecdh_curve("X25519")      # a classical server: no ML-KEM
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
            self.scheme = "https"
        self.port = self.srv.server_address[1]
        host = "localhost" if tls else "127.0.0.1"
        self.base = f"{self.scheme}://{host}:{self.port}"
        self.url = self.base + "/rel"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class TestVersions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(U.parse_version("v0.0.2"), (0, 0, 2))
        self.assertEqual(U.parse_version("1.2"), (1, 2))
        self.assertEqual(U.parse_version("1.2.3-rc1+b5"), (1, 2, 3))
        for bad in ("", "abc", "1..2", "v", None, 5, "1.x", "-1"):
            self.assertIsNone(U.parse_version(bad), bad)

    def test_compare(self):
        c = U.compare
        self.assertEqual(c("0.0.1", "v0.0.2"), "newer")
        self.assertEqual(c("0.0.2", "0.0.2"), "current")
        self.assertEqual(c("0.0.3", "0.0.2"), "current")
        self.assertEqual(c("0.9.0", "0.10.0"), "newer")          # numeric, not lexical
        self.assertEqual(c("1.0", "1.0.0"), "current")           # missing components are 0
        self.assertEqual(c("1.0", "1.0.1"), "newer")
        self.assertEqual(c("1.0.0-beta", "1.0.0"), "current")    # suffix ignored
        self.assertEqual(c("0.0.1", "garbage"), "unknown")
        self.assertEqual(c("x", "0.0.2"), "unknown")


class TestParsing(unittest.TestCase):
    def test_sums_formats(self):
        a, b, c, d = ("%064x" % i for i in (1, 2, 3, 4))
        t = f"{a} *one.deb\n{b}  two.deb\n{c} ./dir/three.msi\n{d.upper()}  some/dir/four.zip\nnot a line\n{'z' * 64}  bad\n"
        s = U.parse_sums(t)
        self.assertEqual(s, {"one.deb": a, "two.deb": b, "three.msi": c, "four.zip": d})

    def test_asset_selection(self):
        rel = {"assets": [{"name": n, "size": 1, "browser_download_url": "https://github.com/x/" + n} for n in (
            "oneqrelay_0.0.2_amd64.deb", "oneqnode_0.0.2_amd64.deb", "oneq-server_0.0.2_all.deb", "oneq-node-windows-x64.msi",
            "oneq-node-macos-arm64.tar.gz", "oneq-android.apk", "oneq-mesh-firefox-0.0.2.zip", "SHA256SUMS")]}
        sel = lambda k, **kw: (U.select_asset(rel, k, "0.0.2", **kw) or {}).get("name")
        self.assertEqual(sel("relay", server_pkg=False), "oneqrelay_0.0.2_amd64.deb")
        self.assertEqual(sel("relay", server_pkg=True), "oneq-server_0.0.2_all.deb")
        self.assertEqual(sel("node"), "oneqnode_0.0.2_amd64.deb")
        self.assertEqual(sel("windows"), "oneq-node-windows-x64.msi")
        self.assertEqual(sel("macos-arm64"), "oneq-node-macos-arm64.tar.gz")
        self.assertIsNone(sel("macos-x64"))
        self.assertEqual(sel("firefox"), "oneq-mesh-firefox-0.0.2.zip")
        self.assertIsNone(sel("chromium"))
        self.assertIsNone(sel("bogus"))
        rel["assets"].append({"name": "../evil", "size": 1, "browser_download_url": "https://github.com/x"})
        self.assertNotIn("../evil", U._assets(rel))
        rel2 = {"assets": [{"name": "oneqrelay_0.0.2_amd64.deb", "size": 1, "browser_download_url": "https://github.com/x/a"}]}
        self.assertEqual(U.select_asset(rel2, "relay", "0.0.2", server_pkg=True)["name"], "oneqrelay_0.0.2_amd64.deb")   # fallback

    def test_notes(self):
        self.assertEqual(len(U.clean_notes("a" * 1000)), 600)
        self.assertEqual(U.clean_notes("<script>alert(1)</script>hi\x00"), "alert(1)hi")
        self.assertEqual(U.clean_notes(None), "")

    def test_url_policy(self):
        for ok in ("https://api.github.com/x", "http://127.0.0.1:5/x", "http://localhost/x"):
            self.assertEqual(U.resolve_url(ok), ok)
        for bad in ("http://example.com/x", "ftp://127.0.0.1/", "file:///etc/passwd", "http://127.0.0.1.evil.com/"):
            with self.assertRaises(U.UpdateError):
                U.resolve_url(bad)

    def test_allowlist(self):
        f = U.Fetcher("https://api.github.com/repos/a/b/releases/latest")
        for ok in ("https://github.com/a", "https://objects.githubusercontent.com/a", "https://release-assets.githubusercontent.com/x",
                   "https://foo.githubusercontent.com/x"):
            self.assertTrue(f.allowed(ok), ok)
        for bad in ("http://github.com/a", "https://evilgithub.com/a", "https://github.com.evil.org/a", "https://githubusercontent.com.evil/x",
                    "https://user:pw@github.com/a", "http://127.0.0.1:1/x", "ftp://github.com/"):
            self.assertFalse(f.allowed(bad), bad)
        g = U.Fetcher("http://127.0.0.1:5000/rel")
        self.assertTrue(g.allowed("http://127.0.0.1:5000/blob"))
        self.assertFalse(g.allowed("http://127.0.0.1:5001/blob"))     # another port


class TestCheckAndDownload(unittest.TestCase):
    def setUp(self):
        self.m = Mock()
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        self.m.close()
        shutil.rmtree(self.d, ignore_errors=True)

    def test_newer(self):
        r = U.check("0.0.1", "node", self.m.url, server_pkg=False)
        self.assertEqual((r["status"], r["update_available"], r["latest"], r["error"]), ("newer", True, "0.0.2", None))
        self.assertEqual(r["asset"]["name"], "oneqnode_0.0.2_amd64.deb")
        self.assertEqual(r["asset"]["download_url"], f"{self.m.base}/blob/oneqnode_0.0.2_amd64.deb")
        self.assertLessEqual(len(r["notes"]), 600)
        self.assertNotIn("<b>", r["notes"])
        self.assertTrue(r["url"].startswith("https://github.com/"))

    def test_env_override(self):
        os.environ["ONEQ_UPDATE_URL"] = self.m.url
        try:
            self.assertEqual(U.check("0.0.1", "node")["status"], "newer")
        finally:
            del os.environ["ONEQ_UPDATE_URL"]

    def test_current_and_older(self):
        self.assertEqual(U.check("0.0.2", "relay", self.m.url)["status"], "current")
        r = U.check("0.0.9", "relay", self.m.url)
        self.assertEqual((r["status"], r["update_available"]), ("current", False))

    def test_no_release(self):
        self.m.api_status = 404
        r = U.check("0.0.1", "relay", self.m.url)
        self.assertEqual((r["status"], r["update_available"]), ("error", False))
        self.assertIn("404", r["error"])

    def test_draft_and_prerelease(self):
        for k in ("draft", "prerelease"):
            setattr(self.m, k, True)
            r = U.check("0.0.1", "relay", self.m.url)
            self.assertFalse(r["update_available"], k)
            setattr(self.m, k, False)

    def test_bad_tag_unknown_never_newer(self):
        self.m.tag = "nightly"
        r = U.check("0.0.1", "relay", self.m.url)
        self.assertEqual((r["status"], r["update_available"]), ("unknown", False))

    def test_connection_failure_does_not_raise(self):
        r = U.check("0.0.1", "relay", "http://127.0.0.1:9/rel")
        self.assertEqual(r["status"], "error")
        r = U.check("0.0.1", "relay", "http://example.com/x")
        self.assertEqual(r["status"], "error")

    def test_download_ok(self):
        r = U.check("0.0.1", "node", self.m.url, server_pkg=False)
        d = U.download(r, self.d, self.m.url)
        self.assertTrue(d["ok"], d)
        self.assertEqual((d["size"], d["sha256"], d["name"]), (len(BIN), BIN_SHA, "oneqnode_0.0.2_amd64.deb"))
        self.assertEqual(open(d["path"], "rb").read(), BIN)
        self.assertEqual(os.listdir(self.d), ["oneqnode_0.0.2_amd64.deb"])          # no .part left
        if os.name == "posix":
            self.assertFalse(os.stat(d["path"]).st_mode & 0o111)                   # never executable
        n = len(self.m.hits)
        d2 = U.download(r, self.d, self.m.url)                                      # same hash present: reported, not fetched again
        self.assertTrue(d2["ok"])
        self.assertNotIn("/blob/oneqnode_0.0.2_amd64.deb", self.m.hits[n:])

    def test_hash_mismatch_deletes(self):
        self.m.sums = f"{'0' * 64}  oneqrelay_0.0.2_amd64.deb\n"
        r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
        d = U.download(r, self.d, self.m.url)
        self.assertFalse(d["ok"])
        self.assertIn("SHA-256", d["error"])
        self.assertEqual(os.listdir(self.d), [])

    def test_mismatch_keeps_old_file(self):
        old = os.path.join(self.d, "oneqrelay_0.0.2_amd64.deb")
        open(old, "wb").write(b"old")
        self.m.sums = f"{'0' * 64}  oneqrelay_0.0.2_amd64.deb\n"
        r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
        self.assertFalse(U.download(r, self.d, self.m.url)["ok"])
        self.assertEqual(open(old, "rb").read(), b"old")                            # replaced only after verification
        self.assertEqual(os.listdir(self.d), ["oneqrelay_0.0.2_amd64.deb"])

    def test_missing_entry_or_sums(self):
        r = U.check("0.0.1", "relay", self.m.url, server_pkg=True)                  # oneq-server deb has no sums line
        d = U.download(r, self.d, self.m.url)
        self.assertFalse(d["ok"])
        self.assertEqual(os.listdir(self.d), [])
        self.m.no_sums = True
        r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
        d = U.download(r, self.d, self.m.url)
        self.assertFalse(d["ok"])
        self.assertEqual(os.listdir(self.d), [])

    def test_size_cap_deletes(self):
        old = U.MAX_DOWNLOAD
        U.MAX_DOWNLOAD = 1000
        try:
            r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
            d = U.download(r, self.d, self.m.url)
        finally:
            U.MAX_DOWNLOAD = old
        self.assertFalse(d["ok"])
        self.assertIn("large", d["error"])
        self.assertEqual(os.listdir(self.d), [])

    def test_api_size_cap(self):
        old = U.MAX_API
        U.MAX_API = 100
        try:
            r = U.check("0.0.1", "relay", self.m.url)
        finally:
            U.MAX_API = old
        self.assertEqual(r["status"], "error")
        self.assertIn("large", r["error"])

    def test_bad_asset_names_refused(self):
        for n in ("../x.deb", "a/b.deb", "", ".hidden", "a b", "x\\y"):
            d = U.download({"asset": {"name": n, "size": 1, "download_url": "https://github.com/x"}}, self.d, self.m.url)
            self.assertFalse(d["ok"], n)
        self.assertFalse(U.download({"asset": None}, self.d, self.m.url)["ok"])
        self.assertFalse(U.download(None, self.d, self.m.url)["ok"])
        self.assertEqual(os.listdir(self.d), [])

    def test_unknown_file_not_in_release(self):
        d = U.download({"asset": {"name": "other.deb"}}, self.d, self.m.url)
        self.assertFalse(d["ok"])

    def test_redirect_to_foreign_host_refused(self):
        self.m.redirect["/blob/oneqrelay_0.0.2_amd64.deb"] = "https://evil.example.com/x"
        r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
        d = U.download(r, self.d, self.m.url)
        self.assertFalse(d["ok"])
        self.assertIn("refused", d["error"])
        self.assertEqual(os.listdir(self.d), [])
        self.m.redirect["/rel"] = "http://127.0.0.1:1/x"
        self.assertEqual(U.check("0.0.1", "relay", self.m.url)["status"], "error")

    def test_redirect_limit_and_relative_redirect(self):
        for i in range(8):
            self.m.redirect[f"/r{i}"] = f"/r{i + 1}"
        f = U.Fetcher(self.m.url)
        with self.assertRaises(U.UpdateError) as e:
            f.read(self.m.base + "/r0", 100)
        self.assertIn("redirects", str(e.exception))
        self.m.redirect["/a"] = "/sums"
        self.assertIn(b"oneqrelay", U.Fetcher(self.m.url).read(self.m.base + "/a", 4096))

    def test_one_download_at_a_time(self):
        self.assertTrue(U._dl_lock.acquire(blocking=False))
        try:
            r = U.check("0.0.1", "relay", self.m.url, server_pkg=False)
            self.assertIn("in progress", U.download(r, self.d, self.m.url)["error"])
        finally:
            U._dl_lock.release()

    def test_checker_cache_and_manual_rate(self):
        c = U.Checker("0.0.1", "node", self.m.url)
        c.get()
        n = len(self.m.hits)
        c.get()
        self.assertEqual(len(self.m.hits), n)               # cached
        c.get(force=True)
        self.assertGreater(len(self.m.hits), n)             # manual bypasses the cache
        n = len(self.m.hits)
        c.get(force=True)
        self.assertEqual(len(self.m.hits), n)               # but not twice within 60 s

    def test_async_wrappers_and_loop(self):
        async def go():
            c = U.Checker("0.0.1", "node", self.m.url)
            r = await c.aget(force=True)
            self.assertEqual(r["status"], "newer")
            d = await c.adownload(self.d)
            self.assertTrue(d["ok"], d)
            lines = []

            class L:
                def info(self, *a):
                    lines.append(a[0] % a[1:])

                def debug(self, *a):
                    pass
            c2 = U.Checker("0.0.1", "node", self.m.url)
            t = asyncio.ensure_future(c2.loop(L(), first_delay=0.01, interval=0.05))
            await asyncio.sleep(0.5)
            t.cancel()
            self.assertEqual(len(lines), 1)                 # one line per new version
            self.assertIn("0.0.2", lines[0])
        asyncio.run(go())


class TestNodeCli(unittest.TestCase):
    def test_update_check_and_download_commands(self):
        try:
            import oneqnode
        except ImportError:
            raise unittest.SkipTest("oneqnode needs fcntl/aiohttp")
        import contextlib
        import io
        m = Mock()
        d = tempfile.mkdtemp()
        orig = U.server_package_installed
        try:
            for argv, key in ((["update-check", "--url", m.url], "status"), (["update-download", "--url", m.url, "--dir", d], "ok")):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(oneqnode.main(argv), 0)
                res = json.loads(out.getvalue())
                self.assertEqual(res[key], "newer" if key == "status" else True, res)
            self.assertEqual(os.listdir(d), ["oneqnode_0.0.2_amd64.deb"])
            m.api_status = 500                       # a failing network still exits 0
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(oneqnode.main(["update-check", "--url", m.url]), 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "error")
        finally:
            U.server_package_installed = orig
            m.close()
            shutil.rmtree(d, ignore_errors=True)


class TestTls(unittest.TestCase):
    """The process runs with the PQ-only OPENSSL_CONF (pqtls); the update fetch must still work against a classical server."""

    @classmethod
    def setUpClass(cls):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
            import datetime
        except ImportError:
            raise unittest.SkipTest("cryptography not available")
        cls.dir = tempfile.mkdtemp()
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        cls.crt, cls.key = os.path.join(cls.dir, "c.pem"), os.path.join(cls.dir, "k.pem")
        open(cls.crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(cls.key, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_check_and_download_over_classical_tls(self):
        self.assertTrue(os.environ["OPENSSL_CONF"].endswith("pq_openssl.cnf"))
        m = Mock(tls=(self.crt, self.key))
        d = tempfile.mkdtemp()
        try:
            r = U.check("0.0.1", "node", m.url, cafile=self.crt, server_pkg=False)
            self.assertEqual(r["status"], "newer", r)
            res = U.download(r, d, m.url, cafile=self.crt)
            self.assertTrue(res["ok"], res)
        finally:
            m.close()
            shutil.rmtree(d, ignore_errors=True)

    def test_untrusted_certificate_refused(self):
        m = Mock(tls=(self.crt, self.key))
        try:
            r = U.check("0.0.1", "node", m.url)              # system CA store does not know the test CA
            self.assertEqual(r["status"], "error")
        finally:
            m.close()

    def test_plain_pq_context_would_fail(self):
        """Control: the unmodified pqtls context cannot talk to a classical server, so the override in _tls_context is what makes it work.

        Only meaningful on OpenSSL >= 3.3 where X25519MLKEM768 is actually supported; on older builds the group is
        silently ignored and both sides fall back to classical X25519, so the failure cannot be provoked."""
        if ssl.OPENSSL_VERSION_INFO < (3, 3, 0):
            self.skipTest("OpenSSL < 3.3 does not support X25519MLKEM768; PQ-only restriction is inactive")
        m = Mock(tls=(self.crt, self.key))
        try:
            ctx = pqtls.client_context(self.crt)
            import http.client
            c = http.client.HTTPSConnection("localhost", m.port, timeout=5, context=ctx)
            with self.assertRaises((ssl.SSLError, OSError)):
                c.connect()
        finally:
            m.close()


if __name__ == "__main__":
    unittest.main()
