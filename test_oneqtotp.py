#!/usr/bin/env python3
"""Second factor of the admin page: TOTP against the RFC 6238 test vectors, replay protection, recovery codes, the login flow with an
authenticator code, the address allow-list, and the refusal to start the admin page unprotected."""
import pqtls  # noqa: F401

import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit

import oneqadmin
import oneqrelay as sn
import oneqtotp as tp
from test_oneqadmin import ADMIN_PW, AdminFed

HERE = os.path.dirname(os.path.abspath(__file__))
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")      # the SHA-1 test secret of RFC 6238, appendix B


class TestTotp(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # (time, 8-digit code from the RFC); the 6 digit code is its last six digits
        for t, code8 in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"),
                         (2000000000, "69279037"), (20000000000, "65353130")):
            self.assertEqual(tp.hotp(RFC_SECRET, t // 30, 8), code8, t)
            self.assertEqual(tp.totp_now(RFC_SECRET, t), code8[2:], t)

    def test_window_and_replay(self):
        t = 1_700_000_000.0
        step = int(t // 30)
        cur = tp.totp_now(RFC_SECRET, t)
        self.assertEqual(tp.match(RFC_SECRET, cur, t), step)
        self.assertEqual(tp.match(RFC_SECRET, tp.totp_now(RFC_SECRET, t - 30), t), step - 1)     # slightly slow clock
        self.assertEqual(tp.match(RFC_SECRET, tp.totp_now(RFC_SECRET, t + 30), t), step + 1)     # slightly fast clock
        self.assertIsNone(tp.match(RFC_SECRET, tp.totp_now(RFC_SECRET, t + 120), t))              # too far away
        self.assertIsNone(tp.match(RFC_SECRET, cur, t, last=step))                                # the same step cannot be used twice
        self.assertEqual(tp.match(RFC_SECRET, f"{cur[:3]} {cur[3:]}", t), step)                   # apps show "123 456"
        for bad in ("", "12345", "1234567", "abcdef", "000000" if cur != "000000" else "111111"):
            self.assertIsNone(tp.match(RFC_SECRET, bad, t))

    def test_provisioning_uri_is_what_authenticator_apps_expect(self):
        secret = tp.new_secret()
        self.assertEqual((len(secret), "=" in secret), (32, False))
        base64.b32decode(secret)                                                                  # valid base32
        u = urlsplit(tp.otpauth_uri(secret, "admin", "oneqrelay x"))
        q = parse_qs(u.query)
        self.assertEqual((u.scheme, u.netloc, u.path), ("otpauth", "totp", "/oneqrelay%20x%3Aadmin"))
        self.assertEqual((q["secret"], q["issuer"], q["algorithm"], q["digits"], q["period"]),
                         ([secret], ["oneqrelay x"], ["SHA1"], ["6"], ["30"]))

    def test_store_file_recovery_codes_and_replay(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "totp.json")
        secret, codes = tp.TotpStore.create(path)
        self.assertEqual((len(codes), stat.S_IMODE(os.stat(path).st_mode)), (10, 0o600))
        self.assertNotIn(codes[0].replace("-", ""), open(path).read())                            # only hashes are stored
        with self.assertRaises(FileExistsError):
            tp.TotpStore.create(path)
        st = tp.TotpStore(path)
        t = time.time()
        code = tp.totp_now(secret, t)
        self.assertTrue(st.check(code, t))
        self.assertFalse(st.check(code, t), "the same code twice")
        self.assertFalse(tp.TotpStore(path).check(code, t), "and not after a restart either")
        self.assertTrue(tp.TotpStore(path).check(tp.totp_now(secret, t + 30), t + 30), "the next step is fine")
        self.assertFalse(st.check("123456", t))
        # recovery codes: any case, with or without the dash, once
        rc = codes[3]
        self.assertTrue(st.check(rc.upper(), t))
        self.assertFalse(st.check(rc, t))
        self.assertFalse(tp.TotpStore(path).check(rc, t))
        self.assertTrue(st.check(codes[4].replace("-", " "), t))
        self.assertEqual(len(json.load(open(path))["recovery"]), 8)
        self.assertFalse(st.check("0000-0000-00", t) or st.check("zzzzz-zzzzz", t))
        # the file must be private, and a damaged secret is refused
        os.chmod(path, 0o644)
        with self.assertRaises(SystemExit):
            tp.TotpStore(path)
        os.chmod(path, 0o600)
        json.dump({"secret": "not base32 !!"}, open(path, "w"))
        with self.assertRaises(Exception):
            tp.TotpStore(path)

    def test_the_service_refuses_to_start_when_it_could_not_save_the_state(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "totp.json")
        tp.TotpStore.create(path)
        st = tp.TotpStore(path)
        st.ensure_writable()                                    # fine
        os.chmod(d, 0o500)
        os.chmod(path, 0o400)
        try:
            if os.access(path, os.W_OK):
                self.skipTest("running as root: permissions do not apply")
            with self.assertRaises(SystemExit) as cm:
                st.ensure_writable()
            self.assertIn("/var/lib/oneq/relay", str(cm.exception))
        finally:
            os.chmod(d, 0o700)
            os.chmod(path, 0o600)

    def test_state_is_saved_in_place_when_the_directory_is_not_writable_and_refused_when_the_file_is_not_either(self):
        # /etc/oneq is root's: the service user owns only the file (this was found on the real relays)
        d = tempfile.mkdtemp()
        path = os.path.join(d, "totp.json")
        secret, codes = tp.TotpStore.create(path)
        st = tp.TotpStore(path)
        os.chmod(d, 0o500)                                     # the directory is no longer writable
        try:
            if os.access(d, os.W_OK):
                self.skipTest("running as root: permissions do not apply")
            t = time.time()
            self.assertTrue(st.check(tp.totp_now(secret, t), t))
            self.assertFalse(tp.TotpStore(path).check(tp.totp_now(secret, t), t), "consumed on disk, not only in memory")
            self.assertTrue(st.check(codes[0], t))
            self.assertEqual(len(json.load(open(path))["recovery"]), 9)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            # the file itself cannot be written: the code must not count
            os.chmod(path, 0o400)
            other = tp.totp_now(secret, t + 30)
            self.assertFalse(st.check(other, t + 30))
            self.assertEqual(st.last, int(t // 30))
            self.assertFalse(st.check(codes[1], t))
            self.assertEqual(len(st.recovery), 9)
        finally:
            os.chmod(d, 0o700)


class TwoFactorFed(AdminFed):
    """The admin page of relay 0 with a second factor."""
    N = 2

    async def start(self, i, fresh=False):
        node = await super().start(i, fresh)
        if i == 0:
            d = tempfile.mkdtemp()
            self.tpath = os.path.join(d, "totp.json")
            self.secret, self.recovery = tp.TotpStore.create(self.tpath)
            node.admin.totp = tp.TotpStore(self.tpath)
        return node

    async def login_with(self, pw, code):
        return await self.a("POST", "/login", {"password": pw, "code": code})


class TestAdminLoginWithAuthenticator(TwoFactorFed):
    async def test_info_tells_the_form_to_ask_for_a_code(self):
        st, d = await self.a("GET", "/info")
        self.assertEqual((st, d), (200, {"two_factor": True}))
        self.nodes[0].admin.totp = None
        self.assertEqual((await self.a("GET", "/info"))[1], {"two_factor": False})

    async def test_both_factors_are_needed_and_a_code_works_once(self):
        t = time.time()
        code = tp.totp_now(self.secret, t)
        self.assertEqual((await self.login_with(ADMIN_PW, ""))[0], 401)                 # password alone
        self.assertEqual((await self.a("POST", "/login", {"password": ADMIN_PW}))[0], 401)
        self.assertEqual((await self.login_with("wrong-wrong-wrong", code))[0], 401)    # code alone
        # a wrong password must not burn the code
        st, body = await self.login_with(ADMIN_PW, code)
        self.assertEqual(st, 200, body)
        tok = body["token"]
        self.assertEqual((await self.a("GET", "/overview", tok=tok))[0], 200)
        self.assertEqual((await self.login_with(ADMIN_PW, code))[0], 401)               # replay of the same code
        # both failures read the same: nobody learns which factor was right
        s1, m1 = await self.login_with("wrong-wrong-wrong", code)
        s2, m2 = await self.login_with(ADMIN_PW, "000000")
        self.assertEqual((s1, s2, m1), (401, 401, m2))

    async def test_recovery_code_logs_in_once(self):
        rc = self.recovery[0]
        st, body = await self.login_with(ADMIN_PW, rc)
        self.assertEqual(st, 200, body)
        self.assertEqual((await self.login_with(ADMIN_PW, rc))[0], 401)

    async def test_wrong_codes_lock_the_account_out_like_wrong_passwords(self):
        for _ in range(sn.LOGIN_MAX_FAILS):
            await self.login_with(ADMIN_PW, "000000")
        st, body = await self.login_with(ADMIN_PW, tp.totp_now(self.secret))
        self.assertEqual(st, 429, body)                                                  # even the right pair is refused while locked

    async def test_the_code_is_needed_from_every_network(self):
        admin = self.nodes[0].admin
        class Req:
            pass
        for ip in ("127.0.0.1", "10.1.2.3", "::ffff:10.1.2.3", "fd12::1", "2001:db8::1", "not an ip", ""):
            admin.relay.client_ip = lambda request, ip=ip: ip
            self.assertTrue(admin.needs_code(Req()), ip)
        self.assertEqual((await self.a("GET", "/info"))[1], {"two_factor": True})
        self.assertEqual((await self.login_with(ADMIN_PW, ""))[0], 401)

    async def test_login_without_a_configured_second_factor_still_works_for_tests_and_internal_use(self):
        self.nodes[0].admin.totp = None
        self.assertEqual((await self.a("POST", "/login", {"password": ADMIN_PW}))[0], 200)


class TestAdminAddressAllowList(AdminFed):
    N = 1

    async def test_only_listed_networks_see_the_page(self):
        admin = self.nodes[0].admin
        admin.allow = [__import__("ipaddress").ip_network("127.0.0.0/8")]
        self.assertEqual((await self.http.get(self.urls[0] + "/admin/")).status, 200)
        self.assertEqual((await self.a("POST", "/login", {"password": ADMIN_PW}))[0], 200)
        admin.allow = [__import__("ipaddress").ip_network("203.0.113.0/24")]               # we are 127.0.0.1: not listed
        self.assertEqual((await self.http.get(self.urls[0] + "/admin/")).status, 404)
        self.assertEqual((await self.a("GET", "/info"))[0], 404)
        self.assertEqual((await self.a("POST", "/login", {"password": ADMIN_PW}))[0], 404)
        tok = oneqadmin.make_admin_token(self.nodes[0].secret)                               # even a valid token is no use from outside
        self.assertEqual((await self.a("GET", "/overview", tok=tok))[0], 404)
        # the client API of the relay is not affected
        self.assertEqual((await self.login(0))[0], 200)


class TestCli(unittest.TestCase):
    def run_cli(self, *args, **kw):
        return subprocess.run([sys.executable, os.path.join(HERE, "oneqrelay.py"), *args], capture_output=True, text=True, **kw)

    def test_admin_totp_command_writes_a_private_file_and_shows_the_enrolment(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, "totp.json")
        enrol = os.path.join(d, "enrol.txt")
        r = self.run_cli("admin-totp", "--out", out, "--issuer", "oneqrelay test", "--save-enrolment", enrol)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(enrol).st_mode), 0o600)
        text = open(enrol).read()
        secret = json.load(open(out))["secret"]
        self.assertIn(secret, text)
        self.assertIn("otpauth://totp/oneqrelay%20test%3Aadmin?secret=" + secret, text)
        self.assertEqual(sum(1 for l in text.splitlines() if len(l.strip()) == 11 and l.strip()[5] == "-"), 10)
        self.assertNotIn(secret, r.stdout, "with --save-enrolment the secret stays out of the terminal output")
        again = self.run_cli("admin-totp", "--out", out)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(json.load(open(out))["secret"], secret, "the existing file is not overwritten")

    def test_the_admin_page_refuses_to_start_without_a_second_factor(self):
        d = tempfile.mkdtemp()
        sec, pwf = os.path.join(d, "s"), os.path.join(d, "pw")
        open(sec, "w").write(base64.b64encode(b"x" * 32).decode())
        open(pwf, "w").write("a-long-operator-password\n")
        os.chmod(sec, 0o600)
        os.chmod(pwf, 0o600)
        r = self.run_cli("run", "--db", os.path.join(d, "r.db"), "--secret-file", sec, "--insecure-http", "--listen", "127.0.0.1:0",
                         "--no-stun", "--admin-password-file", pwf, timeout=20)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("second factor", r.stderr)


if __name__ == "__main__":
    unittest.main()
