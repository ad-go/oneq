"""`oneqrelay init`: the directory it creates is complete, consistent and loadable by `oneqrelay run --config`."""
import json
import os
import tempfile
import unittest

import pqtls  # noqa: F401  (before ssl)
import oneqconf
import oneqinit
import oneqrelay
import oneqtotp


class InitTest(unittest.TestCase):
    def setUp(self):
        self.d = os.path.join(tempfile.mkdtemp(), "relay")
        self.out = []
        self.res = oneqinit.init(self.d, "relay.example.org", ["203.0.113.7"], 9443, out=self.out.append)

    def test_files_and_modes(self):
        for n in ("ca.crt", "ca.key", "relay.crt", "relay.key", "relay.secret", "admin.pw", "admin.totp", "admin-enrolment.txt", "relay.conf"):
            self.assertTrue(os.path.exists(os.path.join(self.d, n)), n)
        if os.name == "posix":
            for n in ("ca.key", "relay.key", "relay.secret", "admin.pw", "admin.totp", "admin-enrolment.txt"):
                self.assertEqual(os.stat(os.path.join(self.d, n)).st_mode & 0o077, 0, n)
            self.assertEqual(os.stat(self.d).st_mode & 0o077, 0)

    def test_certificate_is_signed_by_the_generated_ca_and_names_the_host(self):
        from cryptography import x509
        ca = x509.load_pem_x509_certificate(open(os.path.join(self.d, "ca.crt"), "rb").read())
        leaf = x509.load_pem_x509_certificate(open(os.path.join(self.d, "relay.crt"), "rb").read())
        leaf.verify_directly_issued_by(ca)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("relay.example.org", san.get_values_for_type(x509.DNSName))
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
        self.assertIn("203.0.113.7", [str(i) for i in san.get_values_for_type(x509.IPAddress)])
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)

    def test_relay_conf_is_accepted_by_the_relay(self):
        conf = oneqconf.load(os.path.join(self.d, "relay.conf"), ["relay"], oneqrelay.RELAY_KEYS)
        self.assertEqual(conf["listen"], "0.0.0.0:9443")
        self.assertEqual(conf["insecure_http"], "no")
        for k in ("cert", "key", "db", "secret_file", "admin_password_file", "admin_totp_file"):
            self.assertTrue(conf[k].replace("\\", "/").startswith(self.d.replace("\\", "/")), k)
        self.assertEqual(len(oneqrelay.load_secret(conf["secret_file"])), 32)
        self.assertGreaterEqual(len(oneqrelay.load_admin_password(conf["admin_password_file"])), 12)
        oneqtotp.TotpStore(conf["admin_totp_file"]).ensure_writable()
        import pqtls as q
        q.server_context(conf["cert"], conf["key"])        # the certificate and key load into the PQ-only TLS context

    def test_enrolment_file_has_what_the_operator_needs(self):
        text = open(self.res["enrolment"]).read()
        self.assertIn("https://relay.example.org:9443/admin/", text)
        self.assertIn("otpauth://totp/", text)
        self.assertGreaterEqual(sum(1 for l in text.splitlines() if len(l.strip()) == 11 and l.strip()[5] == "-"), 10)

    def test_second_init_refuses_and_changes_nothing(self):
        before = open(os.path.join(self.d, "relay.secret")).read()
        with self.assertRaises(SystemExit):
            oneqinit.init(self.d, "other.example.org", [], out=lambda *_: None)
        self.assertEqual(open(os.path.join(self.d, "relay.secret")).read(), before)

    def test_no_admin_leaves_the_page_off(self):
        d = os.path.join(tempfile.mkdtemp(), "r2")
        oneqinit.init(d, "h.example.org", [], admin=False, out=lambda *_: None)
        conf = oneqconf.load(os.path.join(d, "relay.conf"), ["relay"], oneqrelay.RELAY_KEYS)
        self.assertNotIn("admin_password_file", conf)
        self.assertFalse(os.path.exists(os.path.join(d, "admin.pw")))


if __name__ == "__main__":
    unittest.main()
