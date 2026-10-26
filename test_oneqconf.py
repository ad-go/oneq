#!/usr/bin/env python3
"""Tests for the configuration files (/etc/oneq/relay.conf, /etc/oneq/node.conf)."""
import pqtls  # noqa: F401

import argparse
import os
import stat
import tempfile
import unittest
from unittest import mock

import oneqconf
import oneqnode
import oneqrelay


def write(text, mode=0o640):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "x.conf")
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(p, mode)
    return p


def silent_parser():
    p = argparse.ArgumentParser()
    p.error = lambda msg: (_ for _ in ()).throw(SystemExit(msg))      # raise instead of printing usage
    return p


class TestLoad(unittest.TestCase):
    def test_sections_merge_and_dashes(self):
        p = write("[defaults]\nrelay-after = 5\ncafile = /ca.pem\n\n[lan]\ncafile = /other.pem\ncommunity = lan\n")
        c = oneqconf.load(p, ["defaults", "lan"], oneqnode.NODE_KEYS)
        self.assertEqual(c, {"relay_after": "5", "cafile": "/other.pem", "community": "lan"})

    def test_comments_blank_lines_and_missing_section(self):
        p = write("# a comment\n; another\n\n[relay]\n# listen = 1.2.3.4:5\nlisten = 127.0.0.1:8080\n")
        self.assertEqual(oneqconf.load(p, ["relay"], oneqrelay.RELAY_KEYS), {"listen": "127.0.0.1:8080"})
        self.assertEqual(oneqconf.load(p, ["nothing"], oneqrelay.RELAY_KEYS), {})

    def test_unknown_option_is_an_error_naming_it(self):
        p = write("[relay]\nlisten = 127.0.0.1:8080\nlisen = typo\n")
        with self.assertRaises(oneqconf.ConfigError) as cm:
            oneqconf.load(p, ["relay"], oneqrelay.RELAY_KEYS)
        self.assertIn("lisen", str(cm.exception))

    def test_unreadable_and_malformed(self):
        with self.assertRaises(oneqconf.ConfigError):
            oneqconf.load("/nonexistent/x.conf", ["relay"], set())
        with self.assertRaises(oneqconf.ConfigError):
            oneqconf.load(write("not an ini file\n"), ["relay"], set())
        with self.assertRaises(oneqconf.ConfigError):
            oneqconf.load(write("[relay]\nlisten = a\nlisten = b\n"), ["relay"], oneqrelay.RELAY_KEYS)   # duplicates

    def test_converters(self):
        self.assertEqual([oneqconf.to_bool(v) for v in ("yes", "TRUE", "on", "1")], [True] * 4)
        self.assertEqual([oneqconf.to_bool(v) for v in ("no", "False", "off", "0")], [False] * 4)
        with self.assertRaises(oneqconf.ConfigError):
            oneqconf.to_bool("maybe", "k")
        self.assertEqual(oneqconf.to_list("a, b  c\n d"), ["a", "b", "c", "d"])
        self.assertEqual(oneqconf.to_list(""), [])
        self.assertEqual(oneqconf.to_float("2.5"), 2.5)
        with self.assertRaises(oneqconf.ConfigError):
            oneqconf.to_float("fast")


class TestRelayResolve(unittest.TestCase):
    def ns(self, **kw):
        base = dict(config=None, id=None, db=None, secret_file=None, listen=None, cert=None, key=None,
                    insecure_http=False, trust_proxy=False, fed_peer=[], cafile=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_file_values_are_applied(self):
        p = write("[relay]\nid = r1\ndb = /var/lib/oneq/relay/registry.db\nsecret_file = /etc/oneq/relay.secret\n"
                  "listen = 127.0.0.1:8080\ninsecure_http = yes\ntrust_proxy = yes\n"
                  "federation_peers = https://r2.example.org, https://r3.example.org\ncafile = /ca.pem\n")
        a = self.ns(config=p)
        oneqrelay.resolve(a, silent_parser(), run=True)
        self.assertEqual((a.id, a.db, a.listen, a.insecure_http, a.trust_proxy, a.cafile),
                         ("r1", "/var/lib/oneq/relay/registry.db", "127.0.0.1:8080", True, True, "/ca.pem"))
        self.assertEqual(a.fed_peer, ["https://r2.example.org", "https://r3.example.org"])

    def test_update_options(self):
        p = write("[relay]\nid = r1\ndb = /a.db\nsecret_file = /s\nupdate_check = no\nupdate_url = https://example.org/rel\nupdate_dir = /u\n")
        a = self.ns(config=p, no_update_check=False, update_url=None, update_dir=None)
        oneqrelay.resolve(a, silent_parser(), run=True)
        self.assertEqual((a.no_update_check, a.update_url, a.update_dir), (True, "https://example.org/rel", "/u"))
        a = self.ns(config=write("[relay]\nid = r1\ndb = /a.db\nsecret_file = /s\n"), no_update_check=False, update_url=None, update_dir=None)
        oneqrelay.resolve(a, silent_parser(), run=True)
        self.assertFalse(a.no_update_check)                      # default: on

    def test_command_line_overrides_the_file(self):
        p = write("[relay]\nid = r1\ndb = /a.db\nsecret_file = /s\nlisten = 127.0.0.1:8080\nfederation_peers = https://x\n")
        a = self.ns(config=p, listen="0.0.0.0:9999", fed_peer=["https://cli"])
        oneqrelay.resolve(a, silent_parser(), run=True)
        self.assertEqual((a.listen, a.fed_peer, a.id), ("0.0.0.0:9999", ["https://cli"], "r1"))

    def test_defaults_and_requirements(self):
        with mock.patch("socket.gethostname", return_value="relay-host.example.org"):
            a = self.ns(db="/d.db", secret_file="/s")
            oneqrelay.resolve(a, silent_parser(), run=True)
            self.assertEqual((a.id, a.listen), ("relay-host", "0.0.0.0:8443"))
        with self.assertRaises(SystemExit) as cm:
            oneqrelay.resolve(self.ns(secret_file="/s"), silent_parser(), run=True)
        self.assertIn("database", str(cm.exception))
        with self.assertRaises(SystemExit) as cm:
            oneqrelay.resolve(self.ns(db="/d"), silent_parser(), run=True)
        self.assertIn("secret", str(cm.exception))

    def test_bad_value_and_unknown_key_stop_startup(self):
        for text in ("[relay]\ninsecure_http = sometimes\ndb=/d\nsecret_file=/s\n", "[relay]\nbogus = 1\n"):
            with self.assertRaises(SystemExit):
                oneqrelay.resolve(self.ns(config=write(text)), silent_parser(), run=True)

    def test_admin_only_needs_the_three_paths(self):
        p = write("[relay]\nid = r9\ndb = /d.db\nsecret_file = /s\nlisten = 1.2.3.4:1\n")
        a = self.ns(config=p)
        oneqrelay.resolve(a, silent_parser(), run=False)
        self.assertEqual((a.id, a.db, a.secret_file), ("r9", "/d.db", "/s"))
        self.assertIsNone(a.listen)


class TestNodeResolve(unittest.TestCase):
    CONF = ("[defaults]\ncafile = /etc/ssl/ca.pem\nrelay_after = 7\n\n"
            "[lan]\nrelays = https://r1.example.org https://r2.example.org\ncommunity = lan\nuser = alice\n"
            "label = laptop\nkey_file = /etc/oneq/node-lan.key\npassword_file = /etc/oneq/node-lan.password\n"
            "listen = 0.0.0.0:51820\nadvertise = 203.0.113.5:51820\n\n"
            "[other]\nrelays = https://r9\ncommunity = c\nuser = u\nkey_file = /k\nconfigure_interface = no\n"
            "force_relay = yes\n")

    def ns(self, **kw):
        base = dict(config=None, node=None, key=None, relay=[], community=None, user=None, password_file=None,
                    name=None, ifname=None, listen=None, via=None, advertise=[], stun=None, cafile=None,
                    force_relay=False, no_relay=False, relay_after=None, no_config=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_update_options(self):
        a = self.ns(config=write("[lan]\nrelays = https://r\ncommunity = c\nuser = u\nkey_file = /k\nupdate_check = no\nupdate_url = https://e.org/r\n"),
                    node="lan", no_update_check=False, update_url=None)
        oneqnode.resolve(a, silent_parser())
        self.assertEqual((a.no_update_check, a.update_url), (True, "https://e.org/r"))

    def test_node_section_over_defaults_and_interface_name(self):
        a = self.ns(config=write(self.CONF), node="lan")
        oneqnode.resolve(a, silent_parser())
        self.assertEqual((a.relay, a.community, a.user, a.name), (["https://r1.example.org", "https://r2.example.org"],
                                                                  "lan", "alice", "laptop"))
        self.assertEqual((a.ifname, a.listen, a.relay_after, a.cafile), ("oneq-lan", "0.0.0.0:51820", 7.0, "/etc/ssl/ca.pem"))
        self.assertEqual(a.advertise, ["203.0.113.5:51820"])
        self.assertFalse(a.no_config)

    def test_booleans_and_inverse_option(self):
        a = self.ns(config=write(self.CONF), node="other")
        oneqnode.resolve(a, silent_parser())
        self.assertTrue(a.no_config and a.force_relay)

    def test_command_line_overrides_and_sections_are_isolated(self):
        a = self.ns(config=write(self.CONF), node="lan", community="cli", ifname="mytap", relay=["https://cli"])
        oneqnode.resolve(a, silent_parser())
        self.assertEqual((a.community, a.ifname, a.relay), ("cli", "mytap", ["https://cli"]))
        self.assertEqual(a.user, "alice")
        with self.assertRaises(SystemExit) as cm:
            oneqnode.resolve(self.ns(config=write(self.CONF), node="missing"), silent_parser())
        self.assertIn("missing", str(cm.exception))

    def test_requirements(self):
        with self.assertRaises(SystemExit):
            oneqnode.resolve(self.ns(), silent_parser())                            # nothing at all
        with self.assertRaises(SystemExit):
            oneqnode.resolve(self.ns(node="lan"), silent_parser())                  # --node without --config
        a = self.ns(key="/k", relay=["https://r"], community="c", user="u")        # plain command line still works
        oneqnode.resolve(a, silent_parser())
        self.assertEqual((a.ifname, a.listen, a.relay_after, a.name), ("oneq0", "0.0.0.0:0", 10.0, ""))


class TestEditing(unittest.TestCase):
    def test_set_section_preserves_everything_else(self):
        p = write("# my notes\n[defaults]\ncafile = /ca.pem\n\n[old]\ncommunity = o\n\n# trailing comment\n", mode=0o640)
        oneqconf.set_section(p, "lan", {"relays": "https://r1", "community": "lan"})
        text = open(p, encoding="utf-8").read()
        self.assertIn("# my notes", text)
        self.assertIn("# trailing comment", text)
        self.assertEqual(oneqconf.load(p, ["lan"], oneqnode.NODE_KEYS), {"relays": "https://r1", "community": "lan"})
        self.assertEqual(oneqconf.load(p, ["old"], oneqnode.NODE_KEYS), {"community": "o"})
        self.assertEqual(oneqconf.load(p, ["defaults"], oneqnode.NODE_KEYS), {"cafile": "/ca.pem"})
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o640)

    def test_set_section_replaces_instead_of_duplicating(self):
        p = write("[lan]\nuser = a\ncommunity = c1\n\n[other]\nuser = z\n")
        oneqconf.set_section(p, "lan", {"user": "b"})
        oneqconf.set_section(p, "lan", {"user": "c", "community": "c2"})
        self.assertEqual(open(p, encoding="utf-8").read().count("[lan]"), 1)
        self.assertEqual(oneqconf.load(p, ["lan"], oneqnode.NODE_KEYS), {"user": "c", "community": "c2"})
        self.assertEqual(oneqconf.load(p, ["other"], oneqnode.NODE_KEYS), {"user": "z"})

    def test_new_file_and_deletion(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "node.conf")
        oneqconf.set_section(p, "a", {"user": "u"})
        oneqconf.set_section(p, "b", {"user": "v"})
        self.assertTrue(oneqconf.del_section(p, "a"))
        self.assertFalse(oneqconf.del_section(p, "a"))
        self.assertFalse(oneqconf.del_section(os.path.join(d, "none.conf"), "a"))
        self.assertEqual(oneqconf.load(p, ["a", "b"], oneqnode.NODE_KEYS), {"user": "v"})
        self.assertEqual(os.listdir(d), ["node.conf"])                             # no temp files left behind

    def test_bad_section_names_rejected(self):
        for name in ("a b", "[x]", "", "x" * 80, "a\nb"):
            with self.assertRaises(oneqconf.ConfigError):
                oneqconf.set_section(write(""), name, {"user": "u"})

    def test_cli_config_set_and_del(self):
        p = write("[defaults]\ncafile = /ca.pem\n")
        self.assertEqual(oneqnode.main(["config-set", "--file", p, "lan", "relays=https://r1 https://r2",
                                       "community=lan", "user=alice", "advertise=203.0.113.5:51820"]), 0)
        c = oneqconf.load(p, ["defaults", "lan"], oneqnode.NODE_KEYS)
        self.assertEqual((c["community"], c["cafile"]), ("lan", "/ca.pem"))
        with self.assertRaises(SystemExit):
            oneqnode.main(["config-set", "--file", p, "lan", "bogus=1"])            # unknown option refused
        with self.assertRaises(SystemExit):
            oneqnode.main(["config-set", "--file", p, "lan", "no-equals-sign"])
        self.assertEqual(oneqnode.main(["config-del", "--file", p, "lan"]), 0)
        self.assertFalse(oneqconf.has_section(p, "lan"))


class TestShippedDefaults(unittest.TestCase):
    """The default files that the packages install must parse and pass the same checks."""

    def test_packaged_relay_conf(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packaging", "oneqrelay", "etc", "oneq", "relay.conf")
        if not os.path.exists(path):
            self.skipTest("packaging tree not present")
        a = argparse.Namespace(config=path, id=None, db=None, secret_file=None, listen=None, cert=None, key=None,
                               insecure_http=False, trust_proxy=False, fed_peer=[], cafile=None)
        oneqrelay.resolve(a, silent_parser(), run=True)
        self.assertEqual((a.db, a.secret_file, a.listen, a.insecure_http), ("/var/lib/oneq/relay/registry.db",
                                                                              "/etc/oneq/relay.secret", "127.0.0.1:8080", True))

    def test_packaged_node_conf(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packaging", "oneqnode", "etc", "oneq", "node.conf")
        if not os.path.exists(path):
            self.skipTest("packaging tree not present")
        self.assertEqual(oneqconf.load(path, ["defaults"], oneqnode.NODE_KEYS), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
