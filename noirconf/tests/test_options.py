import json
import os
import unittest

import helpers
import optforms
import ovpnconf
from tools import gen_options  # noqa: E402


class GeneratorTest(unittest.TestCase):
    DOC = """## Supported

| Option | Applies to | Arguments | Pushable | Notes |
|---|---|---|---|---|
| `port` | both | 1 |  | local and remote port |
| `remote` | client | 1-3 |  | client only |
| `bus-allow` | both | 3+ |  | map a uid, gid or SID to bus roles: bus-allow uid|gid|sid id role... |
| `ifconfig-push` | server | 2-3 |  | fixed tunnel address for one client; only valid in a client config file |
| `client-to-client` | server | 0 |  | forward traffic between clients |

## New in noirvpn

| Option | Applies to | Arguments | Pushable | Notes |
|---|---|---|---|---|
| `peer-keys` | server | 1 |  | peers file |

## Not applied yet

| Option | Applies to | Arguments | Pushable | Notes |
|---|---|---|---|---|
| `mark` | both | 1 |  | not applied yet (warning): the firewall mark is not set |
| `mlock` | both | 0 |  | not applied yet (warning): memory is not locked |

## Ignored (warning)

| Option | Applies to | Arguments | Pushable | Notes |
|---|---|---|---|---|
| `dh` | both | 1 |  | no effect |
"""

    def test_parse(self):
        rows = {r["name"]: r for r in gen_options.parse_doc(self.DOC)}
        self.assertEqual(set(rows), {"port", "bus-allow", "client-to-client", "peer-keys", "mark"})
        self.assertEqual((rows["bus-allow"]["min"], rows["bus-allow"]["max"]), (3, None))
        self.assertEqual((rows["port"]["min"], rows["port"]["max"]), (1, 1))
        self.assertEqual(rows["client-to-client"]["max"], 0)
        self.assertIn("uid|gid|sid", rows["bus-allow"]["note"])
        self.assertEqual(rows["mark"]["status"], "not_applied")
        self.assertNotIn("mlock", rows)
        self.assertEqual(rows["peer-keys"]["status"], "new")
        self.assertTrue(rows["bus-allow"]["repeat"])

    def test_checked_in_file_is_current(self):
        doc = os.path.join(helpers.ROOT, "docs", "options.md")
        if not os.path.exists(doc):
            self.skipTest("docs/options.md is not here")
        with open(doc, encoding="utf-8") as f:
            want = gen_options.build(f.read())
        with open(os.path.join(helpers.APP, "options.json"), encoding="utf-8") as f:
            have = json.load(f)
        self.assertEqual(have, want)


class OptionsTest(unittest.TestCase):
    def test_required_options_present(self):
        opts = optforms.all_options()
        for n in ("server", "port", "proto", "topology", "keepalive", "cert", "key", "ca",
                  "crl-verify", "peer-keys", "peer-keys-mode", "tls-crypt", "bus-control",
                  "bus-events", "bus-allow", "stats-interval", "client-to-client", "push", "verb"):
            self.assertIn(n, opts)
        self.assertNotIn("remote", opts)
        for gone in ("ccd-exclusive", "dev", "dev-type", "persist-tun", "bind", "tls-server", "mlock",
                     "dco-socket", "disable-dco"):
            self.assertNotIn(gone, opts)

    def test_groups(self):
        ids = [g["id"] for g in optforms.load_options()["groups"]]
        for want in ("network", "service", "identity", "tls", "datapath", "bus", "logging", "other"):
            self.assertIn(want, ids)

    def test_defaults(self):
        d = optforms.defaults("srv", "/etc/noirvpn/server")
        self.assertEqual(d["server"], [["10.8.0.0", "255.255.255.0"]])
        self.assertEqual(d["bus-control"], [["/run/noirvpn/srv.control", "mode", "0660"]])
        self.assertEqual(d["bus-events"], [["/run/noirvpn/srv.events", "mode", "0640"]])
        self.assertEqual(d["bus-allow"], [["uid", "0", "admin"]])
        self.assertEqual(d["peer-keys-mode"], [["either"]])
        self.assertEqual(d["keepalive"], [["10", "60"]])

    def test_parse_form_arity_and_flags(self):
        opts = optforms.all_options()
        v, e = optforms.parse_form({"o.client-to-client": "on", "o.keepalive": "10 60",
                                    "o.push": 'route 1.2.3.0 255.255.255.0\n\n"dhcp-option DNS 1.1.1.1"'}, opts)
        self.assertEqual(e, [])
        self.assertEqual(v["client-to-client"], [[]])
        self.assertEqual(v["push"], [["route 1.2.3.0 255.255.255.0"], ["dhcp-option DNS 1.1.1.1"]])
        v, e = optforms.parse_form({"o.keepalive": "10"}, opts)
        self.assertEqual(len(e), 1)
        v, e = optforms.parse_form({"o.keepalive": "10 60 70"}, opts)
        self.assertEqual(len(e), 1)
        v, e = optforms.parse_form({"o.port": "1\n2"}, opts)
        self.assertEqual(len(e), 1)
        v, e = optforms.parse_form({"o.port": "# only a comment"}, opts)
        self.assertEqual(len(e), 1)

    def test_form_cannot_inject_lines(self):
        opts = optforms.all_options()
        v, e = optforms.parse_form({"o.port": "1194\nup /bin/evil"}, opts)
        self.assertTrue(e)
        v, e = optforms.parse_form({"o.port": "1194\r"}, opts)
        self.assertTrue(e or v["port"] == [["1194"]])


if __name__ == "__main__":
    unittest.main()


class Round2OptionsTest(unittest.TestCase):
    def setUp(self):
        self.data = optforms.load_options()
        self.opts = optforms.all_options()

    def group(self, gid):
        return [o["name"] for g in self.data["groups"] if g["id"] == gid for o in g["options"]]

    def test_group_names_and_order(self):
        ids = [g["id"] for g in self.data["groups"]]
        self.assertEqual(ids[:3], ["network", "service", "identity"])
        titles = {g["id"]: g["title"] for g in self.data["groups"]}
        self.assertEqual(titles["service"], "Service")
        self.assertEqual(self.group("network")[:2], ["server", "server-ipv6"])
        self.assertEqual(self.group("service")[:2], ["port", "proto"])
        self.assertEqual(self.group("datapath")[:2], ["datapath", "workers"])

    def test_labels_and_defaults(self):
        for o in self.opts.values():
            self.assertTrue(o["label"], o["name"])
        self.assertEqual(self.opts["port"]["default"], "1194")
        self.assertEqual(self.opts["max-clients"]["default"], "1024")
        self.assertIsNone(self.opts["keepalive"]["default"])
        self.assertEqual(self.opts["server"]["label"], "IPv4 tunnel network")

    def test_tls_block_options(self):
        block = sorted(n for n, o in self.opts.items() if o["block"] == "tls")
        self.assertEqual(block, sorted(n for n in self.opts if n.startswith("tls-transport-")))
        self.assertIn("tls-transport-ws", block)

    def test_verb_choices(self):
        vals = [c[0] for c in self.opts["verb"]["choices"]]
        self.assertEqual(vals, ["", "0", "1", "2", "3", "4"])
        v, e = optforms.parse_form({"o.verb": ""}, self.opts)
        self.assertEqual((v, e), ({}, []))
        v, e = optforms.parse_form({"o.verb": "3"}, self.opts)
        self.assertEqual(v["verb"], [["3"]])

    def test_new_config_writes_dev_tun(self):
        vals = optforms.defaults("srv", "/etc/x")
        text = optforms.new_config(vals).render()
        self.assertIn("\ndev tun\n", text)
        self.assertNotIn("datapath", text)
        self.assertNotIn("tls-server", text)

    def test_tls_switch(self):
        v, e = optforms.parse_form({"o.proto": "udp", "v.tls": "on"}, self.opts)
        self.assertEqual(v["proto"], [["tls-server"]])
        v, e = optforms.parse_form({"o.proto": "tcp-server"}, self.opts)
        self.assertEqual(v["proto"], [["tcp-server"]])
        cfg = ovpnconf.Config.parse("proto tls4-server\n")
        self.assertTrue(optforms.tls_on(cfg))
        v, e = optforms.parse_form({"o.proto": "", "v.tls": "on"}, self.opts, cfg)
        self.assertEqual(v["proto"], [["tls4-server"]])
        v, e = optforms.parse_form({"o.proto": "udp"}, self.opts, cfg)
        self.assertEqual(v["proto"], [["udp"]])
        v, e = optforms.parse_form({"o.proto": ""}, self.opts, cfg)
        self.assertNotIn("proto", v)

    def test_dco_switch(self):
        v, e = optforms.parse_form({"v.dco": "on"}, self.opts)
        self.assertEqual(v["datapath"], [["dco"]])
        v, e = optforms.parse_form({}, self.opts)
        self.assertNotIn("datapath", v)
        for keep in ("udco", "auto", "userspace"):
            cfg = ovpnconf.Config.parse("datapath %s\ndco-socket /x\n" % keep)
            v, e = optforms.parse_form({}, self.opts, cfg)
            self.assertEqual(v["datapath"], [[keep]])
            cfg2 = ovpnconf.Config.parse(cfg.render())
            optforms.apply_values(cfg2, v, self.opts)
            self.assertEqual(cfg2.render(), cfg.render())
        cfg = ovpnconf.Config.parse("datapath dco\n")
        v, e = optforms.parse_form({}, self.opts, cfg)
        self.assertNotIn("datapath", v)

    def test_removed_options_stay_in_file(self):
        text = "dev tun\nccd-exclusive\npersist-tun\nbind\nmlock\ntls-server\ndisable-dco\nport 1\n"
        cfg = ovpnconf.Config.parse(text)
        v, e = optforms.parse_form({"o.port": "2"}, self.opts, cfg)
        optforms.apply_values(cfg, v, self.opts)
        self.assertEqual(cfg.render(), text.replace("port 1", "port 2"))


class Round3OptionsTest(unittest.TestCase):
    def setUp(self):
        self.data = optforms.load_options()
        self.opts = optforms.all_options()

    def test_not_applied_options_are_gone(self):
        for o in self.opts.values():
            self.assertNotEqual(o["status"], "not_applied", o["name"])
        for n in ("ping-exit", "mark", "mtu-disc", "capath", "x509-username-field",
                  "data-ciphers-fallback", "replay-window"):
            self.assertNotIn(n, self.opts)

    def test_removed_from_service_and_tls(self):
        for n in ("mode", "lport", "multihome", "ping-exit", "ncp-ciphers", "allow-compression"):
            self.assertNotIn(n, self.opts)

    def test_tun_mtu_default(self):
        self.assertEqual(self.opts["tun-mtu"]["default"], "1400")

    def test_accepts(self):
        self.assertEqual(self.opts["proto"]["accepts"], ["udp", "tcp-server", "tls-server"])
        self.assertEqual(self.opts["verify-client-cert"]["accepts"], ["require", "optional", "none"])
        self.assertEqual(self.opts["peer-keys-mode"]["accepts"], ["pin", "both", "either"])
        self.assertEqual(self.opts["pq-mode"]["accepts"], ["off", "prefer", "require"])
        self.assertEqual(self.opts["tls-version-min"]["accepts"], ["1.2", "1.3"])
        self.assertEqual(self.opts["remote-cert-tls"]["accepts"], ["server", "client"])
        self.assertEqual(self.opts["data-ciphers"]["accepts"], optforms.CIPHERS)
        self.assertEqual(self.opts["data-ciphers"]["virtual"], "ciphers")
        self.assertIsNone(self.opts["port"]["accepts"])

    def test_dropdowns_match_accepts(self):
        for n in ("proto", "verify-client-cert", "peer-keys-mode", "pq-mode", "tls-version-max",
                  "key-direction", "remote-cert-tls", "verb"):
            vals = [c[0] for c in self.opts[n]["choices"]]
            self.assertEqual(vals[0], "", n)
            self.assertTrue(set(vals[1:]) <= set(self.opts[n]["accepts"]) | {"0", "1", "2", "3", "4"}, n)
        self.assertEqual([c[0] for c in self.opts["pq-mode"]["choices"]], ["", "off", "prefer", "require"])
        self.assertEqual(self.opts["pq-mode"]["choices"][0][1], "Default (prefer)")

    def cipher_form(self, ticked, existing=None):
        form = {"v.cipher." + c: "on" for c in ticked}
        cfg = ovpnconf.Config.parse(existing) if existing is not None else None
        v, e = optforms.parse_form(form, self.opts, cfg)
        self.assertEqual(e, [])
        return v.get("data-ciphers")

    def test_ciphers_default_and_order(self):
        self.assertEqual(optforms.CIPHERS, ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"])
        self.assertEqual(self.opts["data-ciphers"]["default"], "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
        self.assertIsNone(self.cipher_form([]))
        self.assertEqual(self.cipher_form(["CHACHA20-POLY1305", "AES-256-GCM"]),
                         [["AES-256-GCM:CHACHA20-POLY1305"]])
        self.assertEqual(self.cipher_form(optforms.CIPHERS), [[":".join(optforms.CIPHERS)]])

    def test_ciphers_keep_existing_order(self):
        old = "data-ciphers CHACHA20-POLY1305:AES-256-GCM\n"
        self.assertEqual(self.cipher_form(["AES-256-GCM", "CHACHA20-POLY1305"], old),
                         [["CHACHA20-POLY1305:AES-256-GCM"]])
        self.assertEqual(self.cipher_form(["AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"], old),
                         [["CHACHA20-POLY1305:AES-256-GCM:AES-128-GCM"]])
        self.assertEqual(self.cipher_form(["AES-128-GCM", "CHACHA20-POLY1305"], old),
                         [["CHACHA20-POLY1305:AES-128-GCM"]])
        self.assertIsNone(self.cipher_form([], old))
        v, _ = optforms.parse_form({}, self.opts, ovpnconf.Config.parse(old))
        cfg = ovpnconf.Config.parse(old)
        optforms.apply_values(cfg, v, self.opts)
        self.assertNotIn("data-ciphers", cfg.render())

    def test_ciphers_other_names_stay(self):
        old = "data-ciphers AES-256-GCM:AES-192-GCM\n"
        self.assertEqual(self.cipher_form(["AES-256-GCM"], old), [["AES-256-GCM:AES-192-GCM"]])
        self.assertEqual(self.cipher_form([], old), [["AES-192-GCM"]])

    def test_ciphers_unchanged_keeps_file(self):
        old = "data-ciphers aes-256-gcm:CHACHA20-POLY1305\nport 1\n"
        cfg = ovpnconf.Config.parse(old)
        v, _ = optforms.parse_form({"o.port": "1", "v.cipher.AES-256-GCM": "on",
                                    "v.cipher.CHACHA20-POLY1305": "on"}, self.opts, cfg)
        optforms.apply_values(cfg, v, self.opts)
        self.assertEqual(cfg.render(), old)

    def test_tls_switch_ignores_disabled_proto(self):
        v, _ = optforms.parse_form({"v.tls": "on"}, self.opts)
        self.assertEqual(v["proto"], [["tls-server"]])
        v, _ = optforms.parse_form({"v.tls": "on", "o.proto": "udp"}, self.opts)
        self.assertEqual(v["proto"], [["tls-server"]])
