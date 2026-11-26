import os
import subprocess
import unittest

import helpers
import essentials
import fixtures
import ovpnconf
import store
import views


COMBOS = [
    # (form fields, proto option, external proto, ws path, profile remote proto)
    ({"e.clients": "compat", "e.compat_transport": "udp"}, "udp", "udp", "", "udp"),
    ({"e.clients": "compat", "e.compat_transport": "tcp"}, "tcp-server", "tcp", "", "tcp-client"),
    ({"e.clients": "noir", "e.noir_transport": "udp"}, "udp", "udp", "", "udp"),
    ({"e.clients": "noir", "e.noir_transport": "tcp"}, "tcp-server", "tcp", "", "tcp-client"),
    ({"e.clients": "noir", "e.noir_transport": "tls"}, "tls-server", "tls", "", "tls-client"),
    ({"e.clients": "noir", "e.noir_transport": "ws"}, "tls-server", "tls", "/noir-srv", "tls-client"),
]


def ess_form(**over):
    f = {"e.port": "1194", "e.host": "vpn.example.com", "e.public_port": "", "e.network": "10.8.0.0/24",
         "e.clients": "compat", "e.compat_transport": "udp", "e.noir_transport": "udp"}
    f.update(over)
    return f


class ParseTest(unittest.TestCase):
    def test_defaults_and_fields(self):
        e = essentials.parse(ess_form(), "srv")
        self.assertEqual((e["port"], e["public_port"], e["network"]), ("1194", "1194", "10.8.0.0 255.255.255.0"))
        self.assertEqual((e["proto"], e["ext_proto"], e["ws"]), ("udp", "udp", ""))
        e = essentials.parse(ess_form(**{"e.port": "443", "e.public_port": "8443"}), "srv")
        self.assertEqual((e["port"], e["public_port"]), ("443", "8443"))

    def test_network_validation(self):
        ok = {"10.8.0.0/24": "10.8.0.0 255.255.255.0", "10.8.0.0/16": "10.8.0.0 255.255.0.0",
              "192.168.4.0/30": "192.168.4.0 255.255.255.252", "": "10.8.0.0 255.255.255.0",
              " 172.16.0.0/20 ": "172.16.0.0 255.255.240.0"}
        for text, want in ok.items():
            self.assertEqual(essentials.parse_network(text), want, text)
        for bad in ["10.8.0.1/24", "10.8.0.0/15", "10.8.0.0/31", "10.8.0.0/32", "10.8.0.0", "10.8.0.0/33",
                    "fd00::/64", "abc", "10.8.0.0/24 x", "10.8.0.0/255.255.255.0", "10.8.0.0/8"]:
            with self.assertRaises(ValueError, msg=bad):
                essentials.parse_network(bad)
        with self.assertRaises(ValueError) as cm:
            essentials.parse_network("10.8.0.1/24")
        self.assertIn("host bits", str(cm.exception))
        self.assertIn("10.8.0.0/24", str(cm.exception))

    def test_ws_path_validation(self):
        for good in ["/a", "/noir-srv", "/vpn/ws_1.2~x", "/" + "a" * 64]:
            self.assertEqual(essentials.check_ws_path(good), good)
        for bad in ["", "a", "/", "vpn", "/a b", "/a?x", "/a/../b", "/..", "/a..b", "/" + "a" * 65,
                    "/a#", "/\u00e4", "//\\"]:
            with self.assertRaises(ValueError, msg=bad):
                essentials.check_ws_path(bad)

    def test_ws_default_and_use(self):
        self.assertEqual(essentials.default_ws_path("srv"), "/noir-srv")
        e = essentials.parse(ess_form(**{"e.clients": "noir", "e.noir_transport": "ws"}), "srv")
        self.assertEqual(e["ws"], "/noir-srv")
        e = essentials.parse(ess_form(**{"e.clients": "noir", "e.noir_transport": "ws", "e.ws_path": "/x"}), "srv")
        self.assertEqual(e["ws"], "/x")
        with self.assertRaises(ValueError):
            essentials.parse(ess_form(**{"e.clients": "noir", "e.noir_transport": "ws", "e.ws_path": "/a/../b"}), "srv")
        # a path is ignored when the choice is not WebSocket
        e = essentials.parse(ess_form(**{"e.clients": "noir", "e.noir_transport": "tls", "e.ws_path": "/bad .."}), "srv")
        self.assertEqual(e["ws"], "")

    def test_compat_has_no_tls(self):
        for t in ("tls", "ws"):
            with self.assertRaises(ValueError):
                essentials.parse(ess_form(**{"e.compat_transport": t}), "srv")

    def test_bad_ports_and_host(self):
        for k, v in [("e.port", "0"), ("e.port", "70000"), ("e.port", "x"), ("e.public_port", "99999")]:
            with self.assertRaises(ValueError):
                essentials.parse(ess_form(**{k: v}), "srv")
        with self.assertRaises(ValueError):
            essentials.parse(ess_form(**{"e.host": ""}), "srv")

    def test_form_fields(self):
        h = views.create_form_html({"groups": []}, {}, "", "srv", ess=essentials.defaults("srv"))
        self.assertIn('name="essentials" value="on" class="modebox" checked>', h)
        self.assertIn("Create with Essentials", h)
        self.assertLess(h.index("Create with Essentials"), h.index('name="name"'))
        self.assertIn('value="10.8.0.0/24"', h)
        self.assertIn("Key type: <b>Ed25519</b>", h)
        self.assertNotIn('name="e.key_type"', h)
        self.assertIn('name="e.compat_transport" value="udp" checked', h)
        self.assertNotIn('value="tls"', h.split('class="indent tg-compat"')[1].split('class="indent tg-noir"')[0])
        self.assertIn('name="e.noir_transport" value="ws"', h)
        self.assertIn('value="/noir-srv" class="mono" data-auto="1"', h)
        self.assertIn("There is no IPv6 field here", h)
        self.assertIn("OpenVPN clients cannot connect", h)
        h2 = views.create_form_html({"groups": []}, {}, "", "srv", essentials=False, ess=essentials.defaults("srv"))
        self.assertNotIn("modebox\" checked", h2)
        # the fields of the full form do not have required, so a hidden one cannot block the submit
        self.assertNotIn("required", h.split('name="name"')[1].split(">")[0].replace("required ", "", 1))
        css = helpers.css()
        self.assertIn(".modebox:checked ~ .full-block { display: none; }", css)
        self.assertIn(".modebox:not(:checked) ~ .ess-block { display: none; }", css)
        self.assertIn("#nt-ws:checked ~ .ws-path { display: block; }", css)

    def test_edited_path_is_not_auto(self):
        ess = dict(essentials.defaults("srv"), **{"e.ws_path": "/mine"})
        h = views.create_form_html({"groups": []}, {}, "", "srv", ess=ess)
        self.assertIn('value="/mine" class="mono" data-auto="0"', h)

    def test_js_shows_rejected_forms(self):
        with open(os.path.join(helpers.APP, "static", "app.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertIn('"htmx:beforeSwap"', js)
        self.assertIn("d.xhr.status === 400", js)
        self.assertIn("d.shouldSwap = true", js)

    def test_js_updates_default_path(self):
        with open(os.path.join(helpers.APP, "static", "app.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertIn('"f-name"', js)
        self.assertIn('"/noir-" + (t.value || "server")', js)
        self.assertIn('dataset.auto', js)


class CreateEssentialsTest(fixtures.StoreCase):
    def test_six_combinations(self):
        for i, (fields, proto, ext_proto, ws, remote) in enumerate(COMBOS):
            with self.subTest(fields=fields):
                name = "srv" if ws else "s%d" % i
                text = self.store.create_essentials(name, ess_form(**dict(fields, **{"e.ws_path": ws}) if ws else fields))
                cfg = ovpnconf.Config.parse(text)
                self.assertEqual(cfg.first("proto"), [proto])
                self.assertEqual(cfg.first("port"), ["1194"])
                self.assertEqual(cfg.first("server"), ["10.8.0.0", "255.255.255.0"])
                self.assertEqual(cfg.first("dev"), ["tun"])
                self.assertEqual(cfg.first("tls-transport-ws"), [ws] if ws else None)
                for opt in ("keepalive", "cert", "key", "ca", "crl-verify", "peer-keys", "tls-crypt",
                            "bus-control", "bus-events", "bus-allow"):
                    self.assertIsNotNone(cfg.first(opt), opt)
                self.assertNotIn("pq-mode", text)
                # the server config passes the check
                ok, out = self.store.check_text(name, text)
                self.assertTrue(ok, out)
                # data
                p = self.store.paths(name)
                for f in ("accounts.conf", "peers", "tls-crypt.key", "noirconf.ini"):
                    self.assertTrue(os.path.exists(os.path.join(p.data, f)), f)
                self.assertEqual(self.store.key_type(name), "ed25519")
                ext = self.store.externals(name)
                self.assertEqual(len(ext), 1)
                self.assertEqual(tuple(ext[0]), ("vpn.example.com", "1194", ext_proto))
                self.assertEqual(ext[0].ws, ws)
                # profile
                self.store.add_user(name, "alice")
                fname, prof = self.store.build_profile(name, "alice", None, "generate", "")
                self.assertIn("remote vpn.example.com 1194 %s\n" % remote, prof)
                if ws:
                    self.assertIn("tls-transport-ws %s\n" % ws, prof)
                else:
                    self.assertNotIn("tls-transport-ws", prof)
                self.assertIn("<ca>", prof)
                pf = os.path.join(self.tmp, "%s.ovpn" % name)
                with open(pf, "w") as f:
                    f.write(prof)
                ok, out = self.store.check_config(pf)
                self.assertTrue(ok, "profile: " + out)

    def test_ports_and_network(self):
        text = self.store.create_essentials(
            "a", ess_form(**{"e.port": "443", "e.public_port": "8443", "e.network": "192.168.77.0/28",
                             "e.host": "203.0.113.9", "e.clients": "noir", "e.noir_transport": "tls"}))
        cfg = ovpnconf.Config.parse(text)
        self.assertEqual(cfg.first("port"), ["443"])
        self.assertEqual(cfg.first("server"), ["192.168.77.0", "255.255.255.240"])
        self.assertEqual(tuple(self.store.externals("a")[0]), ("203.0.113.9", "8443", "tls"))
        ok, out = self.store.check_text("a", text)
        self.assertTrue(ok, out)
        self.store.add_user("a", "alice")
        _, prof = self.store.build_profile("a", "alice", None, "generate", "")
        self.assertIn("remote 203.0.113.9 8443 tls-client\n", prof)
        pf = os.path.join(self.tmp, "a.ovpn")
        with open(pf, "w") as f:
            f.write(prof)
        ok, out = self.store.check_config(pf)
        self.assertTrue(ok, out)

    def test_refusals_leave_nothing(self):
        for over in [{"e.host": "127.0.0.1"}, {"e.host": "localhost"}, {"e.host": "0.0.0.0"},
                     {"e.host": "::"}, {"e.network": "10.8.0.1/24"}, {"e.network": "10.8.0.0/8"},
                     {"e.port": "0"}, {"e.host": ""},
                     {"e.clients": "noir", "e.noir_transport": "ws", "e.ws_path": "/a/../b"}]:
            with self.assertRaises(store.StoreError, msg=str(over)):
                self.store.create_essentials("x", ess_form(**over))
        with self.assertRaises(store.StoreError):
            self.store.create_essentials("bad name", ess_form())
        self.assertEqual(os.listdir(self.etc), [])

    def test_name_exists(self):
        self.store.create_essentials("x", ess_form())
        with self.assertRaises(store.StoreError):
            self.store.create_essentials("x", ess_form())

    def test_clients_setting_is_stored(self):
        self.store.create_essentials("a", ess_form(**{"e.clients": "noir", "e.noir_transport": "tls"}))
        self.store.create_essentials("b", ess_form())
        self.assertEqual(self.store.clients("a"), "noirvpn")
        self.assertEqual(self.store.clients("b"), "openvpn")
        # the setting survives a write of the addresses, and changes only when asked
        self.store.set_externals("a", "vpn.example.com 1194 tls", "t")
        self.assertEqual(self.store.clients("a"), "noirvpn")
        self.store.set_externals("a", "vpn.example.com 1194 tls", "t", clients="openvpn")
        self.assertEqual(self.store.clients("a"), "openvpn")
        with self.assertRaises(store.StoreError):
            self.store.set_externals("a", "vpn.example.com 1194 tls", "t", clients="x")

    def test_full_form_server_is_openvpn(self):
        self.create()
        self.assertEqual(self.store.clients("server"), "openvpn")


class IniTest(helpers.TmpCase):
    def paths(self):
        p = store.Paths(self.tmp, "srv")
        os.makedirs(p.data)
        return p

    def test_old_ini_reads(self):
        p = self.paths()
        with open(p.ini, "w") as f:
            f.write("[server]\nkey-type = ec-p256\n\n[external]\nremote.1 = vpn.example.com 1194 udp\n"
                    "remote.2 = b.example 443 tls\nremote.3 = c.example 80 tcp\n")
        self.assertEqual(store.read_clients(p), "openvpn")
        self.assertEqual(store.read_key_type(p), "ec-p256")
        got = store.read_externals(p)
        self.assertEqual([tuple(x) for x in got], [("vpn.example.com", "1194", "udp"),
                                                    ("b.example", "443", "tls"), ("c.example", "80", "tcp")])
        self.assertEqual([x.ws for x in got], ["", "", ""])
        # an ini with no [server] section at all
        with open(p.ini, "w") as f:
            f.write("[external]\nremote.1 = a.example 1 udp\n")
        self.assertEqual(store.read_clients(p), "openvpn")

    def test_new_format_roundtrip(self):
        p = self.paths()
        items = store.parse_externals("a.example 443 tls ws=/noir-x\nb.example 1194 udp")
        store.write_externals(p, items, "ed25519", "noirvpn")
        with open(p.ini) as f:
            text = f.read()
        self.assertIn("remote.1 = a.example 443 tls ws=/noir-x\n", text)
        self.assertIn("remote.2 = b.example 1194 udp\n", text)
        self.assertIn("clients = noirvpn\n", text)
        got = store.read_externals(p)
        self.assertEqual(got[0].ws, "/noir-x")
        self.assertEqual(got[1].ws, "")
        self.assertEqual(store.read_clients(p), "noirvpn")
        # None keeps the value that is there
        store.write_externals(p, items)
        self.assertEqual(store.read_clients(p), "noirvpn")

    def test_bad_values_read_leniently(self):
        p = self.paths()
        with open(p.ini, "w") as f:
            f.write("[server]\nclients = banana\n\n[external]\nremote.1 = a.example 443 tcp ws=/x\n"
                    "remote.2 = b.example 443 tls ws=/a/../b\nremote.3 = c.example 443 tls ws=/ok\n")
        self.assertEqual(store.read_clients(p), "openvpn")
        got = store.read_externals(p)
        self.assertEqual([x[0] for x in got], ["c.example"])

    def test_external_parse_rules(self):
        for bad in ["a.example 1 udp ws=/x", "a.example 1 tls x=/x", "a.example 1 tls ws=x",
                    "a.example 1 tls ws=/x extra"]:
            with self.assertRaises(store.StoreError, msg=bad):
                store.parse_externals(bad)
        got = store.parse_externals("a.example 1 tls ws=/x")
        self.assertEqual(store.externals_text(got), "a.example 1 tls ws=/x")
        self.assertEqual(got[0], ("a.example", "1", "tls"))


class ProfileTest(unittest.TestCase):
    def test_profile_text_ws(self):
        rem = store.parse_externals("a.example 443 tls ws=/p\nb.example 443 tls ws=/p")
        t = store.profile_text(rem, "CA", "TC", "CERT")
        self.assertEqual(t.count("tls-transport-ws /p\n"), 1)
        self.assertIn("remote a.example 443 tls-client\n", t)
        self.assertIn("remote-random", t)
        with self.assertRaises(store.StoreError):
            store.profile_text(store.parse_externals("a.example 443 tls ws=/p\nb.example 443 tls ws=/q"), "CA", "TC", "C")
        with self.assertRaises(store.StoreError):
            store.profile_text(store.parse_externals("a.example 443 tls ws=/p\nb.example 443 tls"), "CA", "TC", "C")
        # udp and tcp addresses can sit next to a ws address
        t = store.profile_text(store.parse_externals("a.example 443 tls ws=/p\nb.example 1194 udp"), "CA", "TC", "C")
        self.assertIn("remote b.example 1194 udp\n", t)


class ClientsHintTest(unittest.TestCase):
    def test_widget_and_profile_warning(self):
        import accounts as acct
        d = {"connected": 0, "accounts": 0, "system": {}, "uptime": None, "listen": [], "externals": [],
             "clients": "noirvpn"}
        self.assertIn("noirvpn clients only", views.widgets_html("s", d))
        d["clients"] = "openvpn"
        self.assertNotIn("noirvpn clients only", views.widgets_html("s", d))
        u = acct.Accounts().add_user("alice")
        ext = store.parse_externals("a.example 1 udp")
        h = views.user_html("s", u, ext, csrf="x", clients="noirvpn")
        self.assertIn("noirvpn clients only: OpenVPN clients cannot connect to this server.", h)
        h = views.user_html("s", u, ext, csrf="x", clients="openvpn")
        self.assertNotIn("OpenVPN clients cannot connect", h)

    def test_config_select(self):
        h = views.config_form_html("s", {"groups": []}, {}, [], [], "", clients="noirvpn")
        self.assertIn('<select name="clients">', h)
        self.assertIn('<option value="noirvpn" selected>', h)
        h = views.config_form_html("s", {"groups": []}, {}, [], [], "", clients="openvpn")
        self.assertIn('<option value="openvpn" selected>', h)


if __name__ == "__main__":
    unittest.main()
