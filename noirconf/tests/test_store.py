import os
import re
import subprocess
import unittest

import helpers
import accounts as acct
import fixtures
import optforms
import ovpnconf
import pki
import store


class CreateTest(fixtures.StoreCase):
    def test_create_passes_check_config(self):
        text = self.create()
        p = self.store.paths("server")
        self.assertTrue(os.path.isfile(p.conf))
        ok, out = self.store.check_config(p.conf)
        self.assertTrue(ok, out)
        cfg = ovpnconf.Config.parse(text)
        self.assertEqual(cfg.first("server"), ["10.8.0.0", "255.255.255.0"])
        self.assertEqual(cfg.first("peer-keys-mode"), ["either"])
        self.assertEqual(cfg.first("bus-allow"), ["uid", "0", "admin"])
        self.assertEqual(cfg.first("stats-interval"), ["5"])

    def test_files_and_modes(self):
        self.create()
        p = self.store.paths("server")
        for f in ("pki/ca.crt", "pki/ca.key", "pki/server.crt", "pki/server.key", "pki/crl.pem",
                  "pki/index.txt", "pki/serial", "pki/crlnumber", "tls-crypt.key", "accounts.conf",
                  "peers", "noirconf.ini"):
            self.assertTrue(os.path.exists(os.path.join(p.data, f)), f)
        self.assertEqual(os.stat(os.path.join(p.pki, "ca.key")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(p.pki, "server.key")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(p.pki).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(p.peers).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(p.conf).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(p.accounts).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(p.tls_crypt).st_mode & 0o777, 0o640)
        self.assertEqual(self.store.externals("server"), [("vpn.example.com", "1194", "udp")])
        self.assertEqual(self.store.servers(), ["server"])

    def test_externals_follow_port_and_proto(self):
        self.create(port="443", proto="tcp-server", ext="a.example\nb.example 8443 tls")
        self.assertEqual(self.store.externals("server"),
                         [("a.example", "443", "tcp"), ("b.example", "8443", "tls")])

    def test_duplicate_and_bad_names(self):
        self.create()
        with self.assertRaises(store.StoreError):
            self.create()
        for bad in ["", "a/b", "../x", "appserver", "a b", "x" * 41]:
            with self.assertRaises(store.StoreError):
                self.create(bad)

    def test_check_failure_rolls_back(self):
        with self.assertRaises(store.StoreError) as cm:
            self.create(proto="bogus-proto")
        self.assertIn("check", str(cm.exception).lower())
        self.assertFalse(os.path.exists(self.store.paths("server").data))
        self.assertFalse(os.path.exists(self.store.paths("server").conf))
        self.assertEqual(os.listdir(self.etc), [])

    def test_bad_externals(self):
        for bad in ["bad host!", "a.example 99999", "a.example 1194 sctp", "a b c d"]:
            with self.assertRaises(store.StoreError):
                self.create(ext=bad)
        self.assertEqual(os.listdir(self.etc), [])

    def test_scan_ignores_appserver(self):
        for n in ("appserver.conf", "x.conf", "bad name.conf"):
            open(os.path.join(self.etc, n), "w").close()
        self.assertEqual(store.scan(self.etc), ["x"])

    def test_edit_keeps_unmanaged_lines(self):
        self.create()
        p = self.store.paths("server")
        with open(p.conf, "a") as f:
            f.write("setenv FORWARD_COMPATIBLE 1\n")
        form = self.form(verb="4")
        form["o.port"] = "1195"
        new, old, errors = self.store.form_to_config("server", form)
        self.assertEqual(errors, [])
        cfg = ovpnconf.Config.parse(new)
        self.assertEqual(cfg.first("port"), ["1195"])
        self.assertEqual(cfg.first("verb"), ["4"])
        self.assertEqual(cfg.first("setenv"), ["FORWARD_COMPATIBLE", "1"])
        diff = self.store.diff(old, new, "server")
        self.assertIn("-port 1194", diff)
        self.assertIn("+port 1195", diff)
        ok, out = self.store.check_text("server", new)
        self.assertTrue(ok, out)

    def test_unchanged_form_gives_no_diff(self):
        self.create()
        form = self.form()
        new, old, errors = self.store.form_to_config("server", form)
        self.assertEqual(new, old)

    def test_form_errors(self):
        form = self.form()
        form["o.server"] = "10.8.0.0"
        form["o.port"] = '"open'
        _, errors = optforms.parse_form(form, self.store.opts)
        self.assertEqual(len(errors), 2)

    def test_init_data_for_foreign_config(self):
        with open(os.path.join(self.etc, "other.conf"), "w") as f:
            f.write("port 1200\nproto tcp-server\n")
        self.assertFalse(self.store.managed("other"))
        self.store.init_data("other", "h.example", "tester")
        self.assertTrue(self.store.managed("other"))
        self.assertEqual(self.store.externals("other"), [("h.example", "1200", "tcp")])


class UserTest(fixtures.StoreCase):
    def setUp(self):
        super().setUp()
        self.create()
        self.daemon = self.start_daemon()

    def test_add_user_syncs(self):
        notes = self.store.add_user("server", "alice", "note", actor="t")
        self.assertIn("peers.reload", self.daemon.names())
        self.assertTrue(any("peers file" in n for n in notes))
        with self.assertRaises(acct.AccountError):
            self.store.add_user("server", "bad name")

    def test_peers_file_written(self):
        self.store.add_user("server", "alice")
        pin = "sha256:" + "A" * 43 + "="
        self.store.add_key("server", "alice", pin, "dev")
        with open(self.store.paths("server").peers) as f:
            rows = acct.parse_peers(f.read())
        self.assertEqual(rows, [("alice", pin, [])])

    def test_add_key_from_cert_and_pubkey(self):
        self.store.add_user("server", "alice")
        key, crt, serial, pin = self.store.ca("server").issue_client("tmp")
        self.store.add_key("server", "alice", crt, "from cert")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual((u.keys[0].pin, u.keys[0].source, u.keys[0].serial), (pin, "cert", serial))
        pub = subprocess.run(["openssl", "pkey", "-pubout"], input=key.encode(),
                             stdout=subprocess.PIPE, check=True).stdout.decode()
        with self.assertRaises(acct.AccountError):
            self.store.add_key("server", "alice", pub, "same key again")
        with self.assertRaises(pki.PkiError):
            self.store.add_key("server", "alice", key, "private key")

    def test_disable_enable(self):
        self.store.add_user("server", "alice")
        self.store.add_key("server", "alice", "sha256:" + "B" * 43 + "=")
        self.daemon.ops.clear()
        self.store.set_enabled("server", "alice", False)
        self.assertIn("peer.kick", self.daemon.names())
        kicks = [a for o, a in self.daemon.ops if o == "peer.kick"]
        self.assertIn({"name": "alice", "halt": True, "reason": "noirconf"}, kicks)
        with open(self.store.paths("server").peers) as f:
            self.assertEqual(acct.parse_peers(f.read())[0][2], ["disabled"])
        self.store.set_enabled("server", "alice", True)
        with open(self.store.paths("server").peers) as f:
            self.assertEqual(acct.parse_peers(f.read())[0][2], [])

    def test_profile_revoke_flow(self):
        self.store.add_user("server", "alice")
        name, text = self.store.build_profile("server", "alice", None, "generate", "")
        self.assertEqual(name, "server-alice.ovpn")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual(len(u.keys), 1)
        k = u.keys[0]
        self.assertEqual((k.source, k.state), ("ca", "active"))
        self.daemon.ops.clear()
        notes = self.store.revoke_user("server", "alice")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual(u.keys[0].state, "revoked")
        self.assertIn(k.serial, self.store.ca("server").revoked_serials())
        kicks = [a for o, a in self.daemon.ops if o == "peer.kick"]
        self.assertIn({"serial": k.serial, "halt": True, "reason": "noirconf"}, kicks)
        self.assertIn({"pin": acct.bus_pin(k.pin), "halt": True, "reason": "noirconf"}, kicks)
        self.assertRegex(acct.bus_pin(k.pin), r"^sha256:[0-9a-f]{64}$")
        self.assertIn("peers.reload", self.daemon.names())
        with open(self.store.paths("server").peers) as f:
            self.assertEqual(acct.parse_peers(f.read())[0][2], ["disabled"])
        with open(os.path.join(self.store.paths("server").pki, "crl.pem")) as f:
            crl = f.read()
        txt = subprocess.run(["openssl", "crl", "-noout", "-text"], input=crl.encode(),
                             stdout=subprocess.PIPE).stdout.decode()
        self.assertIn(k.serial, txt.upper())

    def test_sign_csr_flow(self):
        import test_pki
        self.store.add_user("server", "alice")
        key, csr = test_pki.make_csr("ec-p256")
        self.daemon.ops.clear()
        crt, notes = self.store.sign_csr("server", "alice", csr, "laptop", actor="t")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual(len(u.keys), 1)
        k = u.keys[0]
        self.assertEqual((k.source, k.state, k.label), ("ca", "active", "laptop"))
        self.assertEqual(k.serial, pki.cert_serial(crt))
        self.assertEqual(k.pin, test_pki.pin_of_key(key))
        with open(self.store.paths("server").peers) as f:
            self.assertIn(k.pin, f.read())
        self.assertIn("peers.reload", self.daemon.names())
        ca_crt = os.path.join(self.store.paths("server").pki, "ca.crt")
        cp = os.path.join(self.tmp, "c.crt")
        with open(cp, "w") as f:
            f.write(crt)
        r = subprocess.run(["openssl", "verify", "-CAfile", ca_crt, cp], stdout=subprocess.PIPE)
        self.assertEqual(r.returncode, 0)
        # the profile with the own key accepts this certificate
        _, text = self.store.build_profile("server", "alice", None, "own", "", crt)
        self.assertIn("<cert>", text)
        self.assertNotIn("<key>", text)
        # same key again
        with self.assertRaises(store.StoreError):
            self.store.sign_csr("server", "alice", csr)
        self.assertEqual(len(self.store.ca("server").revoked_serials()), 0)
        self.store.revoke_key("server", "alice", k.id)
        self.assertIn(k.serial, self.store.ca("server").revoked_serials())
        with open(os.path.join(self.store.paths("server").pki, "crl.pem")) as f:
            txt = subprocess.run(["openssl", "crl", "-noout", "-text"], input=f.read().encode(),
                                 stdout=subprocess.PIPE).stdout.decode()
        self.assertIn(k.serial, txt.upper())

    def test_sign_csr_refusals(self):
        import test_pki
        self.store.add_user("server", "alice")
        idx = os.path.join(self.store.paths("server").pki, "index.txt")
        with open(idx) as f:
            before = f.read()
        key, csr = test_pki.make_csr("ed25519")
        for text in ("", "junk", key, csr + key):
            with self.assertRaises(pki.PkiError):
                self.store.sign_csr("server", "alice", text)
        self.store.set_enabled("server", "alice", False)
        with self.assertRaises(store.StoreError):
            self.store.sign_csr("server", "alice", csr)
        self.assertEqual(self.store.ca("server").revoked_serials(), set())
        with open(idx) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.store.load_accounts("server").user("alice").keys, [])

    def test_delete_user_revokes(self):
        self.store.add_user("server", "alice")
        self.store.build_profile("server", "alice", None, "generate", "")
        serial = self.store.load_accounts("server").user("alice").keys[0].serial
        self.store.delete_user("server", "alice")
        self.assertNotIn("alice", self.store.load_accounts("server").users)
        self.assertIn(serial, self.store.ca("server").revoked_serials())

    def test_delete_key(self):
        self.store.add_user("server", "alice")
        self.store.build_profile("server", "alice", None, "generate", "")
        self.store.build_profile("server", "alice", None, "generate", "")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual(len(u.keys), 2)
        self.store.delete_key("server", "alice", "k1")
        u = self.store.load_accounts("server").user("alice")
        self.assertEqual([k.id for k in u.keys], ["k2"])

    def test_daemon_not_running_is_a_note(self):
        self.daemon.close()
        self.daemon = None
        notes = self.store.add_user("server", "bob")
        self.assertTrue(any("not running" in n for n in notes))

    def test_not_found_kick_ignored(self):
        self.daemon.fail["peer.kick"] = "not_found"
        self.store.add_user("server", "alice")
        self.store.set_enabled("server", "alice", False)

    def test_other_bus_error_reported(self):
        self.daemon.fail["peers.reload"] = "denied"
        notes = self.store.add_user("server", "alice")
        self.assertTrue(any("denied" in n for n in notes))


class ProfileTest(fixtures.StoreCase):
    def setUp(self):
        super().setUp()
        self.create(ext="a.example 1194 udp\nb.example 443 tcp")
        self.store.add_user("server", "alice")

    def blocks(self, text, tag):
        m = re.search(r"<%s>\n(.*?)</%s>" % (tag, tag), text, re.S)
        return m.group(1) if m else None

    def test_plain_profile(self):
        name, text = self.store.build_profile("server", "alice", None, "generate", "")
        cfg = ovpnconf.Config.parse(text)
        self.assertTrue(cfg.has("client"))
        self.assertEqual(cfg.first("dev"), ["tun"])
        self.assertEqual(cfg.get("remote"), [["a.example", "1194", "udp"], ["b.example", "443", "tcp-client"]])
        self.assertEqual(cfg.first("remote-cert-tls"), ["server"])
        for tag in ("ca", "tls-crypt", "cert", "key"):
            self.assertIn(tag, cfg.block_tags())
        self.assertIn("BEGIN PRIVATE KEY", cfg.block("key"))
        self.assertNotIn("ENCRYPTED", cfg.block("key"))
        self.assertFalse(cfg.has("key"))
        self.assertEqual(pki.pin_from_pem(cfg.block("cert")),
                         self.store.load_accounts("server").user("alice").keys[0].pin)

    def test_single_remote(self):
        _, text = self.store.build_profile("server", "alice", 1, "generate", "")
        cfg = ovpnconf.Config.parse(text)
        self.assertEqual(cfg.get("remote"), [["b.example", "443", "tcp-client"]])
        self.assertFalse(cfg.has("remote-random"))

    def test_encrypted_profile(self):
        _, text = self.store.build_profile("server", "alice", None, "generate", "pass phrase 1")
        key = ovpnconf.Config.parse(text).block("key")
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", key)
        self.assertTrue(pki.decrypt_check(key.encode(), "pass phrase 1"))
        self.assertFalse(pki.decrypt_check(key.encode(), "nope"))

    def test_key_not_kept_on_server(self):
        _, text = self.store.build_profile("server", "alice", None, "generate", "")
        body = ovpnconf.Config.parse(text).block("key").splitlines()[1]
        for root, _, files in os.walk(self.tmp):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(body.encode(), fh.read(), os.path.join(root, f))

    def test_tls_crypt_inline_matches_file(self):
        _, text = self.store.build_profile("server", "alice", None, "generate", "")
        with open(self.store.paths("server").tls_crypt) as f:
            self.assertEqual(ovpnconf.Config.parse(text).block("tls-crypt").strip(), f.read().strip())

    def test_own_key_profile(self):
        key, crt, serial, pin = self.store.ca("server").issue_client("someone")
        self.store.add_key("server", "alice", crt, "mine")
        _, text = self.store.build_profile("server", "alice", 0, "own", own_cert=crt)
        cfg = ovpnconf.Config.parse(text)
        self.assertEqual(cfg.first("key"), ["/path/to/your-private-key.pem"])
        self.assertIsNone(cfg.block("key"))
        self.assertEqual(pki.pin_from_pem(cfg.block("cert")), pin)
        self.assertIn("# Point the next line", text)

    def test_own_key_unregistered_refused(self):
        key, crt, serial, pin = self.store.ca("server").issue_client("someone")
        with self.assertRaises(store.StoreError):
            self.store.build_profile("server", "alice", 0, "own", own_cert=crt)

    def test_disabled_user_refused(self):
        self.store.set_enabled("server", "alice", False)
        with self.assertRaises(store.StoreError):
            self.store.build_profile("server", "alice", None, "generate", "")

    def test_no_externals_refused(self):
        p = self.store.paths("server")
        store.write_externals(p, [])
        with self.assertRaises(store.StoreError):
            self.store.build_profile("server", "alice", None, "generate", "")

    def test_bad_remote_index(self):
        with self.assertRaises(store.StoreError):
            self.store.build_profile("server", "alice", 9, "generate", "")


class SystemInfoTest(helpers.TmpCase):
    def test_parse(self):
        with open(os.path.join(self.tmp, "loadavg"), "w") as f:
            f.write("0.10 0.20 0.30 1/200 999\n")
        with open(os.path.join(self.tmp, "meminfo"), "w") as f:
            f.write("MemTotal:  1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n")
        i = store.system_info(self.tmp)
        self.assertEqual(i["load"], "0.10 0.20 0.30")
        self.assertEqual((i["mem_total"], i["mem_used"]), (1000 * 1024, 600 * 1024))

    def test_missing(self):
        self.assertEqual(store.system_info(self.tmp)["load"], None)


if __name__ == "__main__":
    unittest.main()


class KeyTypeTest(fixtures.StoreCase):
    def algo(self, path):
        return subprocess.run(["openssl", "x509", "-in", path, "-noout", "-text"],
                              stdout=subprocess.PIPE).stdout.decode()

    def test_default_ed25519_and_check_config(self):
        self.create()
        p = self.store.paths("server")
        self.assertEqual(self.store.key_type("server"), "ed25519")
        for f in ("ca.crt", "server.crt"):
            self.assertIn("ED25519", self.algo(os.path.join(p.pki, f)))
        ok, out = self.store.check_config(p.conf)
        self.assertTrue(ok, out)
        self.store.add_user("server", "alice")
        _, text = self.store.build_profile("server", "alice", None, "generate", "pp")
        cfg = ovpnconf.Config.parse(text)
        self.assertIn("ED25519", subprocess.run(["openssl", "x509", "-noout", "-text"],
                                                input=cfg.block("cert").encode(),
                                                stdout=subprocess.PIPE).stdout.decode())
        self.assertTrue(pki.decrypt_check(cfg.block("key").encode(), "pp"))

    def test_other_type_at_creation(self):
        self.store.create_server("rsa", self.form("rsa"), "a.example", "t", key_type="rsa-3072")
        p = self.store.paths("rsa")
        self.assertIn("rsaEncryption", self.algo(os.path.join(p.pki, "server.crt")))
        ok, out = self.store.check_config(p.conf)
        self.assertTrue(ok, out)
        self.assertEqual(self.store.key_type("rsa"), "rsa-3072")

    def test_change_applies_to_new_client_keys(self):
        self.create()
        self.store.add_user("server", "alice")
        self.store.set_externals("server", "vpn.example.com", "t", key_type="ec-p256")
        self.assertEqual(self.store.key_type("server"), "ec-p256")
        self.assertEqual(self.store.externals("server"), [("vpn.example.com", "1194", "udp")])
        _, text = self.store.build_profile("server", "alice", None, "generate", "")
        self.assertIn("id-ecPublicKey", subprocess.run(
            ["openssl", "x509", "-noout", "-text"], input=ovpnconf.Config.parse(text).block("cert").encode(),
            stdout=subprocess.PIPE).stdout.decode())
        # a change of the externals alone keeps the key type
        self.store.set_externals("server", "b.example", "t")
        self.assertEqual(self.store.key_type("server"), "ec-p256")

    def test_bad_type_refused(self):
        with self.assertRaises(pki.PkiError):
            self.store.create_server("x", self.form("x"), "a.example", "t", key_type="dsa")
        self.assertEqual(os.listdir(self.etc), [])


class SwitchesTest(fixtures.StoreCase):
    def test_dco_and_tls_switches_pass_check(self):
        self.create()
        p = self.store.paths("server")
        form = self.form()
        form["v.dco"] = "on"
        new, old, errors = self.store.form_to_config("server", form)
        self.assertEqual(errors, [])
        self.assertIn("datapath dco\n", new)
        ok, out = self.store.check_text("server", new)
        self.assertTrue(ok, out)
        form = self.form()
        form["v.tls"] = "on"
        new, old, errors = self.store.form_to_config("server", form)
        cfg = ovpnconf.Config.parse(new)
        self.assertEqual(cfg.first("proto"), ["tls-server"])
        ok, out = self.store.check_text("server", new)
        self.assertTrue(ok, out)
        with open(p.conf, "w") as f:
            f.write(new)
        new2, old2, _ = self.store.form_to_config("server", dict(self.form(), **{"v.tls": "on"}))
        self.assertEqual(new2, old2)
        new3, _, _ = self.store.form_to_config("server", self.form())
        self.assertEqual(ovpnconf.Config.parse(new3).first("proto"), ["udp"])

    def test_udco_line_kept(self):
        self.create()
        p = self.store.paths("server")
        with open(p.conf, "a") as f:
            f.write("datapath udco\n")
        new, old, _ = self.store.form_to_config("server", self.form())
        self.assertEqual(new, old)
        self.assertIn("datapath udco", new)

    def test_unchecked_dco_removes_dco_line(self):
        self.create()
        p = self.store.paths("server")
        with open(p.conf, "a") as f:
            f.write("datapath dco\n")
        new, old, _ = self.store.form_to_config("server", self.form())
        self.assertNotIn("datapath", new)

    def test_loopback_external_refused_at_creation(self):
        with self.assertRaises(store.StoreError):
            self.create(ext="127.0.0.1")
        self.assertEqual(os.listdir(self.etc), [])

    def test_generated_config_has_dev_tun(self):
        text = self.create()
        self.assertEqual(ovpnconf.Config.parse(text).first("dev"), ["tun"])
