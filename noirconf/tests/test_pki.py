import os
import re
import subprocess
import unittest

import helpers
import fsutil
import pki


def shell_pin(cert_path):
    """The pipeline of docs/server.md."""
    cmd = ("openssl x509 -in %s -noout -pubkey | openssl pkey -pubin -outform DER "
           "| openssl dgst -sha256 -binary | base64 -w0" % cert_path)
    return "sha256:" + subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, check=True).stdout.decode()


class PkiTest(helpers.TmpCase):
    def setUp(self):
        super().setUp()
        self.ca = pki.CA(os.path.join(self.tmp, "pki"))
        self.ca.init("test CA")

    def test_ca_files_and_modes(self):
        d = self.ca.dir
        for f in ("ca.crt", "ca.key", "index.txt", "serial", "crlnumber", "crl.pem", "openssl.cnf"):
            self.assertTrue(os.path.exists(os.path.join(d, f)), f)
        self.assertEqual(os.stat(os.path.join(d, "ca.key")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertTrue(os.path.isdir(os.path.join(d, "issued")))

    def test_group_gives_group_access(self):
        import grp
        name = grp.getgrgid(os.getgid()).gr_name
        fsutil.DAEMON_GROUP = name
        ca = pki.CA(os.path.join(self.tmp, "pki2"))
        ca.init("g")
        self.assertEqual(os.stat(ca.dir).st_mode & 0o777, 0o750)
        self.assertEqual(os.stat(os.path.join(ca.dir, "crl.pem")).st_gid, os.getgid())

    def test_server_cert(self):
        crt, key = os.path.join(self.tmp, "s.crt"), os.path.join(self.tmp, "s.key")
        self.ca.issue_server("vpn.example.com", ["vpn.example.com", "192.0.2.7"], key, crt)
        text = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-text"],
                              stdout=subprocess.PIPE).stdout.decode()
        self.assertIn("DNS:vpn.example.com", text)
        self.assertIn("IP Address:192.0.2.7", text)
        self.assertIn("TLS Web Server Authentication", text)
        ok = subprocess.run(["openssl", "verify", "-CAfile", os.path.join(self.ca.dir, "ca.crt"), crt],
                            stdout=subprocess.PIPE)
        self.assertEqual(ok.returncode, 0)

    def test_pin_matches_openssl_pipeline(self):
        key, crt, serial, pin = self.ca.issue_client("alice")
        path = os.path.join(self.tmp, "alice.crt")
        with open(path, "w") as f:
            f.write(crt)
        self.assertEqual(pin, shell_pin(path))
        self.assertEqual(pki.pin_from_pem(crt), shell_pin(path))
        self.assertEqual(pki.cert_serial(crt), serial)

    def test_pin_from_public_key(self):
        key, crt, serial, pin = self.ca.issue_client("alice")
        pub = subprocess.run(["openssl", "pkey", "-pubout"], input=key.encode(),
                             stdout=subprocess.PIPE, check=True).stdout.decode()
        self.assertEqual(pki.pin_from_pem(pub), pin)

    def test_private_key_refused(self):
        key, *_ = self.ca.issue_client("alice")
        with self.assertRaises(pki.PkiError):
            pki.pin_from_pem(key)
        with self.assertRaises(pki.PkiError):
            pki.pin_from_pem("hello")

    def test_encrypted_key(self):
        key, crt, serial, pin = self.ca.issue_client("alice", "secret pass")
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", key)
        self.assertTrue(pki.decrypt_check(key.encode(), "secret pass"))
        self.assertFalse(pki.decrypt_check(key.encode(), "wrong"))

    def test_plain_key_and_not_on_disk(self):
        key, crt, serial, pin = self.ca.issue_client("alice")
        self.assertIn("BEGIN PRIVATE KEY", key)
        for root, _, files in os.walk(self.tmp):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(b"PRIVATE KEY-----\n" + key.splitlines()[1].encode(), fh.read(),
                                     os.path.join(root, f))

    def test_passphrase_not_in_argv(self):
        seen = []
        real = subprocess.run

        def spy(argv, *a, **k):
            seen.append(list(argv))
            return real(argv, *a, **k)
        subprocess.run = spy
        try:
            self.ca.issue_client("alice", "very-secret-phrase")
        finally:
            subprocess.run = real
        self.assertTrue(seen)
        for argv in seen:
            self.assertNotIn("very-secret-phrase", " ".join(argv))
            self.assertTrue(all(isinstance(x, str) for x in argv))

    def test_passphrase_with_newline_refused(self):
        with self.assertRaises(pki.PkiError):
            self.ca.issue_client("alice", "a\nb")

    def test_revoke_and_crl(self):
        key, crt, serial, pin = self.ca.issue_client("alice")
        self.assertEqual(self.ca.revoked_serials(), set())
        self.assertTrue(self.ca.revoke(serial))
        self.ca.gen_crl()
        self.assertFalse(self.ca.revoke(serial))
        self.assertEqual(self.ca.revoked_serials(), {serial})
        crl = os.path.join(self.ca.dir, "crl.pem")
        text = subprocess.run(["openssl", "crl", "-in", crl, "-noout", "-text"],
                              stdout=subprocess.PIPE).stdout.decode()
        self.assertIn(serial, text.upper())
        cpath = os.path.join(self.tmp, "a.crt")
        with open(cpath, "w") as f:
            f.write(crt)
        r = subprocess.run(["openssl", "verify", "-crl_check", "-CAfile", os.path.join(self.ca.dir, "ca.crt"),
                            "-CRLfile", crl, cpath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("revoked", r.stdout.decode())

    def test_revoke_bad_serial(self):
        with self.assertRaises(pki.PkiError):
            self.ca.revoke("../../etc/passwd")
        with self.assertRaises(pki.PkiError):
            self.ca.revoke("DEADBEEF")

    def test_serials_differ(self):
        a = self.ca.issue_client("a")[2]
        b = self.ca.issue_client("a")[2]
        self.assertNotEqual(a, b)


class MiscTest(helpers.TmpCase):
    def test_tls_crypt_key_format(self):
        text = pki.tls_crypt_key_text()
        lines = text.splitlines()
        i = lines.index("-----BEGIN OpenVPN Static key V1-----")
        body = lines[i + 1:lines.index("-----END OpenVPN Static key V1-----")]
        self.assertEqual(len(body), 16)
        for ln in body:
            self.assertTrue(re.fullmatch(r"[0-9a-f]{32}", ln))
        self.assertNotEqual(text, pki.tls_crypt_key_text())

    def test_self_signed(self):
        crt, key = os.path.join(self.tmp, "a.crt"), os.path.join(self.tmp, "a.key")
        pki.make_self_signed(crt, key, "noirconf", ["localhost", "127.0.0.1", "::1", "box.example"])
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(crt).st_mode & 0o777, 0o644)
        text = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-text"],
                              stdout=subprocess.PIPE).stdout.decode()
        for want in ("DNS:localhost", "IP Address:127.0.0.1", "IP Address:0:0:0:0:0:0:0:1", "DNS:box.example"):
            self.assertIn(want, text)
        self.assertIn("prime256v1", text)
        self.assertFalse(pki.cert_expires_within(crt, 30 * 86400))
        self.assertTrue(pki.cert_expires_within(crt, 900 * 86400))
        self.assertRegex(pki.fingerprint_sha256(crt), r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_san_list_drops_bad_names(self):
        self.assertEqual(pki.san_list(["a.example", "1.2.3.4", "bad name!", "", "a.example"]),
                         ["DNS:a.example", "IP:1.2.3.4"])


if __name__ == "__main__":
    unittest.main()


class KeyTypesTest(helpers.TmpCase):
    def algo(self, path):
        out = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-text"],
                             stdout=subprocess.PIPE).stdout.decode()
        return out

    def test_default_is_ed25519(self):
        self.assertEqual(pki.DEFAULT_KEY_TYPE, "ed25519")
        self.assertEqual(pki.CA(os.path.join(self.tmp, "p")).key_type, "ed25519")

    def test_chain_for_each_type(self):
        for kt, want in (("ed25519", "ED25519"), ("ec-p256", "id-ecPublicKey"), ("rsa-3072", "rsaEncryption")):
            d = os.path.join(self.tmp, kt)
            ca = pki.CA(os.path.join(d, "pki"), kt)
            ca.init("CA " + kt)
            crt, key = os.path.join(d, "s.crt"), os.path.join(d, "s.key")
            ca.issue_server("vpn.example.com", ["vpn.example.com"], key, crt)
            kpem, cpem, serial, pin = ca.issue_client("alice", "pw")
            cc = os.path.join(d, "c.crt")
            with open(cc, "w") as f:
                f.write(cpem)
            caf = os.path.join(ca.dir, "ca.crt")
            for c in (crt, cc):
                r = subprocess.run(["openssl", "verify", "-CAfile", caf, c], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
                self.assertEqual(r.returncode, 0, (kt, r.stdout))
            self.assertIn(want, self.algo(caf), kt)
            self.assertIn(want, self.algo(crt), kt)
            self.assertIn(want, self.algo(cc), kt)
            self.assertEqual(pin, shell_pin(cc), kt)
            self.assertIn("ENCRYPTED PRIVATE KEY", kpem)
            self.assertTrue(pki.decrypt_check(kpem.encode(), "pw"), kt)
            self.assertFalse(pki.decrypt_check(kpem.encode(), "bad"), kt)
            ca.revoke(serial)
            ca.gen_crl()
            r = subprocess.run(["openssl", "verify", "-crl_check", "-CAfile", caf,
                                "-CRLfile", os.path.join(ca.dir, "crl.pem"), cc],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(r.returncode, 0, kt)

    def test_ed25519_pin_and_no_digest(self):
        ca = pki.CA(os.path.join(self.tmp, "p"))
        ca.init("CA")
        key, crt, serial, pin = ca.issue_client("alice")
        self.assertIn("Signature Algorithm: ED25519", self.algo(os.path.join(ca.dir, "ca.crt")))
        pub = subprocess.run(["openssl", "pkey", "-pubout"], input=key.encode(),
                             stdout=subprocess.PIPE, check=True).stdout.decode()
        self.assertEqual(pki.pin_from_pem(pub), pin)
        self.assertRegex(pin, r"^sha256:[A-Za-z0-9+/]{43}=$")

    def test_web_cert_stays_ec(self):
        crt, key = os.path.join(self.tmp, "a.crt"), os.path.join(self.tmp, "a.key")
        pki.make_self_signed(crt, key, "noirconf", ["localhost"])
        self.assertIn("prime256v1", self.algo(crt))
        self.assertNotIn("ED25519", self.algo(crt))

    def test_bad_type(self):
        with self.assertRaises(pki.PkiError):
            pki.CA(os.path.join(self.tmp, "p"), "dsa")


KEYGEN = {
    "ed25519": ["-algorithm", "ED25519"],
    "ec-p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "ec-p384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "rsa-2048": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    "rsa-3072": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
}


def make_csr(kind, subj="/CN=someone/O=Evil Corp/OU=x"):
    """(key_pem, csr_pem) with the openssl program."""
    key = subprocess.run(["openssl", "genpkey"] + KEYGEN[kind], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    csr = subprocess.run(["openssl", "req", "-new", "-key", "/dev/stdin", "-subj", subj,
                          "-addext", "basicConstraints=CA:TRUE",
                          "-addext", "subjectAltName=DNS:attacker.example"],
                         input=key, stdout=subprocess.PIPE, check=True).stdout.decode()
    return key.decode(), csr


def pin_of_key(key_pem):
    pub = subprocess.run(["openssl", "pkey", "-pubout"], input=key_pem.encode(),
                         stdout=subprocess.PIPE, check=True).stdout
    return pki.pin_from_pem(pub.decode())


class CsrTest(helpers.TmpCase):
    def setUp(self):
        super().setUp()
        self.ca = pki.CA(os.path.join(self.tmp, "pki"))
        self.ca.init("test CA")

    def index_text(self):
        with open(self.ca.p("index.txt")) as f:
            return f.read()

    def cert_text(self, crt):
        return subprocess.run(["openssl", "x509", "-noout", "-text"], input=crt.encode(),
                              stdout=subprocess.PIPE, check=True).stdout.decode()

    def test_sign_each_key_type(self):
        for kind in KEYGEN:
            with self.subTest(kind):
                key, csr = make_csr(kind)
                crt, serial, pin = self.ca.issue_from_csr(csr, "alice")
                path = os.path.join(self.tmp, kind + ".crt")
                with open(path, "w") as f:
                    f.write(crt)
                ok = subprocess.run(["openssl", "verify", "-CAfile", self.ca.p("ca.crt"), path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(ok.returncode, 0, ok.stderr)
                self.assertEqual(pin, pin_of_key(key))
                self.assertEqual(pin, shell_pin(path))
                self.assertEqual(serial, pki.cert_serial(crt))
                text = self.cert_text(crt)
                self.assertRegex(text, r"Subject: CN\s*=\s*alice\s*\n")
                self.assertNotIn("Evil", text)
                self.assertNotIn("attacker.example", text)
                self.assertIn("TLS Web Client Authentication", text)
                self.assertNotIn("TLS Web Server Authentication", text)
                self.assertRegex(text, r"CA:FALSE")
                self.assertIn("Digital Signature", text)

    def test_same_validity_as_issued_client_cert(self):
        _, csr = make_csr("ed25519")
        crt, _, _ = self.ca.issue_from_csr(csr, "alice")
        _, own, _, _ = self.ca.issue_client("alice")
        def days(c):
            out = subprocess.run(["openssl", "x509", "-noout", "-startdate", "-enddate"],
                                 input=c.encode(), stdout=subprocess.PIPE, check=True).stdout.decode()
            from email.utils import parsedate_to_datetime
            a, b = [parsedate_to_datetime(l.split("=")[1].replace(" GMT", " +0000")) for l in out.split("\n") if "=" in l]
            return (b - a).days
        self.assertEqual(days(crt), days(own))
        self.assertEqual(days(crt), pki.CLIENT_DAYS)

    def test_bad_requests_refused(self):
        key, csr = make_csr("ed25519")
        for text, want in [
            ("", "no certificate request"),
            ("hello", "no certificate request"),
            (key, "private key"),
            (csr + key, "private key"),
            ("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", "not valid"),
            ("x" * (pki.CSR_MAX + 1), "too long"),
        ]:
            with self.assertRaises(pki.PkiError, msg=text[:30]) as cm:
                self.ca.issue_from_csr(text, "alice")
            self.assertIn(want, str(cm.exception))
        self.assertEqual(self.index_text(), "")

    def test_certificate_is_not_a_request(self):
        _, crt, _, _ = self.ca.issue_client("bob")
        with self.assertRaises(pki.PkiError):
            self.ca.issue_from_csr(crt, "alice")

    def test_mismatched_signature_refused(self):
        _, csr = make_csr("ec-p256")
        _, other = make_csr("ec-p256")
        # take the signature of one request into the other: parse the DER with openssl asn1
        import base64
        der = bytearray(base64.b64decode("".join(csr.strip().splitlines()[1:-1])))
        der[-5] ^= 0x55
        bad = "-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n" % \
            base64.b64encode(bytes(der)).decode()
        with self.assertRaises(pki.PkiError) as cm:
            self.ca.issue_from_csr(bad, "alice")
        self.assertIn("signature", str(cm.exception))
        # a changed subject without a new signature
        der = bytearray(base64.b64decode("".join(other.strip().splitlines()[1:-1])))
        i = der.index(b"someone")
        der[i] = ord("S")
        bad2 = "-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n" % \
            base64.b64encode(bytes(der)).decode()
        with self.assertRaises(pki.PkiError):
            self.ca.issue_from_csr(bad2, "alice")
        self.assertEqual(self.index_text(), "")

    def test_weak_key_refused(self):
        _, csr = make_csr("rsa-2048")
        self.ca.issue_from_csr(csr, "alice")
        key = subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        small = subprocess.run(["openssl", "req", "-new", "-key", "/dev/stdin", "-subj", "/CN=x"],
                               input=key, stdout=subprocess.PIPE, check=True).stdout.decode()
        with self.assertRaises(pki.PkiError) as cm:
            self.ca.issue_from_csr(small, "alice")
        self.assertIn("2048", str(cm.exception))

    def test_bad_user_name(self):
        _, csr = make_csr("ed25519")
        for name in ("a/b", "a b", "", "x" * 65, "a\nb"):
            with self.assertRaises(pki.PkiError):
                self.ca.issue_from_csr(csr, name)

    def test_revoked_cert_is_in_crl(self):
        _, csr = make_csr("ed25519")
        _, serial, _ = self.ca.issue_from_csr(csr, "alice")
        self.assertTrue(self.ca.revoke(serial))
        self.ca.gen_crl()
        self.assertEqual(self.ca.revoked_serials(), {serial})
        text = subprocess.run(["openssl", "crl", "-in", self.ca.p("crl.pem"), "-noout", "-text"],
                              stdout=subprocess.PIPE, check=True).stdout.decode()
        self.assertIn(serial, text.upper())
