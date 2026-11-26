"""Start the program as a normal user with --etc in a temp folder."""
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import unittest
import urllib.request

import helpers

HERE = helpers.APP


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class AppProcessTest(helpers.TmpCase):
    def start(self, *extra):
        self.port = free_port()
        etc = os.path.join(self.tmp, "etc")
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "noirconf.py"), "--etc", etc, "--port", str(self.port),
             "--manager", "spawn", "--log", os.path.join(self.tmp, "app.log")] + list(extra),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return etc
            except OSError:
                if self.proc.poll() is not None:
                    self.fail("the program ended: " + self.proc.stderr.read())
                time.sleep(0.2)
        self.fail("the program did not start")

    def stop(self):
        self.proc.terminate()
        try:
            return self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.communicate()

    def fetch(self, path, ctx=None):
        ctx = ctx or ssl._create_unverified_context()
        try:
            r = urllib.request.urlopen("https://127.0.0.1:%d%s" % (self.port, path), context=ctx, timeout=10)
            return r.status, r.read().decode("utf-8", "replace"), r
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e

    def test_start_and_serve(self):
        etc = self.start()
        try:
            crt, key = os.path.join(etc, "appserver.crt"), os.path.join(etc, "appserver.key")
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(crt).st_mode & 0o777, 0o644)
            self.assertEqual(os.stat(crt).st_uid, os.getuid())
            s, text, _ = self.fetch("/")
            self.assertEqual(s, 200)
            self.assertIn("Log in", text)
            self.assertIn("Account:", text)
            s, js, r = self.fetch("/static/htmx.min.js")
            self.assertEqual(s, 200)
            self.assertIn("htmx", js[:200])
            with open(crt) as f:
                pem = f.read()
            ctx = ssl.create_default_context(cadata=pem)
            s, text, _ = self.fetch("/login", ctx)
            self.assertEqual(s, 200)
            raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            ctx = ssl._create_unverified_context()
            with ctx.wrap_socket(raw) as tls:
                self.assertIn(tls.version(), ("TLSv1.2", "TLSv1.3"))
        finally:
            out, err = self.stop()
        m = re.search(r"SHA-256 fingerprint: ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})", out)
        self.assertTrue(m, out)
        self.assertIn("https://127.0.0.1:%d/" % self.port, out)
        self.assertIn("ssh -L", out)
        want = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-fingerprint", "-sha256"],
                              stdout=subprocess.PIPE).stdout.decode().strip().partition("=")[2]
        self.assertEqual(m.group(1), want)
        with open(os.path.join(self.tmp, "app.log")) as f:
            self.assertIn("created the web certificate", f.read())

    def test_cert_is_kept_and_renewed(self):
        etc = self.start()
        self.stop()
        crt = os.path.join(etc, "appserver.crt")
        with open(crt, "rb") as f:
            first = f.read()
        self.start()
        self.stop()
        with open(crt, "rb") as f:
            self.assertEqual(f.read(), first)
        os.utime(crt)
        import pki
        pki.make_self_signed(crt, os.path.join(etc, "appserver.key"), "noirconf", ["localhost"], days=10)
        with open(crt, "rb") as f:
            short = f.read()
        self.start()
        self.stop()
        with open(crt, "rb") as f:
            self.assertNotEqual(f.read(), short)

    def test_refuses_under_etc_when_not_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        r = subprocess.run([sys.executable, os.path.join(HERE, "noirconf.py"), "--etc", "/etc/noirvpn/server",
                            "--port", str(free_port())], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=20)
        self.assertEqual(r.returncode, 1)
        self.assertIn("run as root", r.stderr)
        self.assertFalse(os.path.exists("/etc/noirvpn/server/appserver.crt"))


if __name__ == "__main__":
    unittest.main()
