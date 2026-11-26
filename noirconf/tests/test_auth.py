import ctypes
import os
import unittest

import helpers
import auth


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class LoginUserTest(unittest.TestCase):
    def test_order(self):
        self.assertEqual(auth.login_user({"DOAS_USER": "d", "SUDO_USER": "s"}), "d")
        self.assertEqual(auth.login_user({"SUDO_USER": "s"}), "s")
        self.assertEqual(auth.login_user({}), "root")

    def test_bad_names_ignored(self):
        self.assertEqual(auth.login_user({"SUDO_USER": "a b;c"}), "root")
        self.assertEqual(auth.login_user({"SUDO_USER": "-x"}), "root")


class SessionTest(unittest.TestCase):
    def test_create_get_destroy(self):
        s = auth.SessionStore()
        tok, sess = s.create("root")
        self.assertRegex(tok, r"^[0-9a-f]{64}$")
        self.assertIs(s.get(tok), sess)
        self.assertIsNone(s.get("0" * 64))
        self.assertIsNone(s.get(None))
        self.assertIsNone(s.get("../../x"))
        s.destroy(tok)
        self.assertIsNone(s.get(tok))

    def test_tokens_differ(self):
        s = auth.SessionStore()
        self.assertNotEqual(s.create("a")[0], s.create("a")[0])

    def test_idle_timeout(self):
        clock = FakeClock()
        s = auth.SessionStore(idle=1800, clock=clock)
        tok, _ = s.create("root")
        clock.t += 1700
        self.assertIsNotNone(s.get(tok))
        clock.t += 1700
        self.assertIsNotNone(s.get(tok))
        clock.t += 1801
        self.assertIsNone(s.get(tok))
        self.assertEqual(len(s.data), 0)

    def test_token_not_stored_in_clear(self):
        s = auth.SessionStore()
        tok, _ = s.create("root")
        self.assertNotIn(tok, s.data)


class CsrfTest(unittest.TestCase):
    def test_csrf(self):
        s = auth.SessionStore()
        _, sess = s.create("root")
        self.assertTrue(auth.csrf_ok(sess, sess.csrf))
        self.assertFalse(auth.csrf_ok(sess, "x" * len(sess.csrf)))
        self.assertFalse(auth.csrf_ok(sess, ""))
        self.assertFalse(auth.csrf_ok(sess, None))
        self.assertFalse(auth.csrf_ok(None, "a"))

    def test_login_token(self):
        g = auth.LoginGuard()
        n = g.new_nonce()
        t = g.token_for(n)
        self.assertTrue(g.token_ok(n, t))
        self.assertFalse(g.token_ok(n, "bad"))
        self.assertFalse(g.token_ok(None, t))
        self.assertFalse(g.token_ok(g.new_nonce(), t))


class RateLimitTest(unittest.TestCase):
    def test_block_after_five(self):
        clock = FakeClock()
        g = auth.LoginGuard(clock)
        for i in range(4):
            g.fail("1.2.3.4")
        self.assertFalse(g.blocked("1.2.3.4"))
        g.fail("1.2.3.4")
        self.assertTrue(g.blocked("1.2.3.4"))
        self.assertFalse(g.blocked("5.6.7.8"))
        clock.t += 61
        self.assertFalse(g.blocked("1.2.3.4"))

    def test_success_clears(self):
        g = auth.LoginGuard(FakeClock())
        for i in range(3):
            g.fail("a")
        g.ok("a")
        for i in range(4):
            g.fail("a")
        self.assertFalse(g.blocked("a"))


class ShadowTest(helpers.TmpCase):
    def setUp(self):
        super().setUp()
        try:
            self.lib = ctypes.CDLL("libcrypt.so.1")
        except OSError:
            self.skipTest("no libcrypt")
        self.lib.crypt.restype = ctypes.c_char_p
        self.lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.hash = self.lib.crypt(b"correct horse", b"$6$saltsalt$").decode()
        self.path = os.path.join(self.tmp, "shadow")
        with open(self.path, "w") as f:
            f.write("root:!:1:::::\nalice:%s:19000:0:99999:7:::\nbob:*:1:::::\ncarl::1:::::\n" % self.hash)
        self.sh = auth.ShadowAuth(self.path)

    def test_good_and_bad(self):
        self.assertTrue(self.sh.check("alice", "correct horse"))
        self.assertFalse(self.sh.check("alice", "wrong"))
        self.assertFalse(self.sh.check("alice", ""))

    def test_locked_and_missing(self):
        for u in ("root", "bob", "carl", "nobody"):
            self.assertFalse(self.sh.check(u, "anything"))


class PamTest(unittest.TestCase):
    """The PAM call with a fake library, to cover the conversation code."""

    class FakeLib:
        def __init__(self, ok=True):
            self.ok = ok
            self.calls = []

        def _f(self, name, ret=0):
            def fn(*a):
                self.calls.append(name)
                return ret
            return type("F", (), {"argtypes": None, "__call__": lambda s, *a: fn(*a)})()

    def test_missing_library(self):
        orig = auth._load
        auth._load = lambda names, short: None if short == "pam" else orig(names, short)
        try:
            with self.assertRaises(OSError):
                auth.PamAuth()
            obj, kind = auth.make_authenticator()
            self.assertEqual(kind, "shadow")
        finally:
            auth._load = orig

    def test_conversation_gives_password(self):
        """Run the real conv callback through a fake pam_authenticate."""
        pam = auth.PamAuth.__new__(auth.PamAuth)
        pam.service = "login"
        libc = ctypes.CDLL(None)
        libc.calloc.restype = ctypes.c_void_p
        libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        libc.strdup.restype = ctypes.c_void_p
        libc.strdup.argtypes = [ctypes.c_char_p]
        libc.free.argtypes = [ctypes.c_void_p]
        pam.libc = libc
        got = {}

        class Lib:
            def pam_start(s, service, user, conv, handle):
                got["conv"] = conv._obj
                got["user"] = user
                return 0

            def pam_authenticate(s, h, flags):
                conv = got["conv"].conv
                msg = auth._PamMessage(auth.PAM_PROMPT_ECHO_OFF, b"Password: ")
                ptr = ctypes.pointer(msg)
                arr = (ctypes.POINTER(auth._PamMessage) * 1)(ptr)
                resp = ctypes.POINTER(auth._PamResponse)()
                rc = conv(1, arr, ctypes.byref(resp), None)
                got["pw"] = ctypes.string_at(resp[0].resp)
                libc.free(resp[0].resp)
                libc.free(ctypes.cast(resp, ctypes.c_void_p))
                return rc if got["pw"] == b"pw" else 7

            def pam_acct_mgmt(s, h, flags):
                return 0

            def pam_end(s, h, rc):
                return 0
        pam.lib = Lib()
        self.assertTrue(pam.check("alice", "pw"))
        self.assertEqual(got["user"], b"alice")
        self.assertFalse(pam.check("alice", "other"))
        self.assertFalse(pam.check("alice", ""))
        self.assertFalse(pam.check("alice", "a\0b"))


if __name__ == "__main__":
    unittest.main()
