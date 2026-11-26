import unittest

import helpers  # noqa: F401
import accounts as acct

PIN1 = "sha256:EEdckfvr1RFzY9Di1QZKLSTburVA1g5a1196kqf4Ggw="
PIN2 = "sha256:u71INZi4g51GDiQRtoLUQJjxDlECXqu6UnkdLUaMTSE="
PIN3 = "sha256:s1bZtq+1tYCqfLLoLAqmzfICXVkFcldVI0CZP0+nYkI="


class NameTest(unittest.TestCase):
    def test_valid(self):
        for n in ["alice", "a", "Bob.Smith", "x_y-z", "u@example.com", "a" * 64]:
            self.assertTrue(acct.valid_name(n), n)

    def test_invalid(self):
        for n in ["", "a" * 65, ".", "..", "-x", "a b", "a/b", "a\\b", "a\nb", "\u00fc", "a;b", "a#b", "a:b"]:
            self.assertFalse(acct.valid_name(n), repr(n))

    def test_pin(self):
        acct.check_pin(PIN1)
        for bad in ["", "sha256:abc", "md5:" + PIN1[7:], PIN1 + "x", "sha256:" + "!" * 43 + "="]:
            with self.assertRaises(acct.AccountError):
                acct.check_pin(bad)


class AccountsTest(unittest.TestCase):
    def make(self):
        a = acct.Accounts()
        a.add_user("alice", "the boss")
        a.add_key("alice", PIN1, "laptop")
        a.add_key("alice", PIN2, "phone", serial="0A1B", source="ca")
        a.add_user("bob")
        a.add_key("bob", PIN3, "")
        return a

    def test_round_trip(self):
        a = self.make()
        a.user("alice").key("k2").state = "revoked"
        b = acct.Accounts.parse(a.render())
        self.assertEqual(b.render(), a.render())
        k = b.user("alice").key("k2")
        self.assertEqual((k.pin, k.serial, k.state, k.source), (PIN2, "0A1B", "revoked", "ca"))
        self.assertEqual(b.user("alice").notes, "the boss")

    def test_peers(self):
        a = self.make()
        rows = acct.parse_peers(acct.peers_text(a))
        self.assertEqual(rows, [("alice", PIN1, []), ("alice", PIN2, []), ("bob", PIN3, [])])

    def test_peers_disabled_and_revoked(self):
        a = self.make()
        a.user("alice").key("k2").state = "revoked"
        a.user("bob").enabled = False
        rows = acct.parse_peers(acct.peers_text(a))
        self.assertEqual(rows, [("alice", PIN1, []), ("alice", PIN2, ["disabled"]),
                                ("bob", PIN3, ["disabled"])])

    def test_peers_options_on_first_active_key(self):
        a = self.make()
        a.user("alice").options = acct.check_options("ifconfig-push=10.8.0.10 iroute=192.168.50.0/24")
        a.user("alice").key("k1").state = "revoked"
        rows = acct.parse_peers(acct.peers_text(a))
        self.assertEqual(rows[0], ("alice", PIN1, ["disabled"]))
        self.assertEqual(rows[1], ("alice", PIN2, ["ifconfig-push=10.8.0.10", "iroute=192.168.50.0/24"]))

    def test_label_comment_is_safe(self):
        a = acct.Accounts()
        a.add_user("alice")
        a.add_key("alice", PIN1, "x ifconfig-push=1.1.1.1")
        rows = acct.parse_peers(acct.peers_text(a))
        self.assertEqual(rows, [("alice", PIN1, [])])

    def test_label_rejects_control(self):
        a = acct.Accounts()
        a.add_user("alice")
        with self.assertRaises(acct.AccountError):
            a.add_key("alice", PIN1, "a\nb")

    def test_duplicates(self):
        a = self.make()
        with self.assertRaises(acct.AccountError):
            a.add_user("ALICE")
        with self.assertRaises(acct.AccountError):
            a.add_key("bob", PIN1)

    def test_options_validation(self):
        for bad in ["disabled", "foo=bar", "ifconfig-push=1.2.3.4;x", "iroute=1.2.3.0/24 evil"]:
            with self.assertRaises(acct.AccountError):
                acct.check_options(bad)
        self.assertEqual(acct.check_options("  iroute=10.1.0.0/16 "), "iroute=10.1.0.0/16")

    def test_parse_rejects_bad_files(self):
        with self.assertRaises(acct.AccountError):
            acct.Accounts.parse("[a/b]\nenabled = yes\n")
        with self.assertRaises(acct.AccountError):
            acct.Accounts.parse("[a]\nkey.k1.pin = nope\n")
        with self.assertRaises(acct.AccountError):
            acct.Accounts.parse("[a]\nkey.k1.pin = %s\n[b]\nkey.k1.pin = %s\n" % (PIN1, PIN1))
        with self.assertRaises(acct.AccountError):
            acct.Accounts.parse("[a]\n[A]\n")

    def test_next_key_id(self):
        a = self.make()
        a.delete_key("alice", "k1")
        self.assertEqual(a.user("alice").next_key_id(), "k3")


if __name__ == "__main__":
    unittest.main()
