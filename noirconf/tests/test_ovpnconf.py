import unittest

import helpers  # noqa: F401
import ovpnconf
from ovpnconf import Config, ConfError, tokenize

SAMPLE = """# my server
port 1194
proto udp
server 10.8.0.0 255.255.255.0   # the tunnel net
push "route 10.9.0.0 255.255.255.0"
push "dhcp-option DNS 10.8.0.1"
;old-option 1
my-custom-option "a b" 'c d' e\\ f
<ca>
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
</ca>
verb 3
"""


class TokenizeTest(unittest.TestCase):
    def test_quotes(self):
        self.assertEqual(tokenize('push "route 1.2.3.4 255.0.0.0"'), ["push", "route 1.2.3.4 255.0.0.0"])
        self.assertEqual(tokenize("a 'b c' d\\ e"), ["a", "b c", "d e"])
        self.assertEqual(tokenize('a "x \\"y\\" z"'), ["a", 'x "y" z'])

    def test_comment(self):
        self.assertEqual(tokenize("port 1 # note"), ["port", "1"])
        self.assertEqual(tokenize("# all"), [])
        self.assertEqual(tokenize("a b#c"), ["a", "b#c"])

    def test_errors(self):
        with self.assertRaises(ConfError):
            tokenize('a "open')
        with self.assertRaises(ConfError):
            tokenize("a 'open")

    def test_quote_round_trip(self):
        for arg in ["plain", "with space", 'q"uote', "back\\slash", "", "#x", "it's", ";semi"]:
            self.assertEqual(tokenize("x " + ovpnconf.quote_arg(arg)), ["x", arg], arg)

    def test_quote_refuses_newline(self):
        with self.assertRaises(ConfError):
            ovpnconf.quote_arg("a\nb")


class ConfigTest(unittest.TestCase):
    def test_round_trip_unchanged(self):
        self.assertEqual(Config.parse(SAMPLE).render(), SAMPLE)

    def test_round_trip_no_final_newline(self):
        self.assertEqual(Config.parse("port 1").render(), "port 1")

    def test_queries(self):
        c = Config.parse(SAMPLE)
        self.assertEqual(c.first("server"), ["10.8.0.0", "255.255.255.0"])
        self.assertEqual(len(c.get("push")), 2)
        self.assertEqual(c.first("my-custom-option"), ["a b", "c d", "e f"])
        self.assertIn("BEGIN CERTIFICATE", c.block("ca"))
        self.assertEqual(c.block_tags(), ["ca"])
        self.assertIsNone(c.first("old-option"))

    def test_set_same_value_keeps_text(self):
        c = Config.parse(SAMPLE)
        self.assertFalse(c.set_option("server", [["10.8.0.0", "255.255.255.0"]]))
        self.assertFalse(c.set_option("push", c.get("push")))
        self.assertEqual(c.render(), SAMPLE)

    def test_change_keeps_unmanaged(self):
        c = Config.parse(SAMPLE)
        self.assertTrue(c.set_option("port", [["443"]]))
        self.assertTrue(c.set_option("push", [["route 10.9.0.0 255.255.255.0"]]))
        out = c.render()
        self.assertIn("port 443\n", out)
        self.assertNotIn("dhcp-option", out)
        self.assertIn("my-custom-option", out)
        self.assertIn("# my server", out)
        self.assertIn(";old-option 1", out)
        self.assertIn("<ca>", out)
        self.assertIn("server 10.8.0.0 255.255.255.0   # the tunnel net", out)
        again = Config.parse(out)
        self.assertEqual(again.first("port"), ["443"])
        self.assertEqual(again.first("my-custom-option"), ["a b", "c d", "e f"])

    def test_add_goes_before_blocks(self):
        c = Config.parse(SAMPLE)
        c.set_option("max-clients", [["10"]])
        out = c.render()
        self.assertLess(out.index("max-clients 10"), out.index("<ca>"))

    def test_add_more_values_after_last(self):
        c = Config.parse(SAMPLE)
        c.set_option("push", [["a"], ["b"], ["c"]])
        self.assertEqual([x[0] for x in Config.parse(c.render()).get("push")], ["a", "b", "c"])

    def test_remove(self):
        c = Config.parse(SAMPLE)
        c.remove_option("push")
        self.assertFalse(c.has("push"))
        self.assertIn("verb 3", c.render())

    def test_double_dash(self):
        self.assertEqual(Config.parse("--port 5\n").first("port"), ["5"])

    def test_unclosed_block(self):
        with self.assertRaises(ConfError):
            Config.parse("<ca>\nabc\n")

    def test_block_comment_lines_kept(self):
        text = "<tls-crypt>\n#\n# 2048 bit\n-----BEGIN X-----\nab\n-----END X-----\n</tls-crypt>\n"
        self.assertEqual(Config.parse(text).render(), text)


if __name__ == "__main__":
    unittest.main()
