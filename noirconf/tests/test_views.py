import os
import re
import unittest

import helpers
import optforms
import store
import views


class WidgetTest(unittest.TestCase):
    def data(self, **over):
        d = {"connected": 3, "accounts": 7,
             "system": {"load": "0.1 0.2 0.3", "mem_used": 2 * 1024 ** 3, "mem_total": 8 * 1024 ** 3},
             "uptime": 3700, "listen": ["udp [::]:1194", "tcp 0.0.0.0:443"],
             "externals": [("vpn.example.com", "1194", "udp")]}
        d.update(over)
        return d

    def test_clients_system_server(self):
        h = views.widgets_html("srv", self.data())
        self.assertNotIn("box-icon", h)
        self.assertIn('<div class="big">3 connected</div>', h)
        self.assertIn("7 accounts", h)
        self.assertIn('<progress class="bar" max="100" value="25">', h)
        self.assertIn("2.0 GiB / 8.0 GiB", h)
        self.assertIn('<div class="box-line">Load 0.1</div>', h)
        self.assertNotIn("0.2", h)
        self.assertLess(h.index("Memory"), h.index("Load"))
        self.assertIn("Listening on udp [::]:1194", h)
        self.assertIn("Listening on tcp 0.0.0.0:443", h)
        self.assertIn("Connections to", h)
        self.assertLess(h.index("Listening on"), h.index("Connections to"))
        self.assertIn("vpn.example.com:1194 udp", h)
        self.assertNotIn("style=", h)

    def test_box_fills(self):
        h = views.widgets_html("srv", self.data())
        for c in ("blue", "green", "amber", "purple"):
            self.assertIn('class="box box-%s"' % c, h)
        css = helpers.css()
        self.assertRegex(css, r"\.box-blue \{ background:")
        self.assertRegex(css, r"\.box-title \{ font-weight: 400;.*text-transform: uppercase")
        self.assertRegex(css, r"\.big \{ font-size: 20px")

    def test_stopped(self):
        h = views.widgets_html("srv", self.data(uptime=None, listen=[], externals=[]))
        self.assertIn("stopped", h)
        self.assertIn("no external address", h)


class DashboardTest(unittest.TestCase):
    def test_stats_table(self):
        status = {"mode": "server", "uptime_s": 5, "server": {"peers": 1, "listen": ["udp [::]:1194", "tcp 0.0.0.0:443"]}}
        stats = {"uptime_s": 5, "datapath": "userspace", "totals": {"bytes_in": 9},
                 "counters": {"drops": {"ring": 0}, "sent": 4, "errors": {"send": 2}}}
        h = views.dashboard_html("s", None, status, stats, "<div>peers</div>")
        self.assertIn("Noir server status", h)
        self.assertNotIn("Daemon status", h)
        self.assertNotIn("counters.", h)
        self.assertIn("<th>server.peers</th>", h)
        self.assertIn("<th>totals.bytes_in</th>", h)
        self.assertEqual(h.count("<th>uptime_s</th>"), 1)
        self.assertIn("<td>udp [::]:1194, tcp 0.0.0.0:443</td>", h)
        self.assertNotIn("[&quot;", h)
        # Stats is its own table, right of the status table, with four columns
        self.assertIn('<div class="two"><div class="card"><h3>Noir server status</h3>', h)
        st = h[h.index("<h3>Stats</h3>"):]
        self.assertIn('<table class="table table-kv table-kv4">', st)
        self.assertIn("<tr><th>drops.ring</th><td>0</td><th>sent</th><td>4</td></tr>", st)
        self.assertIn("<tr><th>errors.send</th><td>2</td><th></th><td></td></tr>", st)
        self.assertLess(h.index("Noir server status"), h.index("<h3>Stats</h3>"))
        self.assertNotIn("<th>sent</th>", h[:h.index("<h3>Stats</h3>")])
        css = helpers.css()
        self.assertIn("@media (max-width: 900px) { .two { grid-template-columns: 1fr; } }", css)
        self.assertRegex(css, r"\.two \{ display: grid; grid-template-columns: 1fr 1fr;")

    def test_no_stats(self):
        h = views.dashboard_html("s", None, {"mode": "server"}, None, "")
        self.assertNotIn("Stats", h)


class UserPageTest(unittest.TestCase):
    def test_texts_and_indent(self):
        import accounts as acct
        a = acct.Accounts()
        u = a.add_user("alice")
        h = views.user_html("srv", u, [("vpn.example.com", "1194", "udp")], csrf="x")
        self.assertIn("Load key from file", h)
        self.assertNotIn(">Load from file", h)
        self.assertIn("<h3>Create client profile</h3>", h)
        self.assertNotIn("<h3>Client profile</h3>", h)
        gen = h.index('value="generate"')
        own = h.index('value="own"')
        self.assertRegex(h[gen:own], r'<div class="indent">.*name="pass1".*name="pass2".*</div>')
        self.assertRegex(h[own:], r'<div class="indent"><textarea name="cert"')


class ConfigFormTest(unittest.TestCase):
    def setUp(self):
        self.options = optforms.load_options()
        self.opts = optforms.all_options()
        vals = optforms.defaults("srv", "/etc/x")
        self.html = views.option_fields(self.options, vals)

    def test_tabs(self):
        ids = [g["id"] for g in self.options["groups"]]
        for gid in ids:
            self.assertIn('id="tab-%s"' % gid, self.html)
            self.assertIn('id="panel-%s"' % gid, self.html)
            self.assertIn('<label for="tab-%s">' % gid, self.html)
        self.assertEqual(len(re.findall(r'class="tabradio"', self.html)), len(ids))
        self.assertEqual(len(re.findall(r" checked>", re.findall(r'<input type="radio"[^>]*>', self.html)[0])), 1)
        css = helpers.css()
        for gid in ids:
            self.assertIn("#tab-%s:checked ~ .tabbar" % gid, css, gid)
            self.assertIn("#tab-%s:checked ~ .panels #panel-%s" % (gid, gid), css, gid)
        self.assertNotIn("<script", self.html)

    def test_field_format(self):
        m = re.search(r'<div class="field" title="[^"]*"><label class="frow"><span><span class="fname">'
                      r'Port</span> <code>port</code></span><input name="o.port" value="1194" '
                      r'class="mono"><span class="def">\(default 1194\)</span>', self.html)
        self.assertTrue(m)

    def test_no_hint_lines_and_tooltips(self):
        self.assertNotIn('class="hint">local and remote port', self.html)
        self.assertIn('title="local and remote port"', self.html)

    def test_network_order(self):
        panel = self.html[self.html.index('id="panel-network"'):self.html.index('id="panel-service"')]
        names = re.findall(r'<code>([a-z0-9-]+)</code>', panel)
        self.assertEqual(names[:2], ["server", "server-ipv6"])
        for gone in ("dev", "dev-type", "persist-tun", "ccd-exclusive"):
            self.assertNotIn(gone, names)

    def test_service_tab(self):
        panel = self.html[self.html.index('id="panel-service"'):self.html.index('id="panel-identity"')]
        names = re.findall(r'<code>([a-z0-9-]+)</code>', panel)
        self.assertEqual(names[:2], ["port", "proto"])
        self.assertNotIn("bind", names)
        self.assertNotIn("tls-server", [n for n in names if n != "proto tls-server"])
        self.assertIn('<select name="o.proto">', panel)
        self.assertIn('Run as TLS server', panel)
        sw = panel.index('name="v.tls"')
        block = panel.index('class="indent tls-block"')
        self.assertLess(sw, block)
        for n in ("tls-transport-ws", "tls-transport-cert", "tls-transport-accept-tcp"):
            self.assertGreater(panel.index("<code>%s</code>" % n), block, n)
        after = panel[block:]
        self.assertIn("tls-transport-ws", after)
        css = helpers.css()
        self.assertIn(".tlsgroup .toggle:checked ~ .tls-block { display: block; }", css)
        self.assertRegex(css, r"\.tls-block \{ display: none;")

    def test_tls_checked_state(self):
        vals = {"proto": [["tls-server"]]}
        h = views.option_fields(self.options, vals)
        self.assertRegex(h, r'id="v-tls" name="v.tls" class="toggle" checked>')
        self.assertNotRegex(self.html, r'id="v-tls" name="v.tls" class="toggle" checked>')

    def test_dco_checkbox(self):
        panel = self.html[self.html.index('id="panel-datapath"'):self.html.index('id="panel-bus"')]
        self.assertIn('name="v.dco"', panel)
        self.assertIn("Use kernel DCO", panel)
        self.assertIn("use DCO only if you have a specific need", panel)
        self.assertNotIn("dco-socket", panel)
        self.assertNotIn("disable-dco", panel)
        self.assertIn("<code>workers</code>", panel)
        h = views.option_fields(self.options, {"datapath": [["dco"]]})
        self.assertRegex(h, r'name="v.dco" checked>')

    def test_dco_readonly_for_udco_and_auto(self):
        for v in ("udco", "auto"):
            h = views.option_fields(self.options, {"datapath": [[v]]})
            self.assertIn("<code>datapath %s</code>" % v, h)
            self.assertNotIn('name="v.dco"', h)

    def test_verb_dropdown(self):
        panel = self.html[self.html.index('id="panel-logging"'):self.html.index('id="panel-other"')]
        self.assertIn('<select name="o.verb">', panel)
        for n in range(5):
            self.assertIn('<option value="%d">%d:' % (n, n), panel)
        self.assertNotIn('<option value="5"', panel)
        h = views.option_fields(self.options, {"verb": [["7"]]})
        self.assertIn('<option value="7" selected>7</option>', h)
        h = views.option_fields(self.options, {"verb": [["2"]]})
        self.assertIn('<option value="2" selected>', h)

    def test_other_tab_has_no_mlock(self):
        self.assertNotIn("<code>mlock</code>", self.html)


class Round3FormTest(unittest.TestCase):
    def setUp(self):
        self.options = optforms.load_options()
        self.html = views.option_fields(self.options, optforms.defaults("srv", "/etc/x"))

    def panel(self, a, b):
        return self.html[self.html.index('id="panel-%s"' % a):self.html.index('id="panel-%s"' % b)]

    def test_no_not_applied_tag(self):
        self.assertNotIn("not applied yet", self.html)
        self.assertNotIn("tag-off", self.html)

    def test_code_colour(self):
        self.assertRegex(helpers.css(), r"\.field code \{ color: #[0-9a-f]{6}; \}")
        self.assertIn("code, .mono, pre { font-family: var(--mono);", helpers.css())

    def test_default_and_accepts_text(self):
        self.assertIn('<span class="def">(default udp; accepts udp, tcp-server, tls-server)</span>', self.html)
        self.assertIn("(default prefer; accepts off, prefer, require)", self.html)
        self.assertIn("(default require; accepts require, optional, none)", self.html)
        self.assertIn("(accepts 1.2, 1.3)", self.html)
        self.assertIn("(default 1400)", self.html)

    def test_service_tab_removed(self):
        names = re.findall(r"<code>([a-z0-9-]+)</code>", self.panel("service", "identity"))
        for n in ("mode", "lport", "multihome", "ping-exit"):
            self.assertNotIn(n, names)
        self.assertIn("tls-transport-accept-tcp", names)

    def test_tls_line_and_proto_state(self):
        p = self.panel("service", "identity")
        self.assertIn("serves noirvpn clients over TCP inside TLS", p)
        self.assertIn("looks like HTTPS", p)
        self.assertIn("UDP is not served on this port", p)
        self.assertLess(p.index("UDP is not served"), p.index('class="indent tls-block"'))
        self.assertIn('<select name="o.proto">', p)
        on = views.option_fields(self.options, {"proto": [["tls-server"]]})
        self.assertIn('<select name="o.proto" disabled>', on)
        js = open(os.path.join(helpers.APP, "static", "app.js"), encoding="utf-8").read()
        self.assertIn('"v-tls"', js)
        self.assertIn("sel.disabled = box.checked", js)

    def test_ciphers_checkboxes(self):
        p = self.panel("tls", "datapath")
        for c in optforms.CIPHERS:
            self.assertIn('name="v.cipher.%s">' % c, p)
        self.assertIn("(default AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305; accepts AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)", p)
        self.assertNotIn('name="o.data-ciphers"', p)
        self.assertNotIn("ncp-ciphers", p)
        self.assertNotIn("allow-compression", p)
        h = views.option_fields(self.options, {"data-ciphers": [["CHACHA20-POLY1305:AES-192-GCM"]]})
        self.assertIn('name="v.cipher.CHACHA20-POLY1305" checked>', h)
        self.assertIn('name="v.cipher.AES-256-GCM">', h)
        self.assertIn("Also in the file: AES-192-GCM", h)


class UserKeyBlockTest(unittest.TestCase):
    def test_block(self):
        import accounts as acct
        u = acct.Accounts().add_user("alice")
        h = views.user_html("srv", u, [], csrf="x")
        self.assertIn("<h3>Add a key or sign a CSR</h3>", h)
        self.assertIn("The server pins the public key of the user", h)
        self.assertIn('hx-post="/s/srv/u/alice/key/csr"', h)
        self.assertIn("Sign a certificate request", h)
        self.assertIn('data-fill="csr"', h)
        self.assertNotIn("Signed certificate", h)
        h = views.user_html("srv", u, [], csrf="x", signed="-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n")
        self.assertIn("Signed certificate", h)
        self.assertIn("Download alice.crt", h)
        self.assertIn('action="/s/srv/u/alice/cert/download"', h)


class ExternalAddressTest(unittest.TestCase):
    def test_refused(self):
        for bad in ["127.0.0.1", "127.5.6.7 443", "::1", "localhost", "LOCALHOST. 1194 tcp", "0.0.0.0",
                    "::", "foo.localhost", "::ffff:127.0.0.1", "[::1]"]:
            with self.assertRaises(store.StoreError, msg=bad) as cm:
                store.parse_externals(bad)
            self.assertRegex(str(cm.exception), r"loopback|local computer|unspecified|not a host name", bad)

    def test_message_is_clear(self):
        with self.assertRaises(store.StoreError) as cm:
            store.parse_externals("127.0.0.1")
        self.assertIn("127.0.0.1 is a loopback address", str(cm.exception))
        self.assertIn("other computers cannot reach it", str(cm.exception))

    def test_accepted(self):
        got = store.parse_externals("vpn.example.com\n203.0.113.5 443 tcp\n2001:db8::1 1194 udp")
        self.assertEqual([g[0] for g in got], ["vpn.example.com", "203.0.113.5", "2001:db8::1"])
        store.parse_externals("10.0.0.5")

    def test_lenient_read(self):
        got = store.parse_externals("127.0.0.1\nvpn.example.com 1194\nlocalhost\n0.0.0.0 1 udp\nb.example",
                                    strict=False)
        self.assertEqual([g[0] for g in got], ["vpn.example.com", "b.example"])


class ExternalIniTest(helpers.TmpCase):
    def test_ini_with_loopback_is_filtered(self):
        paths = store.Paths(self.tmp, "srv")
        os.makedirs(paths.data)
        with open(paths.ini, "w") as f:
            f.write("[external]\nremote.1 = 127.0.0.1 1194 udp\nremote.2 = vpn.example.com 443 tcp\n"
                    "remote.3 = localhost 1 udp\nremote.4 = 0.0.0.0 1 udp\n")
        self.assertEqual(store.read_externals(paths), [("vpn.example.com", "443", "tcp")])

    def test_saving_loopback_refused(self):
        import fixtures
        st = fixtures.StoreCase("run")
        st.setUp()
        try:
            with open(os.path.join(st.etc, "a.conf"), "w") as f:
                f.write("port 1194\n")
            os.makedirs(os.path.join(st.etc, "a"))
            with self.assertRaises(store.StoreError):
                st.store.set_externals("a", "127.0.0.1")
            with self.assertRaises(store.StoreError):
                st.store.init_data("a", "localhost")
        finally:
            st.tearDown()


if __name__ == "__main__":
    unittest.main()


class NavbarTest(unittest.TestCase):
    def shell(self, servers=("srv",), server="srv", active="dash"):
        return views.shell("T", "<p>x</p>", "tok", "root", server, list(servers), active)

    def test_one_bar_and_no_sidebar(self):
        h = self.shell()
        self.assertEqual(h.count('<header'), 1)
        self.assertNotIn("sidebar", h)
        self.assertNotIn("topbar", h)
        self.assertIn('<a class="navbrand" href="/s/srv/" hx-get="/s/srv/" hx-push-url="true">NOIR</a>', h)
        order = [h.index(x) for x in ('class="navbrand"', 'id="main-nav"', 'class="navright"')]
        self.assertEqual(order, sorted(order))
        labels = re.findall(r'<li><a[^>]*>([^<]+)</a></li>', h)
        self.assertEqual(labels, ["Dashboard", "Users", "Config", "Service", "New server", "Help"])
        self.assertIn('<a class="active" href="/s/srv/" ', h)
        right = h[h.index('class="navright"'):]
        self.assertIn("root", right)
        self.assertIn("Log out", right)
        self.assertIn('action="/logout"', right)

    def test_selector(self):
        one = self.shell()
        self.assertIn("<b>srv</b>", one)
        self.assertNotIn("<select", one)
        two = self.shell(servers=("a", "srv"))
        self.assertIn('<select name="server" hx-get="/switch"', two)
        self.assertLess(two.index("<select"), two.index('class="who"'))

    def test_without_server(self):
        h = self.shell(servers=(), server=None, active="new")
        self.assertIn('href="/" ', h)
        labels = re.findall(r'<li><a[^>]*>([^<]+)</a></li>', h)
        self.assertEqual(labels, ["New server", "Help"])

    def test_login_has_no_menu(self):
        h = views.login_page("root", "nonce")
        self.assertNotIn("navbar", h)
        self.assertNotIn("main-nav", h)

    def test_toggle_without_script(self):
        h = self.shell()
        self.assertIn('<input type="checkbox" id="nav-toggle" class="navtoggle">', h)
        self.assertIn('<label for="nav-toggle" class="navburger"', h)
        self.assertNotIn("<script>", h)
        self.assertNotIn("onclick", h)
        css = helpers.css()
        self.assertIn("#3d5c6e", css)
        self.assertIn(".navtoggle:checked ~ nav, .navtoggle:checked ~ .navright { display: block; }", css)
        self.assertRegex(css, r"@media \(max-width: 760px\) \{\n  \.navburger \{ display: block; \}")

    def test_fragment_swaps_nav(self):
        f = views.fragment("T", "<p>x</p>", "srv", ["srv"], "users")
        self.assertIn('<nav id="main-nav" hx-swap-oob="true">', f)
        self.assertIn('<a class="active" href="/s/srv/users"', f)

    def test_card_headings_have_a_rule(self):
        self.assertRegex(helpers.css(), r"\.card h3 \{ border-bottom: 1px solid var\(--line\); padding-bottom: 6px;")
