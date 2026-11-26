import http.client
import json
import os
import re
import threading
import unittest
import urllib.parse

import helpers
import auth
import fixtures
import web


class FakeAuth:
    def __init__(self):
        self.calls = []

    def check(self, user, password):
        self.calls.append((user, password))
        return password == "good password"


class Client:
    def __init__(self, port):
        self.port = port
        self.cookies = {}
        self.last = None

    def request(self, method, path, form=None, headers=None, body=None):
        h = dict(headers or {})
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if body is not None:
            data = body
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        text = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val = rest.split(";")[0]
                if val:
                    self.cookies[name] = val
                else:
                    self.cookies.pop(name, None)
        c.close()
        self.last = r
        return r.status, r, text.decode("utf-8", "replace")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, form=None, **kw):
        return self.request("POST", path, form=form or {}, **kw)


class WebCase(fixtures.StoreCase):
    needs_noirvpn = False

    def setUp(self):
        super().setUp()
        self.auth = FakeAuth()
        self.app = web.App(self.etc, self.store, self.svc, "tester", self.auth)
        self.app.fail_delay = 0
        self.httpd = web.Server(("127.0.0.1", 0), self.app)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.c = Client(self.port)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def login(self, c=None):
        c = c or self.c
        status, r, text = c.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', text).group(1)
        status, r, text = c.post("/login", {"csrf": csrf, "password": "good password"})
        self.assertEqual(status, 303, text)
        return c

    def csrf(self, c=None):
        c = c or self.c
        sess = self.app.sessions.get(c.cookies[auth.COOKIE])
        return sess.csrf

    def post(self, path, form=None, c=None):
        c = c or self.c
        return c.post(path, form, headers={"X-CSRF-Token": self.csrf(c), "HX-Request": "true"})


class LoginTest(WebCase):
    def test_redirect_when_logged_out(self):
        s, r, _ = self.c.get("/")
        self.assertEqual((s, r.getheader("Location")), (303, "/login"))
        s, r, _ = self.c.get("/s/x/users", headers={"HX-Request": "true"})
        self.assertEqual((s, r.getheader("HX-Redirect")), (401, "/login"))
        s, r, _ = self.c.post("/servers/create", {})
        self.assertEqual(s, 303)

    def test_login_page_shows_fixed_account(self):
        s, r, text = self.c.get("/login")
        self.assertEqual(s, 200)
        self.assertIn("<b>tester</b>", text)
        self.assertNotIn('name="user"', text)
        self.assertIn("noirconf_login=", r.getheader("Set-Cookie"))

    def test_security_headers(self):
        s, r, _ = self.c.get("/login")
        self.assertEqual(r.getheader("Content-Security-Policy").split(";")[0], "default-src 'self'")
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("Referrer-Policy"), "same-origin")
        s, r, _ = self.c.get("/static/app.js")
        self.assertEqual(r.getheader("Content-Security-Policy").split(";")[0], "default-src 'self'")

    def test_login_without_csrf_refused(self):
        s, _, _ = self.c.post("/login", {"password": "good password"})
        self.assertEqual(s, 403)
        self.assertEqual(self.auth.calls, [])

    def test_wrong_password(self):
        s, r, text = self.c.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', text).group(1)
        s, r, text = self.c.post("/login", {"csrf": csrf, "password": "nope"})
        self.assertEqual(s, 401)
        self.assertIn("not right", text)
        self.assertNotIn(auth.COOKIE, self.c.cookies)
        self.assertNotIn("nope", text)

    def test_cookie_flags_and_logout(self):
        self.login()
        s, r, _ = self.c.get("/help")
        self.assertEqual(s, 200)
        sc = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        self.assertEqual(sc, [])
        token = self.c.cookies[auth.COOKIE]
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        s, _, _ = self.c.post("/logout", {"csrf": self.csrf()})
        self.assertEqual(s, 303)
        self.assertIsNone(self.app.sessions.get(token))
        self.assertEqual(self.c.get("/help")[0], 303)

    def test_cookie_attributes(self):
        s, r, text = self.c.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', text).group(1)
        s, r, _ = self.c.post("/login", {"csrf": csrf, "password": "good password"})
        cookie = [v for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith(auth.COOKIE)][0]
        for attr in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
            self.assertIn(attr, cookie)

    def test_rate_limit(self):
        s, r, text = self.c.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', text).group(1)
        for i in range(5):
            s, _, text = self.c.post("/login", {"csrf": csrf, "password": "bad%d" % i})
            self.assertEqual(s, 401)
            csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', text).group(1)
        n = len(self.auth.calls)
        s, _, text = self.c.post("/login", {"csrf": csrf, "password": "good password"})
        self.assertEqual(s, 429)
        self.assertEqual(len(self.auth.calls), n)
        self.assertNotIn(auth.COOKIE, self.c.cookies)

    def test_session_idle_timeout(self):
        clock = [1000.0]
        self.app.sessions.clock = lambda: clock[0]
        self.login()
        self.assertEqual(self.c.get("/help")[0], 200)
        clock[0] += 1801
        self.assertEqual(self.c.get("/help")[0], 303)

    def test_polling_does_not_extend_session(self):
        clock = [1000.0]
        self.app.sessions.clock = lambda: clock[0]
        self.login()
        with open(os.path.join(self.etc, "server.conf"), "w") as f:
            f.write("port 1194\n")
        for i in range(3):
            clock[0] += 1000
            s, _, _ = self.c.get("/s/server/widgets", headers={"X-Poll": "1", "HX-Request": "true"})
            if i < 1:
                self.assertEqual(s, 200)
        s, _, _ = self.c.get("/s/server/widgets", headers={"X-Poll": "1", "HX-Request": "true"})
        self.assertEqual(s, 401)


class CsrfTest(WebCase):
    def test_post_needs_token(self):
        self.login()
        s, _, text = self.c.post("/s/x/users/add", {"user": "a"})
        self.assertEqual(s, 403)
        s, _, text = self.c.post("/s/x/users/add", {"user": "a"}, headers={"X-CSRF-Token": "wrong"})
        self.assertEqual(s, 403)

    def test_token_from_form_field(self):
        self.login()
        s, _, _ = self.c.post("/logout", {"csrf": "bad"})
        self.assertEqual(s, 403)

    def test_origin_check(self):
        self.login()
        h = {"X-CSRF-Token": self.csrf(), "Origin": "https://evil.example"}
        s, _, _ = self.c.post("/s/x/users/add", {"user": "a"}, headers=h)
        self.assertEqual(s, 403)
        h["Origin"] = "http://127.0.0.1:%d" % self.port
        s, _, _ = self.c.post("/s/x/users/add", {"user": "a"}, headers=h)
        self.assertNotEqual(s, 403)

    def test_body_too_large(self):
        self.login()
        try:
            s, _, _ = self.c.post("/s/x/users/add", {"user": "a" * (web.MAX_BODY + 10)},
                                  headers={"X-CSRF-Token": self.csrf()})
        except (BrokenPipeError, ConnectionError):
            return  # the server closed the connection before the whole body arrived
        self.assertEqual(s, 413)

    def test_page_has_hx_headers(self):
        self.login()
        s, r, text = self.c.get("/help")
        self.assertIn("hx-headers=", text)
        self.assertIn(self.csrf(), text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("onclick", text)


class PagesTest(WebCase):
    needs_noirvpn = True

    def setUp(self):
        super().setUp()
        self.create()
        self.daemon = self.start_daemon()
        self.login()

    def test_dashboard_and_widgets(self):
        s, r, text = self.c.get("/s/server/")
        self.assertEqual(s, 200)
        self.assertIn('id="widgets"', text)
        self.assertIn("every 5s", text)
        s, r, text = self.c.get("/s/server/widgets")
        self.assertIn("1 connected</div>", text)
        self.assertIn("0 accounts", text)
        self.assertIn("Listening on udp 0.0.0.0:1194", text)
        self.assertIn("vpn.example.com:1194 udp", text)
        self.assertIn("Load", text)

    def test_hx_fragment_has_no_shell(self):
        s, r, text = self.c.get("/s/server/users", headers={"HX-Request": "true"})
        self.assertNotIn("<html", text)
        self.assertIn("Add a user", text)
        self.assertIn('<nav id="main-nav" hx-swap-oob', text)

    def test_peers_escaped(self):
        self.daemon.rep.handler = lambda p: json.dumps({
            "v": 1, "id": json.loads(p)["id"], "ok": True,
            "result": {"count": 1, "peers": [{"session": "s-1", "name": "<script>alert(1)</script>",
                                             "real_addr": "1.2.3.4:5", "proto": "udp", "state": "active",
                                             "bytes_in": 5, "bytes_out": 6}], "server": {"peers": 1}}}).encode()
        s, r, text = self.c.get("/s/server/peers")
        self.assertNotIn("<script>alert", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("Kick", text)

    def test_kick(self):
        s, r, text = self.post("/s/server/kick", {"session": "s-1"})
        self.assertEqual(s, 200)
        kicks = [a for o, a in self.daemon.ops if o == "peer.kick"]
        self.assertEqual(kicks, [{"session": "s-1", "reason": "noirconf"}])

    def test_user_flow_and_escaping(self):
        s, _, text = self.post("/s/server/users/add", {"user": "alice", "notes": "<b>hi</b>"})
        self.assertEqual(s, 200)
        self.assertIn("alice", text)
        self.assertNotIn("<b>hi</b>", text)
        self.assertIn("&lt;b&gt;hi&lt;/b&gt;", text)
        s, _, text = self.post("/s/server/users/add", {"user": "<x>"})
        self.assertIn("alert-error", text)
        s, _, text = self.post("/s/server/u/alice/key/add",
                               {"text": "sha256:" + "C" * 43 + "=", "label": "<i>l</i>"})
        self.assertIn("The key is added", text)
        self.assertNotIn("<i>l</i>", text)
        s, _, text = self.post("/s/server/u/alice/key/add", {"text": "garbage"})
        self.assertIn("alert-error", text)
        s, _, text = self.post("/s/server/u/alice/disable")
        self.assertIn("disabled", text)
        s, _, text = self.post("/s/server/u/alice/revoke")
        self.assertIn("revoked", text)
        s, _, text = self.post("/s/server/u/alice/delete")
        self.assertIn("deleted", text)
        self.assertNotIn("alice</a>", text)
        self.assertEqual(self.c.get("/s/server/u/alice", headers={"HX-Request": "true"})[0], 400)

    def test_profile_download(self):
        self.post("/s/server/users/add", {"user": "alice"})
        s, r, text = self.c.post("/s/server/u/alice/profile", {
            "csrf": self.csrf(), "remote": "all", "mode": "generate", "pass1": "pp", "pass2": "pp"})
        self.assertEqual(s, 200)
        self.assertIn('attachment; filename="server-alice.ovpn"', r.getheader("Content-Disposition"))
        self.assertIn("ENCRYPTED PRIVATE KEY", text)
        self.assertNotIn("pp\n", text.split("<key>")[0])
        s, r, text = self.c.post("/s/server/u/alice/profile", {
            "csrf": self.csrf(), "remote": "all", "mode": "generate", "pass1": "a", "pass2": "b"})
        self.assertIn("not the same", text)
        self.assertIsNone(r.getheader("Content-Disposition"))

    def test_sign_csr_page_and_download(self):
        import test_pki
        self.post("/s/server/users/add", {"user": "alice"})
        s, _, text = self.c.get("/s/server/u/alice")
        self.assertIn("Add a key or sign a CSR", text)
        self.assertIn("The server pins the public key of the user", text)
        _, csr = test_pki.make_csr("ed25519")
        s, _, text = self.post("/s/server/u/alice/key/csr", {"csr": csr, "label": "phone"})
        self.assertEqual(s, 200)
        self.assertIn("The request is signed.", text)
        m = re.search(r'<textarea name="cert"[^>]*readonly>(.*?)</textarea>', text, re.S)
        cert = m.group(1)
        self.assertIn("BEGIN CERTIFICATE", cert)
        self.assertIn("Download alice.crt", text)
        s, r, body = self.c.post("/s/server/u/alice/cert/download", {"csrf": self.csrf(), "cert": cert})
        self.assertEqual(s, 200)
        self.assertEqual(r.getheader("Content-Disposition"), 'attachment; filename="alice.crt"')
        self.assertIn("BEGIN CERTIFICATE", body)
        self.assertNotIn("PRIVATE", body)
        s, r2, text = self.c.post("/s/server/u/alice/cert/download", {"csrf": self.csrf(), "cert": "junk"})
        self.assertIsNone(r2.getheader("Content-Disposition"))
        self.assertIn("no certificate found", text)
        # a bad request shows an error and no certificate
        s, _, text = self.post("/s/server/u/alice/key/csr", {"csr": "junk"})
        self.assertIn("no certificate request", text)
        self.assertNotIn("Signed certificate", text)
        s, _, text = self.post("/s/server/u/alice/key/csr", {"csr": csr + "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"})
        self.assertIn("private key", text)

    def test_config_preview_and_apply(self):
        s, _, text = self.c.get("/s/server/config")
        self.assertEqual(s, 200)
        self.assertIn('name="o.server"', text)
        form = {"externals": "vpn.example.com 1194 udp"}
        for line in re.findall(r'<input name="(o\.[^"]+)" value="([^"]*)"', text):
            form[line[0]] = line[1].replace("&quot;", '"')
        for m in re.finditer(r'<textarea name="(o\.[^"]+)"[^>]*>([^<]*)</textarea>', text):
            form[m.group(1)] = m.group(2)
        for m in re.finditer(r'<select name="(o\.[^"]+)">(.*?)</select>', text, re.S):
            sel = re.search(r'<option value="([^"]*)" selected', m.group(2))
            form[m.group(1)] = sel.group(1) if sel else ""
        form["o.verb"] = "4"
        s, _, text = self.post("/s/server/config/preview", form)
        self.assertEqual(s, 200)
        self.assertIn("+verb 4", text)
        self.assertIn("result: ok", text)
        pid = re.search(r"&quot;pending&quot;: &quot;([0-9a-f]+)&quot;", text).group(1)
        s, _, text = self.post("/s/server/config/apply", {"pending": pid})
        self.assertIn("The config is written", text)
        with open(self.store.paths("server").conf) as f:
            self.assertIn("verb 4", f.read())
        s, _, text = self.post("/s/server/config/apply", {"pending": pid})
        self.assertIn("The preview is old", text)

    def test_config_error_blocks_apply(self):
        form = {"externals": "vpn.example.com", "o.server": "10.8.0.0 255.255.255.0", "o.proto": "bogus"}
        s, _, text = self.post("/s/server/config/preview", form)
        self.assertIn("result: FAILED", text)
        self.assertNotIn("Write the config", text)
        self.assertIn("The check found errors", text)

    def test_service_pages(self):
        s, _, text = self.c.get("/s/server/service")
        self.assertEqual(s, 200)
        self.assertIn("Start", text)
        s, _, text = self.post("/s/server/service/check")
        self.assertIn("The check passed", text)
        s, _, text = self.post("/s/server/service/reload")
        self.assertIn("Reloaded", text)
        self.assertIn("daemon.reload", self.daemon.names())
        s, _, text = self.post("/s/server/service/reload-peers")
        self.assertIn("peers.reload", self.daemon.names())

    def test_unknown_server(self):
        s, _, text = self.c.get("/s/nosuch/users", headers={"HX-Request": "true"})
        self.assertEqual(s, 400)
        self.assertEqual(self.c.get("/nope")[0], 404)

    def test_switch_and_create_page(self):
        s, r, _ = self.c.get("/switch?server=server", headers={"HX-Request": "true"})
        self.assertEqual(r.getheader("HX-Redirect"), "/s/server/")
        s, _, text = self.c.get("/servers/new")
        self.assertIn('name="name"', text)
        self.assertIn('name="externals"', text)

    def test_second_server_selector(self):
        s, r, text = self.post("/servers/create", dict(self.form("second"), name="second",
                                                       externals="b.example"))
        self.assertEqual(r.getheader("HX-Redirect"), "/s/second/")
        s, _, text = self.c.get("/help")
        self.assertIn('<select name="server"', text)


    def test_help_and_new_keep_server_menu(self):
        for path in ("/help", "/servers/new"):
            s, _, text = self.c.get(path)
            self.assertIn('href="/s/server/users"', text, path)
            self.assertIn('href="%s?server=server"' % path, text, path)

    def test_help_menu_follows_current_server(self):
        self.post("/servers/create", dict(self.form("second"), name="second", externals="b.example"))
        s, _, text = self.c.get("/help", headers={"HX-Request": "true",
                                                  "HX-Current-URL": "https://h/s/second/users"})
        self.assertIn('href="/s/second/users"', text)
        s, _, text = self.c.get("/help?server=second")
        self.assertIn('href="/s/second/config"', text)
        s, _, text = self.c.get("/help")
        self.assertNotIn('href="/s/second/users"', text)
        self.assertNotIn('href="/s/server/users"', text)


class StaticTest(WebCase):
    def test_static(self):
        s, r, text = self.c.get("/static/htmx.min.js")
        self.assertEqual(s, 200)
        self.assertIn("javascript", r.getheader("Content-Type"))
        self.assertEqual(self.c.get("/static/app.css")[0], 200)
        self.assertEqual(self.c.get("/static/htmx.LICENSE")[0], 200)
        for bad in ("/static/../web.py", "/static/..%2fweb.py", "/static/nope.js", "/static/"):
            self.assertEqual(self.c.get(bad)[0], 404, bad)

    def test_no_external_assets(self):
        self.login()
        s, r, text = self.c.get("/help")
        for url in re.findall(r'(?:src|href)="([^"]+)"', text):
            self.assertTrue(url.startswith("/"), url)


class EmptyTest(WebCase):
    def test_first_start_goes_to_create(self):
        self.login()
        s, r, _ = self.c.get("/")
        self.assertEqual(r.getheader("Location"), "/servers/new")
        s, _, text = self.c.get("/servers/new")
        self.assertIn("There is no server yet", text)


class EssentialsWebTest(WebCase):
    needs_noirvpn = True

    def form(self, **over):
        f = {"name": "srv", "essentials": "on", "e.port": "1194", "e.host": "vpn.example.com",
             "e.public_port": "", "e.network": "10.8.0.0/24", "e.clients": "noir",
             "e.noir_transport": "ws", "e.ws_path": "/noir-srv", "e.compat_transport": "udp"}
        f.update(over)
        return f

    def test_new_page_defaults(self):
        self.login()
        s, _, text = self.c.get("/servers/new")
        self.assertIn('name="essentials" value="on" class="modebox" checked>', text)
        self.assertIn('name="name" id="f-name" value="server"', text)
        self.assertIn('value="/noir-server"', text)

    def test_create_with_essentials(self):
        self.login()
        s, r, _ = self.post("/servers/create", self.form())
        self.assertEqual(s, 204, _)
        self.assertEqual(r.getheader("HX-Redirect"), "/s/srv/")
        cfg = self.store.read_config("srv")
        self.assertEqual(cfg.first("proto"), ["tls-server"])
        self.assertEqual(cfg.first("tls-transport-ws"), ["/noir-srv"])
        self.assertEqual(self.store.clients("srv"), "noirvpn")
        s, _, text = self.c.get("/s/srv/widgets")
        self.assertIn("noirvpn clients only", text)
        self.assertIn("vpn.example.com:1194 tls ws /noir-srv", text)
        self.post("/s/srv/users/add", {"user": "alice"})
        s, _, text = self.c.get("/s/srv/u/alice")
        self.assertIn("OpenVPN clients cannot connect to this server.", text)
        s, r, text = self.c.post("/s/srv/u/alice/profile", {
            "csrf": self.csrf(), "remote": "all", "mode": "generate", "pass1": "", "pass2": ""})
        self.assertEqual(s, 200)
        self.assertIn("remote vpn.example.com 1194 tls-client", text)
        self.assertIn("tls-transport-ws /noir-srv", text)

    def test_error_keeps_the_mode_and_values(self):
        self.login()
        s, _, text = self.post("/servers/create", self.form(**{"e.host": "127.0.0.1"}))
        self.assertEqual(s, 400)
        self.assertIn("is a loopback address", text)
        self.assertIn('class="modebox" checked>', text)
        self.assertIn('value="/noir-srv"', text)
        self.assertIn('name="e.noir_transport" value="ws" checked', text)
        s, _, text = self.post("/servers/create", self.form(**{"e.network": "10.8.0.1/24"}))
        self.assertEqual(s, 400)
        self.assertIn("host bits", text)
        self.assertFalse(os.path.exists(os.path.join(self.etc, "srv.conf")))

    def test_full_mode_when_unticked(self):
        self.login()
        f = {"name": "full", "externals": "vpn.example.com 1194 udp", "key_type": "ed25519"}
        import optforms
        vals = optforms.defaults("full", self.etc)
        for k, v in vals.items():
            f["o." + k] = "\n".join(optforms.join_args(a) for a in v)
        f["e.host"] = "127.0.0.1"
        s, r, text = self.post("/servers/create", f)
        self.assertEqual(s, 204, text)
        self.assertEqual(self.store.clients("full"), "openvpn")

    def test_config_page_changes_the_hint_only(self):
        self.login()
        self.post("/servers/create", self.form(**{"e.clients": "compat"}))
        s, _, text = self.c.get("/s/srv/config")
        self.assertIn('<select name="clients">', text)
        before = self.store.read_config("srv").render()
        form = {"externals": "vpn.example.com 1194 udp", "clients": "noirvpn", "key_type": "ed25519"}
        import optforms
        cfg = self.store.read_config("srv")
        for k, v in optforms.values_from_config(cfg, self.store.opts).items():
            form["o." + k] = "\n".join(optforms.join_args(a, k) for a in v)
        s, _, text = self.post("/s/srv/config/preview", form)
        self.assertEqual(s, 200, text)
        pid = re.search(r"&quot;pending&quot;: &quot;([0-9a-f]+)&quot;", text).group(1)
        s, _, text = self.post("/s/srv/config/apply", {"pending": pid})
        self.assertEqual(self.store.clients("srv"), "noirvpn")
        self.assertEqual(self.store.read_config("srv").render().split(), before.split())


if __name__ == "__main__":
    unittest.main()
