"""The web server: routing, login, pages and HTMX fragments."""
import http.cookies
import http.server
import logging
import os
import re
import socket
import ssl
import time
import urllib.parse

import accounts as acct
import auth
import bus as busmod
import essentials
import optforms
import pki
import store as storemod
import svcctl
import views
from views import esc

log = logging.getLogger("noirconf")
audit_log = logging.getLogger("noirconf.audit")

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")
STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".LICENSE": "text/plain; charset=utf-8"}
MAX_BODY = 512 * 1024

KNOWN_ERRORS = (storemod.StoreError, acct.AccountError, pki.PkiError, svcctl.ServiceError,
                busmod.BusError, busmod.BusProtocolError)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


class Response:
    def __init__(self, status=200, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.ctype = ctype
        self.headers = list((headers or {}).items()) if isinstance(headers, dict) else list(headers or [])


def redirect(url, status=303):
    return Response(status, b"", headers={"Location": url})


class Ctx:
    def __init__(self, handler, method, path, query, form):
        self.h = handler
        self.method = method
        self.path = path
        self.query = query
        self.form = form
        self.session = None
        self.token = None
        self.hx = (handler.headers.get("HX-Request") == "true"
                   and handler.headers.get("HX-History-Restore-Request") != "true")
        self.poll = handler.headers.get("X-Poll") == "1"
        self.actor = "-"
        self.source = handler.client_address[0] if handler.client_address else "-"


class App:
    def __init__(self, etc, store, svc, user, authenticator, sessions=None, guard=None):
        self.etc = etc
        self.store = store
        self.svc = svc
        self.user = user
        self.authenticator = authenticator
        self.sessions = sessions or auth.SessionStore()
        self.guard = guard or auth.LoginGuard()
        self.fail_delay = auth.FAIL_DELAY
        self.routes = []
        self._routes()

    def _routes(self):
        r = self.routes.append

        def add(method, pattern, fn, public=False):
            r((method, re.compile("^" + pattern + "$"), fn, public))
        add("GET", r"/login", self.get_login, True)
        add("POST", r"/login", self.post_login, True)
        add("POST", r"/logout", self.post_logout)
        add("GET", r"/", self.get_root)
        add("GET", r"/help", self.get_help)
        add("GET", r"/switch", self.get_switch)
        add("GET", r"/servers/new", self.get_new)
        add("POST", r"/servers/create", self.post_create)
        add("GET", r"/s/([^/]+)/", self.get_dash)
        add("GET", r"/s/([^/]+)", self.get_dash)
        add("GET", r"/s/([^/]+)/widgets", self.get_widgets)
        add("GET", r"/s/([^/]+)/peers", self.get_peers)
        add("POST", r"/s/([^/]+)/kick", self.post_kick)
        add("POST", r"/s/([^/]+)/init", self.post_init)
        add("GET", r"/s/([^/]+)/users", self.get_users)
        add("POST", r"/s/([^/]+)/users/add", self.post_user_add)
        add("GET", r"/s/([^/]+)/u/([^/]+)", self.get_user)
        add("POST", r"/s/([^/]+)/u/([^/]+)/(enable|disable|revoke|delete)", self.post_user_action)
        add("POST", r"/s/([^/]+)/u/([^/]+)/key/add", self.post_key_add)
        add("POST", r"/s/([^/]+)/u/([^/]+)/key/csr", self.post_key_csr)
        add("POST", r"/s/([^/]+)/u/([^/]+)/cert/download", self.post_cert_download)
        add("POST", r"/s/([^/]+)/u/([^/]+)/key/([^/]+)/(revoke|delete)", self.post_key_action)
        add("POST", r"/s/([^/]+)/u/([^/]+)/profile", self.post_profile)
        add("GET", r"/s/([^/]+)/config", self.get_config)
        add("POST", r"/s/([^/]+)/config/preview", self.post_config_preview)
        add("POST", r"/s/([^/]+)/config/apply", self.post_config_apply)
        add("GET", r"/s/([^/]+)/service", self.get_service)
        add("POST", r"/s/([^/]+)/service/([a-z-]+)", self.post_service)

    # Dispatch

    def dispatch(self, ctx):
        """Returns a Response."""
        if ctx.path.startswith("/static/"):
            return self.static(ctx.path[len("/static/"):])
        found = None
        path_ok = False
        for method, rx, fn, public in self.routes:
            m = rx.match(ctx.path)
            if m:
                path_ok = True
                if method == ctx.method:
                    found = (fn, m.groups(), public)
                    break
        if found is None:
            return Response(405 if path_ok else 404, "Not found")
        fn, groups, public = found
        ctx.token = self.cookie(ctx, auth.COOKIE)
        if ctx.session is None and ctx.token:
            ctx.session = self.sessions.get(ctx.token) if not ctx.poll else self._peek(ctx.token)
        if ctx.session is not None:
            ctx.actor = ctx.session.user
        if ctx.method == "POST" and not self.origin_ok(ctx):
            log.warning("refused a POST to %s: Origin %r does not match Host %r", ctx.path,
                        ctx.h.headers.get("Origin"), ctx.h.headers.get("Host"))
            return Response(403, "Bad origin")
        if not public:
            if ctx.session is None:
                if ctx.hx:
                    return Response(401, "Log in again", headers={"HX-Redirect": "/login"})
                return redirect("/login")
            if ctx.method == "POST":
                supplied = ctx.h.headers.get("X-CSRF-Token") or ctx.form.get("csrf")
                if not auth.csrf_ok(ctx.session, supplied):
                    return Response(403, "Bad CSRF token")
        try:
            return fn(ctx, *groups)
        except KNOWN_ERRORS as e:
            return self.page(ctx, "Error", views.alert("error", str(e)), self.server_from_query(ctx),
                             "dash", status=400)

    def _peek(self, token):
        """Look up a session without extending it (polling requests)."""
        s = self.sessions
        key = s._key(token) if re.fullmatch(r"[0-9a-f]{64}", token or "") else None
        with s.lock:
            sess = s.data.get(key) if key else None
            if sess is None:
                return None
            if s.clock() - sess.last > s.idle:
                del s.data[key]
                return None
            return sess

    @staticmethod
    def cookie(ctx, name):
        raw = ctx.h.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = http.cookies.SimpleCookie()
            c.load(raw)
        except http.cookies.CookieError:
            return None
        m = c.get(name)
        return m.value if m else None

    @staticmethod
    def origin_ok(ctx):
        origin = ctx.h.headers.get("Origin")
        if not origin or origin == "null":
            return origin is None
        host = ctx.h.headers.get("Host", "")
        return urllib.parse.urlsplit(origin).netloc == host

    def static(self, name):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name not in os.listdir(STATIC_DIR):
            return Response(404, "Not found")
        ext = os.path.splitext(name)[1]
        ctype = STATIC_TYPES.get(ext)
        if name.endswith(".LICENSE"):
            ctype = STATIC_TYPES[".LICENSE"]
        if ctype is None:
            return Response(404, "Not found")
        with open(os.path.join(STATIC_DIR, name), "rb") as f:
            data = f.read()
        return Response(200, data, ctype, {"Cache-Control": "max-age=3600"})

    # Rendering

    def servers(self):
        return self.store.servers()

    def page(self, ctx, title, body, server, active, status=200):
        servers = self.servers()
        if ctx.hx:
            return Response(status, views.fragment(title, body, server, servers, active))
        wid = ""
        if server and self.store.exists(server):
            wid = views.widgets_html(server, self.widget_data(server))
        csrf = ctx.session.csrf if ctx.session else ""
        return Response(status, views.shell(title, body, csrf, self.user, server, servers, active, wid))

    def need_server(self, name):
        if not self.store.exists(name):
            raise storemod.StoreError("no such server")
        return name

    # Login

    def get_login(self, ctx):
        nonce = self.guard.new_nonce()
        body = views.login_page(self.user, self.guard.token_for(nonce))
        return Response(200, body, headers=[
            ("Set-Cookie", "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/login" % (auth.LOGIN_COOKIE, nonce))])

    def post_login(self, ctx):
        nonce = self.cookie(ctx, auth.LOGIN_COOKIE)
        if not self.guard.token_ok(nonce, ctx.form.get("csrf")):
            return Response(403, "Bad CSRF token")
        if self.guard.blocked(ctx.source):
            audit_log.warning("login blocked source=%s", ctx.source)
            return self._login_fail(ctx, "Too many failed attempts. Try again in a minute.", 429, delay=False)
        password = ctx.form.get("password", "")
        ok = False
        try:
            ok = self.authenticator.check(self.user, password)
        except Exception as e:  # PAM or crypt failure
            log.error("password check failed: %s", e)
        if not ok:
            self.guard.fail(ctx.source)
            audit_log.warning("login failed user=%s source=%s", self.user, ctx.source)
            return self._login_fail(ctx, "The password is not right.", 401)
        self.guard.ok(ctx.source)
        token, _ = self.sessions.create(self.user)
        audit_log.info("login ok user=%s source=%s", self.user, ctx.source)
        return Response(303, b"", headers=[
            ("Location", "/"),
            ("Set-Cookie", "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/" % (auth.COOKIE, token)),
            ("Set-Cookie", "%s=; Max-Age=0; Path=/login; Secure; HttpOnly; SameSite=Strict" % auth.LOGIN_COOKIE)])

    def _login_fail(self, ctx, msg, status, delay=True):
        if delay and self.fail_delay:
            time.sleep(self.fail_delay)
        nonce = self.guard.new_nonce()
        body = views.login_page(self.user, self.guard.token_for(nonce), msg)
        return Response(status, body, headers=[
            ("Set-Cookie", "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/login" % (auth.LOGIN_COOKIE, nonce))])

    def post_logout(self, ctx):
        self.sessions.destroy(ctx.token)
        audit_log.info("logout user=%s", ctx.actor)
        return Response(303, b"", headers=[
            ("Location", "/login"),
            ("Set-Cookie", "%s=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict" % auth.COOKIE)])

    # Simple pages

    def get_root(self, ctx):
        servers = self.servers()
        if not servers:
            return redirect("/servers/new")
        return redirect("/s/%s/" % urllib.parse.quote(servers[0]))

    def get_help(self, ctx):
        return self.page(ctx, "Help", views.help_html(), self.server_from_query(ctx), "help")

    def server_from_query(self, ctx):
        """The server that the user was on: the query, then the page htmx came from, else the only one."""
        names = [ctx.query.get("server")]
        for header in ("HX-Current-URL", "Referer"):
            url = ctx.h.headers.get(header) or ""
            parts = urllib.parse.urlsplit(url)
            m = re.match(r"/s/([^/]+)", parts.path)
            names.append(urllib.parse.unquote(m.group(1)) if m else
                         urllib.parse.parse_qs(parts.query).get("server", [None])[0])
        for s in names:
            if s and self.store.exists(s):
                return s
        servers = self.servers()
        return servers[0] if len(servers) == 1 else None

    def get_switch(self, ctx):
        s = ctx.query.get("server", "")
        if not self.store.exists(s):
            return redirect("/")
        url = "/s/%s/" % urllib.parse.quote(s)
        return Response(204, b"", headers={"HX-Redirect": url}) if ctx.hx else redirect(url)

    # Create a server

    def get_new(self, ctx):
        name = "server"
        servers = self.servers()
        if name in servers:
            name = ""
        values = optforms.defaults(name or "server", self.etc)
        ess = essentials.defaults(name or "server")
        return self.page(ctx, "New server", self.create_form(name, values, "", ess=ess),
                         self.server_from_query(ctx), "new")

    def create_form(self, name, values, externals, errors=(), output="", key_type=None, ess=None,
                    mode=True):
        intro = ""
        if not self.servers():
            intro = views.alert("info", "There is no server yet. Create the first one here.")
        return intro + views.create_form_html(self.store.options, values, externals, name, errors,
                                              output, key_type, ess, mode)

    def post_create(self, ctx):
        name = ctx.form.get("name", "").strip()
        ext = ctx.form.get("externals", "")
        mode = ctx.form.get("essentials") == "on"
        try:
            if mode:
                self.store.create_essentials(name, ctx.form, ctx.actor)
            else:
                self.store.create_server(name, ctx.form, ext, ctx.actor, ctx.form.get("key_type"))
        except KNOWN_ERRORS as e:
            values, _ = optforms.parse_form(ctx.form, self.store.opts)
            if not values:
                values = optforms.defaults(name or "server", self.etc)
            ess = dict(essentials.defaults(name or "server"))
            ess.update({k: v for k, v in ctx.form.items() if k.startswith("e.")})
            return self.page(ctx, "New server", self.create_form(
                name, values, ext, [str(e)], key_type=ctx.form.get("key_type"), ess=ess, mode=mode),
                self.server_from_query(ctx), "new", 400)
        url = "/s/%s/" % urllib.parse.quote(name)
        if ctx.hx:
            return Response(204, b"", headers={"HX-Redirect": url})
        return redirect(url)

    # Dashboard

    def bus_of(self, name):
        return self.store.bus(name)

    def live(self, name):
        """(status, stats, peers, error) from the daemon, or Nones."""
        b = self.bus_of(name)
        if b is None:
            return None, None, [], "The control socket is off."
        try:
            status = b.call("status")
        except busmod.NotRunning:
            return None, None, [], "The daemon is not running."
        except (busmod.BusError, busmod.BusProtocolError) as e:
            return None, None, [], "The daemon does not answer: %s" % e
        stats = peers = None
        try:
            stats = b.call("stats.get")
        except (busmod.BusError, busmod.BusProtocolError):
            stats = None
        try:
            res = b.call("peers.list", {"limit": 500})
            peers = [p for p in res.get("peers", []) if isinstance(p, dict)]
        except (busmod.BusError, busmod.BusProtocolError):
            peers = []
        return status, stats, peers, ""

    def widget_data(self, name):
        status, stats, peers, err = self.live(name)
        accounts = 0
        if self.store.managed(name):
            try:
                accounts = len(self.store.load_accounts(name).users)
            except KNOWN_ERRORS:
                accounts = 0
        srv = (status or {}).get("server") or {}
        listen = list(srv.get("listen") or []) if status else self.conf_listen(name)
        return {
            "connected": srv.get("peers", 0) if status else 0,
            "accounts": accounts,
            "system": storemod.system_info(),
            "uptime": (status or {}).get("uptime_s") if status else None,
            "listen": [str(x) for x in listen],
            "externals": self.store.externals(name) if self.store.managed(name) else [],
            "clients": self.store.clients(name) if self.store.managed(name) else "openvpn",
        }

    def conf_listen(self, name):
        try:
            cfg = self.store.read_config(name)
        except Exception:
            return []
        locs = cfg.get("local")
        port = (cfg.first("port") or ["1194"])[0]
        proto = (cfg.first("proto") or ["udp"])[0]
        if not locs:
            return ["%s *:%s" % (proto, port)]
        out = []
        for l in locs:
            host = l[0]
            lport = l[1] if len(l) > 1 else port
            lproto = l[2] if len(l) > 2 else proto
            out.append("%s %s:%s" % (lproto, host, lport))
        return out

    def get_widgets(self, ctx, name):
        self.need_server(name)
        return Response(200, views.widgets_html(name, self.widget_data(name)))

    def get_peers(self, ctx, name):
        self.need_server(name)
        _, _, peers, err = self.live(name)
        return Response(200, views.peers_html(name, peers, err))

    def get_dash(self, ctx, name):
        self.need_server(name)
        status, stats, peers, err = self.live(name)
        notes = []
        if not self.store.managed(name):
            notes.append("This server has no data folder yet. Open Users to set it up.")
        body = views.dashboard_html(name, None, status, stats, views.peers_html(name, peers, err), notes)
        return self.page(ctx, "Dashboard", body, name, "dash")

    def post_kick(self, ctx, name):
        self.need_server(name)
        session = ctx.form.get("session", "")
        b = self.bus_of(name)
        try:
            res = b.call("peer.kick", {"session": session, "reason": "noirconf"}) if b else {}
        except busmod.NotRunning:
            res = {}
        audit_log.info("user=%s action=peer.kick server=%s session=%s", ctx.actor, name, session[:40])
        _, _, peers, err = self.live(name)
        return Response(200, views.peers_html(name, peers, err))

    # Users

    def connected_by_name(self, name):
        _, _, peers, _ = self.live(name)
        out = {}
        for p in peers or []:
            n = str(p.get("name") or "").lower()
            out[n] = out.get(n, 0) + 1
        return out

    def users_page(self, ctx, name, notes=(), errors=()):
        self.need_server(name)
        if not self.store.managed(name):
            ext = storemod.externals_text(self.default_externals(name))
            body = ('<div class="card"><h3>Set up this server</h3><p>This server has no CA and no user list yet. '
                    'Create them here. Clients connect to the addresses below (host [port [proto]]).</p>'
                    '<form hx-post="/s/%s/init"><textarea name="externals" rows="3" class="mono" required>%s</textarea>'
                    '%s<button class="btn btn-primary">Create CA and user list</button></form></div>'
                    % (esc(name), esc(ext), views.key_type_select(None)))
            return self.page(ctx, "Users", views.notes_html(errors, "error") + body, name, "users")
        accs = self.store.load_accounts(name)
        body = views.users_html(name, accs, self.connected_by_name(name), notes, errors)
        return self.page(ctx, "Users", body, name, "users")

    def default_externals(self, name):
        cfg = self.store.read_config(name)
        port = (cfg.first("port") or ["1194"])[0]
        proto = storemod.PROTO_ALIASES.get((cfg.first("proto") or ["udp"])[0], "udp")
        return [("vpn.example.com", port, proto)]

    def get_users(self, ctx, name):
        return self.users_page(ctx, name)

    def post_init(self, ctx, name):
        self.need_server(name)
        try:
            self.store.init_data(name, ctx.form.get("externals", ""), ctx.actor, ctx.form.get("key_type"))
        except KNOWN_ERRORS as e:
            return self.users_page(ctx, name, errors=[str(e)])
        return self.users_page(ctx, name, notes=["The CA and the user list are created."])

    def post_user_add(self, ctx, name):
        self.need_server(name)
        try:
            notes = self.store.add_user(name, ctx.form.get("user", "").strip(),
                                        ctx.form.get("notes", ""), "", ctx.actor)
        except KNOWN_ERRORS as e:
            return self.users_page(ctx, name, errors=[str(e)])
        return self.users_page(ctx, name, notes=["The user is added."] + notes)

    def get_user(self, ctx, name, user):
        return self.user_page(ctx, name, user)

    def user_page(self, ctx, name, user, notes=(), errors=(), signed=None):
        self.need_server(name)
        accs = self.store.load_accounts(name)
        u = accs.user(user)
        body = views.user_html(name, u, self.store.externals(name), notes, errors,
                               ctx.session.csrf, signed, self.store.clients(name))
        return self.page(ctx, "User " + user, body, name, "users")

    def post_user_action(self, ctx, name, user, action):
        self.need_server(name)
        st = self.store
        try:
            if action == "enable":
                notes = ["The user is enabled."] + st.set_enabled(name, user, True, ctx.actor)
            elif action == "disable":
                notes = ["The user is disabled."] + st.set_enabled(name, user, False, ctx.actor)
            elif action == "revoke":
                notes = ["Every key of the user is revoked."] + st.revoke_user(name, user, ctx.actor)
            else:
                notes = ["The user is deleted."] + st.delete_user(name, user, ctx.actor)
        except KNOWN_ERRORS as e:
            return self.users_page(ctx, name, errors=[str(e)])
        return self.users_page(ctx, name, notes=notes)

    def post_key_add(self, ctx, name, user):
        self.need_server(name)
        try:
            notes = self.store.add_key(name, user, ctx.form.get("text", ""),
                                       ctx.form.get("label", ""), ctx.actor)
        except KNOWN_ERRORS as e:
            return self.user_page(ctx, name, user, errors=[str(e)])
        return self.user_page(ctx, name, user, notes=["The key is added."] + notes)

    def post_key_csr(self, ctx, name, user):
        self.need_server(name)
        try:
            cert, notes = self.store.sign_csr(name, user, ctx.form.get("csr", ""),
                                              ctx.form.get("label", ""), ctx.actor)
        except KNOWN_ERRORS as e:
            return self.user_page(ctx, name, user, errors=[str(e)])
        return self.user_page(ctx, name, user, notes=["The request is signed."] + notes, signed=cert)

    def post_cert_download(self, ctx, name, user):
        self.need_server(name)
        try:
            cert = pki.first_pem_block(ctx.form.get("cert", ""), "CERTIFICATE")
            pki.cert_serial(cert)
        except pki.PkiError as e:
            ctx.hx = False
            return self.user_page(ctx, name, user, errors=[str(e)])
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", user)
        return Response(200, cert, "application/x-pem-file",
                        {"Content-Disposition": 'attachment; filename="%s.crt"' % safe})

    def post_key_action(self, ctx, name, user, kid, action):
        self.need_server(name)
        try:
            if action == "revoke":
                notes = ["The key is revoked."] + self.store.revoke_key(name, user, kid, ctx.actor)
            else:
                notes = ["The key is deleted."] + self.store.delete_key(name, user, kid, ctx.actor)
        except KNOWN_ERRORS as e:
            return self.user_page(ctx, name, user, errors=[str(e)])
        return self.user_page(ctx, name, user, notes=notes)

    def post_profile(self, ctx, name, user):
        self.need_server(name)
        remote = ctx.form.get("remote", "all")
        idx = None if remote == "all" else (int(remote) if remote.isdigit() else -1)
        mode = "own" if ctx.form.get("mode") == "own" else "generate"
        p1, p2 = ctx.form.get("pass1", ""), ctx.form.get("pass2", "")
        try:
            if p1 != p2:
                raise storemod.StoreError("The two passphrases are not the same.")
            fname, text = self.store.build_profile(name, user, idx, mode, p1,
                                                   ctx.form.get("cert", ""), ctx.actor)
        except KNOWN_ERRORS as e:
            ctx.hx = False
            return self.user_page(ctx, name, user, errors=[str(e)])
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", fname)
        return Response(200, text, "application/x-openvpn-profile",
                        {"Content-Disposition": 'attachment; filename="%s"' % safe})

    # Config

    def get_config(self, ctx, name):
        return self.config_page(ctx, name)

    def config_page(self, ctx, name, notes=(), errors=(), form=None):
        self.need_server(name)
        cfg = self.store.read_config(name)
        values = optforms.values_from_config(cfg, self.store.opts)
        ext = storemod.externals_text(self.store.externals(name)) if self.store.managed(name) else ""
        kt = self.store.key_type(name) if self.store.managed(name) else None
        clients = self.store.clients(name) if self.store.managed(name) else None
        body = views.config_form_html(
            name, self.store.options, values, optforms.unmanaged_lines(cfg, self.store.opts),
            cfg.block_tags(), ext, notes, errors, kt, clients)
        return self.page(ctx, "Config", body, name, "config")

    def post_config_preview(self, ctx, name):
        self.need_server(name)
        text, old, errors = self.store.form_to_config(name, ctx.form)
        ext_text = ctx.form.get("externals", "")
        if not errors and self.store.managed(name):
            try:
                storemod.parse_externals(ext_text)
                pki.check_key_type(ctx.form.get("key_type") or pki.DEFAULT_KEY_TYPE)
                if ctx.form.get("clients", "openvpn") not in storemod.CLIENT_MODES:
                    raise storemod.StoreError("the clients value is openvpn or noirvpn")
            except (storemod.StoreError, pki.PkiError) as e:
                errors = [str(e)]
        if errors:
            return self.page(ctx, "Config", views.notes_html(errors, "error")
                             + self.config_form_from(name, ctx.form), name, "config", 400)
        ok, out = self.store.check_text(name, text)
        pid = os.urandom(8).hex()
        pend = ctx.session.pending
        if len(pend) > 5:
            pend.pop(next(iter(pend)))
        pend[pid] = {"name": name, "text": text, "externals": ext_text,
                     "key_type": ctx.form.get("key_type"), "clients": ctx.form.get("clients"),
                     "ok": ok, "old": old}
        body = views.diff_html(self.store.diff(old, text, name), ok, out, pid, name)
        return self.page(ctx, "Preview", body, name, "config")

    def config_form_from(self, name, form):
        values, _ = optforms.parse_form(form, self.store.opts)
        return views.config_form_html(name, self.store.options, values, [], [],
                                      form.get("externals", ""), key_type=form.get("key_type"),
                                      clients=form.get("clients"))

    def post_config_apply(self, ctx, name):
        self.need_server(name)
        pend = ctx.session.pending.pop(ctx.form.get("pending", ""), None)
        if not pend or pend["name"] != name:
            return self.config_page(ctx, name, errors=["The preview is old. Make the preview again."])
        if self.store.read_config(name).render() != pend["old"]:
            return self.config_page(ctx, name, errors=["The file changed. Make the preview again."])
        ok, out = self.store.check_text(name, pend["text"])
        if not ok:
            return self.config_page(ctx, name, errors=["The check found errors. Nothing is written."])
        with self.store.lock:
            self.store.write_config(name, pend["text"])
            if self.store.managed(name):
                self.store.set_externals(name, pend["externals"], ctx.actor, pend["key_type"],
                                         pend.get("clients"))
        audit_log.info("user=%s action=config.write server=%s", ctx.actor, name)
        return self.config_page(ctx, name, notes=[
            "The config is written. Restart the server, or use Reload config, to apply it."])

    # Service

    def service_page(self, ctx, name, notes=(), errors=(), check=None):
        self.need_server(name)
        svc = self.svc
        state = svc.state(name)
        installed = svc.installed(name)
        status, _, _, _ = self.live(name)
        unit = ""
        if not installed:
            unit = svc.unit_text() if svc.mode == "systemd" else svc.initscript_text()
        body = views.service_html(name, state, svc.mode, installed, svc.logs(name), status, notes,
                                  errors, unit)
        if check is not None:
            body = views.check_html(*check) + body
        return self.page(ctx, "Service", body, name, "service")

    def get_service(self, ctx, name):
        return self.service_page(ctx, name)

    def post_service(self, ctx, name, action):
        self.need_server(name)
        svc, st = self.svc, self.store
        notes, check = [], None
        audit_log.info("user=%s action=service.%s server=%s", ctx.actor, action, name)
        try:
            if action == "check":
                check = st.check_config(st.paths(name).conf)
            elif action == "install":
                svc.install(name)
                notes = ["Installed."]
            elif action in ("start", "restart"):
                ok, out = st.check_config(st.paths(name).conf)
                if not ok:
                    return self.service_page(ctx, name, errors=["The check found errors. The server is not started."],
                                             check=(ok, out))
                (svc.start if action == "start" else svc.restart)(name)
                notes = ["Done."]
            elif action == "stop":
                svc.stop(name)
                notes = ["Stopped."]
            elif action in ("reload", "reload-peers"):
                b = self.bus_of(name)
                if b is None:
                    raise storemod.StoreError("The control socket is off.")
                try:
                    if action == "reload":
                        res = b.call("daemon.reload")
                        notes = ["Reloaded: %s. Ignored: %s." % (
                            ", ".join(map(str, res.get("reloaded", []))) or "-",
                            ", ".join(map(str, res.get("ignored", []))) or "-")]
                    else:
                        b.call("peers.reload")
                        notes = ["The peers file is read again."]
                except busmod.NotRunning:
                    raise storemod.StoreError("The daemon is not running.")
            elif action in ("boot-on", "boot-off"):
                svc.set_enabled(name, action == "boot-on")
                notes = ["Done."]
            else:
                return Response(404, "Not found")
        except KNOWN_ERRORS as e:
            return self.service_page(ctx, name, errors=[str(e)])
        return self.service_page(ctx, name, notes=notes, check=check)


# HTTP handler

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "noirconf"
    sys_version = ""
    app = None

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(10)
            self.request.do_handshake()
        self.request.settimeout(60)
        super().setup()

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionError, socket.timeout, OSError) as e:
            log.debug("connection ended: %s", e)

    def log_message(self, fmt, *args):
        log.debug("http %s - %s", self.address_string(), fmt % args)

    def do_GET(self):
        self.serve("GET")

    def do_POST(self):
        self.serve("POST")

    def do_HEAD(self):
        self.send_error(405)

    def serve(self, method):
        parts = urllib.parse.urlsplit(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items()}
        form = {}
        if method == "POST":
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                self.send_response(413)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return
            raw = self.rfile.read(n) if n else b""
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("application/x-www-form-urlencoded") or not ctype:
                try:
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(
                        raw.decode("utf-8"), keep_blank_values=True, max_num_fields=2000).items()}
                except (UnicodeDecodeError, ValueError):
                    form = {}
            else:
                self.send_response(415)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        ctx = Ctx(self, method, urllib.parse.unquote(parts.path), query, form)
        try:
            resp = self.app.dispatch(ctx)
        except Exception:
            log.exception("request failed: %s %s", method, parts.path)
            resp = Response(500, "Internal error")
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.ctype)
        self.send_header("Content-Length", str(len(resp.body)))
        hdrs = dict(SECURITY_HEADERS)
        for k, v in resp.headers:
            if k.lower() == "cache-control":
                hdrs["Cache-Control"] = v
        for k, v in hdrs.items():
            self.send_header(k, v)
        for k, v in resp.headers:
            if k.lower() != "cache-control":
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.body)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, app, ctx=None):
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        handler = type("BoundHandler", (Handler,), {"app": app})
        super().__init__(addr, handler)
        if ctx is not None:
            self.socket = ctx.wrap_socket(self.socket, server_side=True,
                                          do_handshake_on_connect=False)


def tls_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    return ctx
