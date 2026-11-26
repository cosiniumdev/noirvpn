"""HTML pieces. Every value that comes from outside goes through esc()."""
import html
import json
import urllib.parse

import essentials
import optforms


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


def human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024


def human_duration(sec):
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return "-"
    d, rest = divmod(sec, 86400)
    h, rest = divmod(rest, 3600)
    m, s = divmod(rest, 60)
    if d:
        return "%dd %dh %dm" % (d, h, m)
    if h:
        return "%dh %dm" % (h, m)
    if m:
        return "%dm %ds" % (m, s)
    return "%ds" % s


def short_pin(pin):
    pin = pin or ""
    return pin[:18] + "..." if len(pin) > 21 else pin


# Page shell

HTMX_CONFIG = json.dumps({"includeIndicatorStyles": False, "allowEval": False,
                          "allowScriptTags": False, "selfRequestsOnly": True,
                          "historyCacheSize": 0})


def nav_html(server, active, servers):
    items = []
    if server:
        base = "/s/%s" % esc(server)
        entries = [("dash", "Dashboard", base + "/"), ("users", "Users", base + "/users"),
                   ("config", "Config", base + "/config"), ("service", "Service", base + "/service")]
    else:
        entries = []
    q = "?server=" + esc(urllib.parse.quote(server)) if server else ""
    entries += [("new", "New server", "/servers/new" + q), ("help", "Help", "/help" + q)]
    for key, label, href in entries:
        cls = ' class="active"' if key == active else ""
        items.append('<li><a%s href="%s" hx-get="%s" hx-push-url="true">%s</a></li>'
                     % (cls, href, href, esc(label)))
    return '<ul class="nav" id="nav-list">%s</ul>' % "".join(items)


def shell(title, body, csrf, user, server, servers, active, widgets_block=""):
    sel = ""
    if len(servers) > 1:
        opts = "".join('<option value="%s"%s>%s</option>'
                       % (esc(s), " selected" if s == server else "", esc(s)) for s in servers)
        sel = ('<label class="selector">Server <select name="server" hx-get="/switch" '
               'hx-trigger="change" hx-target="body">%s</select></label>' % opts)
    elif server:
        sel = '<span class="selector">Server <b>%s</b></span>' % esc(server)
    home = "/s/%s/" % esc(server) if server else "/"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>%s - noirconf</title>'
        "<meta name=\"htmx-config\" content='%s'>"
        '<link rel="stylesheet" href="/static/app.css">'
        '<script src="/static/htmx.min.js" defer></script>'
        '<script src="/static/app.js" defer></script></head>'
        "<body hx-headers='%s' hx-target=\"#content\">"
        '<header class="navbar"><input type="checkbox" id="nav-toggle" class="navtoggle">'
        '<a class="navbrand" href="%s" hx-get="%s" hx-push-url="true">NOIR</a>'
        '<label for="nav-toggle" class="navburger" aria-label="Menu"><span></span><span></span>'
        '<span></span></label>'
        '<nav id="main-nav">%s</nav>'
        '<div class="navright">%s<span class="who">%s</span>'
        '<form method="post" action="/logout" class="inline"><input type="hidden" name="csrf" value="%s">'
        '<button class="btn btn-sm">Log out</button></form></div></header>'
        '<div class="main">%s<main id="content" class="content">%s</main></div></body></html>'
    ) % (esc(title), HTMX_CONFIG, esc(json.dumps({"X-CSRF-Token": csrf})), home, home,
         nav_html(server, active, servers), sel, esc(user), esc(csrf),
         widgets_block, body)


def fragment(title, body, server, servers, active):
    """Response for an HTMX request: content, the navigation and the title."""
    return ('<title>%s - noirconf</title>%s'
            '<nav id="main-nav" hx-swap-oob="true">%s</nav>'
            % (esc(title), body, nav_html(server, active, servers)))


def login_page(user, nonce_token, error=""):
    err = '<p class="alert alert-error">%s</p>' % esc(error) if error else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Log in - noirconf</title><link rel="stylesheet" href="/static/app.css"></head>'
        '<body class="login"><div class="login-box"><div class="brand">noirconf</div>%s'
        '<form method="post" action="/login"><p>Account: <b>%s</b></p>'
        '<input type="hidden" name="csrf" value="%s">'
        '<label>Password<input type="password" name="password" autocomplete="current-password" '
        'autofocus required></label><button class="btn btn-primary">Log in</button></form>'
        '</div></body></html>' % (err, esc(user), esc(nonce_token))
    )


def alert(kind, text):
    return '<div class="alert alert-%s">%s</div>' % (kind, esc(text))


def notes_html(notes, kind="info"):
    return "".join(alert(kind, n) for n in notes or [])


# Widgets

def info_box(color, title, inner):
    return ('<div class="box box-%s"><div class="box-title">%s</div>%s</div>'
            % (color, esc(title), inner))


def line(text):
    return '<div class="box-line">%s</div>' % text


def ext_label(t):
    ws = getattr(t, "ws", "")
    return "%s:%s %s%s" % (t[0], t[1], t[2], " ws " + ws if ws else "")


def widgets_html(server, d):
    clients = info_box("blue", "Clients",
                       '<div class="big">%s connected</div>%s'
                       % (esc(d["connected"]), line("%s accounts" % esc(d["accounts"]))))
    sysi = d["system"]
    if sysi.get("mem_total"):
        pct = max(0, min(100, int(round(100.0 * sysi["mem_used"] / sysi["mem_total"]))))
        mem = (line("Memory <b>%s / %s</b>" % (esc(human_bytes(sysi["mem_used"])),
                                               esc(human_bytes(sysi["mem_total"]))))
               + '<progress class="bar" max="100" value="%d">%d%%</progress>' % (pct, pct))
    else:
        mem = line("Memory -")
    system = info_box("green", "System", mem + line("Load %s" % esc((sysi.get("load") or "-").split()[0])))
    up = info_box("amber", "Uptime",
                  '<div class="big">%s</div>'
                  % (esc(human_duration(d["uptime"])) if d["uptime"] is not None else "stopped"))
    listen = "".join(line("Listening on %s" % esc(x)) for x in d["listen"]) or line("Not listening")
    ext = "".join(line(esc(ext_label(t))) for t in d["externals"]) or line("no external address")
    tag = '<div class="box-line"><span class="tag tag-noir">noirvpn clients only</span></div>' \
        if d.get("clients") == "noirvpn" else ""
    srv = info_box("purple", "Server", listen + '<div class="box-sub">Connections to</div>' + ext + tag)
    return ('<div id="widgets" class="row" hx-get="/s/%s/widgets" hx-trigger="every 5s" '
            'hx-target="this" hx-swap="outerHTML" hx-headers=\'{"X-Poll":"1"}\'>%s%s%s%s</div>'
            % (esc(server), clients, system, up, srv))


# Peers

def peers_html(server, peers, error=""):
    rows = []
    for p in peers:
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td class=\"num\">%s / %s</td><td>"
            "<button class=\"btn btn-sm btn-danger\" hx-post=\"/s/%s/kick\" "
            "hx-vals='%s' hx-target=\"#peers\" hx-swap=\"outerHTML\" "
            "hx-confirm=\"Disconnect this client?\">Kick</button></td></tr>" % (
                esc(p.get("name") or "-"), esc(p.get("real_addr")), esc(p.get("proto")),
                esc(" ".join(x for x in (p.get("vpn4"), p.get("vpn6")) if x) or "-"),
                esc(p.get("state")), esc(p.get("connected_at") or "-"),
                esc(human_bytes(p.get("bytes_in"))), esc(human_bytes(p.get("bytes_out"))),
                esc(server), esc(json.dumps({"session": str(p.get("session", ""))}))))
    if error:
        body = '<p class="muted">%s</p>' % esc(error)
    elif not rows:
        body = '<p class="muted">No clients are connected.</p>'
    else:
        body = ('<table class="table"><thead><tr><th>Name</th><th>Address</th><th>Proto</th>'
                '<th>Tunnel</th><th>State</th><th>Connected</th><th>In / out</th><th></th></tr></thead>'
                '<tbody>%s</tbody></table>' % "".join(rows))
    return ('<div id="peers" hx-get="/s/%s/peers" hx-trigger="every 5s" hx-swap="outerHTML" '
            'hx-target="this" hx-headers=\'{"X-Poll":"1"}\'>%s</div>' % (esc(server), body))


def flatten(d, prefix=""):
    """(key, value) pairs of nested dicts, with dotted keys."""
    out = []
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            out.extend(flatten(v, prefix + k + "."))
        else:
            out.append((prefix + k, v))
    return out


def kv_value(v):
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return v


def kv_rows(items):
    return "".join("<tr><th>%s</th><td>%s</td></tr>" % (esc(k), esc(kv_value(v))) for k, v in items)


def split_status(status, stats):
    """(main, counters): the status entries with the other stats, and the counters of stats.get."""
    main = flatten(status)
    seen = set(k for k, _ in main)
    counters = []
    for k, v in flatten(stats):
        if k.startswith("counters."):
            counters.append((k[len("counters."):], v))
        elif k not in seen:
            main.append((k, v))
    return main, counters


def stats_table(counters):
    """Four columns: label, value, label, value."""
    rows = []
    for i in range(0, len(counters), 2):
        pair = counters[i:i + 2]
        cells = "".join("<th>%s</th><td>%s</td>" % (esc(k), esc(kv_value(v))) for k, v in pair)
        if len(pair) == 1:
            cells += "<th></th><td></td>"
        rows.append("<tr>%s</tr>" % cells)
    return '<table class="table table-kv table-kv4"><tbody>%s</tbody></table>' % "".join(rows)


def dashboard_html(server, state, status, stats, peers_block, notes=()):
    if status is not None:
        main, counters = split_status(status, stats)
        stat = '<div class="card"><h3>Noir server status</h3><table class="table table-kv"><tbody>%s</tbody></table></div>' % kv_rows(main)
        if counters:
            stat += '<div class="card"><h3>Stats</h3>%s</div>' % stats_table(counters)
        stat = '<div class="two">%s</div>' % stat
    else:
        stat = ('<div class="card"><h3>Noir server status</h3>'
                '<p class="muted">The daemon is not reachable.</p></div>')
    return (
        '%s<div class="card"><h3>Connected clients</h3>%s</div>%s' % (notes_html(notes), peers_block, stat))


# Users

def users_html(server, accs, connected, notes=(), errors=()):
    rows = []
    for name in sorted(accs.users, key=str.lower):
        u = accs.users[name]
        active = sum(1 for k in u.keys if k.active)
        base = "/s/%s/u/%s" % (esc(server), esc(name))
        state = '<span class="tag tag-ok">enabled</span>' if u.enabled else '<span class="tag tag-off">disabled</span>'
        toggle = ("disable" if u.enabled else "enable")
        rows.append(
            '<tr><td><a href="%s" hx-get="%s" hx-push-url="true">%s</a></td><td>%s</td>'
            '<td class="num">%d / %d</td><td class="num">%s</td><td>%s</td><td class="actions">'
            '<button class="btn btn-sm" hx-post="%s/%s">%s</button> '
            '<button class="btn btn-sm btn-warn" hx-post="%s/revoke" '
            'hx-confirm="Revoke every key of this user?">Revoke</button> '
            '<button class="btn btn-sm btn-danger" hx-post="%s/delete" '
            'hx-confirm="Delete this user and revoke the keys?">Delete</button></td></tr>'
            % (base, base, esc(name), state, active, len(u.keys),
               esc(connected.get(name.lower(), 0)), esc(u.notes), base, toggle, toggle.capitalize(),
               base, base))
    table = ('<table class="table"><thead><tr><th>User</th><th>State</th><th>Keys</th>'
             '<th>Online</th><th>Notes</th><th></th></tr></thead><tbody>%s</tbody></table>'
             % "".join(rows)) if rows else '<p class="muted">There are no users yet.</p>'
    add = (
        '<form class="card form-inline" hx-post="/s/%s/users/add"><h3>Add a user</h3>'
        '<label>Name<input name="user" maxlength="64" required pattern="[A-Za-z0-9._@\\-]{1,64}"></label>'
        '<label>Notes<input name="notes" maxlength="200"></label>'
        '<button class="btn btn-primary">Add</button></form>' % esc(server))
    return notes_html(errors, "error") + notes_html(notes) + add + '<div class="card"><h3>Users</h3>%s</div>' % table


def user_html(server, user, externals, notes=(), errors=(), csrf="", signed=None, clients="openvpn"):
    base = "/s/%s/u/%s" % (esc(server), esc(user.name))
    rows = []
    for k in user.keys:
        st = '<span class="tag tag-ok">active</span>' if k.active else '<span class="tag tag-off">revoked</span>'
        rows.append(
            '<tr><td>%s</td><td>%s</td><td>%s</td><td class="mono" title="%s">%s</td><td>%s</td><td>%s</td>'
            '<td class="actions">%s'
            '<button class="btn btn-sm btn-danger" hx-post="%s/key/%s/delete" '
            'hx-confirm="Delete this key?">Delete</button></td></tr>'
            % (esc(k.id), esc(k.label), esc(k.source), esc(k.pin), esc(short_pin(k.pin)),
               esc(k.serial or "-"), st,
               ('<button class="btn btn-sm btn-warn" hx-post="%s/key/%s/revoke" '
                'hx-confirm="Revoke this key?">Revoke</button> ' % (base, esc(k.id))) if k.active else "",
               base, esc(k.id)))
    keys = ('<table class="table"><thead><tr><th>Id</th><th>Label</th><th>Source</th><th>Pin</th>'
            '<th>Serial</th><th>State</th><th></th></tr></thead><tbody>%s</tbody></table>'
            % "".join(rows)) if rows else '<p class="muted">This user has no keys.</p>'
    addkey = (
        '<div class="card"><h3>Add a key or sign a CSR</h3>'
        '<p class="hint0">The server pins the public key of the user. The user connects with the '
        'matching private key, which never leaves the user. <a href="/help#keys" hx-get="/help#keys" '
        'hx-push-url="true">More in Help</a></p>'
        '<form hx-post="%s/key/add"><h4>Add a public key or a certificate</h4>'
        '<label>Pin, public key or certificate (PEM)'
        '<textarea name="text" rows="4" class="mono" required></textarea></label>'
        '<label>Load key from file<input type="file" data-fill="text"></label>'
        '<label>Label<input name="label" maxlength="64"></label>'
        '<button class="btn btn-primary">Add key</button></form>'
        '<form hx-post="%s/key/csr"><h4>Sign a certificate request</h4>'
        '<label>Request (PEM, CSR)'
        '<textarea name="csr" rows="4" class="mono" required></textarea></label>'
        '<label>Load request from file<input type="file" data-fill="csr"></label>'
        '<label>Label<input name="label" maxlength="64"></label>'
        '<button class="btn btn-primary">Sign request</button></form></div>' % (base, base))
    if signed:
        addkey = (
            '<form class="card" method="post" action="%s/cert/download" hx-disable>'
            '<h3>Signed certificate</h3><input type="hidden" name="csrf" value="%s">'
            '<p class="hint0">Give this certificate to the user. In "Use my own key" below, paste '
            'it to create a profile.</p>'
            '<textarea name="cert" rows="8" class="mono" readonly>%s</textarea>'
            '<button class="btn btn-primary">Download %s.crt</button></form>'
            % (base, esc(csrf), esc(signed), esc(user.name))) + addkey
    ext_opts = '<option value="all">All addresses</option>' + "".join(
        '<option value="%d">%s</option>' % (i, esc(ext_label(t))) for i, t in enumerate(externals))
    prof = (
        '<form class="card" method="post" action="%s/profile" hx-disable><h3>Create client profile</h3>'
        '<input type="hidden" name="csrf" value="%s">'
        '<label>Server address<select name="remote">%s</select></label>'
        '<fieldset><legend>Key</legend>'
        '<label class="check"><input type="radio" name="mode" value="generate" checked> '
        'Create a new key and certificate</label>'
        '<div class="indent">'
        '<label>Passphrase for the key (optional)<input type="password" name="pass1" autocomplete="new-password"></label>'
        '<label>Repeat the passphrase<input type="password" name="pass2" autocomplete="new-password"></label>'
        '</div>'
        '<label class="check"><input type="radio" name="mode" value="own"> '
        'Use my own key. Paste the certificate:</label>'
        '<div class="indent">'
        '<textarea name="cert" rows="4" class="mono"></textarea>'
        '<label>Load key from file<input type="file" data-fill="cert"></label></div></fieldset>'
        '<button class="btn btn-primary">Download profile</button></form>'
        % (base, esc(csrf), ext_opts))
    if not externals:
        prof = '<div class="card"><h3>Create client profile</h3><p class="muted">Set the external addresses in the Config page first.</p></div>'
    if clients == "noirvpn" and externals:
        prof = prof.replace("<h3>Create client profile</h3>", "<h3>Create client profile</h3>"
                            '<p class="alert alert-info">noirvpn clients only: OpenVPN clients cannot connect to this server.</p>', 1)
    head = '<h2>%s</h2>' % esc(user.name)
    back = '<p><a href="/s/%s/users" hx-get="/s/%s/users" hx-push-url="true">Back to users</a></p>' % (esc(server), esc(server))
    return (head + back + notes_html(errors, "error") + notes_html(notes)
            + '<div class="card"><h3>Keys</h3>%s</div>' % keys + addkey + prof)


# Config form

def default_text(o):
    parts = []
    if o.get("default"):
        parts.append("default %s" % o["default"])
    if o.get("accepts"):
        parts.append("accepts %s" % ", ".join(o["accepts"]))
    return '<span class="def">(%s)</span>' % esc("; ".join(parts)) if parts else ""


def name_text(o):
    return '<span class="fname">%s</span> <code>%s</code>' % (esc(o["label"]), esc(o["name"]))


def field_html(o, values):
    name = o["name"]
    fid = "o." + name
    cur = values.get(name)
    tip = ' title="%s"' % esc(o["note"]) if o["note"] else ""
    if o.get("virtual") == "dco":
        return dco_html(o, cur)
    if o.get("virtual") == "ciphers":
        return ciphers_html(o, cur)
    if o["max"] == 0:
        chk = " checked" if cur else ""
        return ('<div class="field"%s><label class="frow"><span class="fcheck"><input type="checkbox" '
                'name="%s"%s> %s</span>%s</label></div>'
                % (tip, esc(fid), chk, name_text(o), default_text(o)))
    if o.get("choices"):
        cv = optforms.join_args(cur[0], name) if cur else ""
        opts = list(o["choices"])
        if cv and cv not in [c[0] for c in opts]:
            opts.append([cv, cv])
        sel = "".join('<option value="%s"%s>%s</option>'
                      % (esc(v), " selected" if v == cv else "", esc(t)) for v, t in opts)
        off = " disabled" if name == "proto" and optforms.tls_on_values(values) else ""
        return ('<div class="field"%s><label class="frow"><span>%s</span><select name="%s"%s>%s</select>'
                '%s</label></div>' % (tip, name_text(o), esc(fid), off, sel, default_text(o)))
    if o["repeat"]:
        text = "\n".join(optforms.join_args(a, name) for a in cur) if cur else ""
        return ('<div class="field"%s><label class="frow top"><span>%s <span class="muted">(one line each)</span></span>'
                '<textarea name="%s" rows="%d" class="mono">%s</textarea>%s</label></div>'
                % (tip, name_text(o), esc(fid), max(2, min(6, len(cur or []) + 1)), esc(text),
                   default_text(o)))
    text = optforms.join_args(cur[0], name) if cur else ""
    return ('<div class="field"%s><label class="frow"><span>%s</span>'
            '<input name="%s" value="%s" class="mono">%s</label></div>'
            % (tip, name_text(o), esc(fid), esc(text), default_text(o)))


def ciphers_html(o, cur):
    ticked, others = optforms.cipher_state(cur)
    on = [c.upper() for c in ticked]
    boxes = "".join(
        '<label class="inl"><input type="checkbox" name="v.cipher.%s"%s> %s</label>'
        % (esc(c), " checked" if c in on else "", esc(c)) for c in optforms.CIPHERS)
    more = ('<span class="muted">Also in the file: %s</span>' % esc(", ".join(others))) if others else ""
    tip = ' title="%s"' % esc(o["note"]) if o["note"] else ""
    return ('<div class="field"%s><div class="frow cipherrow"><span>%s</span><span class="ciphers">%s%s</span>%s</div></div>'
            % (tip, name_text(o), boxes, more, default_text(o)))


def dco_html(o, cur):
    value = cur[0][0] if cur else ""
    if value in optforms.DATAPATH_KEEP and value != "userspace":
        return ('<div class="field"><p class="note">This config has <code>datapath %s</code>. '
                'noirconf keeps this line as it is.</p></div>' % esc(value))
    return ('<div class="field"><input type="checkbox" id="v-dco" name="v.dco"%s>'
            '<label for="v-dco" class="inl">Use kernel DCO <code>datapath dco</code></label>'
            '<p class="hint">noirvpn has a fast userspace data path, so use DCO only if you have a '
            'specific need. When the kernel has no ovpn module, the server uses the userspace path. '
            '<a href="/help#dco" hx-get="/help#dco" hx-push-url="true">More in Help</a></p></div>'
            % (" checked" if value == "dco" else ""))


def tls_group_html(values, block_opts):
    on = optforms.tls_on_values(values)
    inner = "".join(field_html(o, values) for o in block_opts)
    return ('<div class="field tlsgroup"><input type="checkbox" id="v-tls" name="v.tls" class="toggle"%s>'
            '<label for="v-tls" class="inl">Run as TLS server <code>proto tls-server</code></label>'
            '<p class="hint">The port then serves noirvpn clients over TCP inside TLS, so it looks like '
            'HTTPS. UDP is not served on this port. For a UDP listener next to it, add a Listen '
            'address line. <a href="/help#tls" hx-get="/help#tls" hx-push-url="true">More in Help</a></p>'
            '<div class="indent tls-block">%s</div></div>' % (" checked" if on else "", inner))


def option_fields(options, values):
    groups = options["groups"]
    radios, bar, panels = [], [], []
    for i, g in enumerate(groups):
        gid = esc(g["id"])
        radios.append('<input type="radio" class="tabradio" name="tab" id="tab-%s"%s>'
                      % (gid, " checked" if i == 0 else ""))
        bar.append('<label for="tab-%s">%s</label>' % (gid, esc(g["title"])))
        body = []
        block = [o for o in g["options"] if o.get("block") == "tls"]
        for o in g["options"]:
            if o.get("block") == "tls":
                continue
            body.append(field_html(o, values))
            if o["name"] == "proto" and block:
                body.append(tls_group_html(values, block))
        panels.append('<section class="panel" id="panel-%s">%s</section>' % (gid, "".join(body)))
    return ('<div class="tabs">%s<div class="tabbar">%s</div><div class="panels">%s</div></div>'
            % ("".join(radios), "".join(bar), "".join(panels)))


KEY_TYPE_LABELS = [("ed25519", "Ed25519"), ("ec-p256", "EC P-256"), ("rsa-3072", "RSA 3072")]


def key_type_select(current):
    current = current or "ed25519"
    opts = "".join('<option value="%s"%s>%s</option>' % (k, " selected" if k == current else "", esc(l))
                   for k, l in KEY_TYPE_LABELS)
    return '<label>Key type of new certificates<select name="key_type">%s</select></label>' % opts


CLIENT_LABELS = [("openvpn", "OpenVPN compatible"), ("noirvpn", "noirvpn clients only")]


def clients_select(current):
    opts = "".join('<option value="%s"%s>%s</option>' % (k, " selected" if k == current else "", esc(l))
                   for k, l in CLIENT_LABELS)
    return ('<label>Clients<select name="clients">%s</select></label>'
            '<p class="hint0">Only a hint for the user. It does not change the config. With noirvpn '
            'clients only, the profile page warns that OpenVPN clients cannot connect.</p>' % opts)


def config_form_html(server, options, values, unmanaged, blocks, externals_text, notes=(), errors=(),
                     key_type=None, clients=None):
    extra = ""
    if unmanaged or blocks:
        extra = ('<div class="card"><h3>Kept as they are</h3><p class="muted">The file has lines that '
                 'this form does not show. They stay when the file is written.</p><p>%s</p></div>'
                 % esc(", ".join(list(unmanaged) + ["<%s>" % b for b in blocks])))
    return (
        notes_html(errors, "error") + notes_html(notes) +
        '<form hx-post="/s/%s/config/preview" id="configform">'
        '<div class="card"><h3>Addresses that clients use</h3>'
        '<label>One line each: host [port [udp|tcp|tls [ws=PATH]]]'
        '<textarea name="externals" rows="3" class="mono">%s</textarea></label>%s%s</div>'
        '<div class="card"><h3>Server options</h3>%s</div>%s'
        '<button class="btn btn-primary">Preview changes</button></form>'
        % (esc(server), esc(externals_text), key_type_select(key_type) if key_type else "",
           clients_select(clients) if clients else "",
           option_fields(options, values), extra))


def radio(name, value, checked, label, rid):
    return ('<input type="radio" id="%s" name="%s" value="%s"%s><label for="%s" class="inl">%s</label>'
            % (rid, name, value, " checked" if checked else "", rid, label))


def essentials_html(ess, name):
    """The fields of Create with Essentials. ess holds the values of the form."""
    g = lambda k: esc(ess.get(k, ""))
    noir = ess.get("e.clients") == "noir"
    ct = ess.get("e.compat_transport") or "udp"
    nt = ess.get("e.noir_transport") or "udp"
    compat = "".join(radio("e.compat_transport", v, ct == v, t, "ct-" + v)
                     for v, t in (("udp", "UDP"), ("tcp", "TCP")))
    noirs = "".join(radio("e.noir_transport", v, nt == v, t, "nt-" + v)
                    for v, t in (("udp", "UDP"), ("tcp", "TCP"), ("tls", "TLS"), ("ws", "TLS + WebSocket")))
    return (
        '<label>Listen port<input name="e.port" value="%s" class="short" inputmode="numeric"></label>'
        '<label>Public address that clients use'
        '<input name="e.host" value="%s" placeholder="vpn.example.com"></label>'
        '<label>Public port (default: the listen port)'
        '<input name="e.public_port" value="%s" class="short" inputmode="numeric"></label>'
        '<p class="fixed">Key type: <b>Ed25519</b></p>'
        '<label>Tunnel network (IPv4, optional)'
        '<input name="e.network" value="%s" class="short mono" placeholder="10.8.0.0/24"></label>'
        '<p class="hint0">A prefix from /16 to /30, for example 10.8.0.0/24. There is no IPv6 field here. '
        'Add <code>server-ipv6</code> later on the Config page.</p>'
        '<fieldset class="clients"><legend>Clients</legend>'
        '<div><input type="radio" id="c-compat" name="e.clients" value="compat"%s>'
        '<label for="c-compat" class="inl">OpenVPN compatible</label></div>'
        '<div class="indent tg-compat">%s</div>'
        '<div><input type="radio" id="c-noir" name="e.clients" value="noir"%s>'
        '<label for="c-noir" class="inl">noirvpn clients only</label></div>'
        '<div class="indent tg-noir">%s'
        '<div class="ws-path"><label>WebSocket path<input name="e.ws_path" id="f-ws" value="%s" '
        'class="mono" data-auto="%s"></label></div></div>'
        '<p class="hint0">With noirvpn clients only, OpenVPN clients cannot connect to this server. TLS looks like HTTPS, and WebSocket is for a '
        'proxy or CDN that passes only WebSocket. <a href="/help#essentials" hx-get="/help#essentials" '
        'hx-push-url="true">More in Help</a></p></fieldset>'
        % (g("e.port"), g("e.host"), g("e.public_port"), g("e.network"),
           "" if noir else " checked", compat, " checked" if noir else "", noirs, g("e.ws_path"),
           "0" if ess.get("e.ws_path") not in ("", essentials.default_ws_path(name)) else "1"))


def create_form_html(options, values, externals_text, name, errors=(), output="", key_type=None,
                     ess=None, essentials=True):
    out = ""
    if output:
        out = '<div class="card"><h3>Output</h3><pre class="log">%s</pre></div>' % esc(output)
    ess = ess or {}
    return (
        notes_html(errors, "error") + out +
        '<form hx-post="/servers/create"><div class="card newserver"><h3>New server</h3>'
        '<input type="checkbox" id="v-ess" name="essentials" value="on" class="modebox"%s>'
        '<label for="v-ess" class="inl">Create with Essentials</label>'
        '<label>Name<input name="name" id="f-name" value="%s" maxlength="40" required '
        'pattern="[A-Za-z0-9._\\-]{1,40}"></label>'
        '<div class="ess-block">%s</div>'
        '<div class="full-block">'
        '<label>Addresses that clients use. One line each: host [port [udp|tcp|tls [ws=PATH]]]'
        '<textarea name="externals" rows="3" class="mono">%s</textarea></label>%s'
        '<h4>Server options</h4>%s</div></div>'
        '<button class="btn btn-primary">Create server</button></form>'
        % (" checked" if essentials else "", esc(name), essentials_html(ess, name), esc(externals_text),
           key_type_select(key_type), option_fields(options, values)))


def diff_html(diff, check_ok, check_out, pending_id, server):
    d = []
    for ln in diff.splitlines():
        cls = "add" if ln.startswith("+") and not ln.startswith("+++") else (
            "del" if ln.startswith("-") and not ln.startswith("---") else "")
        d.append('<span class="%s">%s</span>' % (cls, esc(ln)))
    diffbox = ("\n".join(d)) if d else "No changes."
    if check_ok:
        btn = ('<button class="btn btn-primary" hx-post="/s/%s/config/apply" '
               'hx-vals=\'%s\'>Write the config</button>'
               % (esc(server), esc(json.dumps({"pending": pending_id}))))
    else:
        btn = '<p class="alert alert-error">The check found errors. The file is not written.</p>'
    return ('<div class="card"><h3>Changes</h3><pre class="log diff">%s</pre></div>'
            '<div class="card"><h3>Check result</h3><pre class="log">%s</pre></div>%s'
            ' <a class="btn" href="/s/%s/config" hx-get="/s/%s/config">Back to the form</a>'
            % (diffbox, esc(check_out), btn, esc(server), esc(server)))


# Service

def service_html(server, state, mode, installed, logs, status, notes=(), errors=(), unit_text="",
                 managed=True):
    run = state["running"]
    st = '<span class="tag %s">%s</span>' % ("tag-ok" if run else "tag-off", esc(state["text"]))
    base = "/s/%s/service" % esc(server)

    def b(action, label, cls="", confirm=""):
        c = ' hx-confirm="%s"' % esc(confirm) if confirm else ""
        return '<button class="btn %s" hx-post="%s/%s"%s>%s</button> ' % (cls, base, action, c, label)

    buttons = ""
    if installed:
        buttons += (b("start", "Start", "btn-primary") if not run else "")
        if run:
            buttons += b("stop", "Stop", "btn-danger", "Stop the server? Clients disconnect.")
            buttons += b("restart", "Restart", "btn-warn", "Restart the server? Clients disconnect.")
            buttons += b("reload", "Reload config") + b("reload-peers", "Reload peers")
        if state.get("enabled") is not None:
            buttons += b("boot-off" if state["enabled"] else "boot-on",
                         "Do not start at boot" if state["enabled"] else "Start at boot")
    buttons += b("check", "Check the config")
    inst = ""
    if not installed:
        what = "unit" if mode == "systemd" else "init script"
        inst = ('<div class="card"><h3>Service %s</h3><p>The service %s is not installed.</p>'
                '<pre class="log">%s</pre>'
                '<button class="btn btn-primary" hx-post="%s/install" '
                'hx-confirm="Install the service %s?">Install</button></div>'
                % (what, what, esc(unit_text), base, what))
    return (notes_html(errors, "error") + notes_html(notes) +
            '<div class="card"><h3>Service</h3><p>State: %s <span class="muted">(manager: %s)</span></p>%s</div>'
            % (st, esc(mode), buttons) + inst +
            '<div class="card"><h3>Log</h3><pre class="log">%s</pre></div>' % esc(logs))


def check_html(ok, out):
    return ('<div class="alert alert-%s">%s</div><pre class="log">%s</pre>'
            % ("ok" if ok else "error", "The check passed." if ok else "The check found errors.", esc(out)))


def help_html():
    return HELP


HELP = """
<h2>Help</h2>
<div class="card prose">
<h3 id="start">Getting started</h3>
<p>noirconf sets up and runs noirvpn servers on this computer. You log in with the password of the
account that started noirconf, and a session ends after 30 minutes without use. Because anyone who
logs in can change the VPN, noirconf listens on the local address only. To reach it from another
computer, open an SSH tunnel to this one.</p>
<p>Each server has a config file and a folder next to it. The folder holds the server's own
certificate authority (CA, the signer of its certificates), the user list and the keys that the
server needs. noirconf writes all of this for you and tells the running server when something
changes.</p>

<h3 id="essentials">Create a server</h3>
<p>The New server page starts with <b>Create with Essentials</b> ticked. It asks only for what every
server needs, and noirconf chooses the rest, including an Ed25519 certificate for the server. Untick
the box if you want to see every option.</p>
<ul>
<li><b>Listen port.</b> The port where the server waits for clients.</li>
<li><b>Public address and port.</b> What clients put in their profile: a host name or an address,
and a port. The port can differ from the listen port, for example when your router forwards 443 to
it. Loopback and unspecified addresses such as <code>127.0.0.1</code>, <code>localhost</code> and
<code>0.0.0.0</code> are refused, because clients on other computers cannot reach them. The address
also goes into the server certificate when you create the server, so choose the one that clients will really use.</li>
<li><b>Tunnel network.</b> The private IPv4 network that clients join, written as
<code>10.8.0.0/24</code>. The prefix is from /16 to /30, and the address must be the network
address itself, so <code>10.8.0.1/24</code> is refused. The server takes the first address and the
clients share the rest. For IPv6, add <code>server-ipv6</code> later on the Config page.</li>
<li><b>Clients.</b> Choose <b>OpenVPN compatible</b> if any OpenVPN 2.6 or 2.7 client should be able
to connect (noirvpn clients can too). Choose <b>noirvpn clients only</b> if every client runs
noirvpn. That choice only adds a reminder, in the Server widget and on the profile page, so nobody
tries an OpenVPN client on the server. It also unlocks the two transports below that only noirvpn
understands. You can change the reminder later on the Config page.</li>
</ul>
<p>The transport is how the tunnel travels over the network:</p>
<ul>
<li><b>UDP</b> is the fastest and the default.</li>
<li><b>TCP</b> works on networks that block UDP, but it is slower on a poor connection.</li>
<li><b>TLS</b> wraps the tunnel in an ordinary encrypted web connection, so it looks like HTTPS. It
helps on networks that allow only HTTPS. Set the listen port to 443, or forward 443 to it. Clients
do not check this outer certificate, because the tunnel itself proves who the server is, so the
certificate that noirconf made is enough.</li>
<li><b>TLS + WebSocket</b> also hides the tunnel inside a WebSocket, a web protocol that many
proxies and content delivery networks (CDNs) pass along. Use it when a reverse proxy or CDN in
front of the server forwards only WebSocket traffic over HTTPS. You choose a path, which starts with
<code>/</code> and then has 1 to 64 letters, digits or the characters <code>. _ ~ / -</code>, with
no <code>..</code>. The default is <code>/noir-</code> and the server name. Server and clients must use the same path, and
noirconf puts it in the profiles. A proxy that talks plain HTTP to the server needs
<code>proto tcp-server</code> instead, which you can set on the Config page.</li>
</ul>
<p>One more detail for TLS clients: the outer certificate is the server certificate, which is
Ed25519 by default. That works with noirconf profiles. A noirvpn client that you set to the
<code>chrome</code> ClientHello style (which makes the connection look like the Chrome browser)
cannot use an Ed25519 outer certificate, so give the server an ECDSA or RSA one first.</p>

<h3 id="keys">Users and profiles</h3>
<p>Each person who connects is a user. A user can have several keys, one for each device. The
server does not store the keys themselves. It stores a pin, a short fingerprint of the public half
of each key, and a client gets in by showing the matching private key.</p>
<p>The simplest way to give someone access is <b>Create client profile</b>. noirconf makes a new
key and a certificate signed by the server CA, adds the pin, and gives you a profile file to send to
the user. You can protect the key with a passphrase. noirconf does not keep the private key, so if
the user loses the profile, create a new one and revoke the old key.</p>
<p>If the user already has a key, choose <b>Add a key</b> and paste a pin, a public key or a
certificate. noirconf works out the pin. A user can then create a profile with <b>Use my own
key</b> by pasting the matching certificate.</p>
<p>To stop access, you have three choices:</p>
<ul>
<li><b>Disable</b> a user to block every key for now. The keys stay, and Enable brings them back.</li>
<li><b>Revoke</b> a key, or all keys of a user, to cancel them for good. A revoked certificate goes on
the server's revocation list, and the client is disconnected at once.</li>
<li><b>Delete</b> a user to remove the user and revoke the keys.</li>
</ul>

<h3 id="csr">Sign a certificate request</h3>
<p>A user who wants to keep the private key on their own device can send a certificate request
(CSR) instead of a key. The user makes it with <code>openssl req -new -key KEY.pem -out
user.csr</code>. The key can be Ed25519, EC or RSA with 2048 bits or more. Paste the request into
<b>Sign a certificate request</b> on the user page.</p>
<p>noirconf checks the request and refuses it if it contains a private key or if its signature is
wrong. It then signs it with the server CA. The certificate always gets the name
<code>USERNAME</code> and is valid for client login only, whatever the request asked for. You can
copy the certificate or download it as <code>USERNAME.crt</code>, and the user then creates a profile
with <b>Use my own key</b>.</p>

<h3>Starting and stopping</h3>
<p>The Service page starts, stops and restarts the server, and shows its log. With systemd,
noirconf uses the unit <code>noirvpn-server@NAME</code>. On Alpine it uses an OpenRC script. On
anything else it starts the server as a background process and writes the log to
<code>/var/log/noirconf</code>. If the service is not installed yet, noirconf shows what it will
install and asks you to confirm. After you change users, the server learns of it at once. For config
changes, press <b>Reload config</b> to apply the few settings that can change while running
(<code>bus-allow</code>, <code>verb</code> and <code>stats-interval</code>), and restart the server
for all others.</p>

<h3>Change the server config</h3>
<p>The Config page shows the options of the server in tabs, each with a friendly name, the real
option name, and its default and accepted values. Hover over an option for a short description. Change
what you need and press <b>Preview</b>. You see the lines that change and the result of
<code>noirvpn --check-config</code>, and the file is written only when the check finds no error.
Lines that the form does not show, such as comments, stay in the file. The addresses that clients use
are on this page too, and they follow the same rules as on the New server page.</p>

<h3 id="tls">Advanced: TLS server</h3>
<p>The switch <b>Run as TLS server</b> on the Service tab makes the port serve noirvpn clients over
TCP inside TLS, which looks like HTTPS to a firewall. Both ends must be noirvpn. The Protocol list
is off while the switch is on, and the server no longer answers UDP on that port. To serve UDP too,
add a Listen addresses line such as <code>* 1194 udp</code>, plus a line for the TLS port. A server
can have up to 8 listeners, and they share one tunnel and one address pool. The options under the
switch set the certificate and key of the outer TLS (by default the server certificate), a WebSocket
path, and whether plain OpenVPN TCP clients may use the same port.</p>

<h3 id="dco">Advanced: kernel DCO</h3>
<p>noirvpn has a fast data path of its own, and it copes with many clients, so most servers do not
need DCO. DCO moves the encryption of the data into the <code>ovpn</code> module of the Linux kernel
(version 6.16 or later). Turn on <b>Use kernel DCO</b> on the Data path tab to enable it. If the
kernel has no such module, the server logs a warning and uses its own data path. Worker threads do
not apply with DCO. A config that already has <code>datapath udco</code> or
<code>datapath auto</code> keeps that line, and the form shows only a note.</p>

<h3>Advanced: data channel ciphers</h3>
<p>The server accepts only AEAD ciphers: AES-256-GCM, AES-128-GCM and CHACHA20-POLY1305. With no
box ticked it offers all three in that order. When you tick boxes, noirconf writes them as one list,
keeps the order of ciphers that were already in the file, and adds new ones at the end. The server
picks the first cipher in its list that the client also supports.</p>
</div>
"""
