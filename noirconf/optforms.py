"""The server option form: defaults, reading a form, and applying it to a config."""
import json
import os

import ovpnconf
from ovpnconf import Config, ConfError, tokenize

HERE = os.path.dirname(os.path.abspath(__file__))

_cache = None

# The argument of these options is one text. The form shows it without quotes.
RAW_ARG = {"push", "push-remove"}


def load_options(path=None):
    global _cache
    if path is None and _cache is not None:
        return _cache
    with open(path or os.path.join(HERE, "options.json"), encoding="utf-8") as f:
        data = json.load(f)
    if path is None:
        _cache = data
    return data


def all_options(data=None):
    data = data or load_options()
    return {o["name"]: o for g in data["groups"] for o in g["options"]}


def defaults(name, etc):
    """Option lines of a new server: {option: [args, ...]}."""
    d = os.path.join(etc, name)
    rows = [
        ("server", "10.8.0.0 255.255.255.0"),
        ("port", "1194"),
        ("proto", "udp"),
        ("topology", "subnet"),
        ("keepalive", "10 60"),
        ("cert", os.path.join(d, "pki", "server.crt")),
        ("key", os.path.join(d, "pki", "server.key")),
        ("ca", os.path.join(d, "pki", "ca.crt")),
        ("crl-verify", os.path.join(d, "pki", "crl.pem")),
        ("peer-keys", os.path.join(d, "peers")),
        ("peer-keys-mode", "either"),
        ("tls-crypt", os.path.join(d, "tls-crypt.key")),
        ("bus-control", "/run/noirvpn/%s.control mode 0660" % name),
        ("bus-events", "/run/noirvpn/%s.events mode 0640" % name),
        ("bus-allow", "uid 0 admin"),
        ("stats-interval", "5"),
    ]
    return {opt: [split_args(text)] for opt, text in rows}


def split_args(text):
    """Split with the config rules. A quote problem raises ConfError."""
    return tokenize(text)


def join_args(args, name=None):
    if name in RAW_ARG and len(args) == 1 and args[0] and args[0][0] not in "\"'":
        return args[0]
    return " ".join(ovpnconf.quote_arg(a) for a in args)


def values_from_config(cfg, opts):
    """{option: [args, ...]} for the managed options that the file has."""
    out = {}
    for name in opts:
        got = cfg.get(name)
        if got:
            out[name] = got
    return out


def unmanaged_lines(cfg, opts):
    """Option names in the file that the form does not show."""
    skip = {"dev"} if cfg.first("dev") == ["tun"] else set()
    return [n for n in cfg.option_names() if n not in opts and n not in skip]


# Lines that the form does not show but a new config needs: {group: {option: lines}}.
FIXED = {"network": {"dev": [["tun"]]}}

# The values of datapath that this form does not change.
DATAPATH_KEEP = ("udco", "auto", "userspace")


def tls_on_values(values):
    """True when the managed values have a tls-server proto."""
    return tls_on(values)


def tls_on(cfg_or_values):
    """True when proto is a tls-server value (tls-server, tls4-server or tls6-server)."""
    got = _first_value(cfg_or_values, "proto")
    return bool(got) and got[0].startswith("tls") and got[0].endswith("-server")


def _first_value(src, name):
    if src is None:
        return None
    if isinstance(src, dict):
        v = src.get(name)
        return v[0] if v else None
    return src.first(name)


def parse_form(form, opts, existing=None):
    """Read fields "o.NAME" and the switches "v.tls" and "v.dco" of a posted form.

    existing is the current Config, or None for a new server.
    Returns (values, errors). A missing or empty field means "no such line".
    """
    values, errors = {}, []
    for name, o in opts.items():
        key = "o." + name
        raw = form.get(key)
        if o.get("virtual"):
            continue
        if o["max"] == 0:
            if raw in ("on", "1", "yes", "true"):
                values[name] = [[]]
            continue
        if raw is None or not raw.strip():
            continue
        if o["repeat"]:
            lines = [ln for ln in raw.replace("\r", "").split("\n") if ln.strip()]
        else:
            if "\n" in raw.strip() or "\r" in raw:
                errors.append("%s: use one line" % name)
                continue
            lines = [raw.strip()]
        arglists = []
        for ln in lines:
            try:
                args = [ln.strip()] if name in RAW_ARG and ln.strip()[0] not in "\"'" else split_args(ln)
            except ConfError as e:
                errors.append("%s: %s" % (name, e))
                break
            if not args:
                errors.append("%s: the value is empty" % name)
                break
            n = len(args)
            if n < o["min"] or (o["max"] is not None and n > o["max"]):
                want = ("%d" % o["min"]) if o["max"] == o["min"] else (
                    "%d or more" % o["min"] if o["max"] is None else "%d to %d" % (o["min"], o["max"]))
                errors.append("%s: needs %s argument(s), got %d" % (name, want, n))
                break
            arglists.append(args)
        else:
            values[name] = arglists
    _virtual(form, values, existing)
    return values, errors


CIPHERS = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]


def cipher_state(cur):
    """(ticked, others) of a data-ciphers value: the known names and the unknown ones."""
    names = [n for n in (cur[0][0].split(":") if cur and cur[0] else []) if n]
    ticked = [n for n in names if n.upper() in CIPHERS]
    return ticked, [n for n in names if n.upper() not in CIPHERS]


def cipher_value(form, existing):
    """The data-ciphers line from the checkboxes "v.cipher.NAME", or None for no line."""
    on = [c for c in CIPHERS if form.get("v.cipher." + c) in ("on", "1")]
    old, others = cipher_state(existing.get("data-ciphers") if existing is not None else None)
    ordered = [c for c in old if c.upper() in on]
    ordered += [c for c in on if c not in [o.upper() for o in ordered]]
    names = ordered + others
    return ":".join(names) if names else None


def _virtual(form, values, existing):
    """The switches "Run as TLS server" and "Use kernel DCO", and the cipher boxes."""
    val = cipher_value(form, existing)
    if val:
        values["data-ciphers"] = [[val]]
    if form.get("v.tls") in ("on", "1"):
        cur = existing.first("proto") if existing is not None else None
        if cur and tls_on(existing):
            values["proto"] = [cur]
        else:
            values["proto"] = [["tls-server"]]
    cur = existing.first("datapath") if existing is not None else None
    if form.get("v.dco") in ("on", "1"):
        values["datapath"] = [["dco"]]
    elif cur and cur[0] in DATAPATH_KEEP:
        values["datapath"] = [cur]


def apply_values(cfg, values, opts, order=None):
    """Write the managed options into cfg. Returns True when the text changed."""
    changed = False
    names = order or list(opts)
    for name in names:
        want = values.get(name, [])
        if cfg.set_option(name, want):
            changed = True
    return changed


def new_config(values, data=None):
    """A new config text for a server, grouped like the form."""
    data = data or load_options()
    cfg = Config()
    cfg.add_comment("noirvpn server config. Written by noirconf.")
    cfg.add_comment("Lines that noirconf does not manage are kept when it writes the file.")
    for g in data["groups"]:
        lines = [o for o in g["options"] if o["name"] in values]
        fixed = FIXED.get(g["id"], {})
        if not lines and not fixed:
            continue
        cfg.add_blank()
        cfg.add_comment(g["title"])
        for name, arglists in fixed.items():
            cfg.set_option(name, arglists)
        for o in lines:
            cfg.set_option(o["name"], values[o["name"]])
    return cfg
