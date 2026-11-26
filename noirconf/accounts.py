"""Accounts of one server: accounts.conf and the generated peers file.

accounts.conf is an INI file with one [username] section for each user:

    [alice]
    enabled = yes
    created = 2026-11-26T10:00:00Z
    notes = free text on one line
    options = ifconfig-push=10.8.0.10 iroute=192.168.50.0/24
    key.k1.pin = sha256:BASE64
    key.k1.serial = 0A1B...         (only for a cert that the server CA signed)
    key.k1.label = laptop
    key.k1.state = active           (active or revoked)
    key.k1.source = ca              (ca, cert or pin)
    key.k1.created = 2026-11-26T10:00:00Z
"""
import configparser
import re
import threading
import time

NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
PIN_RE = re.compile(r"^(sha256|mldsa65-sha256):[A-Za-z0-9+/]{43}=$")
KEY_ID_RE = re.compile(r"^k[0-9]{1,6}$")
PEER_OPTION_RE = re.compile(
    r"^(ifconfig-push=[0-9.]{7,15}"
    r"|ifconfig-ipv6-push=[0-9A-Fa-f:.]{2,45}/[0-9]{1,3}"
    r"|iroute=[0-9.]{7,15}/[0-9]{1,2}"
    r"|iroute-ipv6=[0-9A-Fa-f:.]{2,45}/[0-9]{1,3})$"
)
STATES = ("active", "revoked")
SOURCES = ("ca", "cert", "pin")
LABEL_MAX = 64
NOTES_MAX = 200


class AccountError(ValueError):
    pass


def valid_name(name):
    """A user name: safe file name characters, and valid in the peers file."""
    return bool(
        isinstance(name, str)
        and NAME_RE.match(name)
        and name not in (".", "..")
        and not name.startswith("-")
    )


def check_name(name):
    if not valid_name(name):
        raise AccountError(
            "a name has 1 to 64 letters, digits or the characters . _ @ -, "
            "and it does not start with -"
        )
    return name


def check_pin(pin):
    if not isinstance(pin, str) or not PIN_RE.match(pin):
        raise AccountError("the pin must look like sha256: and 44 base64 characters")
    return pin


def clean_text(text, limit, what):
    text = (text or "").strip()
    if len(text) > limit:
        raise AccountError("%s is longer than %d characters" % (what, limit))
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise AccountError("%s has a control character" % what)
    return text


def bus_pin(pin):
    """The pin as the control bus writes it: sha256: and 64 hex digits. None for other kinds."""
    import base64
    if not pin.startswith("sha256:"):
        return None
    return "sha256:" + base64.b64decode(pin[7:]).hex()


def now_text():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Key:
    def __init__(self, kid, pin, serial="", label="", state="active", source="pin", created=""):
        self.id = kid
        self.pin = pin
        self.serial = serial
        self.label = label
        self.state = state
        self.source = source
        self.created = created

    @property
    def active(self):
        return self.state == "active"


class User:
    def __init__(self, name, enabled=True, created="", notes="", options=""):
        self.name = name
        self.enabled = enabled
        self.created = created
        self.notes = notes
        self.options = options
        self.keys = []

    def key(self, kid):
        for k in self.keys:
            if k.id == kid:
                return k
        return None

    def next_key_id(self):
        n = 0
        for k in self.keys:
            try:
                n = max(n, int(k.id[1:]))
            except ValueError:
                pass
        return "k%d" % (n + 1)


class Accounts:
    def __init__(self):
        self.users = {}
        self.lock = threading.RLock()

    # Parse and write

    @classmethod
    def parse(cls, text):
        cp = configparser.RawConfigParser(interpolation=None, delimiters=("=",),
                                          comment_prefixes=("#", ";"), strict=True)
        cp.optionxform = str
        try:
            cp.read_string(text)
        except configparser.Error as e:
            raise AccountError("accounts.conf: %s" % str(e).splitlines()[0])
        acc = cls()
        for name in cp.sections():
            check_name(name)
            sec = cp[name]
            u = User(
                name,
                enabled=sec.get("enabled", "yes").strip().lower() in ("yes", "true", "1", "on"),
                created=sec.get("created", "").strip(),
                notes=sec.get("notes", "").strip(),
                options=sec.get("options", "").strip(),
            )
            ids = []
            for k in sec:
                m = re.match(r"^key\.(k[0-9]+)\.([a-z]+)$", k)
                if m and m.group(1) not in ids:
                    ids.append(m.group(1))
            for kid in ids:
                pre = "key.%s." % kid
                pin = sec.get(pre + "pin", "").strip()
                check_pin(pin)
                state = sec.get(pre + "state", "active").strip()
                source = sec.get(pre + "source", "pin").strip()
                if state not in STATES or source not in SOURCES:
                    raise AccountError("accounts.conf: bad state or source for %s %s" % (name, kid))
                u.keys.append(Key(kid, pin, sec.get(pre + "serial", "").strip(),
                                  sec.get(pre + "label", "").strip(), state, source,
                                  sec.get(pre + "created", "").strip()))
            acc.users[name] = u
        acc.check_unique()
        return acc

    def render(self):
        out = ["# Accounts of this server. Written by noirconf.", ""]
        for name in sorted(self.users, key=str.lower):
            u = self.users[name]
            out.append("[%s]" % name)
            out.append("enabled = %s" % ("yes" if u.enabled else "no"))
            if u.created:
                out.append("created = %s" % u.created)
            if u.notes:
                out.append("notes = %s" % u.notes)
            if u.options:
                out.append("options = %s" % u.options)
            for k in u.keys:
                pre = "key.%s." % k.id
                out.append("%spin = %s" % (pre, k.pin))
                if k.serial:
                    out.append("%sserial = %s" % (pre, k.serial))
                if k.label:
                    out.append("%slabel = %s" % (pre, k.label))
                out.append("%sstate = %s" % (pre, k.state))
                out.append("%ssource = %s" % (pre, k.source))
                if k.created:
                    out.append("%screated = %s" % (pre, k.created))
            out.append("")
        return "\n".join(out)

    # Checks

    def check_unique(self):
        names = {}
        for n in self.users:
            low = n.lower()
            if low in names:
                raise AccountError("the names %s and %s are the same user" % (names[low], n))
            names[low] = n
        pins = {}
        for u in self.users.values():
            for k in u.keys:
                if k.pin in pins:
                    raise AccountError("the pin of %s is used twice" % u.name)
                pins[k.pin] = u.name

    def find_pin(self, pin):
        for u in self.users.values():
            for k in u.keys:
                if k.pin == pin:
                    return u, k
        return None, None

    # Changes

    def add_user(self, name, notes="", options=""):
        check_name(name)
        low = name.lower()
        for n in self.users:
            if n.lower() == low:
                raise AccountError("a user with this name exists")
        u = User(name, True, now_text(), clean_text(notes, NOTES_MAX, "the notes"),
                 check_options(options))
        self.users[name] = u
        return u

    def delete_user(self, name):
        if name not in self.users:
            raise AccountError("no such user")
        del self.users[name]

    def user(self, name):
        u = self.users.get(name)
        if u is None:
            raise AccountError("no such user")
        return u

    def add_key(self, name, pin, label="", serial="", source="pin"):
        u = self.user(name)
        check_pin(pin)
        other, _ = self.find_pin(pin)
        if other is not None:
            raise AccountError("this pin belongs to the user %s already" % other.name)
        if source not in SOURCES:
            raise AccountError("bad key source")
        k = Key(u.next_key_id(), pin, serial, clean_text(label, LABEL_MAX, "the label"),
                "active", source, now_text())
        u.keys.append(k)
        return k

    def delete_key(self, name, kid):
        u = self.user(name)
        k = u.key(kid)
        if k is None:
            raise AccountError("no such key")
        u.keys.remove(k)
        return k


def check_options(text):
    """Peers file options of one user, as a space separated string."""
    text = (text or "").strip()
    parts = text.split()
    for p in parts:
        if not PEER_OPTION_RE.match(p):
            raise AccountError("the option %r is not valid for a peers file line" % p[:40])
    return " ".join(parts)


def peers_text(acc):
    """The peers file of the daemon, generated from the accounts."""
    out = ["# Generated by noirconf from accounts.conf. Do not edit.",
           "# name pin options"]
    for name in sorted(acc.users, key=str.lower):
        u = acc.users[name]
        first = next((k for k in u.keys if k.active), None)
        for k in u.keys:
            opts = u.options.split() if (u.options and k is first) else []
            if not u.enabled or not k.active:
                opts = opts + ["disabled"]
            line = "%s %s" % (u.name, k.pin)
            if opts:
                line += " " + " ".join(opts)
            if k.label:
                line += "  # " + re.sub(r"[\r\n]", " ", k.label)
            out.append(line)
    return "\n".join(out) + "\n"


def parse_peers(text):
    """Read a peers file back: list of (name, pin, options). For tests."""
    rows = []
    for line in text.splitlines():
        fields = []
        for f in line.split():
            if f.startswith("#"):
                break
            fields.append(f)
        if len(fields) >= 2:
            rows.append((fields[0], fields[1], fields[2:]))
    return rows
