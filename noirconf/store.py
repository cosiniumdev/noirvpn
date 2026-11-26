"""The data of the servers and the actions on it.

Layout under the etc folder:

    NAME.conf              the daemon config
    NAME/pki/              CA and server certificate
    NAME/tls-crypt.key     control channel key
    NAME/accounts.conf     users and keys
    NAME/peers             generated peers file
    NAME/noirconf.ini      settings of this program (external addresses)
"""
import configparser
import difflib
import glob
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading

import accounts as acct
import bus as busmod
import essentials
import fsutil
import optforms
import ovpnconf
import pki

log = logging.getLogger("noirconf")
audit_log = logging.getLogger("noirconf.audit")

SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
PROTO_ALIASES = {"udp": "udp", "udp4": "udp", "udp6": "udp",
                 "tcp": "tcp", "tcp-server": "tcp", "tcp4-server": "tcp", "tcp6-server": "tcp",
                 "tls": "tls", "tls-server": "tls", "tls4-server": "tls", "tls6-server": "tls"}
PROFILE_PROTO = {"udp": "udp", "tcp": "tcp-client", "tls": "tls-client"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class StoreError(Exception):
    pass


def valid_server_name(name):
    return bool(isinstance(name, str) and SERVER_NAME_RE.match(name)
                and not name.startswith("appserver") and name not in (".", ".."))


def valid_host(host):
    if HOST_RE.match(host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class Paths:
    def __init__(self, etc, name):
        self.etc = etc
        self.name = name
        self.conf = os.path.join(etc, name + ".conf")
        self.data = os.path.join(etc, name)
        self.pki = os.path.join(self.data, "pki")
        self.tls_crypt = os.path.join(self.data, "tls-crypt.key")
        self.accounts = os.path.join(self.data, "accounts.conf")
        self.peers = os.path.join(self.data, "peers")
        self.ini = os.path.join(self.data, "noirconf.ini")


def scan(etc):
    names = []
    for p in sorted(glob.glob(os.path.join(glob.escape(etc), "*.conf"))):
        base = os.path.basename(p)[:-5]
        if base.startswith("appserver.") or base == "appserver":
            continue
        if valid_server_name(base) and os.path.isfile(p):
            names.append(base)
    return names


# External addresses

LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def local_host_reason(host):
    """Why a host cannot be an external address, or "" when it can."""
    h = host.strip().lower().rstrip(".")
    if h in LOCAL_NAMES or h.endswith(".localhost"):
        return "is the local computer"
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return ""
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "is a loopback address"
    if ip.is_unspecified:
        return "is an unspecified address"
    return ""


class External(tuple):
    """An address of the server: (host, port, proto). A tls address can have a WebSocket path
    in the attribute ws. It does not take part in comparisons."""

    def __new__(cls, host, port, proto, ws=""):
        self = super().__new__(cls, (host, port, proto))
        self.ws = ws
        return self


def parse_externals(text, default_port="1194", default_proto="udp", strict=True):
    """Lines "HOST [PORT [PROTO [ws=PATH]]]" into a list of External.

    With strict=False, a line that is not valid is skipped.
    """
    if not strict:
        out = []
        for ln in text.replace("\r", "").split("\n"):
            try:
                out.extend(parse_externals(ln, default_port, default_proto))
            except StoreError:
                continue
        return out
    out = []
    for ln in text.replace("\r", "").split("\n"):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) > 4:
            raise StoreError("an address line has at most host, port, protocol and ws=PATH")
        host = parts[0]
        port = parts[1] if len(parts) > 1 else default_port
        proto = parts[2] if len(parts) > 2 else default_proto
        ws = ""
        if len(parts) > 3:
            if not parts[3].startswith("ws="):
                raise StoreError("the fourth word of an address line is ws=PATH")
            if proto != "tls":
                raise StoreError("ws=PATH needs the protocol tls")
            try:
                ws = essentials.check_ws_path(parts[3][3:])
            except ValueError as e:
                raise StoreError(str(e))
        if not valid_host(host):
            raise StoreError("%r is not a host name or an address" % host[:60])
        why = local_host_reason(host)
        if why:
            raise StoreError("%s %s, so clients on other computers cannot reach it. Use the name "
                             "or the address that clients use to reach this server." % (host[:60], why))
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise StoreError("the port %r is not valid" % port[:10])
        if proto not in PROFILE_PROTO:
            raise StoreError("the protocol must be udp, tcp or tls")
        out.append(External(host, str(int(port)), proto, ws))
    return out


def externals_text(items):
    return "\n".join("%s %s %s%s" % (tuple(t) + ((" ws=" + t.ws) if getattr(t, "ws", "") else "",))
                     for t in items)


def _read_ini(paths):
    cp = configparser.RawConfigParser(interpolation=None)
    cp.optionxform = str
    try:
        cp.read(paths.ini, encoding="utf-8")
    except configparser.Error:
        return configparser.RawConfigParser(interpolation=None)
    return cp


def read_key_type(paths):
    cp = _read_ini(paths)
    kt = cp.get("server", "key-type", fallback=pki.DEFAULT_KEY_TYPE).strip()
    return kt if kt in pki.KEY_TYPES else pki.DEFAULT_KEY_TYPE


CLIENT_MODES = ("openvpn", "noirvpn")


def read_clients(paths):
    """Who can use the server: "openvpn" (the default) or "noirvpn". Only a hint for the user."""
    cp = _read_ini(paths)
    v = cp.get("server", "clients", fallback="openvpn").strip()
    return v if v in CLIENT_MODES else "openvpn"


def read_externals(paths):
    cp = _read_ini(paths)
    out = []
    if cp.has_section("external"):
        keys = sorted((k for k in cp["external"] if re.fullmatch(r"remote\.\d+", k)),
                      key=lambda k: int(k.split(".")[1]))
        text = "\n".join(cp["external"][k] for k in keys)
        out = parse_externals(text, strict=False)
    return out


def write_externals(paths, items, key_type=None, clients=None):
    """Write noirconf.ini: the key type for new keys, the clients hint and the external addresses."""
    if key_type is None:
        key_type = read_key_type(paths)
    if clients is None:
        clients = read_clients(paths)
    pki.check_key_type(key_type)
    if clients not in CLIENT_MODES:
        raise StoreError("the clients value is openvpn or noirvpn")
    lines = ["# Settings of noirconf for this server.", "[server]", "key-type = %s" % key_type,
             "clients = %s" % clients, "", "[external]"]
    for i, t in enumerate(items, 1):
        lines.append("remote.%d = %s" % (i, externals_text([t])))
    fsutil.atomic_write(paths.ini, "\n".join(lines) + "\n", mode=0o640, group=True)


# System information

def system_info(proc="/proc"):
    info = {"load": None, "mem_used": None, "mem_total": None}
    try:
        with open(os.path.join(proc, "loadavg")) as f:
            info["load"] = " ".join(f.read().split()[:3])
    except OSError:
        pass
    try:
        mem = {}
        with open(os.path.join(proc, "meminfo")) as f:
            for line in f:
                k, _, v = line.partition(":")
                mem[k] = int(v.split()[0]) * 1024
        total = mem["MemTotal"]
        avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        info["mem_total"], info["mem_used"] = total, total - avail
    except (OSError, KeyError, ValueError, IndexError):
        pass
    return info


# The store

class Store:
    def __init__(self, etc, noirvpn, svc, run_dir=busmod.DEFAULT_RUN_DIR):
        self.etc = etc
        self.noirvpn = noirvpn
        self.svc = svc
        self.run_dir = run_dir
        self.lock = threading.RLock()
        self.options = optforms.load_options()
        self.opts = optforms.all_options(self.options)

    def paths(self, name):
        if not valid_server_name(name):
            raise StoreError("bad server name")
        return Paths(self.etc, name)

    def servers(self):
        return scan(self.etc)

    def exists(self, name):
        return valid_server_name(name) and os.path.isfile(self.paths(name).conf)

    def managed(self, name):
        return os.path.isfile(self.paths(name).accounts)

    # Config

    def read_config(self, name):
        p = self.paths(name)
        return ovpnconf.Config.parse(fsutil.read_text(p.conf))

    def bus(self, name):
        try:
            cfg = self.read_config(name)
        except (OSError, ovpnconf.ConfError):
            cfg = ovpnconf.Config()
        c = cfg.first("bus-control")
        e = cfg.first("bus-events")
        cv = c[0] if c else None
        ev = e[0] if e else None
        control = busmod.control_path(name, cv, self.run_dir)
        events = busmod.events_path(name, ev, self.run_dir)
        if cv == "off":
            return None
        return busmod.Bus(control, events)

    def check_config(self, path):
        """Run noirvpn --check-config. Returns (ok, text)."""
        if not self.noirvpn or not (os.path.isfile(self.noirvpn) and os.access(self.noirvpn, os.X_OK)):
            return False, "The noirvpn program is not found. Start noirconf with --noirvpn PATH."
        try:
            p = subprocess.run([self.noirvpn, "--check-config", "--config", path],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                               shell=False)
        except subprocess.TimeoutExpired:
            return False, "The check took too long."
        except OSError as e:
            return False, "Cannot run noirvpn: %s" % (e.strerror or e)
        return p.returncode == 0, p.stdout.decode("utf-8", "replace")

    def check_text(self, name, text):
        """Check a candidate config text. The file is next to the real one."""
        fd, tmp = tempfile.mkstemp(prefix=".%s." % name, suffix=".check", dir=self.etc)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            return self.check_config(tmp)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def form_to_config(self, name, form):
        """Apply a posted form to the current file. Returns (new_text, old_text, errors)."""
        p = self.paths(name)
        old = fsutil.read_text(p.conf, default="")
        cfg = ovpnconf.Config.parse(old)
        values, errors = optforms.parse_form(form, self.opts, cfg)
        optforms.apply_values(cfg, values, self.opts)
        return cfg.render(), old, errors

    @staticmethod
    def diff(old, new, name):
        return "".join(difflib.unified_diff(
            old.splitlines(True), new.splitlines(True),
            "%s.conf (now)" % name, "%s.conf (new)" % name))

    def write_config(self, name, text):
        p = self.paths(name)
        fsutil.atomic_write(p.conf, text, mode=0o640, group=True)

    # Servers

    def create_server(self, name, form, externals_text_value, actor="-", key_type=None):
        """Create the data and the config of a new server from the full form.

        Returns the config text.
        """
        if not valid_server_name(name):
            raise StoreError("a server name has 1 to 40 letters, digits or . _ -")
        values, errors = optforms.parse_form(form, self.opts)
        if errors:
            raise StoreError("; ".join(errors))
        if "server" not in values:
            raise StoreError("the option server is required")
        port = (values.get("port") or [["1194"]])[0][0]
        proto = PROTO_ALIASES.get((values.get("proto") or [["udp"]])[0][0], "udp")
        externals = parse_externals(externals_text_value, port, proto)
        return self._create(name, values, externals,
                            pki.check_key_type(key_type or pki.DEFAULT_KEY_TYPE), actor)

    def create_essentials(self, name, form, actor="-"):
        """Create a server from the fields of Create with Essentials. Returns the config text."""
        if not valid_server_name(name):
            raise StoreError("a server name has 1 to 40 letters, digits or . _ -")
        try:
            e = essentials.parse(form, name)
        except ValueError as err:
            raise StoreError(str(err))
        line = "%s %s %s%s" % (e["host"], e["public_port"], e["ext_proto"],
                               " ws=" + e["ws"] if e["ws"] else "")
        externals = parse_externals(line)
        values = optforms.defaults(name, self.etc)
        values["server"] = [e["network"].split()]
        values["port"] = [[e["port"]]]
        values["proto"] = [[e["proto"]]]
        if e["ws"]:
            values["tls-transport-ws"] = [[e["ws"]]]
        return self._create(name, values, externals, pki.DEFAULT_KEY_TYPE, actor,
                            "noirvpn" if form.get("e.clients") == "noir" else "openvpn")

    def _create(self, name, values, externals, key_type, actor, clients="openvpn"):
        with self.lock:
            p = self.paths(name)
            if os.path.exists(p.conf) or os.path.exists(p.data):
                raise StoreError("a server with this name exists")
            cfg = optforms.new_config(values, self.options)
            text = cfg.render()
            try:
                self._init_data(name, externals, key_type, clients)
                ok, out = self.check_text(name, text)
                if not ok:
                    raise StoreError("The check of the config failed:\n" + out)
                self.write_config(name, text)
            except BaseException:
                shutil.rmtree(p.data, ignore_errors=True)
                raise
        audit_log.info("user=%s action=server.create server=%s", actor, name)
        return text

    def _init_data(self, name, externals, key_type=pki.DEFAULT_KEY_TYPE, clients="openvpn"):
        p = self.paths(name)
        fsutil.make_dir(p.data, 0o750 if fsutil.daemon_gid() is not None else 0o700, group=True)
        ca = pki.CA(p.pki, key_type)
        ca.init("noirconf CA %s" % name)
        cn = externals[0][0] if externals else name
        ca.issue_server(cn, [e[0] for e in externals],
                        os.path.join(p.pki, "server.key"), os.path.join(p.pki, "server.crt"))
        fsutil.atomic_write(p.tls_crypt, pki.tls_crypt_key_text(), mode=0o640, group=True)
        fsutil.atomic_write(p.accounts, acct.Accounts().render(), mode=0o640, group=True)
        fsutil.atomic_write(p.peers, acct.peers_text(acct.Accounts()), mode=0o640, group=True)
        write_externals(p, externals, key_type, clients)

    def init_data(self, name, externals_text_value, actor="-", key_type=None):
        """Create the PKI and accounts for a config that other tools wrote."""
        with self.lock:
            p = self.paths(name)
            if not os.path.isfile(p.conf):
                raise StoreError("no such server")
            if os.path.exists(p.data):
                raise StoreError("the data folder exists")
            cfg = self.read_config(name)
            port = (cfg.first("port") or ["1194"])[0]
            proto = PROTO_ALIASES.get((cfg.first("proto") or ["udp"])[0], "udp")
            externals = parse_externals(externals_text_value, port, proto)
            key_type = pki.check_key_type(key_type or pki.DEFAULT_KEY_TYPE)
            try:
                self._init_data(name, externals, key_type)
            except BaseException:
                shutil.rmtree(p.data, ignore_errors=True)
                raise
        audit_log.info("user=%s action=server.init server=%s", actor, name)

    def externals(self, name):
        return read_externals(self.paths(name))

    def key_type(self, name):
        return read_key_type(self.paths(name))

    def clients(self, name):
        return read_clients(self.paths(name))

    def set_externals(self, name, text, actor="-", key_type=None, clients=None):
        p = self.paths(name)
        cfg = self.read_config(name)
        port = (cfg.first("port") or ["1194"])[0]
        proto = PROTO_ALIASES.get((cfg.first("proto") or ["udp"])[0], "udp")
        items = parse_externals(text, port, proto)
        if not os.path.isdir(p.data):
            raise StoreError("this server has no data folder")
        write_externals(p, items, key_type, clients)
        audit_log.info("user=%s action=externals.set server=%s count=%d key_type=%s", actor, name,
                       len(items), key_type or "-")

    # Accounts

    def load_accounts(self, name):
        p = self.paths(name)
        try:
            return acct.Accounts.parse(fsutil.read_text(p.accounts))
        except FileNotFoundError:
            raise StoreError("this server has no accounts file")

    def save_accounts(self, name, accs):
        p = self.paths(name)
        fsutil.atomic_write(p.accounts, accs.render(), mode=0o640, group=True)
        fsutil.atomic_write(p.peers, acct.peers_text(accs), mode=0o640, group=True)

    def ca(self, name):
        ca = pki.CA(self.paths(name).pki, self.key_type(name))
        if not ca.exists():
            raise StoreError("this server has no CA")
        return ca

    def sync_daemon(self, name, kicks=(), reload_peers=True):
        """Tell the running daemon about the peers file and kick sessions.

        Returns a list of short notes for the user.
        """
        notes = []
        b = self.bus(name)
        if b is None:
            return ["The control socket is off, so the daemon was not told."]
        try:
            kicked = 0
            for args in kicks:
                try:
                    res = b.call("peer.kick", dict(args, halt=True, reason="noirconf"))
                    kicked += len(res.get("kicked", []))
                except busmod.BusError as e:
                    if e.code != "not_found":
                        raise
            if kicks:
                notes.append("%d session(s) ended." % kicked)
            if reload_peers:
                b.call("peers.reload")
                notes.append("The daemon read the peers file again.")
        except busmod.NotRunning:
            return ["The daemon is not running. It reads the peers file at start."]
        except (busmod.BusError, busmod.BusProtocolError) as e:
            return ["The daemon did not accept the change (%s)." % e]
        return notes

    def _user_kicks(self, user, key=None):
        kicks = [{"name": user.name}]
        keys = [key] if key else user.keys
        for k in keys:
            if acct.bus_pin(k.pin):
                kicks.append({"pin": acct.bus_pin(k.pin)})
            if k.serial:
                kicks.append({"serial": k.serial})
        return kicks

    def add_user(self, name, user, notes="", options="", actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            accs.add_user(user, notes, options)
            self.save_accounts(name, accs)
            notes_ = self.sync_daemon(name)
        audit_log.info("user=%s action=user.add server=%s target=%s", actor, name, user)
        return notes_

    def delete_user(self, name, user, actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            kicks = self._user_kicks(u)
            self._revoke_keys(name, u, u.keys)
            accs.delete_user(user)
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name, kicks)
        audit_log.info("user=%s action=user.delete server=%s target=%s", actor, name, user)
        return notes

    def set_enabled(self, name, user, enabled, actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            u.enabled = bool(enabled)
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name, [] if enabled else self._user_kicks(u))
        audit_log.info("user=%s action=user.%s server=%s target=%s", actor,
                       "enable" if enabled else "disable", name, user)
        return notes

    def add_key(self, name, user, text, label="", actor="-"):
        """Add a pin from a pin string, a public key PEM or a certificate PEM."""
        text = (text or "").strip()
        serial, source = "", "pin"
        if re.match(r"^(sha256|mldsa65-sha256):", text):
            pin = acct.check_pin(text)
        else:
            kind = pki.classify_pem(text)
            pin = pki.pin_from_pem(text)
            if kind == "cert":
                source = "cert"
                serial = pki.cert_serial(pki.first_pem_block(text, "CERTIFICATE"))
        with self.lock:
            accs = self.load_accounts(name)
            k = accs.add_key(user, pin, label, serial, source)
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name)
        audit_log.info("user=%s action=key.add server=%s target=%s key=%s", actor, name, user, k.id)
        return notes

    def sign_csr(self, name, user, text, label="", actor="-"):
        """Sign a certificate request of a user. Returns (cert_pem, notes)."""
        csr, pin = pki.check_csr(text)
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            if not u.enabled:
                raise StoreError("The user is disabled.")
            other, _ = accs.find_pin(pin)
            if other is not None:
                raise StoreError("This key belongs to the user %s already." % other.name)
            cert, serial, pin = self.ca(name).issue_from_csr(csr, u.name)
            k = accs.add_key(user, pin, label or "csr " + acct.now_text()[:10], serial, "ca")
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name)
        audit_log.info("user=%s action=key.sign server=%s target=%s key=%s serial=%s", actor, name,
                       user, k.id, serial)
        return cert, notes

    def _revoke_keys(self, name, user, keys):
        """Revoke the CA certificates among the keys and update the CRL."""
        any_ca = False
        for k in keys:
            if k.source == "ca" and k.serial and k.active:
                try:
                    self.ca(name).revoke(k.serial)
                    any_ca = True
                except (pki.PkiError, StoreError) as e:
                    log.warning("revoke of %s failed: %s", k.serial, e)
                    raise StoreError("The certificate could not be revoked: %s" % e)
        if any_ca:
            self.ca(name).gen_crl()
        for k in keys:
            k.state = "revoked"

    def revoke_key(self, name, user, kid, actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            k = u.key(kid)
            if k is None:
                raise StoreError("no such key")
            self._revoke_keys(name, u, [k])
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name, self._user_kicks(u, k))
        audit_log.info("user=%s action=key.revoke server=%s target=%s key=%s", actor, name, user, kid)
        return notes

    def revoke_user(self, name, user, actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            self._revoke_keys(name, u, u.keys)
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name, self._user_kicks(u))
        audit_log.info("user=%s action=user.revoke server=%s target=%s", actor, name, user)
        return notes

    def delete_key(self, name, user, kid, actor="-"):
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            k = u.key(kid)
            if k is None:
                raise StoreError("no such key")
            kicks = self._user_kicks(u, k)
            self._revoke_keys(name, u, [k])
            accs.delete_key(user, kid)
            self.save_accounts(name, accs)
            notes = self.sync_daemon(name, kicks)
        audit_log.info("user=%s action=key.delete server=%s target=%s key=%s", actor, name, user, kid)
        return notes

    # Profiles

    def build_profile(self, name, user, remote_index, mode, passphrase="", own_cert="",
                      actor="-"):
        """Returns (file_name, text). mode is "generate" or "own"."""
        p = self.paths(name)
        externals = read_externals(p)
        if not externals:
            raise StoreError("Set the external addresses of the server first.")
        if remote_index is None:
            remotes = externals
        else:
            if not 0 <= remote_index < len(externals):
                raise StoreError("no such address")
            remotes = [externals[remote_index]]
        profile_ws_path(remotes)
        ca_pem = fsutil.read_text(os.path.join(p.pki, "ca.crt"))
        tc = fsutil.read_text(p.tls_crypt)
        with self.lock:
            accs = self.load_accounts(name)
            u = accs.user(user)
            if mode == "own":
                cert = pki.first_pem_block(own_cert, "CERTIFICATE")
                pin = pki.pin_from_pem(cert)
                found = [k for k in u.keys if k.pin == pin and k.active]
                if not found:
                    raise StoreError("This certificate is not an active key of this user. "
                                     "Add it to the user first.")
                key_pem = None
            else:
                if not u.enabled:
                    raise StoreError("The user is disabled.")
                key_pem, cert, serial, pin = self.ca(name).issue_client(
                    user, passphrase or None)
                k = accs.add_key(user, pin, "profile " + acct.now_text()[:10], serial, "ca")
                self.save_accounts(name, accs)
                self.sync_daemon(name)
        text = profile_text(remotes, ca_pem, tc, cert, key_pem)
        audit_log.info("user=%s action=profile.%s server=%s target=%s", actor, mode, name, user)
        return "%s-%s.ovpn" % (name, user), text


def profile_ws_path(remotes):
    """The WebSocket path of a profile, or "". The option applies to every tls address."""
    paths = {t.ws for t in remotes if t[2] == "tls" and getattr(t, "ws", "")}
    tls_plain = any(t[2] == "tls" and not getattr(t, "ws", "") for t in remotes)
    if len(paths) > 1 or (paths and tls_plain):
        raise StoreError("The tls-transport-ws option applies to every tls address of a profile. "
                         "Choose one address, or use one WebSocket path for all tls addresses.")
    return paths.pop() if paths else ""


def profile_text(remotes, ca_pem, tls_crypt, cert_pem, key_pem=None):
    out = ["client", "dev tun"]
    for t in remotes:
        host, port, proto = t[0], t[1], t[2]
        out.append("remote %s %s %s" % (host, port, PROFILE_PROTO[proto]))
    if len(remotes) > 1:
        out.append("remote-random")
    out += ["remote-cert-tls server", "nobind", "resolv-retry infinite"]
    ws = profile_ws_path(remotes)
    if ws:
        out.append("tls-transport-ws %s" % ws)
    if key_pem is None:
        out += ["# Point the next line at your own private key file.",
                "key /path/to/your-private-key.pem"]
    out.append("<ca>\n%s</ca>" % _nl(ca_pem))
    out.append("<tls-crypt>\n%s</tls-crypt>" % _nl(tls_crypt))
    out.append("<cert>\n%s</cert>" % _nl(cert_pem))
    if key_pem is not None:
        out.append("<key>\n%s</key>" % _nl(key_pem))
    return "\n".join(out) + "\n"


def _nl(text):
    text = text.strip("\n")
    return text + "\n"
