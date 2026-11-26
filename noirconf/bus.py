"""Client of the noirvpn control bus (see docs/management.md)."""
import json
import os
import re
import secrets

import nng

DEFAULT_RUN_DIR = "/run/noirvpn"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


class BusError(Exception):
    """The daemon replied with an error."""

    def __init__(self, code, message=""):
        super().__init__("%s: %s" % (code, message) if message else str(code))
        self.code = code
        self.message = message


class NotRunning(Exception):
    """No daemon listens on the control socket."""


class BusProtocolError(Exception):
    """The reply does not follow the bus protocol."""


def control_path(name, conf_value=None, run_dir=DEFAULT_RUN_DIR):
    """The control socket path. conf_value is the first argument of bus-control."""
    return _socket_path(name, "control", conf_value, run_dir)


def events_path(name, conf_value=None, run_dir=DEFAULT_RUN_DIR):
    return _socket_path(name, "events", conf_value, run_dir)


def _socket_path(name, kind, conf_value, run_dir):
    if conf_value and conf_value != "off":
        return nng.ipc_path(conf_value)
    return os.path.join(run_dir, "%s.%s" % (name, kind))


def socket_disabled(conf_value):
    return conf_value == "off"


class Bus:
    def __init__(self, control, events=None, timeout=5.0):
        self.control = control
        self.events = events
        self.timeout = timeout

    def call(self, op, args=None, timeout=None):
        """Run one operation. Returns the result object."""
        rid = secrets.token_hex(16)
        env = {"v": 1, "id": rid, "op": op}
        if args:
            env["args"] = args
        payload = json.dumps(env, separators=(",", ":")).encode()
        try:
            req = nng.Req(self.control, timeout=self.timeout)
        except nng.DialError as e:
            raise NotRunning(str(e))
        try:
            raw = req.request(payload, timeout or self.timeout)
        except nng.NngTimeout:
            raise BusError("timeout", "the daemon did not reply in time")
        except nng.NngError as e:
            raise BusProtocolError(str(e))
        finally:
            req.close()
        try:
            rep = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BusProtocolError("the reply is not JSON")
        if not isinstance(rep, dict) or rep.get("id") != rid:
            raise BusProtocolError("the reply id does not match")
        if not rep.get("ok"):
            err = rep.get("error") or {}
            raise BusError(str(err.get("code", "internal")), str(err.get("message", "")))
        res = rep.get("result")
        return res if res is not None else {}

    def running(self):
        try:
            self.call("status")
            return True
        except NotRunning:
            return False
        except (BusError, BusProtocolError):
            return True

    def subscribe(self, prefixes=(b"",)):
        if not self.events:
            raise NotRunning("no events socket")
        try:
            return nng.Sub(self.events, prefixes, timeout=self.timeout)
        except nng.DialError as e:
            raise NotRunning(str(e))
