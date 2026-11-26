#!/usr/bin/env python3
"""noirconf: a config web service for the noirvpn server.

Run as root:  python3 noirconf.py [--host 127.0.0.1] [--port 9443]
"""
import argparse
import logging
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import auth  # noqa: E402
import pki  # noqa: E402
import store as storemod  # noqa: E402
import svcctl  # noqa: E402
import web  # noqa: E402

DEFAULT_ETC = "/etc/noirvpn/server"
CERT_MIN_SECONDS = 30 * 86400

log = logging.getLogger("noirconf")


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="noirconf", description="Config web service for the noirvpn server.")
    ap.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=9443, help="port to listen on (default 9443)")
    ap.add_argument("--log", metavar="FILE", help="also write the log to this file")
    ap.add_argument("--etc", default=DEFAULT_ETC, help="config folder (default %s)" % DEFAULT_ETC)
    ap.add_argument("--noirvpn", metavar="PATH", help="the noirvpn program (default: from PATH)")
    ap.add_argument("--pam-service", default="login", help="PAM service name (default login)")
    ap.add_argument("--run-dir", default="/run/noirconf", help=argparse.SUPPRESS)
    ap.add_argument("--log-dir", default="/var/log/noirconf", help=argparse.SUPPRESS)
    ap.add_argument("--bus-dir", default="/run/noirvpn", help=argparse.SUPPRESS)
    ap.add_argument("--manager", choices=("systemd", "openrc", "spawn"), help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def setup_logging(logfile):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(fmt)
    root.addHandler(h)
    if logfile:
        fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        os.close(fd)
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        root.addHandler(fh)


def under_etc(path):
    real = os.path.realpath(path)
    return real == "/etc" or real.startswith("/etc/")


def ensure_app_cert(etc, host):
    """Create appserver.crt and appserver.key when missing or near expiry."""
    crt = os.path.join(etc, "appserver.crt")
    key = os.path.join(etc, "appserver.key")
    if (os.path.exists(crt) and os.path.exists(key)
            and not pki.cert_expires_within(crt, CERT_MIN_SECONDS)):
        return crt, key, False
    os.makedirs(etc, exist_ok=True)
    hosts = ["localhost", "127.0.0.1", "::1"]
    if host not in ("0.0.0.0", "::", ""):
        hosts.append(host)
    pki.make_self_signed(crt, key, "noirconf", hosts)
    return crt, key, True


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0 and under_etc(args.etc):
        print("noirconf: run as root, or use --etc with a folder outside /etc.", file=sys.stderr)
        return 1
    setup_logging(args.log)
    os.umask(0o027)
    etc = os.path.abspath(args.etc)
    os.makedirs(etc, exist_ok=True)

    noirvpn = args.noirvpn or shutil.which("noirvpn") or ""
    if not noirvpn:
        log.warning("the noirvpn program is not found; checks and service start do not work (use --noirvpn)")
    noirvpn = os.path.abspath(noirvpn) if noirvpn else ""
    if not shutil.which(pki.OPENSSL):
        log.error("the openssl program is not installed")
        return 1

    try:
        crt, key, created = ensure_app_cert(etc, args.host)
    except pki.PkiError as e:
        log.error("cannot create the web certificate: %s", e)
        return 1
    if created:
        log.info("created the web certificate %s", crt)

    try:
        authenticator, kind = auth.make_authenticator(args.pam_service)
    except OSError as e:
        log.error("no way to check passwords (no libpam and no libcrypt): %s", e)
        return 1
    user = auth.login_user()
    log.info("login account: %s (password check: %s)", user, kind)

    def bus_for(name):
        return st.bus(name)

    svc = svcctl.ServiceManager(etc, noirvpn, mode=args.manager, run_dir=args.run_dir,
                                log_dir=args.log_dir, bus_for=lambda n: bus_for(n))
    st = storemod.Store(etc, noirvpn, svc, run_dir=args.bus_dir)
    app = web.App(etc, st, svc, user, authenticator)
    try:
        httpd = web.Server((args.host, args.port), app, web.tls_context(crt, key))
    except OSError as e:
        log.error("cannot listen on %s port %d: %s", args.host, args.port, e)
        return 1

    port = httpd.server_address[1]
    shown = "[%s]" % args.host if ":" in args.host else args.host
    print("noirconf: listening on https://%s:%d/" % (shown, port), flush=True)
    print("noirconf: certificate SHA-256 fingerprint: %s" % pki.fingerprint_sha256(crt), flush=True)
    print("noirconf: from another computer, use an ssh tunnel: "
          "ssh -L %d:127.0.0.1:%d HOST" % (port, port), flush=True)
    print("noirconf: manager: %s; servers: %s" % (svc.mode, ", ".join(st.servers()) or "none"), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
