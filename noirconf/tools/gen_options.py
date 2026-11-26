#!/usr/bin/env python3
"""Build noirconf/options.json from docs/options.md.

Usage: gen_options.py [--doc docs/options.md] [--out noirconf/options.json]

Keeps the rows whose "Applies to" column is server or both, from the tables
"Supported", "New in noirvpn" and "Not applied yet". Rows that are only valid
in a client config file (client-config-dir) are left out.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

SECTIONS = {
    "Supported": "supported",
    "New in noirvpn": "new",
    "Not applied yet": "not_applied",
}

# Options that may appear on several lines.
REPEAT = {
    "bus-allow", "ignore-unknown-option", "local", "push", "push-remove",
    "route", "route-ipv6", "setenv", "peer-fingerprint", "iroute",
    "iroute-ipv6", "tls-crypt-v2",
}

GROUP_TITLES = [
    ("network", "Network"),
    ("service", "Service"),
    ("identity", "Identity"),
    ("tls", "TLS and control channel"),
    ("datapath", "Data path"),
    ("bus", "Control bus"),
    ("logging", "Logging"),
    ("other", "Other"),
]

GROUPS = {
    "network": """server server-ipv6 topology ifconfig-pool ifconfig-ipv6-pool
        ifconfig-pool-persist ifconfig-noexec dev dev-type push push-remove
        push-reset route route-ipv6 route-noexec route-table client-to-client
        client-config-dir ccd-exclusive iroute iroute-ipv6 ifconfig-push
        ifconfig-ipv6-push max-clients max-routes-per-client block-ipv6
        tun-mtu mssfix txqueuelen persist-tun duplicate-cn""".split(),
    "service": """port proto local lport bind multihome float connect-freq
        connect-freq-initial connect-freq-source tls-transport-accept-tcp
        tls-transport-ws tls-transport-cert tls-transport-key
        tls-transport-dev rcvbuf sndbuf keepalive ping ping-restart
        ping-timer-rem ping-exit explicit-exit-notify mode tls-server
        inactive session-timeout mark mtu-disc max-packet-size""".split(),
    "identity": """ca cert key extra-certs crl-verify peer-keys peer-keys-mode
        peer-passwords peer-fingerprint verify-client-cert verify-x509-name
        remote-cert-tls remote-cert-eku remote-cert-ku auth-external auth-web
        askpass x509-username-field disable capath""".split(),
    "tls": """tls-crypt tls-crypt-v2 tls-crypt-v2-max-age tls-auth key-direction
        auth tls-groups tls-version-min tls-version-max tls-timeout
        hand-window tran-window reneg-bytes reneg-pkts reneg-sec data-ciphers
        ncp-ciphers data-ciphers-fallback pq-mode allow-compression
        replay-window""".split(),
    "datapath": """datapath dco-socket disable-dco workers""".split(),
    "bus": """bus-control bus-events bus-allow stats-interval""".split(),
    "logging": """verb writepid""".split(),
}

# Options that take a file or a path. The form shows them as paths.
PATH_OPTIONS = {
    "ca", "cert", "key", "crl-verify", "peer-keys", "peer-passwords",
    "tls-crypt", "tls-auth", "tls-crypt-v2", "extra-certs", "askpass",
    "client-config-dir", "ifconfig-pool-persist", "tls-transport-cert",
    "tls-transport-key", "dco-socket", "writepid", "config", "cd",
}


# Options that the form does not show. A line in an existing config stays as it is.
HIDDEN = {
    "ccd-exclusive", "dev", "dev-type", "persist-tun",  # the server always uses tun
    "bind",          # a server binds to its listen address by default
    "tls-server",    # only a role marker; the TLS transport is proto tls-server
    "mlock", "dco-socket", "disable-dco",
    "mode", "lport", "multihome", "ping-exit",  # fixed by noirvpn, or no effect
    "ncp-ciphers", "allow-compression",         # old name, and compression is removed
}

# Options of the status "not applied yet" are not in the form.
HIDE_STATUS = {"not_applied"}

# Options that show inside the block of the TLS server checkbox.
TLS_BLOCK_PREFIX = "tls-transport-"

# Options that come first in their group, in this order.
FIRST = {
    "network": ["server", "server-ipv6"],
    "service": ["port", "proto"],
    "datapath": ["datapath", "workers"],
}

# Friendly names. An option without an entry gets its name in words.
LABELS = {
    "server": "IPv4 tunnel network",
    "server-ipv6": "IPv6 tunnel network",
    "ifconfig-pool": "IPv4 address range",
    "ifconfig-ipv6-pool": "IPv6 address range",
    "ifconfig-pool-persist": "Remember client addresses in a file",
    "ifconfig-noexec": "Do not set up the tun device",
    "topology": "Topology",
    "client-to-client": "Let clients reach each other",
    "duplicate-cn": "Allow one identity to connect twice",
    "max-clients": "Most clients at one time",
    "max-routes-per-client": "Most routes for one client",
    "block-ipv6": "Block IPv6 in the tunnel",
    "push": "Settings sent to clients",
    "route": "IPv4 routes to add",
    "route-ipv6": "IPv6 routes to add",
    "route-noexec": "Do not add routes",
    "route-table": "Routing table",
    "mssfix": "Limit the TCP segment size",
    "tun-mtu": "Tunnel MTU",
    "txqueuelen": "Tunnel queue length",
    "port": "Port",
    "proto": "Protocol",
    "local": "Listen addresses",
    "lport": "Local port",
    "keepalive": "Keepalive (ping, timeout)",
    "ping": "Ping interval",
    "ping-restart": "Restart after silence",
    "ping-exit": "Exit after silence",
    "ping-timer-rem": "Ping only when a peer is known",
    "explicit-exit-notify": "Tell clients when the server stops",
    "float": "Accept clients from a new address",
    "multihome": "Several server addresses",
    "inactive": "Disconnect idle clients",
    "session-timeout": "Session time limit",
    "connect-freq": "Limit new connections",
    "connect-freq-initial": "Limit first replies",
    "connect-freq-source": "Limit first replies for one address",
    "max-packet-size": "Largest control packet",
    "mark": "Firewall mark",
    "mtu-disc": "Path MTU discovery",
    "mode": "Mode",
    "rcvbuf": "Receive buffer size",
    "sndbuf": "Send buffer size",
    "tls-transport-accept-tcp": "Also accept plain OpenVPN TCP clients",
    "tls-transport-ws": "WebSocket path",
    "tls-transport-cert": "Certificate of the outer TLS",
    "tls-transport-key": "Key of the outer TLS",
    "tls-transport-dev": "Second tun device",
    "ca": "CA certificate",
    "cert": "Server certificate",
    "key": "Server key",
    "extra-certs": "Extra chain certificates",
    "askpass": "Key passphrase file",
    "crl-verify": "Revocation list",
    "peer-keys": "Peers file",
    "peer-keys-mode": "How a CA and pins work together",
    "peer-passwords": "Password file",
    "peer-fingerprint": "Accepted certificate fingerprints",
    "verify-client-cert": "Client certificate check",
    "verify-x509-name": "Required name in the client certificate",
    "remote-cert-tls": "Required certificate type",
    "remote-cert-eku": "Required extended key usage",
    "remote-cert-ku": "Required key usage",
    "auth-external": "Decide logins on the control bus",
    "auth-web": "Web sign-in",
    "capath": "CA folder",
    "x509-username-field": "Certificate field for the name",
    "tls-crypt": "Control channel key (encrypt)",
    "tls-crypt-v2": "Control channel keys for each client",
    "tls-crypt-v2-max-age": "Oldest client key (days)",
    "tls-auth": "Control channel key (sign)",
    "key-direction": "Key direction",
    "auth": "Control channel digest",
    "data-ciphers": "Data channel ciphers",
    "data-ciphers-fallback": "Fallback cipher",
    "ncp-ciphers": "Data channel ciphers (old name)",
    "pq-mode": "Post-quantum key exchange",
    "tls-groups": "Key exchange groups",
    "tls-version-min": "Lowest TLS version",
    "tls-version-max": "Highest TLS version",
    "tls-timeout": "Control packet resend time",
    "hand-window": "Handshake time limit",
    "tran-window": "Old key valid time",
    "reneg-sec": "Renegotiate after (seconds)",
    "reneg-bytes": "Renegotiate after (bytes)",
    "reneg-pkts": "Renegotiate after (packets)",
    "replay-window": "Replay window",
    "allow-compression": "Compression",
    "datapath": "Data path",
    "workers": "Crypto worker threads",
    "bus-control": "Control socket",
    "bus-events": "Events socket",
    "bus-allow": "Who may use the control socket",
    "stats-interval": "Stats event interval (seconds)",
    "verb": "Log detail",
    "writepid": "Process id file",
    "cd": "Working folder",
    "config": "Include another file",
    "group": "Run as group",
    "user": "Run as user",
    "ignore-unknown-option": "Options to ignore when unknown",
}

# Defaults of the daemon, as text.
DEFAULTS = {
    "port": "1194", "proto": "udp", "topology": "subnet", "max-clients": "1024",
    "max-routes-per-client": "256", "tun-mtu": "1400", "connect-freq-initial": "100 10",
    "connect-freq-source": "20", "verb": "1", "workers": "0", "hand-window": "60",
    "tran-window": "3600", "tls-timeout": "2", "reneg-sec": "3600", "replay-window": "64 15",
    "data-ciphers": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "pq-mode": "prefer",
    "verify-client-cert": "require", "stats-interval": "0, off",
    "peer-keys-mode": "pin, or either with a CA",
    "tls-crypt-v2-max-age": "no limit",
}

# Accepted values of the options that have a fixed set. The form shows them after the default.
CHOICES = {
    "proto": ["udp", "tcp-server", "tls-server"],
    "verify-client-cert": ["require", "optional", "none"],
    "peer-keys-mode": ["pin", "both", "either"],
    "pq-mode": ["off", "prefer", "require"],
    "tls-version-min": ["1.2", "1.3"],
    "tls-version-max": ["1.2", "1.3"],
    "key-direction": ["0", "1"],
    "remote-cert-tls": ["server", "client"],
    "bus-control": ["off", "PATH"],
    "bus-events": ["off", "PATH"],
    "verb": ["0", "1", "2", "3", "4"],
}

# Options that the form shows as a dropdown of their CHOICES.
DROPDOWN = {"proto", "verify-client-cert", "peer-keys-mode", "pq-mode", "tls-version-min",
            "tls-version-max", "key-direction", "remote-cert-tls", "verb"}

# Own dropdown entries: [value, text]. The first has the value "" and means "no line".
DROPDOWN_ENTRIES = {
    "proto": [["", "Default (UDP)"], ["udp", "UDP"], ["tcp-server", "TCP"]],
    "verb": [
        ["", "Default (1: warnings and main events)"],
        ["0", "0: errors only"],
        ["1", "1: warnings and main events"],
        ["2", "2: and rekeys, pushed settings"],
        ["3", "3: and every network step"],
        ["4", "4: and every session event"],
    ],
}

# AEAD ciphers that noirvpn accepts in data-ciphers, in the order of the daemon default.
CIPHERS = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]

# Options that the form shows in its own way.
VIRTUAL = {"datapath": "dco", "data-ciphers": "ciphers"}


def parse_arity(text):
    text = text.strip()
    m = re.fullmatch(r"(\d+)(?:-(\d+)|(\+))?", text)
    if not m:
        return 0, None
    lo = int(m.group(1))
    if m.group(3):
        return lo, None
    if m.group(2):
        return lo, int(m.group(2))
    return lo, lo


def dropdown(name):
    if name not in DROPDOWN:
        return None
    if name in DROPDOWN_ENTRIES:
        return DROPDOWN_ENTRIES[name]
    first = "Default (%s)" % DEFAULTS[name] if name in DEFAULTS else "Not set"
    return [["", first]] + [[v, v] for v in CHOICES[name]]


def auto_label(name):
    text = name.replace("-", " ")
    return text[:1].upper() + text[1:]


def group_of(name):
    for gid, names in GROUPS.items():
        if name in names:
            return gid
    return "other"


def parse_doc(text):
    rows = []
    section = None
    for line in text.splitlines():
        if line.startswith("## "):
            section = SECTIONS.get(line[3:].split(" (")[0].strip())
            continue
        if section is None or not line.startswith("| `"):
            continue
        cells = line.strip()[1:-1].strip().split(" | ", 4)
        if len(cells) < 5:
            cells += [""] * (5 - len(cells))
        name = cells[0].strip().strip("`")
        applies = cells[1].strip()
        if applies not in ("server", "both"):
            continue
        if "client config file" in cells[4]:
            continue
        lo, hi = parse_arity(cells[2])
        if name in HIDDEN:
            continue
        rows.append({
            "name": name,
            "label": LABELS.get(name) or auto_label(name),
            "default": DEFAULTS.get(name),
            "block": "tls" if name.startswith(TLS_BLOCK_PREFIX) else None,
            "accepts": CHOICES.get(name) or (CIPHERS if name == "data-ciphers" else None),
            "choices": dropdown(name),
            "virtual": VIRTUAL.get(name),
            "status": section,
            "applies": applies,
            "min": lo,
            "max": hi,
            "pushable": cells[3].strip() == "yes",
            "repeat": name in REPEAT,
            "path": name in PATH_OPTIONS,
            "group": group_of(name),
            "note": cells[4].strip().rstrip("|").strip(),
        })
    return rows


def build(text):
    rows = parse_doc(text)
    groups = []
    for gid, title in GROUP_TITLES:
        first = FIRST.get(gid, [])
        opts = sorted((dict((k, v) for k, v in r.items() if k != "group")
                        for r in rows if r["group"] == gid and r["status"] not in HIDE_STATUS),
                      key=lambda r: (first.index(r["name"]) if r["name"] in first else len(first),
                                     r["label"].lower()))
        if opts:
            groups.append({"id": gid, "title": title, "options": opts})
    return {"source": "docs/options.md", "groups": groups}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default=os.path.join(ROOT, "docs", "options.md"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(HERE),
                                                  "options.json"))
    a = ap.parse_args(argv)
    with open(a.doc, encoding="utf-8") as f:
        data = build(f.read())
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=True)
        f.write("\n")
    n = sum(len(g["options"]) for g in data["groups"])
    print("wrote %s: %d options in %d groups" % (a.out, n, len(data["groups"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
