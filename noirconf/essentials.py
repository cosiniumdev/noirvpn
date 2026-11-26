"""The fields of "Create with Essentials": checks, and the options that they produce."""
import ipaddress
import re

WS_PATH_RE = re.compile(r"/[A-Za-z0-9._~/-]{1,64}")
DEFAULT_NETWORK = "10.8.0.0/24"
DEFAULT_PORT = "1194"
MIN_PREFIX, MAX_PREFIX = 16, 30

# transport: (proto option, proto of the external address)
COMPAT = {"udp": ("udp", "udp"), "tcp": ("tcp-server", "tcp")}
NOIR = {"udp": ("udp", "udp"), "tcp": ("tcp-server", "tcp"),
        "tls": ("tls-server", "tls"), "ws": ("tls-server", "tls")}


def default_ws_path(name):
    return "/noir-" + (name or "server")


def check_ws_path(path):
    path = (path or "").strip()
    if not WS_PATH_RE.fullmatch(path) or ".." in path:
        raise ValueError("The WebSocket path starts with / and then has 1 to 64 of the characters "
                         "A-Z a-z 0-9 . _ ~ / - and no two dots in a row.")
    return path


def check_port(text, what):
    text = (text or "").strip()
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError("%s must be a number from 1 to 65535." % what)
    return str(int(text))


def parse_network(text):
    """"10.8.0.0/24" into "10.8.0.0 255.255.255.0". An empty text gives the default."""
    text = (text or "").strip() or DEFAULT_NETWORK
    if not re.fullmatch(r"[0-9.]+/[0-9]{1,2}", text):
        raise ValueError("Write the tunnel network with a prefix, for example 10.8.0.0/24.")
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as e:
        if "host bits" in str(e):
            raise ValueError("%s has host bits set. Write the network address, for example %s."
                             % (text[:50], _network_of(text)))
        raise ValueError("%s is not an IPv4 network." % text[:50])
    if net.version != 4:
        raise ValueError("The tunnel network must be IPv4. Use the Config page for IPv6.")
    if not MIN_PREFIX <= net.prefixlen <= MAX_PREFIX:
        raise ValueError("The prefix of the tunnel network is from /%d to /%d." % (MIN_PREFIX, MAX_PREFIX))
    return "%s %s" % (net.network_address, net.netmask)


def _network_of(text):
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return DEFAULT_NETWORK


def parse(form, name):
    """Read the essential fields of a posted form.

    Returns a dict with: port, host, public_port, network (two words), proto (option value),
    ext_proto (udp, tcp or tls), ws (path or ""). Raises ValueError with a text for the user.
    """
    port = check_port(form.get("e.port") or DEFAULT_PORT, "The listen port")
    host = (form.get("e.host") or "").strip()
    if not host:
        raise ValueError("Enter the address that clients use to reach this server.")
    public_port = check_port(form.get("e.public_port") or port, "The public port")
    network = parse_network(form.get("e.network"))
    mode = form.get("e.clients")
    if mode == "noir":
        table, key = NOIR, form.get("e.noir_transport") or "udp"
    else:
        table, key = COMPAT, form.get("e.compat_transport") or "udp"
    if key not in table:
        raise ValueError("Choose one of the transports.")
    proto, ext_proto = table[key]
    ws = ""
    if mode == "noir" and key == "ws":
        ws = check_ws_path(form.get("e.ws_path") or default_ws_path(name))
    return {"port": port, "host": host, "public_port": public_port, "network": network,
            "proto": proto, "ext_proto": ext_proto, "ws": ws}


def defaults(name="server"):
    """The values that the form shows at first."""
    return {"e.port": DEFAULT_PORT, "e.host": "", "e.public_port": "", "e.network": DEFAULT_NETWORK,
            "e.clients": "compat", "e.compat_transport": "udp", "e.noir_transport": "udp",
            "e.ws_path": default_ws_path(name)}
