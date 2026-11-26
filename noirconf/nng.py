"""Small pure-Python nng SP client over the ipc:// transport.

Wire format (from nng 1.11, src/sp/transport/ipc/ipc.c):

    handshake, 8 bytes each way:  00 'S' 'P' 00 <proto u16 BE> 00 00
    message:                      01 <length u64 BE> <body>

Protocol ids: PUB0 0x20, SUB0 0x21, REQ0 0x30, REP0 0x31.
REQ0 and REP0 put a 4 byte big endian request id at the start of the body.
The id of a request has the high bit set. A reply repeats it.
PUB0 messages have no header. A SUB0 socket filters topics by prefix.

The classes Req and Sub are the clients. Rep and Pub are small servers for
tests.
"""
import os
import socket
import struct
import threading
import time

PROTO_PUB0 = 0x20
PROTO_SUB0 = 0x21
PROTO_REQ0 = 0x30
PROTO_REP0 = 0x31

MAX_RECV = 8 * 1024 * 1024
HANDSHAKE_LEN = 8
ID_HIGH_BIT = 0x80000000


class NngError(Exception):
    """Base class of all errors of this module."""


class DialError(NngError):
    """The socket cannot be reached (no daemon)."""


class NngTimeout(NngError):
    """No data in time."""


class ProtocolError(NngError):
    """The peer sent data that does not fit the SP protocol."""


def ipc_path(url):
    """Return the file path of a path or an ipc:// URL."""
    if url.startswith("ipc://"):
        url = url[len("ipc://"):]
    return url


def _deadline(timeout):
    return None if timeout is None else time.monotonic() + timeout


def _remaining(deadline):
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise NngTimeout("timeout")
    return left


def _recv_exact(sock, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        sock.settimeout(_remaining(deadline))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise NngTimeout("timeout")
        except OSError as e:
            raise NngError("receive failed: %s" % e)
        if not chunk:
            raise NngError("connection closed")
        buf += chunk
    return bytes(buf)


def _send_all(sock, data, deadline):
    sock.settimeout(_remaining(deadline))
    try:
        sock.sendall(data)
    except socket.timeout:
        raise NngTimeout("timeout")
    except OSError as e:
        raise NngError("send failed: %s" % e)


def frame(body):
    """Frame one message for the ipc transport."""
    return b"\x01" + struct.pack(">Q", len(body)) + body


def read_frame(sock, deadline, max_size=MAX_RECV):
    head = _recv_exact(sock, 9, deadline)
    if head[0] != 1:
        raise ProtocolError("bad message type %d" % head[0])
    (size,) = struct.unpack(">Q", head[1:])
    if max_size and size > max_size:
        raise ProtocolError("message of %d bytes is too large" % size)
    return _recv_exact(sock, size, deadline) if size else b""


def handshake_bytes(proto):
    return b"\x00SP\x00" + struct.pack(">H", proto) + b"\x00\x00"


def check_handshake(data, want_peer):
    if len(data) != HANDSHAKE_LEN or data[:4] != b"\x00SP\x00" or data[6:] != b"\x00\x00":
        raise ProtocolError("bad SP handshake")
    (peer,) = struct.unpack(">H", data[4:6])
    if peer != want_peer:
        raise ProtocolError("peer protocol 0x%02x, want 0x%02x" % (peer, want_peer))


def _dial(path, proto, peer_proto, timeout):
    """Connect to a Unix socket and run the SP handshake."""
    path = ipc_path(path)
    deadline = _deadline(timeout)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        try:
            s.connect(path)
        except socket.timeout:
            raise DialError("connect timeout")
        except OSError as e:
            raise DialError("cannot connect to %s: %s" % (path, e.strerror or e))
        _send_all(s, handshake_bytes(proto), deadline)
        check_handshake(_recv_exact(s, HANDSHAKE_LEN, deadline), peer_proto)
    except BaseException:
        s.close()
        raise
    return s


class Req:
    """REQ0 client. One connection for each Req object."""

    def __init__(self, path, timeout=5.0, max_recv=MAX_RECV):
        self.path = path
        self.timeout = timeout
        self.max_recv = max_recv
        self.sock = _dial(path, PROTO_REQ0, PROTO_REP0, timeout)
        self._next = (int.from_bytes(os.urandom(4), "big") | ID_HIGH_BIT) & 0xFFFFFFFF
        self.lock = threading.Lock()

    def request(self, payload, timeout=None):
        """Send one request and return the body of the matching reply."""
        if timeout is None:
            timeout = self.timeout
        with self.lock:
            rid = self._next
            self._next = ((self._next + 1) | ID_HIGH_BIT) & 0xFFFFFFFF
            deadline = _deadline(timeout)
            _send_all(self.sock, frame(struct.pack(">I", rid) + payload), deadline)
            while True:
                body = read_frame(self.sock, deadline, self.max_recv)
                if len(body) < 4:
                    raise ProtocolError("reply without a request id")
                (got,) = struct.unpack(">I", body[:4])
                if got == rid:
                    return body[4:]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def split_topic(body):
    """Split a PUB message at the first space into (topic, payload)."""
    i = body.find(b" ")
    if i < 0:
        return body, b""
    return body[:i], body[i + 1:]


class Sub:
    """SUB0 client. Receives every message with a topic that has a prefix."""

    def __init__(self, path, prefixes=(b"",), timeout=5.0, max_recv=MAX_RECV):
        self.prefixes = [p if isinstance(p, bytes) else p.encode() for p in prefixes]
        self.max_recv = max_recv
        self.sock = _dial(path, PROTO_SUB0, PROTO_PUB0, timeout)

    def recv(self, timeout=None):
        """Return (topic, payload) of the next message that matches."""
        deadline = _deadline(timeout)
        while True:
            body = read_frame(self.sock, deadline, self.max_recv)
            topic, payload = split_topic(body)
            if any(body.startswith(p) for p in self.prefixes):
                return topic, payload

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _Listener:
    """Accepts connections on a Unix socket in a thread (used by tests)."""

    own_proto = 0
    peer_proto = 0

    def __init__(self, path):
        self.path = ipc_path(path)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(8)
        self.conns = []
        self.stop = False
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            try:
                c.settimeout(5)
                c.sendall(handshake_bytes(self.own_proto))
                check_handshake(_recv_exact(c, HANDSHAKE_LEN, _deadline(5)), self.peer_proto)
            except (NngError, OSError):
                c.close()
                continue
            with self.lock:
                self.conns.append(c)
            self.on_connect(c)

    def on_connect(self, conn):
        pass

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass
        with self.lock:
            for c in self.conns:
                try:
                    c.close()
                except OSError:
                    pass
            self.conns = []
        try:
            os.unlink(self.path)
        except OSError:
            pass


class Rep(_Listener):
    """REP0 server. handler(bytes) returns the reply bytes."""

    own_proto = PROTO_REP0
    peer_proto = PROTO_REQ0

    def __init__(self, path, handler):
        self.handler = handler
        super().__init__(path)

    def on_connect(self, conn):
        threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            while True:
                body = read_frame(conn, None)
                if len(body) < 4:
                    return
                rid, payload = body[:4], body[4:]
                reply = self.handler(payload)
                conn.sendall(frame(rid + reply))
        except (NngError, OSError):
            pass
        finally:
            conn.close()


class Pub(_Listener):
    """PUB0 server. publish(topic, payload) sends to every subscriber."""

    own_proto = PROTO_PUB0
    peer_proto = PROTO_SUB0

    def publish(self, topic, payload):
        msg = frame(topic.encode() + b" " + payload)
        with self.lock:
            for c in list(self.conns):
                try:
                    c.sendall(msg)
                except OSError:
                    self.conns.remove(c)

    def subscribers(self):
        with self.lock:
            return len(self.conns)
