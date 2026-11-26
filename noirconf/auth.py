"""Login: PAM or /etc/shadow, sessions, CSRF tokens and the login rate limit."""
import ctypes
import ctypes.util
import hashlib
import hmac
import os
import re
import secrets
import threading
import time

SESSION_IDLE = 30 * 60
COOKIE = "noirconf_session"
LOGIN_COOKIE = "noirconf_login"
MAX_FAILS = 5
FAIL_WINDOW = 60
FAIL_DELAY = 1.0

USER_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}$")


def login_user(env=None):
    """The one account of the web interface."""
    env = os.environ if env is None else env
    for key in ("DOAS_USER", "SUDO_USER"):
        v = env.get(key, "")
        if v and USER_RE.match(v):
            return v
    return "root"


# PAM

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_BUF_ERR = 5


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)),
    ctypes.c_void_p,
)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


def _load(names, short):
    for n in names:
        try:
            return ctypes.CDLL(n, use_errno=True)
        except OSError:
            continue
    found = ctypes.util.find_library(short)
    if found:
        try:
            return ctypes.CDLL(found, use_errno=True)
        except OSError:
            pass
    return None


class PamAuth:
    """Check a password with PAM (pam_authenticate and pam_acct_mgmt)."""

    def __init__(self, service="login", lib=None):
        self.service = service
        self.lib = lib if lib is not None else _load(["libpam.so.0"], "pam")
        if self.lib is None:
            raise OSError("libpam is not available")
        self.libc = ctypes.CDLL(None)
        self.libc.calloc.restype = ctypes.c_void_p
        self.libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        self.libc.strdup.restype = ctypes.c_void_p
        self.libc.strdup.argtypes = [ctypes.c_char_p]
        self.libc.free.argtypes = [ctypes.c_void_p]
        self.lib.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                       ctypes.POINTER(_PamConv),
                                       ctypes.POINTER(ctypes.c_void_p)]
        self.lib.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]

    def check(self, user, password):
        if not password or "\0" in password or "\0" in user:
            return False
        pw = password.encode("utf-8")
        libc = self.libc

        def conv(n, msgs, resp, _data):
            arr = libc.calloc(n, ctypes.sizeof(_PamResponse))
            if not arr:
                return PAM_BUF_ERR
            out = ctypes.cast(arr, ctypes.POINTER(_PamResponse))
            for i in range(n):
                style = msgs[i].contents.msg_style
                if style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                    out[i].resp = libc.strdup(pw)
                    out[i].resp_retcode = 0
            resp[0] = out
            return PAM_SUCCESS

        cb = _CONV(conv)
        pc = _PamConv(cb, None)
        handle = ctypes.c_void_p()
        rc = self.lib.pam_start(self.service.encode(), user.encode(), ctypes.byref(pc),
                                ctypes.byref(handle))
        if rc != PAM_SUCCESS:
            return False
        try:
            if self.lib.pam_authenticate(handle, 0) != PAM_SUCCESS:
                return False
            return self.lib.pam_acct_mgmt(handle, 0) == PAM_SUCCESS
        finally:
            self.lib.pam_end(handle, rc)
            del cb


# /etc/shadow with crypt()

class ShadowAuth:
    """Fallback without PAM: compare crypt() of the password with /etc/shadow."""

    _lock = threading.Lock()

    def __init__(self, shadow_path="/etc/shadow", lib=None):
        self.shadow_path = shadow_path
        self.lib = lib if lib is not None else _load(["libcrypt.so.1", "libcrypt.so.2"], "crypt")
        if self.lib is None:
            self.lib = ctypes.CDLL(None)
        try:
            self.crypt = self.lib.crypt
        except AttributeError:
            raise OSError("crypt() is not available")
        self.crypt.restype = ctypes.c_char_p
        self.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

    def _hash_of(self, user):
        try:
            with open(self.shadow_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split(":")
                    if parts[0] == user and len(parts) > 1:
                        return parts[1]
        except OSError:
            pass
        return None

    def check(self, user, password):
        if not password or "\0" in password:
            return False
        h = self._hash_of(user)
        if not h or h[0] in "!*" or not h.startswith("$"):
            return False
        with self._lock:
            out = self.crypt(password.encode("utf-8"), h.encode())
        if not out:
            return False
        got = out.decode("utf-8", "replace")
        if got.startswith("*"):
            return False
        return hmac.compare_digest(got.encode(), h.encode())


def make_authenticator(service="login"):
    """PAM when libpam loads, else the shadow file. Returns (object, name)."""
    try:
        return PamAuth(service), "pam"
    except (OSError, AttributeError):
        return ShadowAuth(), "shadow"


# Sessions

class Session:
    def __init__(self, user, csrf):
        self.user = user
        self.csrf = csrf
        self.last = time.monotonic()
        self.pending = {}


class SessionStore:
    def __init__(self, idle=SESSION_IDLE, clock=time.monotonic):
        self.idle = idle
        self.clock = clock
        self.lock = threading.Lock()
        self.data = {}

    @staticmethod
    def _key(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, user):
        token = secrets.token_hex(32)
        s = Session(user, secrets.token_hex(24))
        s.last = self.clock()
        with self.lock:
            self._purge()
            self.data[self._key(token)] = s
        return token, s

    def get(self, token):
        if not token or not re.fullmatch(r"[0-9a-f]{64}", token):
            return None
        k = self._key(token)
        with self.lock:
            s = self.data.get(k)
            if s is None:
                return None
            now = self.clock()
            if now - s.last > self.idle:
                del self.data[k]
                return None
            s.last = now
            return s

    def destroy(self, token):
        if token:
            with self.lock:
                self.data.pop(self._key(token), None)

    def _purge(self):
        now = self.clock()
        for k in [k for k, s in self.data.items() if now - s.last > self.idle]:
            del self.data[k]


def csrf_ok(session, supplied):
    return bool(session and supplied and hmac.compare_digest(session.csrf.encode(),
                                                             supplied.encode()))


class LoginGuard:
    """Pre-session CSRF token for the login form, and the failure limit."""

    def __init__(self, clock=time.monotonic):
        self.secret = secrets.token_bytes(32)
        self.clock = clock
        self.lock = threading.Lock()
        self.fails = {}

    def new_nonce(self):
        return secrets.token_hex(16)

    def token_for(self, nonce):
        return hmac.new(self.secret, nonce.encode(), hashlib.sha256).hexdigest()

    def token_ok(self, nonce, token):
        if not nonce or not token:
            return False
        return hmac.compare_digest(self.token_for(nonce).encode(), token.encode())

    def blocked(self, source):
        with self.lock:
            now = self.clock()
            recent = [t for t in self.fails.get(source, []) if now - t < FAIL_WINDOW]
            self.fails[source] = recent
            return len(recent) >= MAX_FAILS

    def fail(self, source):
        with self.lock:
            self.fails.setdefault(source, []).append(self.clock())

    def ok(self, source):
        with self.lock:
            self.fails.pop(source, None)
