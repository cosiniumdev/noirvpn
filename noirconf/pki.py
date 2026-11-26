"""Certificate work with the openssl command line tool.

Passwords go to openssl through a pipe (-passin fd:N, -passout fd:N), never
through the argument list. Private keys of clients stay in memory.
"""
import base64
import hashlib
import os
import re
import secrets
import subprocess
import tempfile

import fsutil

OPENSSL = "openssl"
TIMEOUT = 60

CA_DAYS = 3650
SERVER_DAYS = 1825
CLIENT_DAYS = 1825
CRL_DAYS = 3650


# Key types for the VPN certificates. The web interface certificate is always EC P-256.
KEY_TYPES = {
    "ed25519": ["-algorithm", "ED25519"],
    "ec-p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "rsa-3072": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
}
DEFAULT_KEY_TYPE = "ed25519"


class PkiError(Exception):
    pass


def check_key_type(key_type):
    if key_type not in KEY_TYPES:
        raise PkiError("the key type must be ed25519, ec-p256 or rsa-3072")
    return key_type


def generate_key(key_type=DEFAULT_KEY_TYPE):
    """A new private key in PEM form (bytes)."""
    return openssl(["genpkey"] + KEY_TYPES[check_key_type(key_type)])


def openssl(args, input=None, secrets_=(), cwd=None):
    """Run openssl. "@FD0@", "@FD1@" in args become the fd numbers of secrets_.

    Returns stdout bytes. Raises PkiError with the stderr text on failure.
    """
    fds = []
    keep = []
    try:
        for sec in secrets_:
            r, w = os.pipe()
            os.write(w, sec)
            os.close(w)
            fds.append(r)
            keep.append(r)
        argv = [OPENSSL] + [re.sub(r"@FD(\d)@", lambda m: str(fds[int(m.group(1))]), a)
                            for a in args]
        try:
            p = subprocess.run(argv, input=input, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, cwd=cwd, timeout=TIMEOUT,
                               pass_fds=tuple(fds), shell=False)
        except FileNotFoundError:
            raise PkiError("the openssl program is not installed")
        except subprocess.TimeoutExpired:
            raise PkiError("openssl timed out")
    finally:
        for fd in keep:
            try:
                os.close(fd)
            except OSError:
                pass
    if p.returncode != 0:
        msg = p.stderr.decode("utf-8", "replace").strip().splitlines()
        raise PkiError("openssl %s failed: %s" % (args[0], " | ".join(msg[-3:])[:400]))
    return p.stdout


# Pins and certificate information

def pin_from_spki_der(der):
    return "sha256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()


def _pubkey_der_from_pem(pem, kind):
    if kind == "cert":
        pub = openssl(["x509", "-noout", "-pubkey"], input=pem)
    else:
        pub = pem
    return openssl(["pkey", "-pubin", "-outform", "DER"], input=pub)


def classify_pem(text):
    """Return "cert", "pubkey", or raise. Private keys are refused."""
    if "PRIVATE KEY" in text:
        raise PkiError("this is a private key: send a certificate or a public key")
    if "-----BEGIN CERTIFICATE-----" in text or "-----BEGIN TRUSTED CERTIFICATE-----" in text:
        return "cert"
    if "-----BEGIN PUBLIC KEY-----" in text:
        return "pubkey"
    raise PkiError("no certificate or public key in PEM form found")


def first_pem_block(text, label):
    m = re.search(r"-----BEGIN %s-----.*?-----END %s-----" % (label, label), text, re.S)
    if not m:
        raise PkiError("no %s found" % label.lower())
    return m.group(0) + "\n"


def pin_from_pem(text):
    """Pin of a certificate or a public key in PEM form (the first one)."""
    if len(text) > 100000:
        raise PkiError("the text is too long")
    kind = classify_pem(text)
    label = "CERTIFICATE" if kind == "cert" else "PUBLIC KEY"
    block = first_pem_block(text, label).encode()
    return pin_from_spki_der(_pubkey_der_from_pem(block, kind))


CSR_MAX = 20000
CSR_BLOCK = re.compile(r"-----BEGIN (NEW )?CERTIFICATE REQUEST-----.*?-----END (NEW )?CERTIFICATE REQUEST-----",
                       re.S)


def check_csr(text):
    """Check a certificate request in PEM form. Returns (csr_pem, pin).

    Refuses text with a private key, a request with a bad signature and a weak key.
    """
    text = text or ""
    if len(text) > CSR_MAX:
        raise PkiError("the text is too long")
    if "PRIVATE KEY" in text:
        raise PkiError("this text has a private key: send only the certificate request")
    m = CSR_BLOCK.search(text)
    if not m:
        raise PkiError("no certificate request in PEM form found")
    csr = (m.group(0) + "\n").encode()
    try:
        openssl(["req", "-verify", "-noout"], input=csr)
    except PkiError:
        raise PkiError("the certificate request is not valid, or its signature does not match its key")
    info = openssl(["req", "-noout", "-text"], input=csr).decode("utf-8", "replace")
    alg = re.search(r"Public Key Algorithm: (\S+)", info)
    alg = alg.group(1) if alg else ""
    if alg == "rsaEncryption":
        bits = re.search(r"Public-Key: \((\d+) bit\)", info)
        if not bits or int(bits.group(1)) < 2048:
            raise PkiError("the RSA key of the request is smaller than 2048 bits")
    elif alg not in ("id-ecPublicKey", "ED25519"):
        raise PkiError("the key type of the request is not supported; use Ed25519, EC or RSA")
    pub = openssl(["req", "-noout", "-pubkey"], input=csr)
    pin = pin_from_spki_der(openssl(["pkey", "-pubin", "-outform", "DER"], input=pub))
    return csr.decode(), pin


def cert_serial(pem):
    out = openssl(["x509", "-noout", "-serial"], input=pem if isinstance(pem, bytes) else pem.encode())
    m = re.match(rb"serial=([0-9A-Fa-f]+)", out.strip())
    if not m:
        raise PkiError("cannot read the serial")
    return m.group(1).decode().upper()


def cert_info(pem):
    """Dict with subject, serial and notAfter of a certificate."""
    data = pem if isinstance(pem, bytes) else pem.encode()
    out = openssl(["x509", "-noout", "-subject", "-serial", "-enddate", "-nameopt", "RFC2253"],
                  input=data).decode()
    info = {}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        info[k.strip()] = v.strip()
    return {"subject": info.get("subject", ""), "serial": info.get("serial", "").upper(),
            "not_after": info.get("notAfter", "")}


def cert_expires_within(path, seconds):
    """True when the certificate ends within the time, or cannot be read."""
    try:
        subprocess.run([OPENSSL, "x509", "-in", path, "-noout", "-checkend", str(int(seconds))],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=TIMEOUT)
        return False
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True


def fingerprint_sha256(path):
    out = openssl(["x509", "-in", path, "-noout", "-fingerprint", "-sha256"]).decode().strip()
    return out.partition("=")[2]


# tls-crypt key

def tls_crypt_key_text():
    raw = os.urandom(256).hex()
    lines = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    return ("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n"
            + "\n".join(lines) + "\n-----END OpenVPN Static key V1-----\n")


# Self-signed certificate for the web interface

def san_list(hosts):
    sans = []
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        if re.fullmatch(r"[0-9.]+", h) or ":" in h:
            entry = "IP:" + h
        else:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", h):
                continue
            entry = "DNS:" + h
        if entry not in sans:
            sans.append(entry)
    return sans


def make_self_signed(crt_path, key_path, cn, hosts, days=825, mode_key=0o600):
    sans = san_list(hosts)
    key = generate_key("ec-p256")
    with tempfile.TemporaryDirectory(prefix="noirconf-") as tmp:
        kp = os.path.join(tmp, "k.pem")
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        crt = openssl(["req", "-x509", "-new", "-key", kp, "-subj", "/CN=" + cn,
                       "-days", str(days), "-addext", "subjectAltName=" + ",".join(sans),
                       "-addext", "basicConstraints=critical,CA:FALSE",
                       "-addext", "keyUsage=critical,digitalSignature",
                       "-addext", "extendedKeyUsage=serverAuth"])
    fsutil.atomic_write(key_path, key, mode=mode_key)
    fsutil.atomic_write(crt_path, crt, mode=0o644)


# The CA of one server

CNF = """[ca]
default_ca = CA_default

[CA_default]
dir = {pki}
database = $dir/index.txt
new_certs_dir = $dir/issued
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/ca.crt
private_key = $dir/ca.key
default_md = default
default_days = {days}
default_crl_days = {crl_days}
policy = policy_cn
unique_subject = no
copy_extensions = none
email_in_dn = no

[policy_cn]
commonName = supplied
"""

EXT_SERVER = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{san}
"""

EXT_CLIENT = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


class CA:
    def __init__(self, pki_dir, key_type=DEFAULT_KEY_TYPE):
        self.key_type = check_key_type(key_type)
        if "$" in pki_dir or "\n" in pki_dir:
            raise PkiError("the folder name has a character that openssl.cnf cannot hold")
        self.dir = os.path.abspath(pki_dir)
        self.cnf = os.path.join(self.dir, "openssl.cnf")

    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def exists(self):
        return os.path.exists(self.p("ca.crt")) and os.path.exists(self.p("ca.key"))

    def init(self, cn, group_dir=True):
        """Create the CA files, an empty CRL and the folders."""
        fsutil.make_dir(self.dir, 0o750 if fsutil.daemon_gid() is not None else 0o700,
                        group=True)
        fsutil.make_dir(self.p("issued"), 0o700)
        fsutil.atomic_write(self.cnf, CNF.format(pki=self.dir, days=CLIENT_DAYS,
                                                 crl_days=CRL_DAYS), mode=0o600)
        fsutil.atomic_write(self.p("index.txt"), b"", mode=0o600)
        fsutil.atomic_write(self.p("index.txt.attr"), b"unique_subject = no\n", mode=0o600)
        first = secrets.token_hex(8)
        first = "%x" % (int(first, 16) & 0x7FFFFFFFFFFFFFFF)
        if len(first) % 2:
            first = "0" + first
        fsutil.atomic_write(self.p("serial"), (first + "\n").encode(), mode=0o600)
        fsutil.atomic_write(self.p("crlnumber"), b"01\n", mode=0o600)
        key = generate_key(self.key_type)
        fsutil.atomic_write(self.p("ca.key"), key, mode=0o600)
        crt = openssl(["req", "-x509", "-new", "-key", self.p("ca.key"), "-subj", "/CN=" + cn,
                       "-days", str(CA_DAYS),
                       "-addext", "basicConstraints=critical,CA:TRUE",
                       "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                       "-addext", "subjectKeyIdentifier=hash"])
        fsutil.atomic_write(self.p("ca.crt"), crt, mode=0o644, group=True)
        self.gen_crl()

    def _ca(self, args, input=None):
        return openssl(["ca", "-batch", "-config", self.cnf] + args, input=input)

    def gen_crl(self):
        out = self._ca(["-gencrl", "-crldays", str(CRL_DAYS)])
        fsutil.atomic_write(self.p("crl.pem"), out, mode=0o640, group=True)

    def _sign(self, csr, ext_text, days, subject=None):
        with tempfile.TemporaryDirectory(prefix="noirconf-") as tmp:
            csr_p = os.path.join(tmp, "req.csr")
            ext_p = os.path.join(tmp, "ext.cnf")
            with open(csr_p, "wb") as f:
                f.write(csr)
            with open(ext_p, "w") as f:
                f.write("[ext]\n" + ext_text)
            subj = ["-subj", "/CN=" + subject] if subject else []
            pem = self._ca(subj + ["-in", csr_p, "-days", str(days), "-notext", "-outdir", self.p("issued"),
                            "-extfile", ext_p, "-extensions", "ext", "-out", "/dev/stdout"])
        return first_pem_block(pem.decode(), "CERTIFICATE")

    def issue_server(self, cn, hosts, key_path, crt_path):
        """Create the server key and certificate; write them to files."""
        key = generate_key(self.key_type)
        sans = san_list(list(hosts) + [cn])
        ext = EXT_SERVER.format(san="subjectAltName = " + ",".join(sans) if sans else "")
        csr = openssl(["req", "-new", "-key", "/dev/stdin", "-subj", "/CN=" + cn], input=key)
        crt = self._sign(csr, ext, SERVER_DAYS)
        fsutil.atomic_write(key_path, key, mode=0o640 if fsutil.daemon_gid() is not None else 0o600,
                            group=True)
        fsutil.atomic_write(crt_path, crt, mode=0o644, group=True)

    def issue_client(self, cn, passphrase=None):
        """Create a client key and certificate. Returns (key_pem, cert_pem, serial, pin).

        The key is returned in memory only. With a passphrase, it is encrypted.
        """
        key = generate_key(self.key_type)
        csr = openssl(["req", "-new", "-key", "/dev/stdin", "-subj", "/CN=" + cn], input=key)
        crt = self._sign(csr, EXT_CLIENT, CLIENT_DAYS)
        serial = cert_serial(crt)
        pin = pin_from_pem(crt.decode() if isinstance(crt, bytes) else crt)
        if passphrase:
            key = encrypt_key(key, passphrase)
        return key.decode(), crt if isinstance(crt, str) else crt.decode(), serial, pin

    def issue_from_csr(self, csr_pem, cn):
        """Sign a checked request. The subject is CN=cn and the extensions are the ones of
        a client certificate. Returns (cert_pem, serial, pin)."""
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", cn):
            raise PkiError("the user name cannot be a certificate name")
        csr, _ = check_csr(csr_pem)
        crt = self._sign(csr.encode(), EXT_CLIENT, CLIENT_DAYS, subject=cn)
        return crt, cert_serial(crt), pin_from_pem(crt)

    def revoke(self, serial):
        """Revoke a certificate of this CA by serial. Returns False if it was revoked already."""
        path = self.p("issued", serial.upper() + ".pem")
        if not re.fullmatch(r"[0-9A-F]+", serial.upper()) or not os.path.exists(path):
            raise PkiError("no certificate with this serial")
        try:
            self._ca(["-revoke", path, "-crl_reason", "cessationOfOperation"])
        except PkiError as e:
            if "already revoked" in str(e).lower():
                return False
            raise
        return True

    def revoked_serials(self):
        out = set()
        try:
            with open(self.p("index.txt")) as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 4 and parts[0] == "R":
                        out.add(parts[3].upper())
        except FileNotFoundError:
            pass
        return out


def encrypt_key(key_pem, passphrase):
    """Encrypt a private key (PEM bytes) with AES-256-CBC. Returns PEM bytes."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if b"\n" in passphrase or b"\r" in passphrase or b"\0" in passphrase:
        raise PkiError("the passphrase has a line break")
    return openssl(["pkey", "-aes-256-cbc", "-passout", "fd:@FD0@"],
                   input=key_pem, secrets_=[passphrase])


def decrypt_check(key_pem, passphrase):
    """True when the encrypted key opens with the passphrase. For tests."""
    try:
        openssl(["pkey", "-passin", "fd:@FD0@", "-noout"], input=key_pem,
                secrets_=[passphrase.encode() if isinstance(passphrase, str) else passphrase])
        return True
    except PkiError:
        return False
