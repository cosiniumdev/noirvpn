"""File helpers: atomic writes, modes and the daemon group."""
import grp
import os
import tempfile

# Group of the daemon files. Tests can change it.
DAEMON_GROUP = "noirvpn"


def daemon_gid():
    try:
        return grp.getgrnam(DAEMON_GROUP).gr_gid
    except (KeyError, TypeError):
        return None


def set_group(path, gid):
    if gid is None:
        return
    try:
        os.chown(path, -1, gid)
    except OSError:
        pass


def atomic_write(path, data, mode=0o640, group=False):
    """Write a file through a temporary file in the same folder.

    group=True gives the file to the daemon group when it exists.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if group:
            set_group(tmp, daemon_gid())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def read_text(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def make_dir(path, mode, group=False):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    if group:
        set_group(path, daemon_gid())
