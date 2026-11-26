"""Shared test setup: import path, temp folders and the noirvpn tools."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
ROOT = os.path.dirname(APP)
if APP not in sys.path:
    sys.path.insert(0, APP)

import fsutil  # noqa: E402


def runs(path):
    """True when the program starts (a glibc build does not run on musl)."""
    import subprocess
    try:
        subprocess.run([path, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def tool(env, candidates):
    p = os.environ.get(env)
    if p and os.access(p, os.X_OK) and runs(p):
        return p
    for c in candidates:
        c = os.path.join(ROOT, c)
        if os.access(c, os.X_OK) and runs(c):
            return c
    return None


def noirvpn_path():
    return tool("NOIRVPN", ["dist/linux-amd64/bin/noirvpn", "out/noirvpn-dev"])


def noirvpnctl_path():
    return tool("NOIRVPNCTL", ["out/noirvpnctl.dev", "dist/linux-amd64/bin/noirvpnctl"])


def usable_noirvpn():
    """A noirvpn that accepts peer-keys-mode either, or None."""
    path = noirvpn_path()
    if not path:
        return None
    import subprocess
    d = tempfile.mkdtemp(prefix="noirconf-probe-")
    try:
        c = os.path.join(d, "p.conf")
        with open(c, "w") as f:
            f.write("peer-keys-mode either\n")
        out = subprocess.run([path, "--check-config", "--config", c], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=20).stdout.decode()
        return None if "expected pin or both" in out else path
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


class TmpCase(unittest.TestCase):
    """A test case with a temporary folder in self.tmp."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="noirconf-test-")
        self._group = fsutil.DAEMON_GROUP
        fsutil.DAEMON_GROUP = "noirconf-no-such-group"

    def tearDown(self):
        fsutil.DAEMON_GROUP = self._group
        shutil.rmtree(self.tmp, ignore_errors=True)


def css():
    with open(os.path.join(APP, "static", "app.css"), encoding="utf-8") as f:
        return f.read()
