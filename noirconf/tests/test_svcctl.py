import os
import stat
import unittest

import helpers
import fixtures
import svcctl


class Recorder:
    def __init__(self, replies=None):
        self.calls = []
        self.replies = replies or {}

    def __call__(self, argv, timeout=20):
        self.calls.append(list(argv))
        for k, v in self.replies.items():
            if " ".join(argv).startswith(k):
                return v
        return 0, ""


class SystemdTest(helpers.TmpCase):
    def make(self, replies=None):
        self.rec = Recorder(replies)
        return svcctl.ServiceManager("/etc/noirvpn/server", "/usr/local/bin/noirvpn", mode="systemd",
                                     runner=self.rec, unit_dir=self.tmp, init_dir=self.tmp)

    def test_unit_text(self):
        m = self.make()
        t = m.unit_text()
        self.assertIn("ExecStart=/usr/local/bin/noirvpn --config /etc/noirvpn/server/%i.conf --name %i", t)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN", t)
        self.assertIn("RestartPreventExitStatus=1 2", t)
        self.assertIn("RuntimeDirectoryPreserve=yes", t)

    def test_install_needs_confirmation_flow(self):
        m = self.make()
        self.assertFalse(m.installed("a"))
        m.install("a")
        self.assertTrue(m.installed("a"))
        self.assertEqual(self.rec.calls[-1], ["systemctl", "daemon-reload"])
        self.assertEqual(os.stat(m.unit_path()).st_mode & 0o777, 0o644)

    def test_actions(self):
        m = self.make()
        m.start("a")
        m.stop("a")
        m.restart("a")
        m.set_enabled("a", True)
        self.assertEqual(self.rec.calls, [
            ["systemctl", "start", "noirvpn-server@a"], ["systemctl", "stop", "noirvpn-server@a"],
            ["systemctl", "restart", "noirvpn-server@a"], ["systemctl", "enable", "noirvpn-server@a"]])

    def test_state(self):
        m = self.make({"systemctl is-active": (0, "active\n"), "systemctl is-enabled": (0, "enabled\n")})
        self.assertEqual(m.state("a"), {"running": True, "text": "active", "enabled": True})
        m = self.make({"systemctl is-active": (3, "inactive\n"), "systemctl is-enabled": (1, "disabled\n")})
        self.assertFalse(m.state("a")["running"])

    def test_failure_raises(self):
        m = self.make({"systemctl start": (1, "Job failed\n")})
        with self.assertRaises(svcctl.ServiceError):
            m.start("a")

    def test_logs(self):
        m = self.make({"journalctl": (0, "line1\nline2\n")})
        self.assertEqual(m.logs("a"), "line1\nline2\n")
        self.assertEqual(self.rec.calls[-1][:3], ["journalctl", "-u", "noirvpn-server@a"])

    def test_detect(self):
        self.assertEqual(svcctl.detect_mode(self.tmp + "/none", which=lambda n: None), "spawn")
        self.assertEqual(svcctl.detect_mode(self.tmp + "/none", which=lambda n: "/sbin/rc-service"), "openrc")
        self.assertEqual(svcctl.detect_mode("/proc", which=lambda n: None), "systemd")


class OpenrcTest(helpers.TmpCase):
    def test_script_and_actions(self):
        rec = Recorder({"rc-service noirvpn-server.a status": (0, ""), "rc-update show": (0, " noirvpn-server.a | default\n")})
        m = svcctl.ServiceManager("/etc/noirvpn/server", "/usr/bin/noirvpn", mode="openrc", runner=rec,
                                  init_dir=self.tmp)
        self.assertFalse(m.installed("a"))
        m.install("a")
        self.assertTrue(m.installed("a"))
        self.assertTrue(os.path.islink(m.instance_script("a")))
        self.assertTrue(os.stat(m.initscript_path()).st_mode & stat.S_IXUSR)
        with open(m.initscript_path()) as f:
            text = f.read()
        self.assertIn("#!/sbin/openrc-run", text)
        self.assertIn('command="/usr/bin/noirvpn"', text)
        m.start("a")
        self.assertEqual(rec.calls[-1], ["rc-service", "noirvpn-server.a", "start"])
        st = m.state("a")
        self.assertTrue(st["running"])
        self.assertTrue(st["enabled"])


FAKE_DAEMON = """#!/bin/sh
trap 'echo got-term; exit 0' TERM
echo "started $*"
while true; do sleep 0.1; done
"""


class SpawnTest(fixtures.StoreCase):
    needs_noirvpn = False

    def setUp(self):
        super().setUp()
        self.fake = os.path.join(self.tmp, "fake-noirvpn")
        with open(self.fake, "w") as f:
            f.write(FAKE_DAEMON)
        os.chmod(self.fake, 0o755)
        with open(os.path.join(self.etc, "a.conf"), "w") as f:
            f.write("port 1\n")
        self.svc = svcctl.ServiceManager(self.etc, self.fake, mode="spawn",
                                         run_dir=os.path.join(self.tmp, "run2"),
                                         log_dir=os.path.join(self.tmp, "log2"),
                                         bus_for=lambda n: None)

    def tearDown(self):
        try:
            self.svc.stop("a")
        except Exception:
            pass
        super().tearDown()

    def test_start_stop(self):
        self.assertFalse(self.svc.state("a")["running"])
        self.svc.start("a")
        st = self.svc.state("a")
        self.assertTrue(st["running"], st)
        self.assertIn("--name a", self.svc.logs("a"))
        self.assertTrue(os.path.exists(self.svc.pid_path("a")))
        with self.assertRaises(svcctl.ServiceError):
            self.svc.start("a")
        self.svc.stop("a")
        self.assertFalse(self.svc.state("a")["running"])
        self.assertFalse(os.path.exists(self.svc.pid_path("a")))
        self.assertIn("got-term", self.svc.logs("a"))

    def test_restart(self):
        self.svc.start("a")
        pid1 = self.svc._read_pid("a")
        self.svc.restart("a")
        pid2 = self.svc._read_pid("a")
        self.assertNotEqual(pid1, pid2)
        self.assertTrue(self.svc.state("a")["running"])

    def test_early_exit_reported(self):
        with open(self.fake, "w") as f:
            f.write("#!/bin/sh\necho 'config error: bad'\nexit 1\n")
        with self.assertRaises(svcctl.ServiceError) as cm:
            self.svc.start("a")
        self.assertIn("config error", str(cm.exception))

    def test_stale_pid_file(self):
        os.makedirs(self.svc.run_dir, exist_ok=True)
        with open(self.svc.pid_path("a"), "w") as f:
            f.write("1\n")
        self.assertFalse(self.svc.state("a")["running"])

    def test_stop_by_bus_first(self):
        calls = []

        class B:
            def call(s, op, args=None, timeout=None):
                calls.append(op)
                os.kill(self.svc._read_pid("a"), 15)
                return {"stopping": True}
        self.svc.bus_for = lambda n: B()
        self.svc.start("a")
        self.svc.stop("a")
        self.assertEqual(calls, ["daemon.shutdown"])
        self.assertFalse(self.svc.state("a")["running"])


if __name__ == "__main__":
    unittest.main()
