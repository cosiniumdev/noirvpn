"""Start, stop and watch the noirvpn daemons.

Three ways, chosen once:
- systemd: a template unit noirvpn-server@.service
- OpenRC: one init script and a link for each server
- spawn: a detached process with a pid file
"""
import grp
import logging
import os
import pwd
import re
import shutil
import signal
import subprocess
import threading
import time

import bus as busmod

log = logging.getLogger("noirconf.service")

UNIT_NAME = "noirvpn-server@.service"
OPENRC_NAME = "noirvpn-server"


class ServiceError(Exception):
    pass


def default_runner(argv, timeout=20):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, shell=False)
    except FileNotFoundError:
        return 127, "%s: not found" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "%s: timeout" % argv[0]
    return p.returncode, p.stdout.decode("utf-8", "replace")


def detect_mode(systemd_dir="/run/systemd/system", which=shutil.which):
    if os.path.isdir(systemd_dir):
        return "systemd"
    if which("rc-service"):
        return "openrc"
    return "spawn"


def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name):
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


class ServiceManager:
    def __init__(self, etc, noirvpn, mode=None, runner=default_runner,
                 unit_dir="/etc/systemd/system", init_dir="/etc/init.d",
                 run_dir="/run/noirconf", log_dir="/var/log/noirconf",
                 bus_for=None, daemon_user="noirvpn"):
        self.etc = etc
        self.noirvpn = noirvpn
        self.mode = mode or detect_mode()
        self.run = runner
        self.unit_dir = unit_dir
        self.init_dir = init_dir
        self.run_dir = run_dir
        self.log_dir = log_dir
        self.bus_for = bus_for
        self.daemon_user = daemon_user
        self._procs = {}
        self._lock = threading.Lock()

    # Names

    def conf(self, name):
        return os.path.join(self.etc, name + ".conf")

    def unit_path(self):
        return os.path.join(self.unit_dir, UNIT_NAME)

    def initscript_path(self):
        return os.path.join(self.init_dir, OPENRC_NAME)

    def instance_script(self, name):
        return os.path.join(self.init_dir, "%s.%s" % (OPENRC_NAME, name))

    def pid_path(self, name):
        return os.path.join(self.run_dir, name + ".pid")

    def log_path(self, name):
        return os.path.join(self.log_dir, name + ".log")

    # Unit and init script

    def unit_text(self):
        user = ""
        caps = "CAP_NET_ADMIN"
        if self.daemon_user and user_exists(self.daemon_user):
            user = "User=%s\n" % self.daemon_user
            if group_exists(self.daemon_user):
                user += "Group=%s\n" % self.daemon_user
        return (
            "[Unit]\n"
            "Description=noirvpn server %i\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            + user +
            "AmbientCapabilities=" + caps + "\n"
            "CapabilityBoundingSet=" + caps + "\n"
            "ExecStart=" + self.noirvpn + " --config " + self.etc + "/%i.conf --name %i\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "Restart=on-failure\n"
            "RestartPreventExitStatus=1 2\n"
            "TimeoutStopSec=10\n"
            "RuntimeDirectory=noirvpn\n"
            "RuntimeDirectoryMode=0750\n"
            "RuntimeDirectoryPreserve=yes\n"
            "LimitNOFILE=65536\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    def initscript_text(self):
        return (
            "#!/sbin/openrc-run\n"
            "instance=\"${RC_SVCNAME#%s.}\"\n"
            "description=\"noirvpn server $instance\"\n"
            "command=\"%s\"\n"
            "command_args=\"--config %s/${instance}.conf --name ${instance}\"\n"
            "command_background=true\n"
            "pidfile=\"/run/${RC_SVCNAME}.pid\"\n"
            "output_log=\"/var/log/noirvpn/${instance}.log\"\n"
            "error_log=\"/var/log/noirvpn/${instance}.log\"\n"
            "\n"
            "depend() {\n"
            "\tneed net\n"
            "}\n"
            "\n"
            "start_pre() {\n"
            "\tcheckpath -d -m 0750 /run/noirvpn /var/log/noirvpn\n"
            "}\n"
        ) % (OPENRC_NAME, self.noirvpn, self.etc)

    def installed(self, name=None):
        if self.mode == "systemd":
            return os.path.exists(self.unit_path())
        if self.mode == "openrc":
            return os.path.exists(self.initscript_path()) and (
                name is None or os.path.exists(self.instance_script(name)))
        return True

    def install(self, name):
        from fsutil import atomic_write
        if self.mode == "systemd":
            atomic_write(self.unit_path(), self.unit_text(), mode=0o644)
            self._must(["systemctl", "daemon-reload"])
        elif self.mode == "openrc":
            os.makedirs(self.init_dir, exist_ok=True)
            atomic_write(self.initscript_path(), self.initscript_text(), mode=0o755)
            link = self.instance_script(name)
            if not os.path.lexists(link):
                os.symlink(OPENRC_NAME, link)
        else:
            raise ServiceError("nothing to install in this mode")

    def _must(self, argv):
        rc, out = self.run(argv)
        if rc != 0:
            raise ServiceError(out.strip()[-400:] or "%s failed" % argv[0])
        return out

    # State

    def state(self, name):
        """Dict: running (bool), text, enabled (bool or None)."""
        if self.mode == "systemd":
            rc, out = self.run(["systemctl", "is-active", "noirvpn-server@" + name])
            text = out.strip().splitlines()[0] if out.strip() else "unknown"
            rc2, out2 = self.run(["systemctl", "is-enabled", "noirvpn-server@" + name])
            return {"running": text == "active", "text": text,
                    "enabled": out2.strip() == "enabled"}
        if self.mode == "openrc":
            rc, out = self.run(["rc-service", "%s.%s" % (OPENRC_NAME, name), "status"])
            text = "started" if rc == 0 else (out.strip().splitlines()[-1] if out.strip() else "stopped")
            rc2, out2 = self.run(["rc-update", "show"])
            enabled = bool(re.search(r"^\s*%s\.%s\s" % (OPENRC_NAME, re.escape(name)), out2, re.M))
            return {"running": rc == 0, "text": text, "enabled": enabled}
        pid = self._read_pid(name)
        alive = pid is not None and self._pid_matches(pid, name)
        return {"running": alive, "text": "running (pid %d)" % pid if alive else "stopped",
                "enabled": None}

    # Spawn mode helpers

    def _read_pid(self, name):
        try:
            with open(self.pid_path(name)) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _pid_matches(self, pid, name):
        try:
            with open("/proc/%d/stat" % pid) as f:
                stat = f.read()
            if stat.rsplit(")", 1)[1].split()[0] == "Z":
                return False
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                cmd = f.read().split(b"\0")
        except (OSError, IndexError):
            return False
        return self.conf(name).encode() in cmd

    def _spawn(self, name):
        pid = self._read_pid(name)
        if pid is not None and self._pid_matches(pid, name):
            raise ServiceError("the daemon runs already")
        os.makedirs(self.run_dir, mode=0o755, exist_ok=True)
        os.makedirs(self.log_dir, mode=0o750, exist_ok=True)
        logf = open(self.log_path(name), "ab")
        try:
            p = subprocess.Popen([self.noirvpn, "--config", self.conf(name), "--name", name],
                                 stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
                                 start_new_session=True, shell=False)
        except OSError as e:
            raise ServiceError("cannot start %s: %s" % (self.noirvpn, e.strerror or e))
        finally:
            logf.close()
        with self._lock:
            self._procs[name] = p
        threading.Thread(target=p.wait, daemon=True).start()
        from fsutil import atomic_write
        atomic_write(self.pid_path(name), "%d\n" % p.pid, mode=0o644)
        time.sleep(0.6)
        if p.poll() is not None:
            raise ServiceError("the daemon stopped at once (exit code %d). %s"
                               % (p.returncode, self.logs(name, 5).strip()[-300:]))

    def _wait_gone(self, pid, name, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if not self._pid_matches(pid, name):
                return True
            time.sleep(0.1)
        return not self._pid_matches(pid, name)

    def _despawn(self, name):
        pid = self._read_pid(name)
        if pid is None or not self._pid_matches(pid, name):
            return
        b = self.bus_for(name) if self.bus_for else None
        if b is not None:
            try:
                b.call("daemon.shutdown", {"timeout_s": 5}, timeout=5)
            except (busmod.BusError, busmod.NotRunning, busmod.BusProtocolError):
                pass
            if self._wait_gone(pid, name, 8):
                self._drop_pid(name)
                return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not self._wait_gone(pid, name, 8):
            raise ServiceError("the daemon does not stop")
        self._drop_pid(name)

    def _drop_pid(self, name):
        try:
            os.unlink(self.pid_path(name))
        except OSError:
            pass

    # Actions

    def start(self, name):
        if self.mode == "systemd":
            self._must(["systemctl", "start", "noirvpn-server@" + name])
        elif self.mode == "openrc":
            self._must(["rc-service", "%s.%s" % (OPENRC_NAME, name), "start"])
        else:
            self._spawn(name)

    def stop(self, name):
        if self.mode == "systemd":
            self._must(["systemctl", "stop", "noirvpn-server@" + name])
        elif self.mode == "openrc":
            self._must(["rc-service", "%s.%s" % (OPENRC_NAME, name), "stop"])
        else:
            self._despawn(name)

    def restart(self, name):
        if self.mode == "systemd":
            self._must(["systemctl", "restart", "noirvpn-server@" + name])
        elif self.mode == "openrc":
            self._must(["rc-service", "%s.%s" % (OPENRC_NAME, name), "restart"])
        else:
            self._despawn(name)
            self._spawn(name)

    def set_enabled(self, name, on):
        if self.mode == "systemd":
            self._must(["systemctl", "enable" if on else "disable", "noirvpn-server@" + name])
        elif self.mode == "openrc":
            self._must(["rc-update", "add" if on else "del", "%s.%s" % (OPENRC_NAME, name),
                        "default"])
        else:
            raise ServiceError("start at boot needs systemd or OpenRC")

    def logs(self, name, lines=30):
        if self.mode == "systemd":
            rc, out = self.run(["journalctl", "-u", "noirvpn-server@" + name, "-n", str(lines),
                                "--no-pager", "-o", "short-iso"])
            return out
        path = self.log_path(name) if self.mode == "spawn" else "/var/log/noirvpn/%s.log" % name
        return tail_file(path, lines)


def tail_file(path, lines=30, max_bytes=65536):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return ""
    return "\n".join(data.decode("utf-8", "replace").splitlines()[-lines:]) + "\n"
