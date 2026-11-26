import json
import os
import socket
import struct
import subprocess
import time
import unittest

import helpers
import bus
import nng


def fake_handler(payload):
    r = json.loads(payload)
    op = r["op"]
    results = {
        "status": {"mode": "server", "name": "srv", "uptime_s": 61,
                   "bus": {"run": "9f3a0c51d27be8a4", "seq": 42},
                   "server": {"state": "running", "peers": 1, "listen": ["udp 0.0.0.0:1194"]}},
        "peers.list": {"count": 1, "peers": [{
            "session": "s-1", "name": "alice", "state": "active", "proto": "udp",
            "real_addr": "203.0.113.5:51000", "vpn4": "10.8.0.6", "vpn6": None,
            "connected_at": "2026-01-15T09:26:53.589Z", "bytes_in": 1200, "bytes_out": 3400}]},
    }
    if op == "fail":
        return json.dumps({"v": 1, "id": r["id"], "ok": False,
                           "error": {"code": "not_found", "message": "no such session"}}).encode()
    if op == "wrongid":
        return json.dumps({"v": 1, "id": "x" * 32, "ok": True, "result": {}}).encode()
    if op == "slow":
        time.sleep(1.0)
    return json.dumps({"v": 1, "id": r["id"], "ok": True, "result": results.get(op, {})}).encode()


class FramingTest(unittest.TestCase):
    def test_handshake_bytes(self):
        self.assertEqual(nng.handshake_bytes(nng.PROTO_REQ0), b"\x00SP\x00\x00\x30\x00\x00")
        self.assertEqual(nng.handshake_bytes(nng.PROTO_SUB0), b"\x00SP\x00\x00\x21\x00\x00")

    def test_handshake_check(self):
        nng.check_handshake(b"\x00SP\x00\x00\x31\x00\x00", nng.PROTO_REP0)
        with self.assertRaises(nng.ProtocolError):
            nng.check_handshake(b"\x00SP\x00\x00\x30\x00\x00", nng.PROTO_REP0)
        with self.assertRaises(nng.ProtocolError):
            nng.check_handshake(b"XXXXXXXX", nng.PROTO_REP0)

    def test_frame(self):
        self.assertEqual(nng.frame(b"abc"), b"\x01\x00\x00\x00\x00\x00\x00\x00\x03abc")

    def test_read_frame_limits(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"\x01" + struct.pack(">Q", nng.MAX_RECV + 1))
            with self.assertRaises(nng.ProtocolError):
                nng.read_frame(a, None)
            a2, b2 = socket.socketpair()
            b2.sendall(b"\x02" + struct.pack(">Q", 1) + b"x")
            with self.assertRaises(nng.ProtocolError):
                nng.read_frame(a2, None)
            a2.close()
            b2.close()
        finally:
            a.close()
            b.close()

    def test_read_frame_timeout(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaises(nng.NngTimeout):
                nng.read_frame(a, time.monotonic() + 0.1)
        finally:
            a.close()
            b.close()

    def test_split_topic(self):
        self.assertEqual(nng.split_topic(b'peer.rekey {"a":1}'), (b"peer.rekey", b'{"a":1}'))
        self.assertEqual(nng.split_topic(b"x"), (b"x", b""))

    def test_ipc_path(self):
        self.assertEqual(nng.ipc_path("ipc:///run/x.control"), "/run/x.control")
        self.assertEqual(nng.ipc_path("/run/x"), "/run/x")


class BusTest(helpers.TmpCase):
    def setUp(self):
        super().setUp()
        self.ctl = os.path.join(self.tmp, "x.control")
        self.ev = os.path.join(self.tmp, "x.events")
        self.rep = nng.Rep(self.ctl, fake_handler)
        self.pub = nng.Pub(self.ev)
        self.bus = bus.Bus(self.ctl, self.ev, timeout=3)

    def tearDown(self):
        self.rep.close()
        self.pub.close()
        super().tearDown()

    def test_call(self):
        res = self.bus.call("status")
        self.assertEqual(res["uptime_s"], 61)
        res = self.bus.call("peers.list", {"limit": 5})
        self.assertEqual(res["peers"][0]["name"], "alice")

    def test_error_code(self):
        with self.assertRaises(bus.BusError) as cm:
            self.bus.call("fail")
        self.assertEqual(cm.exception.code, "not_found")

    def test_wrong_reply_id(self):
        with self.assertRaises(bus.BusProtocolError):
            self.bus.call("wrongid")

    def test_timeout(self):
        b = bus.Bus(self.ctl, timeout=0.3)
        with self.assertRaises(bus.BusError) as cm:
            b.call("slow")
        self.assertEqual(cm.exception.code, "timeout")

    def test_not_running(self):
        b = bus.Bus(os.path.join(self.tmp, "none.control"))
        with self.assertRaises(bus.NotRunning):
            b.call("status")
        self.assertFalse(b.running())
        self.assertTrue(self.bus.running())

    def test_envelope(self):
        seen = []

        def h(p):
            seen.append(json.loads(p))
            return fake_handler(p)
        r2 = nng.Rep(os.path.join(self.tmp, "y.control"), h)
        try:
            bus.Bus(os.path.join(self.tmp, "y.control")).call("peer.kick", {"name": "a", "halt": True})
        finally:
            r2.close()
        env = seen[0]
        self.assertEqual(env["v"], 1)
        self.assertRegex(env["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(env["op"], "peer.kick")
        self.assertEqual(env["args"], {"name": "a", "halt": True})

    def test_sub(self):
        with self.bus.subscribe([b"peer."]) as sub:
            for _ in range(50):
                if self.pub.subscribers():
                    break
                time.sleep(0.05)
            self.pub.publish("daemon.stop", b"{}")
            self.pub.publish("peer.connect", b'{"data":{"session":"s-1"}}')
            topic, payload = sub.recv(2)
        self.assertEqual(topic, b"peer.connect")
        self.assertEqual(json.loads(payload)["data"]["session"], "s-1")

    def test_paths(self):
        self.assertEqual(bus.control_path("srv", None, "/run/noirvpn"), "/run/noirvpn/srv.control")
        self.assertEqual(bus.control_path("srv", "ipc:///tmp/a.sock"), "/tmp/a.sock")
        self.assertEqual(bus.events_path("srv", None, "/r"), "/r/srv.events")


@unittest.skipUnless(helpers.noirvpnctl_path(), "noirvpnctl is not built")
class CtlInteropTest(helpers.TmpCase):
    """The Python fake daemon against the real noirvpnctl, then the Python client against it."""

    def setUp(self):
        super().setUp()
        self.ctl = os.path.join(self.tmp, "x.control")
        self.ev = os.path.join(self.tmp, "x.events")
        self.rep = nng.Rep(self.ctl, fake_handler)
        self.pub = nng.Pub(self.ev)
        self.exe = helpers.noirvpnctl_path()

    def tearDown(self):
        self.rep.close()
        self.pub.close()
        super().tearDown()

    def run_ctl(self, *args):
        return subprocess.run([self.exe, "--socket", self.ctl] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15)

    def test_status(self):
        r = self.run_ctl("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("uptime_s", r.stdout.decode())
        self.assertIn("udp 0.0.0.0:1194", r.stdout.decode())

    def test_peers_json(self):
        r = self.run_ctl("--json", "peers")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["result"]["peers"][0]["name"], "alice")

    def test_error_exit_code(self):
        r = self.run_ctl("kick", "s-9")
        self.assertEqual(r.returncode, 0)

    def test_events(self):
        p = subprocess.Popen([self.exe, "--socket", self.ctl, "events", "-n", "2"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                if self.pub.subscribers():
                    break
                time.sleep(0.05)
            time.sleep(0.3)
            for i in range(2):
                env = {"v": 1, "run": "9f3a0c51d27be8a4", "seq": i + 1, "ts": "2026-01-15T09:26:53.589Z",
                       "topic": "peer.connect", "data": {"session": "s-%d" % i}}
                self.pub.publish("peer.connect", json.dumps(env).encode())
            out, err = p.communicate(timeout=10)
        finally:
            p.kill()
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(out.count("peer.connect"), 2)


if __name__ == "__main__":
    unittest.main()
