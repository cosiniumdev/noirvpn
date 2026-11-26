"""A store in a temp folder with a fake daemon on the bus."""
import json
import os

import helpers
import nng
import optforms
import store
import svcctl


class FakeDaemon:
    def __init__(self, path):
        self.ops = []
        self.fail = {}
        self.rep = nng.Rep(path, self.handle)

    def handle(self, payload):
        r = json.loads(payload)
        self.ops.append((r["op"], r.get("args", {})))
        if r["op"] in self.fail:
            code = self.fail[r["op"]]
            return json.dumps({"v": 1, "id": r["id"], "ok": False,
                               "error": {"code": code, "message": "x"}}).encode()
        res = {"status": {"uptime_s": 7, "server": {"peers": 1, "listen": ["udp 0.0.0.0:1194"]}},
               "peer.kick": {"kicked": ["s-1"]},
               "peers.list": {"count": 0, "peers": []}}.get(r["op"], {})
        return json.dumps({"v": 1, "id": r["id"], "ok": True, "result": res}).encode()

    def names(self):
        return [o[0] for o in self.ops]

    def close(self):
        self.rep.close()


class StoreCase(helpers.TmpCase):
    needs_noirvpn = True

    def setUp(self):
        super().setUp()
        self.noirvpn = helpers.usable_noirvpn()
        if self.needs_noirvpn and not self.noirvpn:
            self.skipTest("no noirvpn that accepts peer-keys-mode either (set NOIRVPN)")
        self.etc = os.path.join(self.tmp, "etc")
        os.makedirs(self.etc)
        self.sock = os.path.join(self.tmp, "run")
        os.makedirs(self.sock)
        self.svc = svcctl.ServiceManager(self.etc, self.noirvpn or "/nonexistent", mode="spawn",
                                         run_dir=os.path.join(self.tmp, "r"),
                                         log_dir=os.path.join(self.tmp, "l"))
        self.store = store.Store(self.etc, self.noirvpn or "/nonexistent", self.svc, run_dir=self.sock)
        self.daemon = None

    def tearDown(self):
        if self.daemon:
            self.daemon.close()
        super().tearDown()

    def start_daemon(self, name="server"):
        self.daemon = FakeDaemon(os.path.join(self.sock, name + ".control"))
        return self.daemon

    def form(self, name="server", **over):
        vals = optforms.defaults(name, self.etc)
        vals["bus-control"] = [[os.path.join(self.sock, name + ".control"), "mode", "0660"]]
        vals["bus-events"] = [[os.path.join(self.sock, name + ".events"), "mode", "0640"]]
        form = {}
        for k, v in vals.items():
            form["o." + k] = "\n".join(optforms.join_args(a) for a in v)
        for k, v in over.items():
            form["o." + k.replace("_", "-")] = v
        return form

    def create(self, name="server", ext="vpn.example.com", **over):
        return self.store.create_server(name, self.form(name, **over), ext, "tester")
