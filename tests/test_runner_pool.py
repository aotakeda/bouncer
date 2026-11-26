from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bouncer_runner_pool", ROOT / "runner" / "runner.py")
runner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner_mod)

FAKE_APP = r'''
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

version = Path("build/version").read_text().strip()
if version == "crash":
    sys.exit(3)
Path("data/started").write_text(str(os.getpid()))
users = []

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/rest/admin/application-version":
            return self.reply(200, {"version": version})
        if self.path == "/api/Challenges":
            return self.reply(200, {"data": [{"key": "x", "solved": bool(users[1:])}]})
        if self.path == "/whoami":
            return self.reply(200, {"version": version, "pid": os.getpid(), "cwd": os.getcwd(), "users": len(users)})
        return self.reply(404, {})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        users.append(1)
        return self.reply(201, {"status": "success"})

HTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
'''


def free_base_port() -> int:
    import socket
    for base in range(23100, 24000, 10):
        ok = True
        for port in range(base, base + 4):
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                ok = False
            finally:
                s.close()
        if ok:
            return base
    raise RuntimeError("no free ports")


class PoolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = self.tmp / "juice"
        for d in ("build", "data", "routes", "node_modules", "frontend/dist", "frontend/src"):
            (self.app / d).mkdir(parents=True)
        (self.app / "build" / "version").write_text("v1")
        (self.app / "data" / "seed.txt").write_text("seed")
        (self.app / "frontend" / "dist" / "index.html").write_text("<title>x</title>")
        (self.app / "package.json").write_text("{}")
        (self.app / "app.py").write_text(FAKE_APP)
        wrapper = self.tmp / "fake-node"
        wrapper.write_text(f"#!/bin/sh\nshift 2\nexec {sys.executable} \"$@\"\n")
        wrapper.chmod(0o755)
        self.cfg = runner_mod.Config({
            "RUNNER_APP_DIR": str(self.app),
            "RUNNER_POOL_SIZE": "2",
            "RUNNER_POOL_BASE_PORT": str(free_base_port()),
            "RUNNER_NODE": str(wrapper),
            "RUNNER_APP_ENTRY": "app.py",
            "RUNNER_READY_TIMEOUT": "10",
            "RUNNER_SETTLE_SECONDS": "0",
        })

    def pool(self):
        pool = runner_mod.Pool(self.cfg)
        pool.start()
        self.addCleanup(pool.close)
        return pool

    def whoami(self, box):
        return json.loads(box.target.call("GET", "/whoami")["body"])

    def test_copies_share_code_but_not_data(self):
        pool = self.pool()
        a, info = pool.take()
        b, _ = pool.take()
        self.assertTrue(info["ok"], info)
        self.assertTrue(a.canary["planted"])
        self.assertNotEqual(a.target.port, b.target.port)
        copy = Path(self.whoami(a)["cwd"])
        self.assertTrue((copy / "build").is_symlink())
        self.assertTrue((copy / "node_modules").is_symlink())
        self.assertTrue((copy / "frontend" / "src").is_symlink())
        self.assertFalse((copy / "data").is_symlink())
        self.assertFalse((copy / "frontend" / "dist").is_symlink())
        self.assertFalse((self.app / "data" / "started").exists())
        pool.give(a)
        pool.give(b)

    def test_taking_is_instant_when_a_copy_is_warm(self):
        pool = self.pool()
        box, _ = pool.take()
        pool.give(box)
        deadline = time.time() + 10
        while time.time() < deadline and not all(s.state == "fresh" for s in pool.slots):
            time.sleep(0.05)
        started = time.time()
        box, info = pool.take()
        self.assertLess(time.time() - started, 0.2)
        self.assertEqual(self.whoami(box)["users"], 1)
        pool.give(box)

    def test_used_copy_is_restarted_before_it_is_handed_out_again(self):
        pool = self.pool()
        seen = set()
        for _ in range(4):
            box, info = pool.take()
            self.assertTrue(info["ok"], info)
            who = self.whoami(box)
            self.assertNotIn(who["pid"], seen)
            self.assertEqual(who["users"], 1)
            seen.add(who["pid"])
            box.target.call("POST", "/api/Users", body=b"{}")
            pool.give(box)

    def test_rebuild_hands_out_only_copies_running_the_new_build(self):
        pool = self.pool()
        box, _ = pool.take()
        self.assertEqual(self.whoami(box)["version"], "v1")
        pool.give(box)
        with pool.hold():
            (self.app / "build" / "version").write_text("v2")
            pool.rebuild()
        for _ in range(3):
            box, info = pool.take()
            self.assertTrue(info["ok"], info)
            self.assertEqual(self.whoami(box)["version"], "v2")
            pool.give(box)

    def test_broken_build_fails_fast_with_the_reason(self):
        (self.app / "build" / "version").write_text("crash")
        pool = self.pool()
        started = time.time()
        box, info = pool.take()
        self.assertIsNone(box)
        self.assertFalse(info["ok"])
        self.assertIn("exited with 3", info["error"])
        self.assertLess(time.time() - started, 8)

    def test_close_stops_every_copy(self):
        pool = self.pool()
        box, _ = pool.take()
        pid = self.whoami(box)["pid"]
        pool.close()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_close_while_copies_are_starting_leaves_nothing_running(self):
        import socket
        pool = runner_mod.Pool(self.cfg)
        pool.start()
        time.sleep(0.15)
        pool.close()
        time.sleep(0.3)
        for slot in pool.slots:
            s = socket.socket()
            try:
                self.assertNotEqual(s.connect_ex(("127.0.0.1", slot.port)), 0)
            finally:
                s.close()

    def test_leftover_copy_from_a_crashed_runner_is_stopped(self):
        pool = self.pool()
        box, _ = pool.take()
        pid = self.whoami(box)["pid"]
        for slot in pool.slots:
            slot.proc = None
        pool.closed = True
        with pool.cond:
            pool.cond.notify_all()
        again = runner_mod.Pool(self.cfg)
        again.start()
        self.addCleanup(again.close)
        box, info = again.take()
        self.assertTrue(info["ok"], info)
        self.assertNotEqual(self.whoami(box)["pid"], pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_runner_patch_runs_against_the_pool(self):
        files = {"routes/a.ts": {"content": "fixed", "base_sha256": runner_mod.hashlib.sha256(b"vuln").hexdigest()}}
        (self.app / "routes" / "a.ts").write_text("vuln")
        self.cfg.build_cmd = "printf v2 > build/version"
        runner = runner_mod.Runner(self.cfg)
        runner.start()
        self.addCleanup(runner.close)
        req = {"method": "GET", "path": "/whoami", "headers": {}}
        out = runner.patch({"request": req, "files": files, "variants": [req, req, req]})
        self.assertTrue(out["ok"], out)
        self.assertEqual(json.loads(out["replay_before"]["attack"]["body"])["version"], "v1")
        self.assertEqual(json.loads(out["replay"]["attack"]["body"])["version"], "v2")
        self.assertEqual({json.loads(v["attack"]["body"])["version"] for v in out["variants"]["after"]}, {"v2"})
        self.assertEqual((self.app / "routes" / "a.ts").read_text(), "vuln")
        self.assertEqual((self.app / "build" / "version").read_text(), "v1")
        box, info = runner.app.take()
        self.assertTrue(info["ok"], info)
        self.assertEqual(self.whoami(box)["version"], "v1")


class LegacyMode(unittest.TestCase):
    def test_pool_is_off_unless_sized(self):
        self.assertIsInstance(runner_mod.make_app(runner_mod.Config({})), runner_mod.CommandApp)
        self.assertIsInstance(runner_mod.make_app(runner_mod.Config({"RUNNER_POOL_SIZE": "3"})), runner_mod.Pool)
        cfg = runner_mod.Config({"RUNNER_APP_DIR": "/srv/juice"})
        self.assertEqual(cfg.pool_dir, Path("/srv/juice-pool"))


class ServerLimits(unittest.TestCase):
    def start(self, max_threads: int, idle: float):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        runner = runner_mod.Runner(runner_mod.Config({"RUNNER_APP_DIR": tmp.name}), app=object())
        handler = runner_mod.make_handler(runner)
        handler.timeout = idle
        server = runner_mod.RunnerServer(("127.0.0.1", 0), handler, max_threads)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_defaults(self):
        self.assertEqual(runner_mod.make_handler(runner_mod.Runner(runner_mod.Config({"RUNNER_APP_DIR": "/nonexistent-bouncer"}), app=object())).timeout, runner_mod.SERVER_IDLE_SECONDS)
        self.assertEqual(runner_mod.server_threads({}), runner_mod.SERVER_MAX_THREADS)
        self.assertEqual(runner_mod.server_threads({"RUNNER_MAX_THREADS": "3"}), 3)
        self.assertEqual(runner_mod.server_threads({"RUNNER_MAX_THREADS": "0"}), 1)

    def test_thread_cap_refuses_extra_connections_and_idle_ones_are_dropped(self):
        port = self.start(max_threads=1, idle=0.5)
        slow = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(slow.close)
        slow.sendall(b"GET /health HTTP/1.1\r\n")
        time.sleep(0.1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 503"))
        started = time.time()
        self.assertEqual(slow.recv(10), b"")
        self.assertLess(time.time() - started, 3)
        time.sleep(0.1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 404"))

if __name__ == "__main__":
    unittest.main()
