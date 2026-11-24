from __future__ import annotations

import csv
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWNER = "9.9.9.9"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def wait_port(port: int, timeout: float = 10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"port {port} never opened")


def call(url: str, ip: str, method: str = "GET", body: dict | None = None, ua: str = "Mozilla/5.0") -> tuple:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Sprite-Client-Ip": ip, "User-Agent": ua, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        p = {k: free_port() for k in ("juice", "jev", "runner", "agent", "door")}
        cls.p = p
        reset = f"{sys.executable} -c \"import urllib.request;urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:{p['juice']}/__reset',method='POST'))\""
        (cls.tmp / "door").mkdir()
        (cls.tmp / "door" / "canaries.json").write_text(json.dumps({"honeypot": {"admin_password": "CANARY-honey-77"}}))
        base = dict(os.environ, PYTHONPATH=str(ROOT))
        specs = [
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "juice", str(p["juice"])], {}),
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "jev", str(p["jev"])], {}),
            ([sys.executable, str(ROOT / "runner" / "runner.py")], {"RUNNER_PORT": p["runner"], "RUNNER_SECRET_SHA256": sha("runner-secret"), "RUNNER_TARGET": f"http://127.0.0.1:{p['juice']}", "RUNNER_RESET_CMD": reset}),
            ([sys.executable, "-m", "agent.agent"], {
                "AGENT_PORT": p["agent"], "AGENT_DATA_DIR": cls.tmp / "agent", "AGENT_EVENTS_SHA256": sha("events-secret"), "AGENT_DASH_SHA256": sha("let me in"),
                "JEV_URL": f"http://127.0.0.1:{p['jev']}/v1/systemone", "RUNNER_URL": f"http://127.0.0.1:{p['runner']}", "RUNNER_TOKEN": "runner-secret",
                "DOOR_URL": f"http://127.0.0.1:{p['door']}", "DOOR_TOKEN": "door-secret", "OWNER_IPS": OWNER}),
            ([sys.executable, str(ROOT / "door" / "door.py")], {
                "DOOR_PORT": p["door"], "DOOR_UPSTREAM": f"http://127.0.0.1:{p['juice']}", "DOOR_DATA_DIR": cls.tmp / "door", "DOOR_ADMIN_SHA256": sha("door-secret"),
                "DOOR_EVENTS_URL": f"http://127.0.0.1:{p['agent']}/events", "DOOR_EVENTS_TOKEN": "events-secret", "DOOR_ALLOWLIST": OWNER,
                "DOOR_TARPIT_SECONDS": "0.2", "DOOR_FLUSH_SECONDS": "0.2"}),
        ]
        cls.procs = []
        for cmd, env in specs:
            e = dict(base, **{k: str(v) for k, v in env.items()})
            cls.procs.append(subprocess.Popen(cmd, cwd=ROOT, env=e, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        for port in p.values():
            wait_port(port)
        cls.door = f"http://127.0.0.1:{p['door']}"

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs:
            proc.terminate()
        for proc in cls.procs:
            proc.wait(timeout=5)

    def decisions(self, expected: int, timeout: float = 20) -> list:
        path = self.tmp / "agent" / "decisions.tsv"
        deadline = time.time() + timeout
        rows = []
        while time.time() < deadline:
            if path.exists():
                with path.open() as f:
                    rows = list(csv.DictReader(f, delimiter="\t"))
                if len(rows) >= expected:
                    return rows
            time.sleep(0.1)
        self.fail(f"expected {expected} decisions, got {len(rows)}: {rows}")

    def test_flow(self):
        sqli = {"email": "' or 1=1--", "password": "x"}
        self.assertEqual(call(self.door + "/", "1.1.1.1")[0], 200)
        call(self.door + "/wp-login.php", "2.2.2.2", ua="Mozilla/5.0 zgrab/0.x")
        self.assertEqual(call(self.door + "/rest/user/login", "3.3.3.3", "POST", sqli, ua="sqlmap/1.8")[0], 200)
        self.assertIn("CANARY-honey-77", call(self.door + "/.env", "4.4.4.4")[1])
        call(self.door + "/rest/user/login", "5.5.5.5", "POST", {"email": "admin@juice-sh.op", "password": "CANARY-honey-77"})
        call(self.door + "/rest/user/login", OWNER, "POST", sqli)
        rows = self.decisions(7)
        by_ip: dict = {}
        for r in rows:
            by_ip.setdefault(r["ip"], []).append(r)

        self.assertNotIn("1.1.1.1", by_ip)
        self.assertEqual(by_ip["2.2.2.2"][-1]["decision"], "ignore")
        self.assertEqual([r["decision"] for r in by_ip["3.3.3.3"]], ["replay", "block"])
        self.assertEqual(by_ip["3.3.3.3"][-1]["replay_verdict"], "PROVEN")
        self.assertIn("loginAdminChallenge", by_ip["3.3.3.3"][-1]["evidence"])
        self.assertEqual(by_ip["4.4.4.4"][-1]["decision"], "tarpit")
        self.assertEqual(by_ip["5.5.5.5"][-1]["decision"], "block")
        self.assertIn("fake .env", by_ip["5.5.5.5"][-1]["line"])
        self.assertEqual(by_ip[OWNER][-1]["replay_verdict"], "PROVEN")

        self.assertEqual(call(self.door + "/", "3.3.3.3")[0], 403)
        self.assertEqual(call(self.door + "/", "5.5.5.5")[0], 403)
        self.assertEqual(call(self.door + "/", OWNER)[0], 200)

    def test_union_leak_is_proven_by_canary(self):
        q = urllib.request.quote("x')) UNION SELECT email,password FROM Users--")
        call(self.door + f"/rest/products/search?q={q}", "6.6.6.6", ua="sqlmap/1.8")
        rows = [r for r in self.decisions(1) if r["ip"] == "6.6.6.6"]
        deadline = time.time() + 20
        while len(rows) < 2 and time.time() < deadline:
            time.sleep(0.2)
            rows = [r for r in self.decisions(1) if r["ip"] == "6.6.6.6"]
        self.assertEqual(rows[-1]["replay_verdict"], "PROVEN")
        self.assertIn('"canaries_leaked":2', rows[-1]["evidence"])

    def test_dashboard_needs_passphrase(self):
        agent = f"http://127.0.0.1:{self.p['agent']}"
        with urllib.request.urlopen(agent + "/api/state") as r:
            self.assertIn(b"password", r.read())
        req = urllib.request.Request(agent + "/events", data=b'{"events":[]}', method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
