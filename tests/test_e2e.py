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
import urllib.parse
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


def call(url: str, ip: str, method: str = "GET", body: dict | None = None, ua: str = "Mozilla/5.0", extra: dict | None = None) -> tuple:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Sprite-Client-Ip": ip, "User-Agent": ua, "Content-Type": "application/json", **(extra or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        p = {k: free_port() for k in ("juice", "replay", "jev", "github", "claude", "runner", "agent", "door")}
        cls.p = p
        reset = f"{sys.executable} -c \"import urllib.request;urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:{p['replay']}/__reset',method='POST'))\""
        app = cls.tmp / "app"
        cls.app = app
        (app / "routes").mkdir(parents=True)
        (app / "build").mkdir()
        (app / "routes" / "login.ts").write_text("export function login () {\n  query(`SELECT * FROM Users WHERE email = '${email}'`) // VULN\n}\n")
        (app / "routes" / "search.ts").write_text("export function searchProducts () {\n  query(`SELECT * FROM Products WHERE name LIKE '%${q}%'`) // VULN\n}\n")
        for name in ("login", "search"):
            (app / "build" / f"{name}.mode").write_text("vuln")
        build = f"{sys.executable} -c \"import pathlib;[pathlib.Path('build/'+n+'.mode').write_text('fixed' if 'replacements' in pathlib.Path('routes/'+n+'.ts').read_text() else 'vuln') for n in ('login','search')]\""
        (cls.tmp / "door").mkdir()
        (cls.tmp / "door" / "canaries.json").write_text(json.dumps({"honeypot": {"admin_password": "CANARY-honey-77"}}))
        base = dict(os.environ, PYTHONPATH=str(ROOT))
        specs = [
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "juice", str(p["juice"])], {}),
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "juice", str(p["replay"]), str(app)], {}),
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "jev", str(p["jev"])], {}),
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "github", str(p["github"]), str(app)], {}),
            ([sys.executable, str(ROOT / "tests" / "fakes.py"), "claude", str(p["claude"])], {}),
            ([sys.executable, str(ROOT / "runner" / "runner.py")], {
                "RUNNER_PORT": p["runner"], "RUNNER_SECRET_SHA256": sha("runner-secret"), "RUNNER_TARGET": f"http://127.0.0.1:{p['replay']}", "RUNNER_RESET_CMD": reset,
                "RUNNER_SERVICE": "", "RUNNER_APP_DIR": app, "RUNNER_BUILD_CMD": build}),
            ([sys.executable, "-m", "agent.agent"], {
                "AGENT_PORT": p["agent"], "AGENT_DATA_DIR": cls.tmp / "agent", "AGENT_EVENTS_SHA256": sha("events-secret"), "AGENT_DASH_SHA256": sha("let me in"),
                "JEV_URL": f"http://127.0.0.1:{p['jev']}/v1/systemone", "RUNNER_URL": f"http://127.0.0.1:{p['runner']}", "RUNNER_TOKEN": "runner-secret",
                "DOOR_URL": f"http://127.0.0.1:{p['door']}", "DOOR_TOKEN": "door-secret", "OWNER_IPS": OWNER,
                "SHIELD_SECONDS": "0", "FIX_MODE": "pr", "ANTHROPIC_URL": f"http://127.0.0.1:{p['claude']}", "GITHUB_URL": f"http://127.0.0.1:{p['github']}", "FIX_PER_HOUR": "20"}),
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

    def decisions(self, expected: int, timeout: float = 20, fixes: bool = False) -> list:
        path = self.tmp / "agent" / "decisions.tsv"
        deadline = time.time() + timeout
        rows = []
        while time.time() < deadline:
            if path.exists():
                with path.open() as f:
                    rows = [r for r in csv.DictReader(f, delimiter="\t") if fixes or r["decision"] != "fix"]
                if len(rows) >= expected:
                    return rows
            time.sleep(0.1)
        self.fail(f"expected {expected} decisions, got {len(rows)}: {rows}")

    def test_flow(self):
        before = len(self.decisions(0))
        sqli = {"email": "' or 1=1--", "password": "x"}
        self.assertEqual(call(self.door + "/", "1.1.1.1")[0], 200)
        call(self.door + "/wp-login.php", "2.2.2.2", ua="Mozilla/5.0 zgrab/0.x")
        self.assertEqual(call(self.door + "/rest/user/login", "3.3.3.3", "POST", sqli, ua="sqlmap/1.8")[0], 200)
        self.assertIn("CANARY-honey-77", call(self.door + "/.env", "4.4.4.4")[1])
        call(self.door + "/rest/user/login", "4.4.4.4", "POST", {"email": "admin@juice-sh.op", "password": "CANARY-honey-77"})
        call(self.door + "/rest/user/login", "5.5.5.5", "POST", {"email": "admin@juice-sh.op", "password": "CANARY-honey-77"})
        call(self.door + "/rest/user/login", OWNER, "POST", sqli)
        deadline = time.time() + 20
        while True:
            rows = self.decisions(before + 8)[before:]
            by_ip: dict = {}
            for r in rows:
                by_ip.setdefault(r["ip"], []).append(r)
            if len(by_ip.get(OWNER, [])) >= 2 or time.time() > deadline:
                break
            time.sleep(0.2)

        self.assertNotIn("1.1.1.1", by_ip)
        self.assertEqual(by_ip["2.2.2.2"][-1]["decision"], "ignore")
        self.assertEqual([r["decision"] for r in by_ip["3.3.3.3"]], ["replay", "block"])
        self.assertEqual(by_ip["3.3.3.3"][-1]["replay_verdict"], "PROVEN")
        self.assertIn("loginAdminChallenge", by_ip["3.3.3.3"][-1]["evidence"])
        self.assertEqual([r["decision"] for r in by_ip["4.4.4.4"]], ["tarpit", "block"])
        self.assertIn("fake .env", by_ip["4.4.4.4"][-1]["line"])
        self.assertEqual(call(self.door + "/", "4.4.4.4")[0], 403)
        self.assertEqual(by_ip["5.5.5.5"][-1]["decision"], "watch")
        self.assertIn("never took the bait", by_ip["5.5.5.5"][-1]["line"])
        self.assertEqual(call(self.door + "/", "5.5.5.5")[0], 200)
        self.assertEqual(by_ip[OWNER][-1]["replay_verdict"], "PROVEN")

        self.assertEqual(call(self.door + "/", "3.3.3.3")[0], 403)
        self.assertEqual(call(self.door + "/", OWNER)[0], 200)

    def test_proven_login_gets_verified_pull_request(self):
        call(self.door + "/rest/user/login", "7.7.7.7", "POST", {"email": "' or 1=1-- x7", "password": "y"}, ua="sqlmap/1.8")
        deadline = time.time() + 40
        while time.time() < deadline:
            rows = [r for r in self.decisions(1, fixes=True) if r["decision"] == "fix" and "routes/login.ts" in r["evidence"]]
            if any(r["replay_verdict"] == "PR_OPENED" for r in rows):
                break
            time.sleep(0.3)
        self.assertTrue(any(r["replay_verdict"] == "PR_OPENED" for r in rows), rows)
        with urllib.request.urlopen(f"http://127.0.0.1:{self.p['github']}/__calls") as r:
            calls = json.loads(r.read())
        puts = [c for c in calls if c["method"] == "PUT" and c["path"].endswith("/contents/routes/login.ts")]
        self.assertEqual(len(puts), 1)
        self.assertIn("replacements", puts[0]["body"]["text"])
        self.assertTrue(puts[0]["body"]["branch"].startswith("bouncer/fix-routes-login-ts"))
        prs = [c for c in calls if c["path"].endswith("/pulls")]
        self.assertTrue(any("Attack after the patch: **NOT_REPRODUCED**" in c["body"]["body"] for c in prs))
        pr_text = next(c["body"]["body"] for c in prs)
        self.assertIn("| same trick, other comment |", pr_text)
        self.assertIn("| target admin by email |", pr_text)
        self.assertEqual(pr_text.count("| worked | blocked |"), 2)
        self.assertNotIn("other endpoint", pr_text)
        self.assertIn("// VULN", (self.app / "routes" / "login.ts").read_text())
        self.assertEqual((self.app / "build" / "login.mode").read_text(), "vuln")

        call(self.door + "/rest/user/login", "8.8.4.4", "POST", {"email": "' or 1=1-- again", "password": "y"}, ua="sqlmap/1.8")
        deadline = time.time() + 40
        rows = []
        while time.time() < deadline and not any(r["replay_verdict"] == "PR_EXISTS" for r in rows):
            time.sleep(0.3)
            rows = [r for r in self.decisions(1, fixes=True) if r["ip"] == "8.8.4.4" and r["decision"] == "fix"]
        self.assertTrue(any(r["replay_verdict"] == "PR_EXISTS" and "pull/1" in r["evidence"] for r in rows), rows)
        with urllib.request.urlopen(f"http://127.0.0.1:{self.p['github']}/__calls") as r:
            self.assertEqual(sum(1 for c in json.loads(r.read()) if c["method"] == "PUT"), 1)

    def test_owner_can_ask_to_be_treated_as_a_stranger(self):
        stranger = {"X-Bouncer-Stranger": "1"}
        prior = sum(1 for r in self.decisions(0) if r["ip"] == "owner-as-stranger" and r["decision"] == "block")
        call(self.door + "/rest/user/login", OWNER, "POST", {"email": "' or 1=1-- demo", "password": "x"}, ua="sqlmap/1.8", extra=stranger)
        deadline = time.time() + 20
        rows = []
        while time.time() < deadline and sum(1 for r in rows if r["decision"] == "block") <= prior:
            time.sleep(0.2)
            rows = [r for r in self.decisions(0) if r["ip"] == "owner-as-stranger"]
        self.assertEqual(rows[-1]["decision"], "block")
        self.assertEqual(call(self.door + "/", OWNER, extra=stranger)[0], 403)
        self.assertEqual(call(self.door + "/", OWNER)[0], 200)
        self.assertEqual(call(self.door + "/", "1.2.3.5", extra=stranger)[0], 200)
        req = urllib.request.Request(self.door + "/_bouncer/blocklist/owner-as-stranger", method="DELETE", headers={"Authorization": "Bearer door-secret"})
        urllib.request.urlopen(req).close()
        self.assertEqual(call(self.door + "/", OWNER, extra=stranger)[0], 200)

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
        with urllib.request.urlopen(agent + "/") as r:
            self.assertIn(b"password", r.read())
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(agent + "/api/state")
        self.assertEqual(ctx.exception.code, 401)
        req = urllib.request.Request(agent + "/events", data=b'{"events":[]}', method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)

    def test_dashboard_can_view_and_unblock_ips(self):
        agent = f"http://127.0.0.1:{self.p['agent']}"
        stranger = {"X-Bouncer-Stranger": "1"}
        call(self.door + "/rest/user/login", OWNER, "POST", {"email": "' or 1=1-- dash-unblock", "password": "x"}, ua="sqlmap/1.8", extra=stranger)
        deadline = time.time() + 20
        while time.time() < deadline and call(self.door + "/", OWNER, extra=stranger)[0] != 403:
            time.sleep(0.2)
        self.assertEqual(call(self.door + "/", OWNER, extra=stranger)[0], 403)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        login_req = urllib.request.Request(agent + "/login", data=b"passphrase=let+me+in", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            opener.open(login_req)
            self.fail("expected 303 redirect on login")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 303)
            cookie = e.headers.get("Set-Cookie", "").split(";", 1)[0]
        self.assertTrue(cookie.startswith("bouncer="))

        state_req = urllib.request.Request(agent + "/api/state", headers={"Cookie": cookie})
        with urllib.request.urlopen(state_req) as r:
            state = json.loads(r.read())
        self.assertTrue(any(x["ip"] == "owner-as-stranger" and x["kind"] == "block" for x in state["lists"]))

        bad_ctype = urllib.request.Request(agent + "/api/unblock", data=b"ip=owner-as-stranger", method="POST", headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(bad_ctype)
        self.assertEqual(ctx.exception.code, 415)

        disguised = urllib.request.Request(agent + "/api/unblock", data=b'{"ip":"owner-as-stranger"}', method="POST", headers={"Cookie": cookie, "Content-Type": "text/plain; x=application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(disguised)
        self.assertEqual(ctx.exception.code, 415)

        foreign = urllib.request.Request(agent + "/api/unblock", data=b'{"ip":"owner-as-stranger"}', method="POST", headers={"Cookie": cookie, "Content-Type": "application/json", "Sec-Fetch-Site": "same-site"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(foreign)
        self.assertEqual(ctx.exception.code, 403)

        unblock_req = urllib.request.Request(agent + "/api/unblock", data=json.dumps({"ip": "owner-as-stranger"}).encode(), method="POST", headers={"Cookie": cookie, "Content-Type": "application/json"})
        with urllib.request.urlopen(unblock_req) as r:
            self.assertTrue(json.loads(r.read())["ok"])
        self.assertEqual(call(self.door + "/", OWNER, extra=stranger)[0], 200)

    def test_dashboard_lists_and_removes_shields(self):
        agent = f"http://127.0.0.1:{self.p['agent']}"
        route = "GET /shield-test"
        admin = {"Authorization": "Bearer door-secret", "Content-Type": "application/json"}
        put = urllib.request.Request(self.door + "/_bouncer/shield", data=json.dumps({route: {"until": time.time() + 600, "reason": "test"}}).encode(), method="PUT", headers=admin)
        urllib.request.urlopen(put).read()
        attack = "/shield-test?q=" + urllib.parse.quote("../../etc/passwd")
        self.assertEqual(call(self.door + attack, "4.3.2.1")[0], 403)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        login_req = urllib.request.Request(agent + "/login", data=b"passphrase=let+me+in", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.build_opener(NoRedirect).open(login_req)
        cookie = ctx.exception.headers.get("Set-Cookie", "").split(";", 1)[0]
        with urllib.request.urlopen(urllib.request.Request(agent + "/api/state", headers={"Cookie": cookie})) as r:
            state = json.loads(r.read())
        self.assertEqual([x["route"] for x in state["shields"]], [route])

        bad = urllib.request.Request(agent + "/api/unshield", data=json.dumps({"route": "GET /x\r\nHost: y"}).encode(), method="POST", headers={"Cookie": cookie, "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(bad)
        self.assertEqual(ctx.exception.code, 400)
        anonymous = urllib.request.Request(agent + "/api/unshield", data=json.dumps({"route": route}).encode(), method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(anonymous)
        self.assertEqual(ctx.exception.code, 401)

        remove = urllib.request.Request(agent + "/api/unshield", data=json.dumps({"route": route}).encode(), method="POST", headers={"Cookie": cookie, "Content-Type": "application/json"})
        with urllib.request.urlopen(remove) as r:
            self.assertTrue(json.loads(r.read())["ok"])
        with urllib.request.urlopen(urllib.request.Request(agent + "/api/state", headers={"Cookie": cookie})) as r:
            self.assertEqual(json.loads(r.read())["shields"], [])
        self.assertNotEqual(call(self.door + attack, "4.3.2.1")[0], 403)

    def test_door_rejects_bad_length_and_decodes_chunked(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.p["door"], timeout=5)
        conn.putrequest("POST", "/rest/user/login")
        conn.putheader("Content-Length", "not-a-number")
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", self.p["door"], timeout=5)
        conn.putrequest("POST", "/rest/user/login")
        conn.putheader("Content-Length", str(5 * 1024 * 1024))
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

        call(self.door + "/.env", "9.8.7.6")
        payload = json.dumps({"email": "admin@juice-sh.op", "password": "CANARY-honey-77"}).encode()
        chunked = f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
        conn = http.client.HTTPConnection("127.0.0.1", self.p["door"], timeout=5)
        conn.putrequest("POST", "/rest/user/login")
        conn.putheader("Sprite-Client-Ip", "9.8.7.6")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        conn.send(chunked)
        self.assertEqual(conn.getresponse().status, 401)
        conn.close()

        deadline = time.time() + 15
        while time.time() < deadline and call(self.door + "/", "9.8.7.6")[0] != 403:
            time.sleep(0.2)
        self.assertEqual(call(self.door + "/", "9.8.7.6")[0], 403)

    def test_repeat_of_proven_exploit_is_blocked_again_without_replay(self):
        attack = {"email": "' or 1=1-- repeat", "password": "x"}
        call(self.door + "/rest/user/login", "7.7.7.8", "POST", attack, ua="sqlmap/1.8")
        deadline = time.time() + 20
        while time.time() < deadline and call(self.door + "/", "7.7.7.8")[0] != 403:
            time.sleep(0.2)
        req = urllib.request.Request(self.door + "/_bouncer/blocklist/7.7.7.8", method="DELETE", headers={"Authorization": "Bearer door-secret"})
        urllib.request.urlopen(req).close()
        self.assertEqual(call(self.door + "/", "7.7.7.8")[0], 200)
        call(self.door + "/rest/user/login", "7.7.7.8", "POST", attack, ua="sqlmap/1.8")
        deadline = time.time() + 10
        while time.time() < deadline and call(self.door + "/", "7.7.7.8")[0] != 403:
            time.sleep(0.2)
        self.assertEqual(call(self.door + "/", "7.7.7.8")[0], 403)
        rows = [r for r in self.decisions(0) if r["ip"] == "7.7.7.8"]
        self.assertEqual([r["decision"] for r in rows], ["replay", "block", "block"])
        self.assertIn("already worked", rows[-1]["line"])

    def test_cross_site_bait_does_not_slow_or_block_a_browser(self):
        site = {"Sec-Fetch-Site": "cross-site"}
        self.assertEqual(call(self.door + "/.env", "8.8.4.5", extra=site)[0], 200)
        call(self.door + "/rest/user/login", "8.8.4.5", "POST", {"email": "a@b.c", "password": "CANARY-honey-77"}, extra=site)
        rows = []
        deadline = time.time() + 10
        while time.time() < deadline and len(rows) < 2:
            time.sleep(0.2)
            rows = [r for r in self.decisions(0) if r["ip"] == "8.8.4.5"]
        self.assertEqual([r["decision"] for r in rows], ["watch", "watch"])
        started = time.time()
        self.assertEqual(call(self.door + "/", "8.8.4.5")[0], 200)
        self.assertLess(time.time() - started, 0.15)

    def test_runner_refusal_does_not_parse_body_as_next_request(self):
        smuggled = b"GET /health HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer runner-secret\r\n\r\n"
        head = b"POST /reset HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(smuggled)
        with socket.create_connection(("127.0.0.1", self.p["runner"]), timeout=5) as s:
            s.sendall(head + smuggled)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.assertIn(b"404 Not Found", data)
        self.assertNotIn(b"200 OK", data)
        self.assertNotIn(b"target_ready", data)


class StubDoor:
    enabled = True

    def __init__(self):
        self.unblocked = []

    def unblock(self, ip):
        self.unblocked.append(ip)
        return True

    def snapshot(self, timeout=3):
        return {"block": {}, "tarpit": {}, "shield": {}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Dashboard(unittest.TestCase):
    def setUp(self):
        import threading

        from agent.agent import Brain
        from agent.config import Config
        from agent.web import AgentServer, make_handler

        self.tmp = tempfile.TemporaryDirectory()
        self.brain = Brain(Config({"AGENT_DATA_DIR": self.tmp.name, "AGENT_DASH_SHA256": sha("let me in")}))
        self.brain.door = StubDoor()
        self.handler = make_handler(self.brain)
        self.server = AgentServer(("127.0.0.1", 0), self.handler, max_threads=4)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.brain.inbox.wait_idle(5)
        self.tmp.cleanup()

    def send(self, path, method="GET", data=None, headers=None):
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def login(self, passphrase="let me in", ip="203.0.113.5"):
        return self.send("/login", "POST", urllib.parse.urlencode({"passphrase": passphrase}).encode(), {"Content-Type": "application/x-www-form-urlencoded", "Sprite-Client-Ip": ip})

    def cookie(self, ip="203.0.113.5"):
        status, headers, _ = self.login(ip=ip)
        self.assertEqual(status, 303)
        return headers["Set-Cookie"].split(";", 1)[0]

    def unblock(self, cookie, ip, client="203.0.113.5"):
        return self.send("/api/unblock", "POST", json.dumps({"ip": ip}).encode(), {"Cookie": cookie, "Content-Type": "application/json", "Sprite-Client-Ip": client})

    def test_sessions_are_random_and_logout_ends_them(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Max-Age=604800"):
            self.assertIn(flag, headers["Set-Cookie"])
        first, second = self.cookie(), self.cookie()
        self.assertNotEqual(first, second)
        self.assertGreater(len(first), len("bouncer=") + 30)
        self.assertEqual(self.send("/api/state", headers={"Cookie": first})[0], 200)
        static = "bouncer=" + __import__("hmac").new(sha("let me in").encode(), b"bouncer-dashboard", hashlib.sha256).hexdigest()
        self.assertEqual(self.send("/api/state", headers={"Cookie": static})[0], 401)
        self.assertEqual(self.send("/logout", "POST", b"{}", {"Cookie": first, "Sec-Fetch-Site": "cross-site"})[0], 403)
        status, headers, _ = self.send("/logout", "POST", b"{}", {"Cookie": first, "Content-Type": "application/json"})
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.send("/api/state", headers={"Cookie": first})[0], 401)
        self.assertEqual(self.send("/api/state", headers={"Cookie": second})[0], 200)

    def test_sessions_expire(self):
        cookie = self.cookie()
        token = cookie.split("=", 1)[1]
        self.handler.session_store.tokens[token] = time.time() - 1
        self.assertEqual(self.send("/api/state", headers={"Cookie": cookie})[0], 401)

    def test_failed_logins_are_throttled_per_ip(self):
        from unittest import mock

        with mock.patch("agent.web.time.sleep"):
            for _ in range(5):
                self.assertEqual(self.login("nope")[0], 401)
            status, headers, _ = self.login("nope")
            self.assertEqual(status, 429)
            self.assertGreater(int(headers["Retry-After"]), 500)
            self.assertEqual(self.login()[0], 429)
            self.assertEqual(self.login(ip="198.51.100.7")[0], 303)

    def test_parallel_logins_share_a_small_number_of_slots(self):
        from unittest import mock

        slots = self.handler.logins.slots
        self.assertTrue(slots.acquire(blocking=False))
        self.assertTrue(slots.acquire(blocking=False))
        try:
            self.assertFalse(slots.acquire(blocking=False))
            with mock.patch("agent.web.LOGIN_WAIT_SECONDS", 0.1):
                self.assertEqual(self.login("nope")[0], 429)
        finally:
            slots.release()
            slots.release()
        self.assertEqual(self.login()[0], 303)

    def test_pages_carry_security_headers_and_a_matching_nonce(self):
        import re

        cookie = self.cookie()
        for path, headers in (("/", {}), ("/", {"Cookie": cookie}), ("/api/state", {"Cookie": cookie}), ("/nope", {}), ("/healthz", {})):
            status, got, body = self.send(path, headers=headers)
            self.assertEqual(got["X-Frame-Options"], "DENY", path)
            self.assertEqual(got["X-Content-Type-Options"], "nosniff", path)
            self.assertEqual(got["Referrer-Policy"], "no-referrer", path)
            self.assertIn("frame-ancestors 'none'", got["Content-Security-Policy"], path)
        _, got, body = self.send("/", headers={"Cookie": cookie})
        csp = got["Content-Security-Policy"]
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        self.assertNotIn("unsafe-inline", re.search(r"script-src[^;]*", csp).group(0))
        self.assertIn(f'<script nonce="{nonce}">'.encode(), body)
        self.assertIn(f'<style nonce="{nonce}">'.encode(), body)
        self.assertNotIn(b"<script>", body)
        _, again, _ = self.send("/", headers={"Cookie": cookie})
        self.assertNotEqual(again["Content-Security-Policy"], csp)
        _, login_headers, login_body = self.send("/")
        login_nonce = re.search(r"'nonce-([^']+)'", login_headers["Content-Security-Policy"]).group(1)
        self.assertIn(f'<style nonce="{login_nonce}">'.encode(), login_body)

    def test_head_matches_get_without_a_body(self):
        cookie = self.cookie()
        for path, headers in (("/healthz", {}), ("/", {}), ("/api/state", {"Cookie": cookie}), ("/stream", {"Cookie": cookie})):
            status, got, body = self.send(path, "HEAD", headers=headers)
            self.assertEqual(status, 200, path)
            self.assertEqual(body, b"", path)
            self.assertIn("Content-Security-Policy", got)
        get_status, get_headers, get_body = self.send("/healthz")
        _, head_headers, _ = self.send("/healthz", "HEAD")
        self.assertEqual(head_headers["Content-Length"], str(len(get_body)))
        self.assertEqual(self.send("/api/state", "HEAD")[0], 401)

    def test_unblock_accepts_ipv4_ipv6_and_ipv6_networks_only(self):
        cookie = self.cookie()
        for given, key in (("1.2.3.4", "1.2.3.4"), ("2001:db8:1:2::/64", "2001:db8:1:2::/64"), ("2001:db8:1:2::5", "2001:db8:1:2::/64"), ("owner-as-stranger", "owner-as-stranger")):
            status, _, body = self.unblock(cookie, given)
            self.assertEqual(status, 200, given)
            self.assertEqual(json.loads(body)["ip"], key)
        for bad in ("10.0.0.0/8", "2001:db8::/48", "2001:db8:1:2::5/64", "1.2.3.4 ", "evil", "../x"):
            self.assertEqual(self.unblock(cookie, bad)[0], 400, bad)
        status, _, body = self.unblock(cookie, "self", client="2001:db8:9:9::42")
        self.assertEqual(json.loads(body)["ip"], "2001:db8:9:9::/64")
        self.assertEqual(self.brain.door.unblocked, ["1.2.3.4", "2001:db8:1:2::/64", "2001:db8:1:2::/64", "owner-as-stranger", "2001:db8:9:9::/64"])

    def test_server_is_bounded_and_idle_connections_time_out(self):
        from agent.web import IDLE_SECONDS

        self.assertEqual(self.handler.timeout, IDLE_SECONDS)
        idle = [socket.create_connection(self.server.server_address) for _ in range(4)]
        try:
            time.sleep(0.2)
            with socket.create_connection(self.server.server_address, timeout=5) as extra:
                extra.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                self.assertIn(b"503", extra.recv(4096).split(b"\r\n", 1)[0])
        finally:
            for s in idle:
                s.close()


if __name__ == "__main__":
    unittest.main()
