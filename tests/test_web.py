from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

from agent import web
from agent.agent import Brain
from agent.config import Config
from agent.views import Views
from agent.web import SESSIONS_FILE, AgentServer, Sessions, header_ip, make_handler, trust_client_ip_header

ROOT = Path(__file__).resolve().parent.parent
PASS = "a test passphrase"
OWNER = "198.51.100.77"
STRANGER = "203.0.113.5"


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class StubDoor:
    enabled = True

    def __init__(self):
        self.unblocked = []
        self.unshielded = []

    def unblock(self, ip):
        self.unblocked.append(ip)
        return True

    def delete_shield(self, route):
        self.unshielded.append(route)
        return True

    def snapshot(self, timeout=3):
        return {"block": {}, "tarpit": {}, "shield": {}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Server:
    def __init__(self, brain: Brain, env: dict | None = None):
        with mock.patch.dict("os.environ", env or {}):
            self.handler = make_handler(brain)
        self.server = AgentServer(("127.0.0.1", 0), self.handler, max_threads=8)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def send(self, path, method="GET", data=None, headers=None):
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def login(self, passphrase=PASS, ip=STRANGER):
        return self.send("/login", "POST", urllib.parse.urlencode({"passphrase": passphrase}).encode(), {"Content-Type": "application/x-www-form-urlencoded", "Sprite-Client-Ip": ip})

    def cookie(self, ip=STRANGER):
        status, headers, _ = self.login(ip=ip)
        assert status == 303, status
        return headers["Set-Cookie"].split(";", 1)[0]

    def whoami(self, cookie, header=None):
        headers = {"Cookie": cookie, "Content-Type": "application/json"}
        if header is not None:
            headers["Sprite-Client-Ip"] = header
        status, _, body = self.send("/api/unblock", "POST", json.dumps({"ip": "self"}).encode(), headers)
        return status, json.loads(body)["ip"] if status == 200 else None


class WebCase(unittest.TestCase):
    passphrase = PASS

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.brain = self.make_brain()
        self.servers = []

    def make_brain(self, passphrase=None):
        brain = Brain(Config({"AGENT_DATA_DIR": self.tmp.name, "AGENT_DASH_SHA256": sha(passphrase or self.passphrase), "OWNER_IPS": OWNER}))
        brain.door = StubDoor()
        return brain

    def start(self, brain=None, env=None) -> Server:
        server = Server(brain or self.brain, env)
        self.servers.append(server)
        return server

    def tearDown(self):
        for server in self.servers:
            server.close()
        self.brain.inbox.wait_idle(5)
        self.tmp.cleanup()


class ClientIpTests(WebCase):
    def test_header_must_parse_as_an_ip(self):
        self.assertEqual(header_ip("203.0.113.9"), "203.0.113.9")
        self.assertEqual(header_ip(" 2001:db8::1 "), "2001:db8::1")
        for bad in (None, "", "evil", "203.0.113.9, 198.51.100.1", "203.0.113.9:80", "owner-as-stranger", "../x", "1.2.3.4/32"):
            self.assertIsNone(header_ip(bad), bad)

    def test_trust_switch_defaults_on(self):
        self.assertTrue(trust_client_ip_header({}))
        for on in ("1", "true", "yes", "on", ""):
            self.assertTrue(trust_client_ip_header({"BOUNCER_TRUST_CLIENT_IP_HEADER": on}), on)
        for off in ("0", "false", "No", " off "):
            self.assertFalse(trust_client_ip_header({"BOUNCER_TRUST_CLIENT_IP_HEADER": off}), off)

    def test_valid_header_is_used_and_bad_one_falls_back_to_the_socket_peer(self):
        server = self.start()
        cookie = server.cookie()
        self.assertEqual(server.whoami(cookie, "203.0.113.9"), (200, "203.0.113.9"))
        self.assertEqual(server.whoami(cookie, "2001:db8:1:2::5"), (200, "2001:db8:1:2::/64"))
        self.assertEqual(server.whoami(cookie, "owner-as-stranger"), (200, "127.0.0.1"))
        self.assertEqual(server.whoami(cookie, "203.0.113.9, 198.51.100.1"), (200, "127.0.0.1"))
        self.assertEqual(server.whoami(cookie), (200, "127.0.0.1"))

    def test_header_is_ignored_when_trust_is_off(self):
        server = self.start(env={"BOUNCER_TRUST_CLIENT_IP_HEADER": "0"})
        cookie = server.cookie()
        self.assertEqual(server.whoami(cookie, "203.0.113.9"), (200, "127.0.0.1"))

    def test_garbage_header_cannot_dodge_the_login_lockout(self):
        server = self.start()
        with mock.patch("agent.web.time.sleep"):
            for i in range(5):
                self.assertEqual(server.login("nope", ip=f"not-an-ip-{i}")[0], 401)
            self.assertEqual(server.login(ip="still-not-an-ip")[0], 429)


class LoginLockoutTests(WebCase):
    def test_owner_is_never_locked_out(self):
        server = self.start()
        with mock.patch("agent.web.time.sleep"):
            for _ in range(12):
                self.assertEqual(server.login("nope", ip=OWNER)[0], 401)
            self.assertEqual(server.login(ip=OWNER)[0], 303)
            self.assertEqual(server.handler.logins.retry_after(OWNER), 0)

    def test_strangers_are_still_locked_out(self):
        server = self.start()
        with mock.patch("agent.web.time.sleep"):
            for _ in range(5):
                self.assertEqual(server.login("nope")[0], 401)
            status, headers, _ = server.login()
            self.assertEqual(status, 429)
            self.assertGreater(int(headers["Retry-After"]), 500)
            self.assertEqual(server.login(ip=OWNER)[0], 303)

    def test_owner_has_a_slot_strangers_cannot_fill(self):
        server = self.start()
        slots = server.handler.logins.slots
        self.assertTrue(slots.acquire(blocking=False))
        self.assertTrue(slots.acquire(blocking=False))
        try:
            with mock.patch("agent.web.LOGIN_WAIT_SECONDS", 0.1):
                self.assertEqual(server.login("nope")[0], 429)
                self.assertEqual(server.login(ip=OWNER)[0], 303)
        finally:
            slots.release()
            slots.release()

    def test_owner_failures_are_still_slowed(self):
        server = self.start()
        with mock.patch("agent.web.time.sleep") as sleep:
            self.assertEqual(server.login("nope", ip=OWNER)[0], 401)
        sleep.assert_called_once_with(1)


class HeaderTests(WebCase):
    def test_every_response_carries_hsts(self):
        server = self.start()
        cookie = server.cookie()
        for method, path, headers in (("GET", "/", {}), ("GET", "/", {"Cookie": cookie}), ("GET", "/api/state", {"Cookie": cookie}), ("GET", "/healthz", {}), ("GET", "/nope", {}), ("HEAD", "/stream", {"Cookie": cookie})):
            _, got, _ = server.send(path, method, headers=headers)
            self.assertEqual(got.get("Strict-Transport-Security"), "max-age=31536000", path)
        _, got, _ = server.login()
        self.assertEqual(got.get("Strict-Transport-Security"), "max-age=31536000")


class SessionTests(WebCase):
    def stored(self) -> dict:
        return json.loads((Path(self.tmp.name) / SESSIONS_FILE).read_text())

    def test_sessions_survive_a_restart(self):
        first = self.start()
        cookie = first.cookie()
        self.assertEqual(first.send("/api/state", headers={"Cookie": cookie})[0], 200)
        first.close()
        self.servers.remove(first)
        second = self.start(self.make_brain())
        self.assertEqual(second.send("/api/state", headers={"Cookie": cookie})[0], 200)
        self.assertEqual(second.send("/api/state", headers={"Cookie": "bouncer=forged"})[0], 401)

    def test_only_token_hashes_are_stored(self):
        server = self.start()
        token = server.cookie().split("=", 1)[1]
        path = Path(self.tmp.name) / SESSIONS_FILE
        raw = path.read_text()
        self.assertNotIn(token, raw)
        self.assertNotIn(sha(PASS), raw)
        data = self.stored()
        self.assertEqual(len(data["sessions"]), 1)
        until = next(iter(data["sessions"].values()))
        self.assertAlmostEqual(until, time.time() + web.SESSION_SECONDS, delta=60)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_logout_removes_the_stored_session(self):
        server = self.start()
        cookie = server.cookie()
        other = server.cookie()
        self.assertEqual(len(self.stored()["sessions"]), 2)
        server.send("/logout", "POST", b"{}", {"Cookie": cookie, "Content-Type": "application/json"})
        self.assertEqual(len(self.stored()["sessions"]), 1)
        restarted = self.start(self.make_brain())
        self.assertEqual(restarted.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(restarted.send("/api/state", headers={"Cookie": other})[0], 200)

    def test_expired_and_tampered_sessions_are_dropped_on_load(self):
        path = Path(self.tmp.name) / SESSIONS_FILE
        store = Sessions(path=path, key=sha(PASS))
        live = store.new()
        dead = store.new()
        data = self.stored()
        data["sessions"][store.digest(dead)] = time.time() - 1
        data["sessions"]["x" * 64] = time.time() + 10 * web.SESSION_SECONDS
        data["sessions"]["short"] = time.time() + 60
        path.write_text(json.dumps(data))
        again = Sessions(path=path, key=sha(PASS))
        self.assertTrue(again.valid(live))
        self.assertFalse(again.valid(dead))
        self.assertEqual(list(self.stored()["sessions"]), [store.digest(live)])

    def test_session_expires_while_running(self):
        server = self.start()
        cookie = server.cookie()
        store = server.handler.session_store
        digest = store.digest(cookie.split("=", 1)[1])
        store.tokens[digest] = time.time() - 1
        self.assertEqual(server.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertNotIn(digest, self.stored()["sessions"])

    def test_changing_the_passphrase_ends_stored_sessions(self):
        cookie = self.start().cookie()
        changed = self.start(self.make_brain("a different passphrase"))
        self.assertEqual(changed.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(changed.login()[0], 401)

    def test_unreadable_file_starts_empty(self):
        path = Path(self.tmp.name) / SESSIONS_FILE
        for junk in ("not json", "[]", '{"key": "x", "sessions": {}}', '{"sessions": []}'):
            path.write_text(junk)
            self.assertEqual(Sessions(path=path, key=sha(PASS)).tokens, {}, junk)

    def test_session_limit_still_applies(self):
        store = Sessions(limit=3, path=Path(self.tmp.name) / SESSIONS_FILE, key=sha(PASS))
        tokens = [store.new() for _ in range(5)]
        self.assertEqual(len(store.tokens), 3)
        self.assertFalse(store.valid(tokens[0]))
        self.assertTrue(store.valid(tokens[-1]))
        self.assertEqual(len(self.stored()["sessions"]), 3)


class SignalStepTests(unittest.TestCase):
    def steps(self, **extra) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            views = Views(Config({"AGENT_DATA_DIR": tmp}), Brain(Config({"AGENT_DATA_DIR": tmp})).store)
            item = {"ts": 1.0, "ip": "203.0.113.9", "event": {"method": "GET", "path": "/x", "ts": 1.0}, "replay": {"why": "leak"}, "jev": {"ok": True, "malicious": 0.97}, **extra}
            return views.proven_signal("proven:GET /x", [item], False)["steps"]

    def test_signal_activity_names_jev(self):
        steps = self.steps()
        self.assertEqual(steps[0]["label"], "Flagged by Jev System One")
        self.assertEqual(steps[0]["note"], "97% attack")

    def test_foreign_client_that_was_not_blocked(self):
        step = self.steps(blocked=False, foreign=True)[2]
        self.assertEqual((step["label"], step["state"]), ("Client not blocked", "todo"))
        self.assertIn("another site's page", step["note"])

    def test_foreign_client_blocked_after_repeated_attacks(self):
        step = self.steps(blocked=True, foreign_strikes=3)[2]
        self.assertEqual((step["label"], step["state"]), ("Client blocked for 5 min", "done"))
        self.assertEqual(step["note"], "after 3 attacks sent from other sites' pages")

    def test_plain_block_has_no_foreign_note(self):
        for extra in ({}, {"foreign_strikes": 0}, {"foreign_strikes": True}, {"foreign_strikes": "3"}):
            step = self.steps(blocked=True, **extra)[2]
            self.assertEqual(step["note"], "", extra)


class DashboardPageTests(unittest.TestCase):
    page = (ROOT / "agent" / "dashboard.html").read_text()

    def script(self) -> str:
        return re.search(r"<script>(.*)</script>", self.page, re.S).group(1)

    def test_model_is_called_jev_not_classifier(self):
        self.assertNotIn("classifier", self.page.lower())
        self.assertIn("Jev System One", self.page)
        self.assertIn("TypeSafe", self.page)

    def test_sign_out_is_a_visible_button(self):
        self.assertRegex(self.page, r'<button type="button" class="signout" id="signOut"[^>]*>.*Sign out</span></button>')
        self.assertIn("if(t.id==='signOut')return signOut();", self.page)

    def test_unblock_and_unshield_ask_first(self):
        js = self.script()
        for name in ("unblock", "unshield"):
            body = re.search(rf"async function {name}\(.*?\n}}\n", js, re.S).group(0)
            self.assertIn("if(!await askConfirm(", body.splitlines()[1], name)
        self.assertIn('role="alertdialog"', self.page)
        self.assertIn("$('cTitle').textContent=title", js)
        self.assertIn("$('cBody').textContent=body", js)

    def test_no_inline_handlers_or_unnonced_scripts(self):
        self.assertIsNone(re.search(r"<[a-z][^>]*\son[a-z]+\s*=", self.page, re.I))
        self.assertNotIn("javascript:", self.page.replace("javascript:|", ""))
        self.assertEqual(self.page.count("<script"), 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_shielded_requests_are_not_shown_as_allowed(self):
        js = self.script()
        helper = re.search(r"const wasKind=.*?;\nconst wasShielded=.*?;\n", js, re.S).group(0)
        outcome = re.search(r"function outcomeOf\(e\)\{.*?\n\}\n", js, re.S).group(0)
        cases = [
            {"kind": "shielded", "decision": "watch"},
            {"kind": "shielded", "decision": "ignore"},
            {"kind": "shielded", "decision": "replay"},
            {"kind": "shielded", "decision": "block"},
            {"kind": "request", "decision": "watch", "steps": [{"kind": "shielded"}, {"kind": "request"}]},
            {"kind": "request", "decision": "watch"},
            {"kind": "shielded", "decision": "would_block"},
            {"kind": "tarpitted", "decision": "replay"},
            {"kind": "tarpitted", "decision": "block", "verdict": "PROVEN"},
            {"kind": "tarpitted", "decision": "watch"},
            {"kind": "tarpitted", "decision": "watch", "verdict": "PROVEN"},
            {"kind": "request", "decision": "ignore", "steps": [{"kind": "tarpitted"}]},
        ]
        code = helper + outcome + f"process.stdout.write(JSON.stringify({json.dumps(cases)}.map(outcomeOf)))"
        got = json.loads(subprocess.run(["node", "-e", code], capture_output=True, text=True, check=True, timeout=20).stdout)
        self.assertEqual(got[0], ["blocked", "Refused by shield", "shielded"])
        self.assertEqual(got[1], ["blocked", "Refused by shield", "shielded"])
        self.assertEqual(got[2], ["blocked", "Refused by shield", "shielded"])
        self.assertEqual(got[3], ["blocked", "Blocked"])
        self.assertEqual(got[4], ["blocked", "Refused by shield", "shielded"])
        self.assertEqual(got[5], ["allowed", "Allowed"])
        self.assertEqual(got[6], ["owner", "Would block (you)"])
        self.assertEqual(got[7], ["testing", "Testing"])
        self.assertEqual(got[8], ["blocked", "Blocked"])
        self.assertEqual(got[9], ["slowed", "Slowed"])
        self.assertEqual(got[10], ["slowed", "Slowed, proven"])
        self.assertEqual(got[11], ["slowed", "Slowed"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_esc_neutralises_markup(self):
        js = self.script()
        esc = re.search(r"const esc=.*?;\n", js).group(0)
        evil = "<img src=x onerror=alert(1)>\"'&"
        code = esc + f"process.stdout.write(esc({json.dumps(evil)}))"
        out = subprocess.run(["node", "-e", code], capture_output=True, text=True, check=True, timeout=20).stdout
        self.assertEqual(out, "&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;")


if __name__ == "__main__":
    unittest.main()
