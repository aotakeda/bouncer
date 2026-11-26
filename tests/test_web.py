from __future__ import annotations

import hashlib
import http.client
import json
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock

from agent import web
from agent.agent import Brain
from agent.config import Config
from agent.views import Views
from agent.web import SESSIONS_FILE, AgentServer, Sessions, header_ip, make_handler, peer_trusted, trust_client_ip_header, trusted_proxies

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
    def __init__(self, brain: Brain, env: dict | None = None, **limits):
        with mock.patch.dict("os.environ", env or {}):
            self.handler = make_handler(brain)
        self.server = AgentServer(("127.0.0.1", 0), self.handler, **{"max_threads": 8, **limits})
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

    def start(self, brain=None, env=None, **limits) -> Server:
        server = Server(brain or self.brain, env, **limits)
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
        server = self.start(env={"BOUNCER_TRUSTED_PROXIES": "127.0.0.1"})
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


class TrustedProxyTests(WebCase):
    def test_trusted_proxies_parse_from_either_variable(self):
        self.assertIsNone(trusted_proxies({}))
        self.assertEqual([str(n) for n in trusted_proxies({"TRUSTED_PROXIES": "10.0.0.0/8"})], ["10.0.0.0/8"])
        self.assertEqual([str(n) for n in trusted_proxies({"TRUSTED_PROXIES": "10.0.0.0/8", "BOUNCER_TRUSTED_PROXIES": "::1"})], ["::1/128"])
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(trusted_proxies({"BOUNCER_TRUSTED_PROXIES": "junk"}), ())
        self.assertIn("ignored a trusted proxy", err.getvalue())
        nets = trusted_proxies({"TRUSTED_PROXIES": "10.0.0.0/8"})
        self.assertTrue(peer_trusted("::ffff:10.0.0.9", nets))
        self.assertFalse(peer_trusted("192.0.2.1", nets))
        self.assertFalse(peer_trusted("192.0.2.1", ()))
        self.assertTrue(peer_trusted("192.0.2.1", None))

    def test_header_from_an_untrusted_peer_is_ignored_and_logged(self):
        server = self.start(env={"BOUNCER_TRUSTED_PROXIES": "10.0.0.0/8"})
        with redirect_stderr(StringIO()) as err:
            cookie = server.send("/login", "POST", urllib.parse.urlencode({"passphrase": PASS}).encode(), {"Content-Type": "application/x-www-form-urlencoded"})[1]["Set-Cookie"].split(";", 1)[0]
            self.assertEqual(server.whoami(cookie, "203.0.113.9"), (200, "127.0.0.1"))
        line = json.loads(err.getvalue().strip().splitlines()[-1])
        self.assertEqual((line["warning"], line["peer"], line["value"]), ("client ip header from an untrusted peer", "127.0.0.1", "203.0.113.9"))

    def test_header_from_a_trusted_peer_is_used(self):
        server = self.start(env={"BOUNCER_TRUSTED_PROXIES": "127.0.0.0/8"})
        cookie = server.cookie()
        self.assertEqual(server.whoami(cookie, "203.0.113.9"), (200, "203.0.113.9"))

    def test_invalid_header_is_logged(self):
        server = self.start()
        cookie = server.cookie()
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(server.whoami(cookie, "evil"), (200, "127.0.0.1"))
        self.assertIn("invalid client ip header", err.getvalue())


class LoginBudgetTests(WebCase):
    def test_untrusted_peer_cannot_rotate_past_its_lock(self):
        server = self.start(env={"BOUNCER_TRUSTED_PROXIES": "10.0.0.0/8"})
        with mock.patch("agent.web.time.sleep"), redirect_stderr(StringIO()):
            for i in range(5):
                self.assertEqual(server.login("nope", ip=f"203.0.113.{i}")[0], 401)
            self.assertEqual(server.login(ip="203.0.113.200")[0], 429)

    def test_forged_address_cannot_lock_out_the_operator(self):
        server = self.start()
        with mock.patch("agent.web.time.sleep") as sleep:
            for _ in range(5):
                self.assertEqual(server.login("nope", ip=STRANGER)[0], 401)
            self.assertGreater(server.handler.logins.retry_after(STRANGER), 0)
            sleep.reset_mock()
            self.assertEqual(server.login("nope", ip=STRANGER)[0], 401)
            sleep.assert_called_once_with(web.LOGIN_SLOW_SECONDS)
            self.assertEqual(server.login(ip=STRANGER)[0], 303)

    def test_rotating_addresses_runs_into_the_global_budget(self):
        server = self.start()
        guard = server.handler.logins
        with mock.patch("agent.web.time.sleep") as sleep:
            for i in range(web.LOGIN_GLOBAL_FAILURES):
                self.assertEqual(server.login("nope", ip=f"203.0.113.{i}")[0], 401)
            self.assertTrue(guard.over_budget())
            sleep.reset_mock()
            self.assertEqual(server.login("nope", ip="198.51.100.1")[0], 401)
            sleep.assert_called_once_with(web.LOGIN_SLOW_SECONDS)
            self.assertTrue(guard.slow_slots.acquire(blocking=False))
            try:
                with mock.patch("agent.web.LOGIN_SLOW_WAIT_SECONDS", 0.1):
                    status, headers, _ = server.login("nope", ip="198.51.100.2")
                    self.assertEqual(status, 429)
                    self.assertEqual(headers["Retry-After"], str(web.LOGIN_SLOW_SECONDS))
            finally:
                guard.slow_slots.release()
            self.assertEqual(server.login(ip="198.51.100.3")[0], 303)

    def test_owner_failures_count_toward_the_budget_and_are_slowed_past_it(self):
        server = self.start()
        guard = server.handler.logins
        with mock.patch("agent.web.time.sleep") as sleep:
            for _ in range(web.LOGIN_GLOBAL_FAILURES):
                self.assertEqual(server.login("nope", ip=OWNER)[0], 401)
            self.assertTrue(guard.over_budget())
            sleep.reset_mock()
            self.assertEqual(server.login("nope", ip=OWNER)[0], 401)
            sleep.assert_called_once_with(web.LOGIN_SLOW_SECONDS)
            self.assertEqual(server.login(ip=OWNER)[0], 303)
        self.assertEqual(guard.retry_after(OWNER), 0)

    def test_budget_forgets_old_failures(self):
        guard = web.LoginGuard(window=0.2, global_failures=2)
        guard.failed("a")
        guard.failed("b")
        self.assertTrue(guard.over_budget())
        time.sleep(0.25)
        self.assertFalse(guard.over_budget())


class StreamLimitTests(WebCase):
    def open_stream(self, server, cookie):
        conn = http.client.HTTPConnection("127.0.0.1", server.server.server_address[1], timeout=5)
        conn.request("GET", "/stream", headers={"Cookie": cookie})
        resp = conn.getresponse()
        self.addCleanup(conn.close)
        return resp

    def test_extra_streams_are_refused_without_starving_intake(self):
        server = self.start(max_threads=2, max_streams=2)
        cookie = server.cookie()
        held = [self.open_stream(server, cookie) for _ in range(2)]
        self.assertEqual([r.status for r in held], [200, 200])
        refused = self.open_stream(server, cookie)
        self.assertEqual(refused.status, 503)
        self.assertEqual(refused.getheader("Retry-After"), str(web.STREAM_RETRY_SECONDS))
        self.assertEqual(refused.read(), web.TOO_MANY_STREAMS)
        for _ in range(3):
            self.assertEqual(server.send("/healthz")[0], 200)
            self.assertEqual(server.send("/events", "POST", b"{}", {"Authorization": "Bearer x"})[0], 404)

    def test_closed_stream_gives_its_slot_back(self):
        server = self.start(max_streams=1)
        cookie = server.cookie()
        with mock.patch.object(server.handler, "serve_stream", lambda self: self.reply(200, b"", "text/event-stream")):
            for _ in range(3):
                resp = self.open_stream(server, cookie)
                self.assertEqual(resp.status, 200)
                resp.read()


class RequestDeadlineTests(WebCase):
    def test_trickling_client_is_cut_off(self):
        server = self.start()
        with mock.patch("agent.web.REQUEST_SECONDS", 0.5):
            started = time.time()
            closed = False
            with socket.create_connection(("127.0.0.1", server.server.server_address[1]), timeout=5) as s:
                try:
                    for byte in b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Slow: " + b"a" * 100:
                        s.sendall(bytes([byte]))
                        time.sleep(0.05)
                except OSError:
                    closed = True
                if not closed:
                    try:
                        closed = s.recv(10) == b""
                    except OSError:
                        closed = True
            self.assertTrue(closed)
            self.assertLess(time.time() - started, 3)
            with socket.create_connection(("127.0.0.1", server.server.server_address[1]), timeout=5) as s:
                s.sendall(b"POST /events HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
                started = time.time()
                self.assertEqual(s.recv(10), b"")
                self.assertLess(time.time() - started, 2)
        self.assertEqual(server.send("/healthz")[0], 200)


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

    def token(self, cookie: str) -> str:
        return cookie.split("=", 1)[1]

    def test_sessions_survive_a_restart(self):
        first = self.start()
        cookie = first.cookie()
        self.assertEqual(first.send("/api/state", headers={"Cookie": cookie})[0], 200)
        first.close()
        self.servers.remove(first)
        second = self.start(self.make_brain())
        self.assertEqual(second.send("/api/state", headers={"Cookie": cookie})[0], 200)
        self.assertEqual(second.send("/api/state", headers={"Cookie": "bouncer=forged"})[0], 401)

    def test_sessions_survive_losing_the_data_dir(self):
        cookie = self.start().cookie()
        shutil.rmtree(self.tmp.name)
        Path(self.tmp.name).mkdir()
        again = self.start(self.make_brain())
        self.assertEqual(again.send("/api/state", headers={"Cookie": cookie})[0], 200)

    def test_cookie_keeps_its_flags(self):
        server = self.start()
        status, headers, _ = server.send("/login", "POST", urllib.parse.urlencode({"passphrase": PASS}).encode(), {"Content-Type": "application/x-www-form-urlencoded", "Host": "bouncer.example"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly;", "Secure;", "SameSite=Lax;", "Path=/;", f"Max-Age={web.SESSION_SECONDS}"):
            self.assertIn(flag, cookie)

    def test_token_carries_no_secret_and_nothing_is_stored_on_login(self):
        server = self.start()
        token = self.token(server.cookie())
        self.assertNotIn(sha(PASS), token)
        self.assertNotIn(PASS, token)
        self.assertFalse((Path(self.tmp.name) / SESSIONS_FILE).exists())

    def test_logout_ends_only_that_session_even_after_a_restart(self):
        server = self.start()
        cookie = server.cookie()
        other = server.cookie()
        server.send("/logout", "POST", b"{}", {"Cookie": cookie, "Content-Type": "application/json"})
        self.assertEqual(server.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(server.send("/api/state", headers={"Cookie": other})[0], 200)
        path = Path(self.tmp.name) / SESSIONS_FILE
        raw = path.read_text()
        self.assertNotIn(self.token(cookie), raw)
        self.assertNotIn(sha(PASS), raw)
        until = next(iter(self.stored()["revoked"].values()))
        self.assertAlmostEqual(until, time.time() + web.SESSION_SECONDS, delta=60)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        restarted = self.start(self.make_brain())
        self.assertEqual(restarted.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(restarted.send("/api/state", headers={"Cookie": other})[0], 200)

    def test_logout_without_a_valid_session_stores_nothing(self):
        server = self.start()
        cookie = server.cookie()
        for junk in ("", "bouncer=forged", "bouncer=v1.1.x.y"):
            server.send("/logout", "POST", b"{}", {"Cookie": junk, "Content-Type": "application/json"})
        self.assertEqual(server.send("/api/state", headers={"Cookie": cookie})[0], 200)
        self.assertFalse((Path(self.tmp.name) / SESSIONS_FILE).exists())

    def test_expired_future_and_tampered_tokens_are_refused(self):
        store = Sessions(key=sha(PASS))
        now = time.time()
        self.assertTrue(store.valid(store.new()))
        self.assertFalse(store.valid(store.new(now=now - web.SESSION_SECONDS - 1)))
        self.assertTrue(store.valid(store.new(now=now - web.SESSION_SECONDS + 60)))
        self.assertFalse(store.valid(store.new(now=now + web.SESSION_SKEW_SECONDS + 60)))
        good = store.new()
        version, issued, nonce, mac = good.split(".")
        flipped = mac[:-1] + ("1" if mac[-1] == "0" else "0")
        for bad in (f"{version}.{int(issued) + 1}.{nonce}.{mac}", f"{version}.{issued}.{nonce}x.{mac}", f"{version}.{issued}.{nonce}.{flipped}", f"v2.{issued}.{nonce}.{mac}", good + ".x", "", "a" * 300):
            self.assertFalse(store.valid(bad), bad)
        self.assertFalse(Sessions(key=sha("other")).valid(good))
        self.assertFalse(Sessions(key="").valid(good))

    def test_changing_the_passphrase_ends_sessions(self):
        cookie = self.start().cookie()
        changed = self.start(self.make_brain("a different passphrase"))
        self.assertEqual(changed.send("/api/state", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(changed.login()[0], 401)

    def test_revocations_from_junk_or_another_passphrase_are_ignored(self):
        path = Path(self.tmp.name) / SESSIONS_FILE
        other = Sessions(path=path, key=sha("other"))
        other.drop(other.new())
        self.assertEqual(Sessions(path=path, key=sha(PASS)).revoked, {})
        store = Sessions(path=path, key=sha(PASS))
        live = store.new()
        far = time.time() + 10 * web.SESSION_SECONDS
        for junk in ("not json", "[]", '{"key": "x", "revoked": {}}', '{"revoked": []}', json.dumps({"key": store.fingerprint(), "revoked": {"short": far, "y" * 64: far, "z" * 64: True}})):
            path.write_text(junk)
            again = Sessions(path=path, key=sha(PASS))
            self.assertEqual(again.revoked, {}, junk)
            self.assertTrue(again.valid(live))

    def test_revocation_list_is_capped(self):
        store = Sessions(limit=3, path=Path(self.tmp.name) / SESSIONS_FILE, key=sha(PASS))
        tokens = [store.new() for _ in range(5)]
        for token in tokens:
            store.drop(token)
        self.assertEqual(len(store.revoked), 3)
        self.assertEqual(len(self.stored()["revoked"]), 3)
        self.assertFalse(store.valid(tokens[-1]))


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
