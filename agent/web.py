from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import queue
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from .net import bare_path, ip_key

if TYPE_CHECKING:
    from .agent import Brain

TEXT = "text/plain"
HTML = "text/html; charset=utf-8"
JSON = "application/json"
COOKIE_NAME = "bouncer"
MAX_BODY = 4 * 1024 * 1024
DASHBOARD = Path(__file__).with_name("dashboard.html").read_text()
LOGIN_TEMPLATE = Template(Path(__file__).with_name("login.html").read_text())
WARN_SVG = '<svg width="16" height="16" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true" style="flex-shrink:0"><path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm-8,56a8,8,0,0,1,16,0v56a8,8,0,0,1-16,0Zm8,104a12,12,0,1,1,12-12A12,12,0,0,1,128,184Z"/></svg>'
LOGIN_ERROR = f'<p class="err" role="alert">{WARN_SVG}<span>Wrong passphrase. Try again.</span></p>'
LOGIN_ERROR_ATTR = ' aria-invalid="true" class="bad"'
FOREIGN_FETCH_SITES = ("cross-site", "same-site")
STRANGER = "owner-as-stranger"
SESSION_SECONDS = 7 * 24 * 3600
MAX_SESSIONS = 200
LOGIN_FAILURES = 5
LOGIN_WINDOW = 600
LOGIN_LOCK_SECONDS = 600
LOGIN_SLOTS = 2
LOGIN_WAIT_SECONDS = 5
MAX_TRACKED_LOGIN_IPS = 10000
IDLE_SECONDS = 30
MAX_THREADS = 64
PAGE_CSP = "default-src 'self'; script-src 'nonce-{n}'; style-src 'self' 'nonce-{n}' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
DATA_CSP = "default-src 'none'; frame-ancestors 'none'"
SECURITY_HEADERS = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
TOO_MANY_LOGINS = b"Too many wrong passphrases. Try again later."


class Rejected(Exception):
    def __init__(self, status: int, message: bytes):
        super().__init__(message)
        self.status = status
        self.message = message


def login_html(error: bool = False) -> str:
    if error:
        return LOGIN_TEMPLATE.substitute(err_attr=LOGIN_ERROR_ATTR, err_block=LOGIN_ERROR)
    return LOGIN_TEMPLATE.substitute(err_attr="", err_block="")


LOGIN = login_html(False)


def sha_matches(secret: str, expected_sha: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), expected_sha)


def with_nonce(html: str, nonce: str) -> str:
    return html.replace("<style>", f'<style nonce="{nonce}">').replace("<script>", f'<script nonce="{nonce}">')


def unblock_key(value: str) -> str | None:
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=True)
            return str(net) if net.version == 6 and net.prefixlen == 64 else None
        return ip_key(str(ipaddress.ip_address(value)))
    except ValueError:
        return None


class Sessions:
    def __init__(self, seconds: int = SESSION_SECONDS, limit: int = MAX_SESSIONS):
        self.seconds = seconds
        self.limit = limit
        self.tokens: dict = {}
        self.lock = threading.Lock()

    def new(self) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.tokens = {t: until for t, until in self.tokens.items() if until > now}
            while len(self.tokens) >= self.limit:
                self.tokens.pop(min(self.tokens, key=self.tokens.get))
            self.tokens[token] = now + self.seconds
        return token

    def valid(self, token: str) -> bool:
        if not token:
            return False
        now = time.time()
        with self.lock:
            found = next((until for t, until in self.tokens.items() if hmac.compare_digest(t, token)), None)
        return found is not None and found > now

    def drop(self, token: str) -> None:
        with self.lock:
            for t in [t for t in self.tokens if hmac.compare_digest(t, token)]:
                del self.tokens[t]


class LoginGuard:
    def __init__(self, failures: int = LOGIN_FAILURES, window: float = LOGIN_WINDOW, lock_seconds: float = LOGIN_LOCK_SECONDS, slots: int = LOGIN_SLOTS):
        self.failures = failures
        self.window = window
        self.lock_seconds = lock_seconds
        self.slots = threading.BoundedSemaphore(slots)
        self.recent: dict = {}
        self.locked: dict = {}
        self.lock = threading.Lock()

    def retry_after(self, ip: str) -> int:
        now = time.time()
        with self.lock:
            until = self.locked.get(ip, 0)
            if until <= now:
                self.locked.pop(ip, None)
                return 0
            return int(until - now) + 1

    def failed(self, ip: str) -> None:
        now = time.time()
        with self.lock:
            if len(self.recent) >= MAX_TRACKED_LOGIN_IPS and ip not in self.recent:
                self._prune(now)
            hits = self.recent.setdefault(ip, deque())
            hits.append(now)
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.failures:
                self.locked[ip] = now + self.lock_seconds
                del self.recent[ip]

    def passed(self, ip: str) -> None:
        with self.lock:
            self.recent.pop(ip, None)

    def _prune(self, now: float) -> None:
        self.recent = {k: v for k, v in self.recent.items() if v and now - v[-1] <= self.window}
        self.locked = {k: v for k, v in self.locked.items() if v > now}
        while len(self.recent) >= MAX_TRACKED_LOGIN_IPS:
            self.recent.pop(next(iter(self.recent)))


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True
    busy_response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nRetry-After: 1\r\nConnection: close\r\n\r\nBusy\n"

    def __init__(self, address, handler, max_threads: int = MAX_THREADS):
        self.slots = threading.BoundedSemaphore(max_threads)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(self.busy_response)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def make_handler(brain: Brain):
    cfg = brain.cfg
    not_found = (404, b"not found", TEXT)
    sessions = Sessions()
    guard = LoginGuard()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer"
        sys_version = ""
        timeout = IDLE_SECONDS
        head_only = False
        logins = guard
        session_store = sessions

        def log_message(self, fmt, *args):
            pass

        def security_headers(self, csp: str = DATA_CSP):
            self.send_header("Content-Security-Policy", csp)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)

        def reply(self, status: int, body: bytes, ctype: str, extra: dict | None = None, csp: str = DATA_CSP):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.security_headers(csp)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if not self.head_only:
                self.wfile.write(body)

        def page(self, status: int, html: str, extra: dict | None = None):
            nonce = secrets.token_urlsafe(16)
            return self.reply(status, with_nonce(html, nonce).encode(), HTML, extra, PAGE_CSP.format(n=nonce))

        def bearer_ok(self, expected_sha: str) -> bool:
            scheme, _, token = self.headers.get("Authorization", "").partition(" ")
            if not expected_sha or scheme != "Bearer" or not token:
                return False
            return sha_matches(token, expected_sha)

        def session_token(self) -> str:
            cookies = dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p)
            return cookies.get(COOKIE_NAME, "")

        def dash_ok(self) -> bool:
            return bool(cfg.dash_sha256) and sessions.valid(self.session_token())

        def client_ip(self) -> str:
            return ip_key(self.headers.get("Sprite-Client-Ip") or self.client_address[0])

        def body(self) -> bytes:
            raw = self.headers.get("Content-Length")
            if not raw:
                return b""
            try:
                n = int(raw)
            except ValueError as exc:
                raise Rejected(400, b"bad request") from exc
            if n < 0:
                raise Rejected(400, b"bad request")
            if n > MAX_BODY:
                raise Rejected(413, b"payload too large")
            return self.rfile.read(n) if n > 0 else b""

        def dash_json(self, data: bytes):
            if not self.dash_ok():
                raise Rejected(401, b"unauthorized")
            if (self.headers.get("Sec-Fetch-Site") or "").lower() in FOREIGN_FETCH_SITES:
                raise Rejected(403, b"cross-site request refused")
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise Rejected(415, b"expected application/json")
            try:
                return json.loads(data or b"{}")
            except ValueError as exc:
                raise Rejected(400, b"bad json") from exc

        def post_events(self, data: bytes):
            if not self.bearer_ok(cfg.events_sha256):
                return self.reply(*not_found)
            try:
                payload = json.loads(data)
                events = payload.get("events", []) if isinstance(payload, dict) else None
            except ValueError:
                return self.reply(400, b"bad json", TEXT)
            if not isinstance(events, list):
                return self.reply(400, b"bad json", TEXT)
            brain.submit(events)
            return self.reply(202, json.dumps({"accepted": len(events)}).encode(), JSON)

        def post_login(self, data: bytes):
            ip = self.client_ip()
            wait = guard.retry_after(ip)
            if wait:
                return self.reply(429, TOO_MANY_LOGINS, TEXT, {"Retry-After": str(wait)})
            if not guard.slots.acquire(timeout=LOGIN_WAIT_SECONDS):
                return self.reply(429, TOO_MANY_LOGINS, TEXT, {"Retry-After": "5"})
            try:
                given = parse_qs(data.decode("utf-8", "replace")).get("passphrase", [""])[0]
                if cfg.dash_sha256 and sha_matches(given, cfg.dash_sha256):
                    guard.passed(ip)
                    cookie = f"{COOKIE_NAME}={sessions.new()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}"
                    return self.reply(303, b"", TEXT, {"Location": "./", "Set-Cookie": cookie})
                guard.failed(ip)
                time.sleep(1)
            finally:
                guard.slots.release()
            return self.page(401, login_html(error=True))

        def post_logout(self, data: bytes):
            if (self.headers.get("Sec-Fetch-Site") or "").lower() in FOREIGN_FETCH_SITES:
                raise Rejected(403, b"cross-site request refused")
            sessions.drop(self.session_token())
            cookie = f"{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
            return self.reply(303, b"", TEXT, {"Location": "./", "Set-Cookie": cookie})

        def post_unblock(self, data: bytes):
            payload = self.dash_json(data)
            if not isinstance(payload, dict):
                return self.reply(400, b"bad json", TEXT)
            ip = payload.get("ip")
            if not ip or ip == "self":
                ip = self.client_ip()
            key = unblock_key(ip) if isinstance(ip, str) and ip != STRANGER else ip
            if not isinstance(key, str) or not key:
                return self.reply(400, b"bad ip", TEXT)
            ip = key
            ok = brain.unblock(ip)
            return self.reply(200, json.dumps({"ok": ok, "ip": ip}).encode(), JSON)

        def post_unshield(self, data: bytes):
            payload = self.dash_json(data)
            route = payload.get("route") if isinstance(payload, dict) else None
            if not isinstance(route, str) or not route or len(route) > 2000 or any(c in route for c in "\r\n"):
                return self.reply(400, b"bad route", TEXT)
            ok = brain.unshield(route)
            return self.reply(200, json.dumps({"ok": ok, "route": route}).encode(), JSON)

        def post_signal(self, data: bytes):
            payload = self.dash_json(data)
            if not isinstance(payload, dict) or not brain.set_signal_status(payload.get("id"), payload.get("status")):
                return self.reply(400, b"bad signal update", TEXT)
            return self.reply(200, json.dumps({"ok": True}).encode(), JSON)

        def healthz(self):
            return self.reply(200, b"ok", TEXT)

        def login_page(self):
            return self.page(200, LOGIN)

        def dashboard(self):
            return self.page(200, DASHBOARD)

        def api_state(self):
            return self.reply(200, json.dumps(brain.state(self.client_ip())).encode(), JSON)

        def stream(self):
            q = brain.feed.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.security_headers()
            self.end_headers()
            self.close_connection = True
            if self.head_only:
                return
            try:
                self._pump(q)
            except OSError:
                pass
            finally:
                brain.feed.unsubscribe(q)

        def _pump(self, q: queue.Queue):
            while True:
                try:
                    item = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()

        PUBLIC_GET_ROUTES = {"/healthz": healthz}
        PRIVATE_GET_ROUTES = {"/": dashboard, "/api/state": api_state, "/stream": stream}
        POST_ROUTES = {"/events": post_events, "/login": post_login, "/logout": post_logout, "/api/unblock": post_unblock, "/api/unshield": post_unshield, "/api/signal": post_signal}

        def do_POST(self):
            try:
                data = self.body()
            except Rejected as refusal:
                self.close_connection = True
                return self.reply(refusal.status, refusal.message, TEXT)
            route = self.POST_ROUTES.get(bare_path(self.path))
            if not route:
                return self.reply(*not_found)
            try:
                return route(self, data)
            except Rejected as refusal:
                return self.reply(refusal.status, refusal.message, TEXT)

        def do_HEAD(self):
            self.head_only = True
            return self.do_GET()

        def do_GET(self):
            path = bare_path(self.path)
            public = self.PUBLIC_GET_ROUTES.get(path)
            if public:
                return public(self)
            if not self.dash_ok():
                if path == "/":
                    return self.login_page()
                if path in self.PRIVATE_GET_ROUTES:
                    return self.reply(401, b"unauthorized", TEXT)
                return self.reply(*not_found)
            route = self.PRIVATE_GET_ROUTES.get(path)
            if not route:
                return self.reply(*not_found)
            return route(self)

    return Handler
