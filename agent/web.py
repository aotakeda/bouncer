from __future__ import annotations

import hashlib
import hmac
import json
import queue
import time
from http.server import BaseHTTPRequestHandler
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


def make_handler(brain: Brain):
    cfg = brain.cfg
    not_found = (404, b"not found", TEXT)

    def cookie_value() -> str:
        return hmac.new(cfg.dash_sha256.encode(), b"bouncer-dashboard", hashlib.sha256).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def reply(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def bearer_ok(self, expected_sha: str) -> bool:
            scheme, _, token = self.headers.get("Authorization", "").partition(" ")
            if not expected_sha or scheme != "Bearer" or not token:
                return False
            return sha_matches(token, expected_sha)

        def dash_ok(self) -> bool:
            if not cfg.dash_sha256:
                return False
            cookies = dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p)
            return hmac.compare_digest(cookies.get(COOKIE_NAME, ""), cookie_value())

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
            given = parse_qs(data.decode("utf-8", "replace")).get("passphrase", [""])[0]
            if cfg.dash_sha256 and sha_matches(given, cfg.dash_sha256):
                cookie = f"{COOKIE_NAME}={cookie_value()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800"
                return self.reply(303, b"", TEXT, {"Location": "./", "Set-Cookie": cookie})
            time.sleep(1)
            return self.reply(401, login_html(error=True).encode(), HTML)

        def post_unblock(self, data: bytes):
            payload = self.dash_json(data)
            if not isinstance(payload, dict):
                return self.reply(400, b"bad json", TEXT)
            ip = payload.get("ip")
            if not ip or ip == "self":
                ip = self.client_ip()
            if not isinstance(ip, str) or any(c.isspace() or c == "/" for c in ip):
                return self.reply(400, b"bad ip", TEXT)
            ok = brain.unblock(ip)
            return self.reply(200, json.dumps({"ok": ok, "ip": ip}).encode(), JSON)

        def post_signal(self, data: bytes):
            payload = self.dash_json(data)
            if not isinstance(payload, dict) or not brain.set_signal_status(payload.get("id"), payload.get("status")):
                return self.reply(400, b"bad signal update", TEXT)
            return self.reply(200, json.dumps({"ok": True}).encode(), JSON)

        def healthz(self):
            return self.reply(200, b"ok", TEXT)

        def login_page(self):
            return self.reply(200, LOGIN.encode(), HTML)

        def dashboard(self):
            return self.reply(200, DASHBOARD.encode(), HTML)

        def api_state(self):
            return self.reply(200, json.dumps(brain.state(self.client_ip())).encode(), JSON)

        def stream(self):
            q = brain.feed.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
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
        POST_ROUTES = {"/events": post_events, "/login": post_login, "/api/unblock": post_unblock, "/api/signal": post_signal}

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
