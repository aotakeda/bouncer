from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from enum import Enum
from typing import Callable, NamedTuple
from urllib.parse import unquote, unquote_plus, urlsplit

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
UPSTREAM_SKIP = HOP_BY_HOP | {"date", "server"}

STATIC_PATH = re.compile(
    r"^/(assets/.*|[\w.-]+\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|webmanifest))$"
)

ATTACK = re.compile(
    r"""(\bunion\b[\s\S]{0,80}\bselect\b|\bor\b\s*['"]?\s*\d+\s*=\s*\d+|'\s*(or|and|\)|;|--|#)|--\s|/\*|\bsleep\s*\(|\bbenchmark\s*\(|\.\./|<script|onerror\s*=|javascript:|\$where|\$ne\b|\$gt\b|etc/passwd)""",
    re.IGNORECASE,
)
TRUSTED_FETCH_SITES = {"", "none", "same-origin"}
CANARY_SKIP_HEADERS = {"referer", "origin"}
BAIT_SECONDS = 86400

QUIET_PATHS = {"/", "/socket.io/", "/rest/admin/application-version", "/rest/admin/application-configuration", "/rest/languages"}
SOCKET_IO_PATH = "/socket.io/"
REPLAY_HEADERS = {"authorization", "cookie", "accept", "x-user-email"}
MAX_STORED_BODY = 65536
MAX_REQUEST_BODY = 2 * 1024 * 1024
MAX_BATCH_BODY = 1048576
PUSH_RETRY_DELAYS = (1.0, 3.0)

STRANGER = "owner-as-stranger"
ADMIN_PREFIX = "/_bouncer/"
BEARER = "Bearer "
LIST_KINDS = {"blocklist": "block", "tarpit": "tarpit", "shield": "shield"}
LIST_NAMES = ("block", "tarpit", "shield", "bait")
TEXT_TYPE = "text/plain; charset=utf-8"
JSON_TYPE = "application/json"


class EventKind(str, Enum):
    REQUEST = "request"
    REFUSED = "refused"
    HONEYPOT = "honeypot"
    CANARY_REUSE = "canary_reuse"
    TARPITTED = "tarpitted"
    SHIELDED = "shielded"

    def __str__(self) -> str:
        return self.value


class Slow(str, Enum):
    NO = "no"
    SLOWED = "slowed"
    REFUSE = "refuse"


class Outcome(NamedTuple):
    kind: EventKind
    status: int
    size: int


class AdminRequest(NamedTuple):
    kind: str
    target: str
    body: bytes


class BadRequest(Exception):
    pass


class PayloadTooLarge(Exception):
    pass


LogFn = Callable[[dict], None]


def bare_path(path: str) -> str:
    return path.split("?", 1)[0]


def client_key(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return str(addr)
    if addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(ipaddress.ip_network(f"{addr}/64", strict=False))


def wire_path(path: str) -> str:
    return "".join(c if 32 < ord(c) < 127 else "%%%02X" % (ord(c) & 0xFF) for c in path)


def route_key(method: str, path: str) -> str:
    return f"{method} {bare_path(path)}"


def looks_like_attack(path: str, body: bytes) -> bool:
    text = unquote_plus(path) + " " + body.decode("utf-8", "replace")
    return bool(ATTACK.search(text))


def trusted_fetch(headers) -> bool:
    return (headers.get("Sec-Fetch-Site") or "").strip().lower() in TRUSTED_FETCH_SITES


def has_traversal(path: str) -> bool:
    low = path.lower()
    return ".." in low or "%2e" in low


def read_chunked(stream, limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        line = stream.readline(4096)
        if not line:
            raise BadRequest("truncated chunked body")
        size_str = line.split(b";", 1)[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError as exc:
            raise BadRequest("bad chunk size") from exc
        if size < 0:
            raise BadRequest("negative chunk size")
        if size == 0:
            while True:
                trailer = stream.readline(4096)
                if trailer in (b"", b"\r\n", b"\n"):
                    break
            return b"".join(chunks)
        total += size
        if total > limit:
            raise PayloadTooLarge("chunked body too large")
        data = stream.read(size)
        if len(data) < size:
            raise BadRequest("truncated chunk data")
        chunks.append(data)
        crlf = stream.read(2)
        if crlf != b"\r\n":
            raise BadRequest("missing chunk terminator")


def json_bytes(obj) -> bytes:
    return json.dumps(obj).encode()


def body_size(event: dict) -> int:
    return len(event.get("body", ""))


def retry_after(entry: dict) -> str:
    return str(max(1, int(entry.get("until", 0) - time.time())))


class Config:
    def __init__(self, env=os.environ):
        self.port = int(env.get("DOOR_PORT", "8080"))
        up = urlsplit(env.get("DOOR_UPSTREAM", "http://127.0.0.1:3000"))
        self.upstream_host = up.hostname or "127.0.0.1"
        self.upstream_port = up.port or 80
        self.data_dir = Path(env.get("DOOR_DATA_DIR", "./door-data"))
        self.admin_sha256 = env.get("DOOR_ADMIN_SHA256", "")
        self.events_url = env.get("DOOR_EVENTS_URL", "")
        self.events_token = env.get("DOOR_EVENTS_TOKEN", "")
        self.allowlist = {client_key(ip.strip()) for ip in env.get("DOOR_ALLOWLIST", "").split(",") if ip.strip()}
        self.tarpit_seconds = float(env.get("DOOR_TARPIT_SECONDS", "10"))
        self.tarpit_max = int(env.get("DOOR_TARPIT_MAX", "50"))
        self.tarpit_per_ip = int(env.get("DOOR_TARPIT_PER_IP", "2"))
        self.tarpit_list_seconds = float(env.get("DOOR_TARPIT_LIST_SECONDS", "600"))
        self.block_seconds = float(env.get("DOOR_BLOCK_SECONDS", "300"))
        self.log_max_bytes = int(env.get("DOOR_LOG_MAX_BYTES", str(50 * 1024 * 1024)))
        self.canaries_file = Path(env.get("DOOR_CANARIES", str(self.data_dir / "canaries.json")))
        self.flush_seconds = float(env.get("DOOR_FLUSH_SECONDS", "2"))

    @property
    def upstream(self) -> str:
        return f"{self.upstream_host}:{self.upstream_port}"


class Lists:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {name: {} for name in LIST_NAMES}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text())
        except ValueError:
            return
        if isinstance(loaded, dict):
            for name in LIST_NAMES:
                if isinstance(loaded.get(name), dict):
                    self.data[name] = loaded[name]

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        tmp.replace(self.path)

    def active(self, kind: str, ip: str) -> dict | None:
        with self.lock:
            entry = self.data[kind].get(ip)
            if not entry:
                return None
            if entry.get("until", 0) < time.time():
                del self.data[kind][ip]
                self._save()
                return None
            return entry

    def put(self, kind: str, entries: dict, allowlist: set) -> dict:
        with self.lock:
            skipped = [ip for ip in entries if ip in allowlist]
            for ip, entry in entries.items():
                if ip not in allowlist:
                    self.data[kind][ip] = entry
            self._save()
            return {"ok": True, "skipped_allowlisted": skipped}

    def add(self, kind: str, key: str, seconds: float, reason: str, allowlist: set) -> None:
        if key in allowlist:
            return
        with self.lock:
            now = time.time()
            current = self.data[kind].get(key)
            until = now + seconds
            if current and current.get("until", 0) > until:
                return
            self.data[kind][key] = {"until": until, "reason": reason, "ts": now}
            self._save()

    def delete(self, kind: str, ip: str) -> bool:
        with self.lock:
            existed = self.data[kind].pop(ip, None) is not None
            self._save()
            return existed

    def snapshot(self) -> dict:
        with self.lock:
            now = time.time()
            return {k: {ip: e for ip, e in v.items() if e.get("until", 0) >= now} for k, v in self.data.items()}


class Pusher:
    def __init__(self, url: str, flush_seconds: float, log: LogFn, token: str = "", retry_delays: tuple[float, ...] = PUSH_RETRY_DELAYS):
        self.url = url
        self.token = token
        self.flush_seconds = flush_seconds
        self.log = log
        self.retry_delays = retry_delays
        self.q: queue.Queue = queue.Queue(maxsize=10000)
        if url:
            threading.Thread(target=self._run, daemon=True).start()

    def push(self, event: dict) -> None:
        if not self.url:
            return
        try:
            self.q.put_nowait(event)
        except queue.Full:
            pass

    def _run(self) -> None:
        while True:
            self._send(self._collect_batch())

    def _collect_batch(self) -> list:
        batch = [self.q.get()]
        size = body_size(batch[0])
        deadline = time.time() + self.flush_seconds
        while len(batch) < 200 and size < MAX_BATCH_BODY:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                batch.append(self.q.get(timeout=remaining))
            except queue.Empty:
                break
            size += body_size(batch[-1])
        return batch

    def _headers(self) -> dict:
        headers = {"Content-Type": JSON_TYPE}
        if self.token:
            headers["Authorization"] = f"{BEARER}{self.token}"
        return headers

    def _send(self, batch: list) -> None:
        body = json_bytes({"events": batch})
        last_error = ""
        for attempt in range(len(self.retry_delays) + 1):
            req = urllib.request.Request(self.url, data=body, method="POST", headers=self._headers())
            try:
                urllib.request.urlopen(req, timeout=15).read()
                return
            except urllib.error.HTTPError as exc:
                last_error = str(exc)[:200]
                if exc.code < 500:
                    break
            except Exception as exc:
                last_error = str(exc)[:200]
            if attempt < len(self.retry_delays):
                time.sleep(self.retry_delays[attempt])
        self.log({"kind": "push_failed", "error": last_error, "events": len(batch)})


class Door:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.lists = Lists(cfg.data_dir / "lists.json")
        self.log_path = cfg.data_dir / "access.log"
        self.log_lock = threading.Lock()
        self.tarpit_lock = threading.Lock()
        self.tarpit_busy: dict = {}
        self.tarpit_total = 0
        self.canaries = self._load_canaries()
        self.pusher = Pusher(cfg.events_url, cfg.flush_seconds, self.write_log, cfg.events_token)

    def _load_canaries(self) -> dict:
        if not self.cfg.canaries_file.exists():
            return {}
        return json.loads(self.cfg.canaries_file.read_text())

    @property
    def honeypot(self) -> dict:
        return self.canaries.get("honeypot", {})

    def honeypot_env(self) -> str:
        c = self.honeypot
        return (
            "NODE_ENV=production\n"
            f"ADMIN_EMAIL={c.get('admin_email', 'ops@juice-sh.op')}\n"
            f"ADMIN_PASSWORD={c.get('admin_password', 'changeme')}\n"
            f"AWS_ACCESS_KEY_ID={c.get('aws_key_id', 'AKIAEXAMPLE')}\n"
            f"AWS_SECRET_ACCESS_KEY={c.get('aws_secret', 'example')}\n"
            f"STRIPE_SECRET_KEY={c.get('stripe_key', 'sk_live_example')}\n"
            "DATABASE_URL=sqlite:///data/juiceshop.sqlite\n"
        )

    def canary_hits(self, text: str) -> list:
        return [value for value in self.honeypot.values() if value and value in text]

    def took_bait(self, ip: str) -> bool:
        return bool(self.lists.active("bait", ip))

    def mark_bait(self, ip: str) -> None:
        self.lists.add("bait", ip, BAIT_SECONDS, "took the honeypot .env", self.cfg.allowlist)
        self.lists.add("tarpit", ip, self.cfg.tarpit_list_seconds, "took the honeypot .env", self.cfg.allowlist)

    def block_bait_reuse(self, ip: str) -> None:
        self.lists.add("block", ip, self.cfg.block_seconds, "reused honeypot credentials", self.cfg.allowlist)

    def shielded(self, ip: str, method: str, path: str, body: bytes) -> bool:
        if ip in self.cfg.allowlist or not self.lists.active("shield", route_key(method, path)):
            return False
        return looks_like_attack(path, body)

    def write_log(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self.log_lock:
            try:
                if self.log_path.stat().st_size > self.cfg.log_max_bytes:
                    self.log_path.replace(self.log_path.with_suffix(".log.1"))
            except OSError:
                pass
            with self.log_path.open("a") as f:
                f.write(line + "\n")

    def admin_ok(self, header: str | None) -> bool:
        if not self.cfg.admin_sha256 or not header or not header.startswith(BEARER):
            return False
        digest = hashlib.sha256(header[len(BEARER):].encode()).hexdigest()
        return hmac.compare_digest(digest, self.cfg.admin_sha256)

    def listed_entry(self, kind: str, ip: str) -> dict | None:
        entry = self.lists.active(kind, ip)
        return entry if entry and ip not in self.cfg.allowlist else None

    def is_listed(self, kind: str, ip: str) -> bool:
        return bool(self.listed_entry(kind, ip))

    def tarpit(self, ip: str) -> Slow:
        if not self.is_listed("tarpit", ip):
            return Slow.NO
        with self.tarpit_lock:
            if self.tarpit_busy.get(ip, 0) >= self.cfg.tarpit_per_ip or self.tarpit_total >= self.cfg.tarpit_max:
                return Slow.REFUSE
            self.tarpit_busy[ip] = self.tarpit_busy.get(ip, 0) + 1
            self.tarpit_total += 1
        try:
            time.sleep(self.cfg.tarpit_seconds)
        finally:
            with self.tarpit_lock:
                self.tarpit_total -= 1
                left = self.tarpit_busy.get(ip, 1) - 1
                if left > 0:
                    self.tarpit_busy[ip] = left
                else:
                    self.tarpit_busy.pop(ip, None)
        return Slow.SLOWED

    @staticmethod
    def is_quiet(method: str, path: str) -> bool:
        if has_traversal(path):
            return False
        bare = bare_path(path)
        if bare == SOCKET_IO_PATH and method in ("GET", "POST"):
            return True
        if method not in ("GET", "HEAD"):
            return False
        if "?" in path and not bare.startswith(SOCKET_IO_PATH):
            return False
        return bare in QUIET_PATHS or bool(STATIC_PATH.match(bare)) or bare.startswith(SOCKET_IO_PATH)

    def should_push(self, kind: EventKind, method: str, path: str) -> bool:
        return kind != EventKind.REQUEST or not self.is_quiet(method, path)


def make_handler(door: Door):
    cfg = door.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer-door"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def client_ip(self) -> str:
            ip = client_key(self.headers.get("Sprite-Client-Ip") or self.client_address[0])
            if ip in cfg.allowlist and self.headers.get("X-Bouncer-Stranger"):
                return STRANGER
            return ip

        def read_body(self) -> bytes:
            te = self.headers.get("Transfer-Encoding", "")
            if "chunked" in te.lower():
                return read_chunked(self.rfile, MAX_REQUEST_BODY)
            raw = self.headers.get("Content-Length")
            if not raw:
                return b""
            try:
                length = int(raw)
            except ValueError as exc:
                raise BadRequest("invalid Content-Length") from exc
            if length < 0:
                raise BadRequest("negative Content-Length")
            if length > MAX_REQUEST_BODY:
                raise PayloadTooLarge("body too large")
            return self.rfile.read(length) if length > 0 else b""

        def write_body(self, body: bytes) -> None:
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def send(self, status: int, body: bytes, ctype: str = TEXT_TYPE, extra: dict | None = None) -> int:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.write_body(body)
            return len(body)

        def send_json(self, obj) -> int:
            return self.send(200, json_bytes(obj), JSON_TYPE)

        def not_found(self) -> int:
            return self.send(404, b"Not Found")

        def method_not_allowed(self) -> int:
            return self.send(405, b"Method Not Allowed")

        def handle_admin(self, body: bytes) -> int:
            if not door.admin_ok(self.headers.get("Authorization")):
                return self.not_found()
            parts = bare_path(self.path).strip("/").split("/")
            if parts[1:] == ["whoami"]:
                return self.send_json({"ip": self.client_ip()})
            if len(parts) < 2 or parts[1] not in LIST_KINDS:
                return self.not_found()
            action = self.ADMIN_ACTIONS.get(self.command)
            if action is None:
                return self.method_not_allowed()
            target = unquote(parts[2]) if len(parts) == 3 else ""
            return action(self, AdminRequest(LIST_KINDS[parts[1]], target, body))

        def admin_snapshot(self, req: AdminRequest) -> int:
            return self.send_json(door.lists.snapshot())

        def admin_put(self, req: AdminRequest) -> int:
            try:
                entries = json.loads(req.body or b"{}")
            except ValueError:
                return self.send(400, b"bad json")
            if not isinstance(entries, dict) or not all(isinstance(v, dict) for v in entries.values()):
                return self.send(400, b"bad json")
            return self.send_json(door.lists.put(req.kind, entries, cfg.allowlist))

        def admin_delete(self, req: AdminRequest) -> int:
            if not req.target:
                return self.method_not_allowed()
            existed = door.lists.delete(req.kind, req.target)
            return self.send_json({"ok": True, "existed": existed})

        ADMIN_ACTIONS = {
            "GET": admin_snapshot,
            "PUT": admin_put,
            "DELETE": admin_delete,
        }

        def upstream_headers(self) -> dict:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            headers["Host"] = cfg.upstream
            headers["X-Forwarded-For"] = self.client_ip()
            return headers

        def proxy(self, body: bytes) -> tuple[int, int]:
            conn = http.client.HTTPConnection(cfg.upstream_host, cfg.upstream_port, timeout=60)
            try:
                conn.request(self.command, wire_path(self.path), body=body or None, headers=self.upstream_headers())
                resp = conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException, ValueError):
                conn.close()
                return 502, self.send(502, b"Bad Gateway")
            self.relay(resp, data)
            conn.close()
            return resp.status, len(data)

        def relay(self, resp: http.client.HTTPResponse, data: bytes) -> None:
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in UPSTREAM_SKIP:
                    self.send_header(k, v)
            if resp.status not in (204, 304):
                self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if resp.status not in (204, 304):
                self.write_body(data)

        def canary_haystack(self, body: bytes) -> str:
            headers = " ".join(v for k, v in self.headers.items() if k.lower() not in CANARY_SKIP_HEADERS)
            return self.path + " " + body.decode("utf-8", "replace") + " " + headers

        def forward(self, ip: str, body: bytes) -> Outcome:
            reuse = bool(door.canary_hits(self.canary_haystack(body)))
            kind = EventKind.CANARY_REUSE if reuse else EventKind.REQUEST
            slow = door.tarpit(ip)
            if slow == Slow.REFUSE:
                wait = str(max(1, int(cfg.tarpit_seconds)))
                return Outcome(EventKind.TARPITTED, 429, self.send(429, b"Slow down.\n", extra={"Retry-After": wait}))
            status, size = self.proxy(body)
            if reuse and trusted_fetch(self.headers) and door.took_bait(ip):
                door.block_bait_reuse(ip)
            if slow == Slow.SLOWED and kind == EventKind.REQUEST:
                kind = EventKind.TARPITTED
            return Outcome(kind, status, size)

        def refuse_blocked(self, block: dict) -> Outcome:
            refused = b"You're not on the list. The bouncer remembers faces. Come back later.\n"
            return Outcome(EventKind.REFUSED, 403, self.send(403, refused, extra={"Retry-After": retry_after(block)}))

        def respond(self, ip: str, body: bytes) -> Outcome:
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return Outcome(EventKind.REQUEST, 400, self.send(400, b"websocket not supported, use polling"))
            if bare_path(self.path) == "/.env":
                if trusted_fetch(self.headers):
                    door.mark_bait(ip)
                return Outcome(EventKind.HONEYPOT, 200, self.send(200, door.honeypot_env().encode()))
            if door.shielded(ip, self.command, self.path, body):
                shield = b"This route is shielded until its security fix is merged.\n"
                return Outcome(EventKind.SHIELDED, 403, self.send(403, shield))
            return self.forward(ip, body)

        def build_record(self, started: float, ip: str, body: bytes, outcome: Outcome) -> dict:
            record = {
                "ts": round(started, 3),
                "ip": ip,
                "method": self.command,
                "path": self.path,
                "ua": self.headers.get("User-Agent", ""),
                "status": outcome.status,
                "bytes": outcome.size,
                "ms": int((time.time() - started) * 1000),
                "kind": outcome.kind,
            }
            if body:
                record["body"] = body[:MAX_STORED_BODY].decode("utf-8", "replace")
            if len(body) > MAX_STORED_BODY:
                record["truncated"] = True
            ctype = self.headers.get("Content-Type")
            if ctype:
                record["ctype"] = ctype
            fetch_site = self.headers.get("Sec-Fetch-Site")
            if fetch_site:
                record["fetch_site"] = fetch_site[:40]
            if outcome.kind in (EventKind.CANARY_REUSE, EventKind.HONEYPOT):
                record["took_bait"] = door.took_bait(ip)
            kept = {k: v for k, v in self.headers.items() if k.lower() in REPLAY_HEADERS}
            if kept:
                record["headers"] = kept
            return record

        def handle_any(self):
            started = time.time()
            ip = self.client_ip()
            block = None if self.path.startswith(ADMIN_PREFIX) else door.listed_entry("block", ip)
            if block:
                self.close_connection = True
                record = self.build_record(started, ip, b"", self.refuse_blocked(block))
                door.write_log(record)
                door.pusher.push(record)
                return
            try:
                body = self.read_body()
            except BadRequest:
                self.close_connection = True
                self.send(400, b"Bad Request")
                return
            except PayloadTooLarge:
                self.close_connection = True
                self.send(413, b"Payload Too Large")
                return
            if self.path.startswith(ADMIN_PREFIX):
                self.handle_admin(body)
                return
            outcome = self.respond(ip, body)
            record = self.build_record(started, ip, body, outcome)
            door.write_log(record)
            if door.should_push(outcome.kind, self.command, self.path):
                door.pusher.push(record)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any

    return Handler


def main(argv=None):
    cfg = Config()
    door = Door(cfg)
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(door))
    server.daemon_threads = True
    print(json.dumps({"door": "listening", "port": cfg.port, "upstream": cfg.upstream}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
