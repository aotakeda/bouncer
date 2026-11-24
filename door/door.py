from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

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

STATIC_PATH = re.compile(
    r"^/(assets/.*|[\w.-]+\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|webmanifest))$"
)

QUIET_PATHS = {"/", "/socket.io/", "/rest/admin/application-version", "/rest/admin/application-configuration", "/rest/languages"}

BODY_PREVIEW = 4096

REPLAY_HEADERS = {"authorization", "cookie", "accept", "x-user-email"}


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
        self.allowlist = {ip.strip() for ip in env.get("DOOR_ALLOWLIST", "").split(",") if ip.strip()}
        self.tarpit_seconds = float(env.get("DOOR_TARPIT_SECONDS", "10"))
        self.tarpit_max = int(env.get("DOOR_TARPIT_MAX", "5"))
        self.canaries_file = Path(env.get("DOOR_CANARIES", str(self.data_dir / "canaries.json")))
        self.flush_seconds = float(env.get("DOOR_FLUSH_SECONDS", "2"))


class Lists:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"block": {}, "tarpit": {}}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text()))
            except ValueError:
                pass

    def _save(self):
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
            skipped = []
            for ip, entry in entries.items():
                if ip in allowlist:
                    skipped.append(ip)
                    continue
                self.data[kind][ip] = entry
            self._save()
            return {"ok": True, "skipped_allowlisted": skipped}

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
    def __init__(self, url: str, flush_seconds: float, log, token: str = ""):
        self.url = url
        self.token = token
        self.flush_seconds = flush_seconds
        self.log = log
        self.q: queue.Queue = queue.Queue(maxsize=10000)
        if url:
            threading.Thread(target=self._run, daemon=True).start()

    def push(self, event: dict):
        if not self.url:
            return
        try:
            self.q.put_nowait(event)
        except queue.Full:
            pass

    def _run(self):
        while True:
            batch = [self.q.get()]
            deadline = time.time() + self.flush_seconds
            while len(batch) < 200:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    batch.append(self.q.get(timeout=remaining))
                except queue.Empty:
                    break
            body = json.dumps({"events": batch}).encode()
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            req = urllib.request.Request(self.url, data=body, method="POST", headers=headers)
            try:
                urllib.request.urlopen(req, timeout=15).read()
            except Exception as exc:
                self.log({"kind": "push_failed", "error": str(exc)[:200], "events": len(batch)})


class Door:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.lists = Lists(cfg.data_dir / "lists.json")
        self.log_path = cfg.data_dir / "access.log"
        self.log_lock = threading.Lock()
        self.tarpit_slots = threading.BoundedSemaphore(cfg.tarpit_max)
        self.canaries = self._load_canaries()
        self.pusher = Pusher(cfg.events_url, cfg.flush_seconds, self.write_log, cfg.events_token)

    def _load_canaries(self) -> dict:
        if self.cfg.canaries_file.exists():
            return json.loads(self.cfg.canaries_file.read_text())
        return {}

    def honeypot_env(self) -> str:
        c = self.canaries.get("honeypot", {})
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
        hits = []
        for value in self.canaries.get("honeypot", {}).values():
            if value and value in text:
                hits.append(value)
        return hits

    def write_log(self, record: dict):
        line = json.dumps(record, separators=(",", ":"))
        with self.log_lock:
            with self.log_path.open("a") as f:
                f.write(line + "\n")

    def admin_ok(self, header: str | None) -> bool:
        if not self.cfg.admin_sha256 or not header or not header.startswith("Bearer "):
            return False
        digest = hashlib.sha256(header[7:].encode()).hexdigest()
        return hmac.compare_digest(digest, self.cfg.admin_sha256)

    @staticmethod
    def is_quiet(method: str, path: str) -> bool:
        bare = path.split("?", 1)[0]
        if bare == "/socket.io/" and method in ("GET", "POST"):
            return True
        if method not in ("GET", "HEAD"):
            return False
        if "?" in path and not bare.startswith("/socket.io/"):
            return False
        return bare in QUIET_PATHS or bool(STATIC_PATH.match(bare)) or bare.startswith("/socket.io/")


def make_handler(door: Door):
    cfg = door.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer-door"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def client_ip(self) -> str:
            return self.headers.get("Sprite-Client-Ip") or self.client_address[0]

        def read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length > 0 else b""

        def send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8", extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return len(body)

        def handle_admin(self, body: bytes) -> int:
            if not door.admin_ok(self.headers.get("Authorization")):
                return self.send(404, b"Not Found")
            parts = self.path.split("?", 1)[0].strip("/").split("/")
            if len(parts) == 2 and parts[1] == "whoami":
                return self.send(200, json.dumps({"ip": self.client_ip()}).encode(), "application/json")
            if len(parts) < 2 or parts[1] not in ("blocklist", "tarpit"):
                return self.send(404, b"Not Found")
            kind = "block" if parts[1] == "blocklist" else "tarpit"
            if self.command == "GET":
                return self.send(200, json.dumps(door.lists.snapshot()).encode(), "application/json")
            if self.command == "PUT":
                try:
                    entries = json.loads(body or b"{}")
                except ValueError:
                    return self.send(400, b"bad json")
                result = door.lists.put(kind, entries, cfg.allowlist)
                return self.send(200, json.dumps(result).encode(), "application/json")
            if self.command == "DELETE" and len(parts) == 3:
                existed = door.lists.delete(kind, parts[2])
                return self.send(200, json.dumps({"ok": True, "existed": existed}).encode(), "application/json")
            return self.send(405, b"Method Not Allowed")

        def proxy(self, body: bytes) -> tuple:
            conn = http.client.HTTPConnection(cfg.upstream_host, cfg.upstream_port, timeout=60)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            headers["Host"] = f"{cfg.upstream_host}:{cfg.upstream_port}"
            headers["X-Forwarded-For"] = self.client_ip()
            try:
                conn.request(self.command, self.path, body=body or None, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException):
                conn.close()
                return 502, self.send(502, b"Bad Gateway")
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            conn.close()
            return resp.status, len(data)

        def handle_any(self):
            started = time.time()
            ip = self.client_ip()
            body = self.read_body()
            kind = "request"
            if self.path.startswith("/_bouncer/"):
                self.handle_admin(body)
                return
            if self.headers.get("Upgrade", "").lower() == "websocket":
                status, size = 400, self.send(400, b"websocket not supported, use polling")
            elif door.lists.active("block", ip) and ip not in cfg.allowlist:
                kind = "refused"
                status, size = 403, self.send(
                    403,
                    b"You're not on the list. The bouncer remembers faces. Come back later.\n",
                    extra={"Retry-After": "900"},
                )
            elif self.path.split("?", 1)[0] == "/.env":
                kind = "honeypot"
                status, size = 200, self.send(200, door.honeypot_env().encode())
            else:
                haystack = self.path + " " + body.decode("utf-8", "replace") + " " + " ".join(self.headers.values())
                hits = door.canary_hits(haystack)
                if hits:
                    kind = "canary_reuse"
                tarpitted = False
                if door.lists.active("tarpit", ip) and ip not in cfg.allowlist and door.tarpit_slots.acquire(blocking=False):
                    try:
                        tarpitted = True
                        time.sleep(cfg.tarpit_seconds)
                    finally:
                        door.tarpit_slots.release()
                status, size = self.proxy(body)
                if tarpitted:
                    kind = "tarpitted" if kind == "request" else kind
            record = {
                "ts": round(started, 3),
                "ip": ip,
                "method": self.command,
                "path": self.path,
                "ua": self.headers.get("User-Agent", ""),
                "status": status,
                "bytes": size,
                "ms": int((time.time() - started) * 1000),
                "kind": kind,
            }
            if body:
                record["body"] = body[:BODY_PREVIEW].decode("utf-8", "replace")
            ctype = self.headers.get("Content-Type")
            if ctype:
                record["ctype"] = ctype
            kept = {k: v for k, v in self.headers.items() if k.lower() in REPLAY_HEADERS}
            if kept:
                record["headers"] = kept
            door.write_log(record)
            if kind != "request" or not door.is_quiet(self.command, self.path):
                door.pusher.push(record)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any

    return Handler


def main(argv=None):
    cfg = Config()
    door = Door(cfg)
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(door))
    server.daemon_threads = True
    print(json.dumps({"door": "listening", "port": cfg.port, "upstream": f"{cfg.upstream_host}:{cfg.upstream_port}"}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
