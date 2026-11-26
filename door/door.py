from __future__ import annotations

import base64
import codecs
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
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
    r"""(\bunion\b[\s\S]{0,80}\bselect\b|\bor\b\s*['"]?\s*\d+\s*=\s*\d+|'\s*(or|and)\b|'\s*[);#]|['`)]\s*--|\b(select|union|null|sleep|benchmark)\b[\s\S]{0,80}--|\bis\s+not\s+null\b|/\*|\bsleep\s*\(|\bbenchmark\s*\(|\.\.[\\/]|<script|<[a-z]{1,20}[\s/][^<>]{0,200}?\bon[a-z]{2,30}\s*=|["'`]\s*/?\s*on[a-z]{2,30}\s*=|onerror\s*=|j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:|\$(where|ne|gt|gte|lt|lte|regex|nin|or|in|exists|elemmatch|and|nor|not|expr)\b|etc/passwd)""",
    re.IGNORECASE,
)
ESCAPED_CHAR = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
SQL_COMMENT = re.compile(r"/\*[^*]{0,64}\*/")
CHARSET = re.compile(r"(;\s*charset\s*=\s*)(\"?)([^\";\s]+)\2", re.IGNORECASE)
CHUNK_SIZE = re.compile(rb"[0-9a-fA-F]{1,16}(;[^\r\n]*)?\r?\n")
DIGITS = re.compile(r"[0-9]{1,19}")
GZIP_WBITS = 31
DEFLATE_WBITS = (15, -15)
MAX_DECODED_BODY = 1 << 20
MAX_TRAILERS = 64
DECODE_ROUNDS = 8
SECRET_HEADERS = {"authorization", "cookie", "x-user-email"}
CLIENT_FORWARD_HEADERS = {"x-forwarded-for", "x-real-ip", "forwarded"}
SECRET_KEY = r"[^\"=&]*(?:password|passwd|pass|secret|token|totp|answer)[^\"=&]*"
SECRET_JSON_FIELD = re.compile(r'("' + SECRET_KEY + r'"\s*:\s*)("(?:[^"\\]|\\.)*"?|[^,}\]\s]+)', re.IGNORECASE)
SECRET_FORM_FIELD = re.compile(r"((?:^|&)" + SECRET_KEY + r"=)([^&]*)", re.IGNORECASE)
SECRET_PARAM = re.compile(r"pass|pwd|secret|token|totp|answer|jwt|auth|session|api_?key|credential|signature|(?:^|[_.\[-])(?:key|code|sig|sid)\]?$", re.IGNORECASE)
FOREIGN_FETCH_SITES = {"cross-site", "same-site"}
FETCH_FIELDS = (("fetch_site", "Sec-Fetch-Site"), ("fetch_mode", "Sec-Fetch-Mode"), ("fetch_dest", "Sec-Fetch-Dest"))
FETCH_FIELD_MAX = 40
BROWSER_UA = re.compile(r"^mozilla/", re.IGNORECASE)
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|zgrab|masscan|nmap|dirbuster|gobuster|ffuf|wpscan|acunetix|python-requests|go-http-client|curl/|wget/|libwww", re.IGNORECASE)
CANARY_SKIP_HEADERS = {"referer", "origin"}
BAIT_SECONDS = 86400
CLIENT_IP_HEADER = "Sprite-Client-Ip"
OFF_VALUES = {"0", "false", "no", "off"}
WARN_INTERVAL = 10.0
BUSY_RESPONSE = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 6\r\nRetry-After: 1\r\nConnection: close\r\n\r\nBusy.\n"

QUIET_PATHS = {"/", "/socket.io/", "/rest/admin/application-version", "/rest/admin/application-configuration", "/rest/languages"}
SOCKET_IO_PATH = "/socket.io/"
REPLAY_HEADERS = {"authorization", "cookie", "accept", "x-user-email"}
MAX_STORED_BODY = 65536
MAX_LIST_ENTRIES = 20000
MAX_REQUEST_BODY = 2 * 1024 * 1024
MAX_BATCH_BODY = 1048576
PUSH_RETRY_DELAYS = (1.0, 3.0, 10.0, 30.0)

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
    repeat: bool = False


class AdminRequest(NamedTuple):
    kind: str
    target: str
    body: bytes


class BadRequest(Exception):
    pass


class PayloadTooLarge(Exception):
    pass


class Seen(NamedTuple):
    text: str = ""
    decoded_from: dict | None = None
    decode_failed: bool = False
    attack: bool = False


LogFn = Callable[[dict], None]


def bare_path(path: str) -> str:
    return path.split("?", 1)[0]


def valid_ip(value: str) -> str:
    value = value.strip()
    if "%" in value:
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ""
    return value


def proxy_networks(raw: str) -> tuple | None:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return None
    nets = []
    for part in parts:
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            print(json.dumps({"door": "warning", "warning": "ignored a trusted proxy that is not an IP network", "value": part[:100]}), file=sys.stderr, flush=True)
    return tuple(nets)


def peer_trusted(peer: str, nets: tuple | None) -> bool:
    if nets is None:
        return True
    try:
        addr = ipaddress.ip_address(peer.split("%", 1)[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in nets)


class Alarm:
    def __init__(self, interval: float = WARN_INTERVAL):
        self.interval = interval
        self.last: dict = {}
        self.muted: dict = {}
        self.lock = threading.Lock()

    def sound(self, reason: str, fields: dict) -> bool:
        now = time.monotonic()
        with self.lock:
            if now - self.last.get(reason, -self.interval) < self.interval:
                self.muted[reason] = self.muted.get(reason, 0) + 1
                return False
            self.last[reason] = now
            muted = self.muted.pop(reason, 0)
        line = {"door": "warning", "warning": reason, **fields}
        if muted:
            line["suppressed"] = muted
        print(json.dumps(line), file=sys.stderr, flush=True)
        return True


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


def route_path(path: str) -> str:
    if not path.startswith("/"):
        path = urlsplit(path).path or "/"
    bare = unquote(path.split("?", 1)[0].split("#", 1)[0]).lower()
    segments = [segment.split(";", 1)[0] for segment in bare.split("/")]
    bare = "/".join(segment.rstrip(".") or segment for segment in segments)
    return re.sub(r"/{2,}", "/", bare).rstrip("/") or "/"


def shield_path(key: str) -> str:
    return route_path(key.split(" ", 1)[-1])


def unescape(text: str) -> str:
    return ESCAPED_CHAR.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def detection_text(text: str) -> str:
    for _ in range(DECODE_ROUNDS):
        decoded = unescape(unquote_plus(text))
        if decoded == text:
            break
        text = decoded
    return text.lower()


def looks_like_attack(path: str, body: str | bytes = "") -> bool:
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    norm_path = detection_text(path)
    if "\x00" in norm_path:
        return True
    text = norm_path + " " + detection_text(body)
    if ATTACK.search(text):
        return True
    collapsed = SQL_COMMENT.sub(" ", text)
    return collapsed != text and bool(ATTACK.search(collapsed))


def b64url_json(segment: str):
    try:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, TypeError):
        return None


def jwt_unsigned(token: str) -> bool:
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        return False
    header = b64url_json(parts[0])
    if not isinstance(header, dict) or not ("alg" in header or "typ" in header):
        return False
    alg = header.get("alg")
    return (isinstance(alg, str) and alg.strip().lower() == "none") or len(parts) == 2 or not parts[2]


def jwt_tampered(headers) -> bool:
    auth = headers.get("Authorization") or ""
    tokens = [auth[len(BEARER):]] if auth[:len(BEARER)].lower() == BEARER.lower() else []
    tokens += [c.partition("=")[2] for c in (headers.get("Cookie") or "").split(";")]
    return any(jwt_unsigned(t) for t in tokens if t.strip())


def inflate(data: bytes, wbits: int) -> bytes:
    out = b""
    while data:
        d = zlib.decompressobj(wbits)
        out += d.decompress(data, MAX_DECODED_BODY + 1 - len(out))
        if len(out) > MAX_DECODED_BODY or d.unconsumed_tail or not d.eof:
            raise ValueError("bad or oversized encoded body")
        data = d.unused_data
    return out


def inflate_deflate(data: bytes) -> bytes:
    try:
        return inflate(data, DEFLATE_WBITS[0])
    except zlib.error:
        return inflate(data, DEFLATE_WBITS[1])


DECODERS = {
    "gzip": lambda data: inflate(data, GZIP_WBITS),
    "x-gzip": lambda data: inflate(data, GZIP_WBITS),
    "deflate": inflate_deflate,
    "identity": lambda data: data,
}


def body_charset(ctype: str) -> str:
    m = CHARSET.search(ctype or "")
    return m.group(3) if m else ""


def utf8_ctype(ctype: str) -> str:
    return CHARSET.sub(lambda m: m.group(1) + "utf-8", ctype)


def decode_body(headers, body: bytes) -> tuple[str, dict | None]:
    decoded_from = {}
    codings = [c.strip().lower() for c in (headers.get("Content-Encoding") or "").split(",") if c.strip()]
    for coding in reversed(codings):
        if coding not in DECODERS:
            raise ValueError("unsupported content-encoding")
        body = DECODERS[coding](body)
    if [c for c in codings if c != "identity"]:
        decoded_from["content_encoding"] = ", ".join(codings)
    charset = body_charset(headers.get("Content-Type") or "")
    if not charset or codecs.lookup(charset).name == "utf-8":
        return body.decode("utf-8", "replace"), decoded_from or None
    decoded_from["charset"] = charset
    return body.decode(charset), decoded_from


def inspect_request(path: str, headers, body: bytes) -> Seen:
    try:
        text, decoded_from = decode_body(headers, body) if body else ("", None)
    except (ValueError, LookupError, zlib.error):
        return Seen(body.decode("utf-8", "replace"), None, True, True)
    return Seen(text, decoded_from, False, looks_like_attack(path, text) or jwt_tampered(headers))


def fetch_value(headers, name: str) -> str:
    return (headers.get(name) or "")[:FETCH_FIELD_MAX].strip().lower()


def browser_fetch(headers) -> bool:
    if fetch_value(headers, "Sec-Fetch-Site") not in FOREIGN_FETCH_SITES:
        return False
    if not fetch_value(headers, "Sec-Fetch-Mode") or not fetch_value(headers, "Sec-Fetch-Dest"):
        return False
    ua = headers.get("User-Agent") or ""
    return bool(BROWSER_UA.search(ua)) and not SCANNER_UA.search(ua)


def trusted_fetch(headers) -> bool:
    return not browser_fetch(headers)


def has_traversal(path: str) -> bool:
    low = path.lower()
    norm = detection_text(path)
    return ".." in low or "%2e" in low or ".." in norm or "\x00" in norm


def read_chunked(stream, limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        line = stream.readline(4096)
        if not line:
            raise BadRequest("truncated chunked body")
        if not CHUNK_SIZE.fullmatch(line):
            raise BadRequest("bad chunk size")
        size = int(line.split(b";", 1)[0].strip(), 16)
        if size == 0:
            for _ in range(MAX_TRAILERS):
                trailer = stream.readline(4096)
                if trailer in (b"", b"\r\n", b"\n"):
                    return b"".join(chunks)
            raise BadRequest("too many trailers")
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
    return str(max(1, int(until_of(entry) - time.time())))


def redact(value: str) -> str:
    scheme, sep, rest = value.partition(" ")
    if not sep or not scheme.isalpha() or len(scheme) > 16:
        scheme, sep, rest = "", "", value
    return f"{scheme}{sep}{rest[:6]}...[{len(rest)}]"


def redact_body(body: str) -> str:
    if body.lstrip()[:1] in ("{", "["):
        return SECRET_JSON_FIELD.sub(lambda m: f'{m.group(1)}"[redacted {len(m.group(2).strip(chr(34)))}]"', body)
    return SECRET_FORM_FIELD.sub(lambda m: f"{m.group(1)}[redacted {len(m.group(2))}]", body)


def redact_query(path: str) -> str:
    bare, sep, query = path.partition("?")
    if not sep:
        return path
    pairs = []
    for pair in query.split("&"):
        name, eq, value = pair.partition("=")
        if eq and value and SECRET_PARAM.search(unquote_plus(name)):
            pair = f"{name}=[redacted {len(value)}]"
        pairs.append(pair)
    return bare + sep + "&".join(pairs)


def disk_record(record: dict) -> dict:
    out = dict(record)
    if isinstance(out.get("path"), str):
        out["path"] = redact_query(out["path"])
    if isinstance(out.get("body"), str):
        out["body"] = redact_body(out["body"])
    headers = out.get("headers")
    if isinstance(headers, dict):
        out["headers"] = {k: redact(str(v)) if k.lower() in SECRET_HEADERS else v for k, v in headers.items()}
    return out


class DeadlineIO(io.RawIOBase):
    def __init__(self, inner, sock, window: Callable[[], float | None]):
        super().__init__()
        self.inner = inner
        self.sock = sock
        self.window = window

    def readable(self) -> bool:
        return True

    def readinto(self, b):
        timeout = self.window()
        if timeout is not None:
            self.sock.settimeout(timeout)
        return self.inner.readinto(b)

    def close(self) -> None:
        if not self.closed:
            self.inner.close()
        super().close()


class Config:
    def __init__(self, env=os.environ):
        self.host = env.get("DOOR_HOST", "0.0.0.0")
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
        self.lists_flush_seconds = float(env.get("DOOR_LISTS_FLUSH_SECONDS", "1"))
        self.list_max = int(env.get("DOOR_LIST_MAX", str(MAX_LIST_ENTRIES)))
        self.idle_seconds = float(env.get("DOOR_IDLE_SECONDS", "15"))
        self.max_threads = int(env.get("DOOR_MAX_THREADS", "256"))
        self.request_seconds = float(env.get("DOOR_REQUEST_SECONDS", "30"))
        self.max_conns_per_ip = int(env.get("DOOR_MAX_CONNS_PER_IP", "32"))
        self.listen_backlog = int(env.get("DOOR_LISTEN_BACKLOG", "128"))
        self.trust_client_ip_header = env.get("DOOR_TRUST_CLIENT_IP_HEADER", "1").strip().lower() not in OFF_VALUES
        self.trusted_proxies = proxy_networks(env.get("DOOR_TRUSTED_PROXIES", env.get("TRUSTED_PROXIES", "")))
        self.honeypot_repeat_seconds = float(env.get("DOOR_HONEYPOT_REPEAT_SECONDS", "600"))

    @property
    def upstream(self) -> str:
        return f"{self.upstream_host}:{self.upstream_port}"


def until_of(entry) -> float:
    try:
        return float(entry.get("until", 0))
    except (AttributeError, TypeError, ValueError):
        return 0.0


class Lists:
    def __init__(self, path: Path, flush_seconds: float = 1.0, cap: int = MAX_LIST_ENTRIES):
        self.path = path
        self.cap = cap
        self.flush_seconds = flush_seconds
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.data = {name: {} for name in LIST_NAMES}
        self.dirty = False
        self.shield_index: dict | None = None
        self.stopped = threading.Event()
        self._load()
        threading.Thread(target=self._flush_loop, daemon=True).start()

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
                    self.data[name] = {k: v for k, v in loaded[name].items() if isinstance(v, dict)}

    def _flush_loop(self) -> None:
        while not self.stopped.wait(self.flush_seconds):
            self.flush()

    def flush(self) -> None:
        with self.write_lock:
            with self.lock:
                if not self.dirty:
                    return
                copy = {k: dict(v) for k, v in self.data.items()}
                self.dirty = False
            try:
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(copy, indent=2))
                tmp.replace(self.path)
            except OSError:
                with self.lock:
                    self.dirty = True

    def close(self) -> None:
        self.stopped.set()
        self.flush()

    def _changed(self, kind: str) -> None:
        self.dirty = True
        if kind == "shield":
            self.shield_index = None

    def _trim(self, kind: str) -> None:
        entries = self.data[kind]
        if len(entries) <= self.cap:
            return
        now = time.time()
        for key in [k for k, e in entries.items() if until_of(e) < now]:
            del entries[key]
        if len(entries) > self.cap:
            for key in sorted(entries, key=lambda k: until_of(entries[k]))[: len(entries) - int(self.cap * 0.9)]:
                del entries[key]

    def active(self, kind: str, ip: str) -> dict | None:
        with self.lock:
            entry = self.data[kind].get(ip)
            if not entry:
                return None
            if until_of(entry) < time.time():
                del self.data[kind][ip]
                self._changed(kind)
                return None
            return entry

    def shielded(self, path: str) -> bool:
        with self.lock:
            if self.shield_index is None:
                self.shield_index = {}
                for key in self.data["shield"]:
                    self.shield_index.setdefault(shield_path(key), []).append(key)
            now = time.time()
            return any(until_of(self.data["shield"].get(k)) >= now for k in self.shield_index.get(route_path(path), ()))

    def put(self, kind: str, entries: dict, allowlist: set) -> dict:
        with self.lock:
            skipped = [ip for ip in entries if ip in allowlist]
            for ip, entry in entries.items():
                if ip not in allowlist:
                    self.data[kind][ip] = entry
            self._trim(kind)
            self._changed(kind)
            return {"ok": True, "skipped_allowlisted": skipped}

    def add(self, kind: str, key: str, seconds: float, reason: str, allowlist: set) -> None:
        if key in allowlist:
            return
        with self.lock:
            now = time.time()
            current = self.data[kind].get(key)
            until = now + seconds
            if current and until_of(current) > until:
                return
            self.data[kind][key] = {"until": until, "reason": reason, "ts": now}
            self._trim(kind)
            self._changed(kind)

    def delete(self, kind: str, ip: str) -> bool:
        with self.lock:
            existed = self.data[kind].pop(ip, None) is not None
            if existed:
                self._changed(kind)
            return existed

    def snapshot(self) -> dict:
        with self.lock:
            now = time.time()
            return {k: {ip: e for ip, e in v.items() if until_of(e) >= now} for k, v in self.data.items()}


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
        self.lists = Lists(cfg.data_dir / "lists.json", cfg.lists_flush_seconds, cfg.list_max)
        self.log_path = cfg.data_dir / "access.log"
        self.log_lock = threading.Lock()
        self.tarpit_lock = threading.Lock()
        self.tarpit_busy: dict = {}
        self.tarpit_total = 0
        self.conn_lock = threading.Lock()
        self.conns: dict = {}
        self.honeypot_lock = threading.Lock()
        self.honeypot_pushed: dict = {}
        self.canaries = self._load_canaries()
        self.pusher = Pusher(cfg.events_url, cfg.flush_seconds, self.write_log, cfg.events_token)
        self.alarm = Alarm()

    def _load_canaries(self) -> dict:
        if not self.cfg.canaries_file.exists():
            return {}
        return json.loads(self.cfg.canaries_file.read_text())

    @property
    def honeypot(self) -> dict:
        return self.canaries.get("honeypot", {})

    @property
    def has_canaries(self) -> bool:
        return any(isinstance(v, str) and v for v in self.honeypot.values())

    def warnings(self) -> list:
        if self.has_canaries:
            return []
        return [f"no honeypot canaries in {self.cfg.canaries_file}: /.env is proxied like any request and bait reuse is not detected"]

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

    def honeypot_repeat(self, ip: str, trusted: bool) -> bool:
        fresh = trusted and ip not in self.cfg.allowlist and not (self.took_bait(ip) and self.is_listed("tarpit", ip))
        key = (ip, trusted)
        now = time.time()
        with self.honeypot_lock:
            last = self.honeypot_pushed.get(key)
            if not fresh and last is not None and now - last < self.cfg.honeypot_repeat_seconds:
                return True
            if key not in self.honeypot_pushed and len(self.honeypot_pushed) >= self.cfg.list_max:
                cutoff = now - self.cfg.honeypot_repeat_seconds
                self.honeypot_pushed = {k: v for k, v in self.honeypot_pushed.items() if v > cutoff}
                if len(self.honeypot_pushed) >= self.cfg.list_max:
                    self.honeypot_pushed = dict(sorted(self.honeypot_pushed.items(), key=lambda kv: kv[1])[-(self.cfg.list_max // 2):])
            self.honeypot_pushed[key] = now
            return False

    def claim_conn(self, key: str) -> bool:
        with self.conn_lock:
            held = self.conns.get(key, 0)
            if held >= self.cfg.max_conns_per_ip:
                return False
            self.conns[key] = held + 1
            return True

    def release_conn(self, key: str | None) -> None:
        if key is None:
            return
        with self.conn_lock:
            left = self.conns.get(key, 1) - 1
            if left > 0:
                self.conns[key] = left
            else:
                self.conns.pop(key, None)

    def block_bait_reuse(self, ip: str) -> None:
        self.lists.add("block", ip, self.cfg.block_seconds, "reused honeypot credentials", self.cfg.allowlist)

    def shielded(self, ip: str, path: str, seen: Seen) -> bool:
        return seen.attack and ip not in self.cfg.allowlist and self.lists.shielded(path)

    def unblock_extras(self, kind: str, target: str) -> None:
        if kind == "block":
            self.lists.delete("bait", target)

    def close(self) -> None:
        self.lists.close()

    def write_log(self, record: dict) -> None:
        line = json.dumps(disk_record(record), separators=(",", ":"))
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
        timeout = cfg.idle_seconds

        def log_message(self, fmt, *args):
            pass

        def version_string(self) -> str:
            return self.server_version

        def setup(self):
            super().setup()
            self.deadline = None
            self.conn_key = None
            self.rfile = io.BufferedReader(DeadlineIO(self.rfile.detach(), self.connection, self.read_window))
            self.crowded = not cfg.trust_client_ip_header and not self.hold_connection(client_key(self.client_address[0]))

        def handle(self):
            if self.crowded:
                self.close_connection = True
                try:
                    self.wfile.write(BUSY_RESPONSE)
                except OSError:
                    pass
                return
            super().handle()

        def finish(self):
            try:
                super().finish()
            finally:
                door.release_conn(self.conn_key)

        def handle_one_request(self):
            self.deadline = time.monotonic() + cfg.request_seconds
            try:
                super().handle_one_request()
            finally:
                if cfg.trust_client_ip_header:
                    door.release_conn(self.conn_key)
                    self.conn_key = None

        def read_window(self) -> float | None:
            if self.deadline is None:
                return None
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("request took too long to arrive")
            return min(cfg.idle_seconds, left)

        def reading_done(self) -> None:
            self.deadline = None
            self.connection.settimeout(cfg.idle_seconds)

        def hold_connection(self, key: str) -> bool:
            if key == self.conn_key:
                return True
            if not door.claim_conn(key):
                return False
            door.release_conn(self.conn_key)
            self.conn_key = key
            return True

        def header_trusted(self) -> bool:
            return cfg.trust_client_ip_header and peer_trusted(self.client_address[0], cfg.trusted_proxies)

        def claimed_ip(self) -> str:
            if not self.header_trusted():
                return ""
            return valid_ip(self.headers.get(CLIENT_IP_HEADER) or "")

        def check_claim(self) -> None:
            raw = self.headers.get(CLIENT_IP_HEADER)
            if raw is None or not cfg.trust_client_ip_header:
                return
            if not self.header_trusted():
                reason = "client ip header from an untrusted peer"
            elif not valid_ip(raw):
                reason = "invalid client ip header"
            else:
                return
            door.alarm.sound(reason, {"peer": self.client_address[0], "value": raw[:100], "path": bare_path(self.path)[:200]})

        def client_ip(self) -> str:
            ip = client_key(self.claimed_ip() or self.client_address[0])
            if ip in cfg.allowlist and self.headers.get("X-Bouncer-Stranger"):
                return STRANGER
            return ip

        def read_body(self) -> bytes:
            try:
                return self.read_framed_body()
            finally:
                self.reading_done()

        def read_framed_body(self) -> bytes:
            te = self.headers.get_all("Transfer-Encoding") or []
            if te:
                codings = [c.strip().lower() for v in te for c in v.split(",") if c.strip()]
                if codings != ["chunked"]:
                    raise BadRequest("unsupported transfer-encoding")
                return read_chunked(self.rfile, MAX_REQUEST_BODY)
            raws = {v.strip() for v in self.headers.get_all("Content-Length") or []}
            if not raws:
                return b""
            raw = raws.pop()
            if raws or not DIGITS.fullmatch(raw):
                raise BadRequest("invalid Content-Length")
            length = int(raw)
            if length > MAX_REQUEST_BODY:
                raise PayloadTooLarge("body too large")
            body = self.rfile.read(length) if length > 0 else b""
            if len(body) < length:
                raise BadRequest("truncated body")
            return body

        def write_body(self, body: bytes) -> None:
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def send(self, status: int, body: bytes, ctype: str = TEXT_TYPE, extra: dict | None = None) -> int:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            try:
                self.end_headers()
                self.write_body(body)
            except OSError:
                self.close_connection = True
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
            target = req.target
            if not target and req.body:
                try:
                    payload = json.loads(req.body)
                except ValueError:
                    return self.send(400, b"bad json")
                target = payload.get("target") if isinstance(payload, dict) else None
                if not isinstance(target, str):
                    return self.send(400, b"bad json")
            if not target:
                return self.method_not_allowed()
            existed = door.lists.delete(req.kind, target)
            door.unblock_extras(req.kind, target)
            return self.send_json({"ok": True, "existed": existed})

        ADMIN_ACTIONS = {
            "GET": admin_snapshot,
            "PUT": admin_put,
            "DELETE": admin_delete,
        }

        def upstream_headers(self) -> dict:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() not in CLIENT_FORWARD_HEADERS}
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
            try:
                self.relay(resp, data)
            except OSError:
                self.close_connection = True
            finally:
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

        def canary_haystack(self, seen: Seen) -> str:
            headers = " ".join(v for k, v in self.headers.items() if k.lower() not in CANARY_SKIP_HEADERS)
            return self.path + " " + seen.text + " " + headers

        def forward(self, ip: str, body: bytes, seen: Seen) -> Outcome:
            reuse = bool(door.canary_hits(self.canary_haystack(seen)))
            kind = EventKind.CANARY_REUSE if reuse else EventKind.REQUEST
            slow = door.tarpit(ip)
            if slow == Slow.REFUSE:
                wait = str(max(1, int(cfg.tarpit_seconds)))
                return Outcome(EventKind.TARPITTED, 429, self.send(429, b"Slow down.\n", extra={"Retry-After": wait}))
            if reuse and trusted_fetch(self.headers) and door.took_bait(ip):
                door.block_bait_reuse(ip)
            status, size = self.proxy(body)
            if slow == Slow.SLOWED and kind == EventKind.REQUEST:
                kind = EventKind.TARPITTED
            return Outcome(kind, status, size)

        def refuse_blocked(self, block: dict) -> Outcome:
            refused = b"You're not on the list. The bouncer remembers faces. Come back later.\n"
            return Outcome(EventKind.REFUSED, 403, self.send(403, refused, extra={"Retry-After": retry_after(block)}))

        def respond(self, ip: str, body: bytes, seen: Seen) -> Outcome:
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return Outcome(EventKind.REQUEST, 400, self.send(400, b"websocket not supported, use polling"))
            if bare_path(self.path) == "/.env" and door.has_canaries:
                trusted = trusted_fetch(self.headers)
                repeat = door.honeypot_repeat(ip, trusted)
                if trusted:
                    door.mark_bait(ip)
                return Outcome(EventKind.HONEYPOT, 200, self.send(200, door.honeypot_env().encode()), repeat)
            if door.shielded(ip, self.path, seen):
                shield = b"This route is shielded until its security fix is merged.\n"
                return Outcome(EventKind.SHIELDED, 403, self.send(403, shield))
            return self.forward(ip, body, seen)

        def build_record(self, started: float, ip: str, body: bytes, outcome: Outcome, seen: Seen = Seen()) -> dict:
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
                record["body"] = seen.text[:MAX_STORED_BODY]
            if len(seen.text) > MAX_STORED_BODY:
                record["truncated"] = True
            if seen.attack:
                record["attack_shaped"] = True
            if seen.decoded_from:
                record["decoded_from"] = seen.decoded_from
            if seen.decode_failed:
                record["decode_failed"] = True
            ctype = self.headers.get("Content-Type")
            if ctype:
                record["ctype"] = utf8_ctype(ctype) if seen.decoded_from and "charset" in seen.decoded_from else ctype
            for field, name in FETCH_FIELDS:
                value = self.headers.get(name)
                if value:
                    record[field] = value[:FETCH_FIELD_MAX]
            if outcome.kind in (EventKind.CANARY_REUSE, EventKind.HONEYPOT):
                record["took_bait"] = door.took_bait(ip)
            kept = {k: v for k, v in self.headers.items() if k.lower() in REPLAY_HEADERS}
            if kept:
                record["headers"] = kept
            return record

        def handle_any(self):
            started = time.time()
            self.check_claim()
            ip = self.client_ip()
            if not self.hold_connection(ip):
                self.reading_done()
                self.close_connection = True
                self.send(503, b"Busy.\n", extra={"Retry-After": "1", "Connection": "close"})
                return
            block = None if self.path.startswith(ADMIN_PREFIX) else door.listed_entry("block", ip)
            if block:
                self.reading_done()
                self.close_connection = True
                record = self.build_record(started, ip, b"", self.refuse_blocked(block))
                door.write_log(record)
                door.pusher.push(record)
                return
            try:
                body = self.read_body()
            except OSError:
                self.close_connection = True
                return
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
            seen = inspect_request(self.path, self.headers, body)
            outcome = self.respond(ip, body, seen)
            record = self.build_record(started, ip, body, outcome, seen)
            door.write_log(record)
            if not outcome.repeat and door.should_push(outcome.kind, self.command, self.path):
                door.pusher.push(record)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any

    return Handler


class DoorServer(ThreadingHTTPServer):
    daemon_threads = True
    busy_response = BUSY_RESPONSE

    def __init__(self, address, handler, max_threads: int, backlog: int = 128):
        self.slots = threading.BoundedSemaphore(max_threads)
        self.request_queue_size = backlog
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.refuse_busy(request)
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

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)

    def refuse_busy(self, request) -> None:
        try:
            request.settimeout(1)
            request.sendall(self.busy_response)
        except OSError:
            pass
        self.shutdown_request(request)


def make_server(door: Door, address: tuple) -> DoorServer:
    return DoorServer(address, make_handler(door), door.cfg.max_threads, door.cfg.listen_backlog)


def main(argv=None):
    cfg = Config()
    door = Door(cfg)
    for warning in door.warnings():
        print(json.dumps({"door": "warning", "warning": warning}), file=sys.stderr, flush=True)
    server = make_server(door, (cfg.host, cfg.port))
    print(json.dumps({"door": "listening", "host": cfg.host, "port": cfg.port, "upstream": cfg.upstream}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
