from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qsl, urlsplit

DROP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-authenticate",
}
DROP_PREFIXES = ("sprite-", "x-forwarded-", "fly-", "via")
PREVIEW = 8192
PATCH_PREFIXES = ("routes/", "lib/", "models/", "server.ts")
MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "tsconfig.json", ".npmrc"}

BEARER = "Bearer "
JSON_HEADERS = {"Content-Type": "application/json"}
POLL_SECONDS = 0.25
ERROR_CHARS = 300
MAX_VARIANTS = 4
MAX_NORMALS = 4
NAME_CHARS = 40
FINGERPRINT_CHARS = 16
MIN_ECHO = 4
JSON_LITERALS = ("true", "false", "null")
MARKUP = re.compile(r"<\s*[a-z!/]|[\s\"'/<]on[a-z]+\s*=|javascript\s*:", re.IGNORECASE)
VOLATILE_KEYS = {"id", "bid", "uid", "token", "time", "date", "timestamp", "uuid", "nonce", "csrf", "session", "expires", "exp", "iat", "etag"}
CAMEL_VOLATILE = re.compile(r"[a-z0-9](?:Id|ID|At|Token|Time|Date|Stamp)$")
SNAKE_VOLATILE = re.compile(r"_(?:id|at|token|time|date)$", re.IGNORECASE)
VOLATILE_TEXT = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?"
    r"|eyJ[\w-]*\.[\w-]*\.[\w-]*"
    r"|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    r"|\b[0-9a-fA-F]{32,}\b"
)
MAX_BODY = 4 * 1024 * 1024
BUSY = {"ok": False, "stage": "busy"}
LOCALHOST = "127.0.0.1"
COPIED_DIRS = {"data", "ftp", "uploads", "logs", "i18n", ".well-known"}
FRONTEND_DIR = "frontend"
FRONTEND_COPIED = {"dist"}
SKIPPED_ENTRIES = {".git", ".bouncer-src-bak"}
PID_FILE = "node.pid"
LOG_FILE = "node.log"
LOOPBACK_JS = """const net = require('node:net')
const listen = net.Server.prototype.listen
net.Server.prototype.listen = function (...args) {
  if ((typeof args[0] === 'number' || /^\\d+$/.test(String(args[0]))) && typeof args[1] !== 'string') args.splice(1, 0, '127.0.0.1')
  return listen.apply(this, args)
}
const ownPort = String(process.env.PORT || '')
const loopback = ['127.0.0.1', 'localhost', '[::1]', '::1']
const ownAddress = (host, port) => loopback.includes(String(host || 'localhost')) && ownPort !== '' && String(port) === ownPort
const connect = net.Socket.prototype.connect
net.Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0]
  const options = first !== null && typeof first === 'object' ? first : { port: first, host: typeof args[1] === 'string' ? args[1] : undefined }
  if ((options.path === undefined || options.path === null) && !ownAddress(options.host, options.port)) {
    process.nextTick(() => this.destroy(new Error('replay copies stay offline')))
    return this
  }
  return connect.apply(this, args)
}
const localFetch = globalThis.fetch
if (localFetch) {
  globalThis.fetch = function (input, init) {
    let host = ''
    let port = ''
    try {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url)
      host = url.hostname
      port = url.port || (url.protocol === 'https:' ? '443' : '80')
    } catch {}
    if (!ownAddress(host, port)) return Promise.reject(new TypeError('replay copies stay offline'))
    return localFetch.call(this, input, init)
  }
}
"""
STOP_SECONDS = 5
TAKE_SLACK_SECONDS = 15
LOG_TAIL = 600


class PayloadTooLarge(Exception):
    pass


def elapsed_ms(started: float) -> int:
    return int((time.time() - started) * 1000)


def newly_solved(before: dict, after: dict) -> dict:
    return {k: v for k, v in after.items() if k not in before}


def empty_canary() -> dict:
    return {"planted": False, "strings": []}


class Config:
    def __init__(self, env=os.environ):
        self.port = int(env.get("RUNNER_PORT", "8080"))
        self.bind = env.get("RUNNER_HOST", "0.0.0.0")
        self.secret_sha256 = env.get("RUNNER_SECRET_SHA256", "")
        target = urlsplit(env.get("RUNNER_TARGET", "http://127.0.0.1:3000"))
        self.host = target.hostname or "127.0.0.1"
        self.port_target = target.port or 80
        self.service = env.get("RUNNER_SERVICE", "juice")
        self.reset_cmd = env.get("RUNNER_RESET_CMD", f"sprite-env services restart {self.service}")
        self.ready_path = env.get("RUNNER_READY_PATH", "/rest/admin/application-version")
        self.ready_timeout = float(env.get("RUNNER_READY_TIMEOUT", "60"))
        self.app_dir = Path(env.get("RUNNER_APP_DIR", "/home/sprite/juice-shop"))
        self.build_cmd = env.get("RUNNER_BUILD_CMD", "./node_modules/.bin/tsc")
        self.build_dir = env.get("RUNNER_BUILD_DIR", "build")
        self.busy_wait = float(env.get("RUNNER_BUSY_WAIT", "10"))
        self.settle = float(env.get("RUNNER_SETTLE_SECONDS", "0.5"))
        self.pool_size = max(0, int(env.get("RUNNER_POOL_SIZE", "0")))
        self.pool_base_port = int(env.get("RUNNER_POOL_BASE_PORT", "3100"))
        self.pool_dir = Path(env.get("RUNNER_POOL_DIR") or self.app_dir.parent / (self.app_dir.name + "-pool"))
        self.node = env.get("RUNNER_NODE", "node")
        self.entry = env.get("RUNNER_APP_ENTRY", "build/app")
        self.node_env = env.get("RUNNER_NODE_ENV", "production")


class Target:
    def __init__(self, cfg: Config, host: str | None = None, port: int | None = None):
        self.cfg = cfg
        self.host = host or cfg.host
        self.port = port or cfg.port_target

    def call(self, method: str, path: str, headers: dict | None = None, body: bytes | None = None, timeout: float = 30) -> dict:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        started = time.time()
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.getheaders()),
                "body": data.decode("utf-8", "replace"),
                "ms": elapsed_ms(started),
            }
        except (OSError, http.client.HTTPException) as exc:
            return {"status": 0, "error": str(exc)[:ERROR_CHARS], "body": "", "headers": {}, "ms": elapsed_ms(started)}
        finally:
            conn.close()

    def ready(self) -> bool:
        return self.call("GET", self.cfg.ready_path, timeout=3).get("status") == 200

    def wait_ready(self) -> bool:
        deadline = time.time() + self.cfg.ready_timeout
        while time.time() < deadline:
            if self.ready():
                return True
            time.sleep(POLL_SECONDS)
        return False

    def solved(self) -> dict:
        r = self.call("GET", "/api/Challenges")
        try:
            return {
                c["key"]: {"name": c.get("name"), "difficulty": c.get("difficulty"), "category": c.get("category")}
                for c in json.loads(r["body"])["data"]
                if c.get("solved")
            }
        except (ValueError, KeyError, TypeError):
            return {}


def clean_headers(raw: dict | None) -> dict:
    return {
        k: v
        for k, v in (raw or {}).items()
        if k.lower() not in DROP_HEADERS and not k.lower().startswith(DROP_PREFIXES)
    }


def plant_canary(target: Target) -> dict:
    tag = secrets.token_hex(6)
    email = f"canary-{tag}@bouncer.test"
    password = f"Canary-{secrets.token_hex(8)}!"
    body = json.dumps({"email": email, "password": password, "passwordRepeat": password, "securityQuestion": None, "securityAnswer": ""}).encode()
    r = target.call("POST", "/api/Users", dict(JSON_HEADERS), body)
    md5 = hashlib.md5(password.encode()).hexdigest()
    return {"planted": r.get("status") in (200, 201), "strings": [email, md5], "email": email, "password": password}


def find_canaries(text: str, canaries: list) -> list:
    return [c for c in canaries if c and c in text]


def reset_error(stdout: str) -> str:
    error = ""
    for raw in stdout.splitlines():
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if msg.get("type") == "error":
            error = str(msg.get("data"))[:ERROR_CHARS]
    return error


def result_count(body: str) -> int | None:
    try:
        data = json.loads(body)
        if isinstance(data.get("data"), list):
            return len(data["data"])
        if "authentication" in data:
            return 1
    except (ValueError, AttributeError):
        pass
    return None


def is_allowed_patch_path(rel: str) -> bool:
    if rel.startswith("/") or ".." in Path(rel).parts or Path(rel).name.lower() in MANIFESTS:
        return False
    return rel.startswith(PATCH_PREFIXES)


def is_volatile_key(key) -> bool:
    key = str(key)
    return key.lower() in VOLATILE_KEYS or bool(CAMEL_VOLATILE.search(key) or SNAKE_VOLATILE.search(key))


def mask_volatile(value):
    if isinstance(value, dict):
        return {k: "<v>" if is_volatile_key(k) and not isinstance(v, (dict, list)) else mask_volatile(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_volatile(v) for v in value]
    return value


def json_strings(value) -> list:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in json_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in json_strings(v)]
    return []


def request_values(req: dict) -> list:
    values = [v for _, v in parse_qsl(urlsplit(str(req.get("path") or "")).query, keep_blank_values=True)]
    body = req.get("body")
    if isinstance(body, str) and body:
        values.append(body)
        try:
            values.extend(json_strings(json.loads(body)))
        except ValueError:
            values.extend(v for _, v in parse_qsl(body, keep_blank_values=True))
    usable = {v for v in values if len(v) >= MIN_ECHO and v.lower() not in JSON_LITERALS}
    return sorted(usable, key=len, reverse=True)


def response_type(headers: dict) -> str:
    return " ".join(str(v) for k, v in (headers or {}).items() if str(k).lower() == "content-type").lower()


def reflected_markup(body: str, headers: dict, req: dict) -> bool:
    if "html" not in response_type(headers):
        return False
    return any(MARKUP.search(v) and v in body for v in request_values(req))


def normalize_body(text: str, canaries: list, echoes: list) -> str:
    for value in canaries:
        if value:
            text = text.replace(value, "<canary>")
    for value in echoes:
        text = text.replace(value, "<input>")
    try:
        text = json.dumps(mask_volatile(json.loads(text)), sort_keys=True)
    except ValueError:
        pass
    return VOLATILE_TEXT.sub("<v>", text)


def fingerprint(text: str, canaries: list, echoes: list) -> str:
    return hashlib.sha256(normalize_body(text, canaries, echoes).encode()).hexdigest()[:FINGERPRINT_CHARS]


def observation(sent: dict) -> dict:
    return {"status": sent.get("status"), "count": sent.get("count"), "fingerprint": sent.get("fingerprint")}


def request_list(raw, limit: int) -> list:
    return [r for r in (raw or []) if isinstance(r, dict)][:limit]


def oracle_pair(raw) -> list:
    if not isinstance(raw, dict) or not all(isinstance(raw.get(k), dict) for k in ("true", "false")):
        return []
    return [raw["true"], raw["false"]]


class Box:
    def __init__(self, target: Target, canary: dict, slot=None):
        self.target = target
        self.canary = canary
        self.slot = slot

    def canary_values(self) -> list:
        return [v for v in (self.canary.get("email"), self.canary.get("password"), *self.canary["strings"]) if v]


def take_result(ok: bool, started: float, error: str = "", canary: dict | None = None, stderr: str = "", restarted: bool = True) -> dict:
    return {
        "ok": ok,
        "ms": elapsed_ms(started),
        "restarted": restarted,
        "error": error,
        "canary_planted": bool(canary and canary.get("planted")),
        "stderr": stderr,
    }


class CommandApp:
    width = 1

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.target = Target(cfg)

    def start(self) -> None:
        pass

    def close(self) -> None:
        pass

    def ready(self) -> bool:
        return self.target.ready()

    @contextmanager
    def hold(self) -> Iterator[None]:
        yield

    def rebuild(self) -> None:
        pass

    def give(self, box: Box) -> None:
        pass

    def service_started(self) -> str | None:
        if not self.cfg.service:
            return None
        try:
            out = subprocess.run(
                ["sprite-env", "services", "get", self.cfg.service], capture_output=True, text=True, timeout=10
            ).stdout
            return json.loads(out)["state"].get("started_at")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return None

    def wait_restarted(self, before: str) -> bool:
        deadline = time.time() + self.cfg.ready_timeout
        while time.time() < deadline:
            now = self.service_started()
            if now and now != before:
                return True
            time.sleep(POLL_SECONDS)
        return False

    def take(self) -> tuple:
        started = time.time()
        before = self.service_started()
        proc = subprocess.run(self.cfg.reset_cmd, shell=True, capture_output=True, text=True, timeout=120)
        error = reset_error(proc.stdout)
        restarted = True if before is None or error else self.wait_restarted(before)
        ok = proc.returncode == 0 and not error and restarted and self.target.wait_ready()
        canary = plant_canary(self.target) if ok else empty_canary()
        info = take_result(ok, started, error, canary, proc.stderr[-ERROR_CHARS:], restarted)
        return (Box(self.target, canary) if ok else None), info


class Slot:
    def __init__(self, index: int, port: int, path: Path):
        self.index = index
        self.port = port
        self.path = path
        self.proc: subprocess.Popen | None = None
        self.state = "new"
        self.gen = -1
        self.leased = False
        self.canary = empty_canary()
        self.error = ""


def log_tail(path: Path) -> str:
    try:
        return path.read_bytes()[-LOG_TAIL:].decode("utf-8", "replace")
    except OSError:
        return ""


def mirror_app(app_dir: Path, dest: Path, skip: set) -> None:
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    for entry in app_dir.iterdir():
        if entry.name in skip:
            continue
        if entry.name in COPIED_DIRS and entry.is_dir():
            shutil.copytree(entry, dest / entry.name, symlinks=True)
        elif entry.name == FRONTEND_DIR and entry.is_dir():
            (dest / entry.name).mkdir()
            for sub in entry.iterdir():
                if sub.name in FRONTEND_COPIED and sub.is_dir():
                    shutil.copytree(sub, dest / entry.name / sub.name, symlinks=True)
                else:
                    (dest / entry.name / sub.name).symlink_to(sub)
        else:
            (dest / entry.name).symlink_to(entry)


def stale_node(pid_file: Path, entry: str) -> int | None:
    try:
        pid = int(pid_file.read_text().strip())
        command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return pid if entry in command else None


class Pool:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.width = cfg.pool_size
        self.cond = threading.Condition()
        self.gen = 0
        self.held = 0
        self.closed = False
        self.slots = [Slot(i, cfg.pool_base_port + i, cfg.pool_dir / f"copy-{i}") for i in range(cfg.pool_size)]
        self.threads: list = []

    @property
    def preload(self) -> Path:
        return self.cfg.pool_dir / "loopback.js"

    def skipped(self) -> set:
        return SKIPPED_ENTRIES | {self.cfg.build_dir + ".bouncer-bak", self.cfg.pool_dir.name}

    def start(self) -> None:
        self.cfg.pool_dir.mkdir(parents=True, exist_ok=True)
        self.preload.write_text(LOOPBACK_JS)
        for slot in self.slots:
            pid = stale_node(slot.path / PID_FILE, self.cfg.entry)
            if pid:
                kill_group(pid)
        for slot in self.slots:
            thread = threading.Thread(target=self._keep, args=(slot,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self) -> None:
        with self.cond:
            self.closed = True
            self.cond.notify_all()
        for thread in self.threads:
            thread.join(STOP_SECONDS * 2)
        for slot in self.slots:
            self._stop(slot)

    def ready(self) -> bool:
        with self.cond:
            return any(s.state == "fresh" and s.gen == self.gen for s in self.slots)

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self.cond:
            self.held += 1
        try:
            yield
        finally:
            with self.cond:
                self.held -= 1
                self.cond.notify_all()

    def rebuild(self) -> None:
        with self.cond:
            self.gen += 1
            self.cond.notify_all()

    def _needs_boot(self, slot: Slot) -> bool:
        if slot.leased or self.held or self.closed:
            return False
        return slot.state in ("new", "down", "used") or (slot.state in ("fresh", "failed") and slot.gen != self.gen)

    def _keep(self, slot: Slot) -> None:
        while True:
            with self.cond:
                while not self._needs_boot(slot):
                    if self.closed:
                        return
                    self.cond.wait()
                first = slot.state == "new"
                gen = self.gen
                slot.state = "starting"
            ok, error, canary = self._boot(slot, first, gen)
            with self.cond:
                if self.closed:
                    self._stop(slot)
                    return
                if self._superseded(gen):
                    slot.state = "down"
                    continue
                slot.gen, slot.canary, slot.error = gen, canary, error
                slot.state = "fresh" if ok else "failed"
                self.cond.notify_all()

    def _superseded(self, gen: int) -> bool:
        return self.closed or bool(self.held) or gen != self.gen

    def _boot(self, slot: Slot, first: bool, gen: int) -> tuple:
        self._stop(slot)
        try:
            if first or not slot.path.is_dir():
                mirror_app(self.cfg.app_dir, slot.path, self.skipped())
            log = open(slot.path / LOG_FILE, "wb")
        except OSError as exc:
            return False, f"could not prepare copy {slot.index}: {exc}"[:ERROR_CHARS], empty_canary()
        env = dict(os.environ, PORT=str(slot.port), NODE_ENV=self.cfg.node_env)
        try:
            slot.proc = subprocess.Popen(
                [self.cfg.node, "--require", str(self.preload), self.cfg.entry],
                cwd=slot.path, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except OSError as exc:
            return False, f"could not start copy {slot.index}: {exc}"[:ERROR_CHARS], empty_canary()
        finally:
            log.close()
        (slot.path / PID_FILE).write_text(str(slot.proc.pid))
        target = Target(self.cfg, LOCALHOST, slot.port)
        deadline = time.time() + self.cfg.ready_timeout
        while not target.ready():
            if slot.proc.poll() is not None:
                return False, f"copy {slot.index} exited with {slot.proc.returncode}: {log_tail(slot.path / LOG_FILE)}"[-ERROR_CHARS:], empty_canary()
            if self._superseded(gen):
                self._stop(slot)
                return False, "superseded", empty_canary()
            if time.time() > deadline:
                return False, f"copy {slot.index} not ready after {self.cfg.ready_timeout:.0f}s", empty_canary()
            time.sleep(POLL_SECONDS)
        canary = plant_canary(target)
        if not canary["planted"]:
            return False, f"copy {slot.index} refused the canary user", canary
        return True, "", canary

    def _stop(self, slot: Slot) -> None:
        proc, slot.proc = slot.proc, None
        if proc and proc.poll() is None:
            kill_group(proc.pid, proc)

    def take(self) -> tuple:
        started = time.time()
        deadline = started + self.cfg.ready_timeout + STOP_SECONDS + TAKE_SLACK_SECONDS
        with self.cond:
            while True:
                for slot in self.slots:
                    if slot.state == "fresh" and slot.gen == self.gen and not slot.leased:
                        slot.leased, slot.state = True, "leased"
                        return Box(Target(self.cfg, LOCALHOST, slot.port), slot.canary, slot), take_result(True, started, canary=slot.canary, restarted=False)
                idle = [s for s in self.slots if not s.leased]
                if idle and all(s.state == "failed" and s.gen == self.gen for s in idle):
                    error = idle[0].error
                    for slot in idle:
                        slot.state = "down"
                    self.cond.notify_all()
                    return None, take_result(False, started, error or "no replay copy would start", restarted=False)
                remaining = deadline - time.time()
                if remaining <= 0 or self.closed:
                    return None, take_result(False, started, "timed out waiting for a fresh replay copy", restarted=False)
                self.cond.wait(remaining)

    def give(self, box: Box) -> None:
        slot = box.slot
        if slot is None:
            return
        with self.cond:
            slot.leased, slot.state = False, "used"
            self.cond.notify_all()


def kill_group(pid: int, proc: subprocess.Popen | None = None) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.time() + STOP_SECONDS
        while time.time() < deadline:
            if proc is not None and proc.poll() is not None:
                return
            if proc is None:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return
            time.sleep(0.05)


def make_app(cfg: Config):
    return Pool(cfg) if cfg.pool_size > 0 else CommandApp(cfg)


class Runner:
    def __init__(self, cfg: Config, app=None):
        self.cfg = cfg
        self.app = app or make_app(cfg)
        self.lock = threading.Lock()
        self.current: Box | None = None
        self.recover_staged()

    def start(self) -> None:
        self.app.start()

    def close(self) -> None:
        self.app.close()

    @property
    def build_path(self) -> Path:
        return self.cfg.app_dir / self.cfg.build_dir

    @property
    def backup_path(self) -> Path:
        return self.cfg.app_dir / (self.cfg.build_dir + ".bouncer-bak")

    @property
    def src_backup_path(self) -> Path:
        return self.cfg.app_dir / ".bouncer-src-bak"

    def recover_staged(self) -> bool:
        recovered = False
        if self.src_backup_path.is_dir():
            for saved in self.src_backup_path.rglob("*"):
                if saved.is_file():
                    rel = saved.relative_to(self.src_backup_path)
                    dest = self.cfg.app_dir / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(saved.read_bytes())
                    recovered = True
            shutil.rmtree(self.src_backup_path, ignore_errors=True)
        if self.backup_path.exists():
            shutil.rmtree(self.build_path, ignore_errors=True)
            self.backup_path.rename(self.build_path)
            recovered = True
        return recovered

    def drop_current(self) -> None:
        box, self.current = self.current, None
        if box is not None:
            self.app.give(box)

    def reset(self) -> dict:
        self.drop_current()
        box, info = self.app.take()
        self.current = box
        return info

    def send(self, box: Box, req: dict) -> dict:
        body = req.get("body")
        data = body.encode() if isinstance(body, str) else None
        r = box.target.call(req.get("method", "GET"), req.get("path", "/"), clean_headers(req.get("headers")), data)
        r["canary_hits"] = find_canaries(r["body"] + json.dumps(r["headers"]), box.canary["strings"])
        r["count"] = result_count(r["body"])
        r["reflected"] = reflected_markup(r["body"], r["headers"], req)
        r["fingerprint"] = fingerprint(r["body"], box.canary_values(), request_values(req))
        r["body"] = r["body"][:PREVIEW]
        return r

    def settled_solved(self, box: Box) -> dict:
        if self.cfg.settle > 0:
            time.sleep(self.cfg.settle)
        return box.target.solved()

    def replay(self, payload: dict) -> dict:
        if not self.lock.acquire(timeout=self.cfg.busy_wait):
            return dict(BUSY)
        try:
            return self._replay(payload)
        finally:
            self.lock.release()

    def _needs_reset(self, payload: dict) -> bool:
        return payload.get("reset", True) or self.current is None or not self.current.canary["planted"]

    def _replay(self, payload: dict) -> dict:
        reset = None
        if self._needs_reset(payload):
            reset = self.reset()
            if not reset["ok"]:
                return {"ok": False, "stage": "reset", "reset": reset}
        return dict(self.run_replay(self.current, payload), reset=reset)

    def run_replay(self, box: Box, payload: dict) -> dict:
        s0 = box.target.solved()
        control = self.send(box, payload["control"]) if payload.get("control") else None
        s1 = self.settled_solved(box) if control else s0
        attack = self.send(box, payload["request"])
        s2 = self.settled_solved(box)
        return {
            "ok": True,
            "reset": None,
            "control": control,
            "control_solved": newly_solved(s0, s1),
            "attack": attack,
            "attack_solved": newly_solved(s1, s2),
        }

    def try_one(self, box: Box, req: dict) -> dict:
        before = box.target.solved()
        attack = self.send(box, req)
        return {"attack": attack, "attack_solved": newly_solved(before, self.settled_solved(box))}

    def smoke_checks(self, box: Box, normals: list) -> list:
        login = json.dumps({"email": box.canary.get("email", ""), "password": box.canary.get("password", "")})
        checks = [
            ("version", {"method": "GET", "path": self.cfg.ready_path, "headers": {}}),
            ("search", {"method": "GET", "path": "/rest/products/search?q=apple", "headers": {}}),
            ("login", {"method": "POST", "path": "/rest/user/login", "headers": dict(JSON_HEADERS), "body": login}),
        ]
        for normal in request_list(normals, MAX_NORMALS):
            if isinstance(normal.get("request"), dict):
                checks.append((str(normal.get("name") or "route")[:NAME_CHARS], normal["request"]))
        return checks

    def smoke(self, box: Box, normals: list | None = None) -> tuple:
        before = box.target.solved()
        out = {name: observation(self.send(box, req)) for name, req in self.smoke_checks(box, normals or [])}
        return out, bool(newly_solved(before, self.settled_solved(box)))

    def run_job(self, box: Box, kind: str, item) -> tuple:
        if kind == "replay":
            out = self.run_replay(box, item)
            return out, bool(out["attack_solved"] or out["control_solved"])
        if kind == "smoke":
            return self.smoke(box, item)
        out = self.try_one(box, item)
        return out, bool(out["attack_solved"])

    def work(self, jobs: queue.Queue, results: dict, failures: list) -> None:
        box = None
        try:
            while not failures:
                try:
                    index, kind, item = jobs.get_nowait()
                except queue.Empty:
                    return
                if box is None:
                    box, info = self.app.take()
                    if box is None:
                        failures.append(info)
                        return
                try:
                    results[index], dirty = self.run_job(box, kind, item)
                except Exception as exc:
                    failures.append(take_result(False, time.time(), f"{kind} failed: {exc}"[:ERROR_CHARS], restarted=False))
                    return
                if dirty:
                    self.app.give(box)
                    box = None
        finally:
            if box is not None:
                self.app.give(box)

    def run_jobs(self, jobs: list) -> tuple:
        pending: queue.Queue = queue.Queue()
        for index, (kind, item) in enumerate(jobs):
            pending.put((index, kind, item))
        results: dict = {}
        failures: list = []
        width = max(1, min(self.app.width, len(jobs)))
        threads = [threading.Thread(target=self.work, args=(pending, results, failures), daemon=True) for _ in range(width)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if failures or len(results) < len(jobs):
            return None, (failures[0] if failures else take_result(False, time.time(), "a replay job never ran", restarted=False))
        return [results[i] for i in range(len(jobs))], None

    def verify_stage(self, payload: dict, variants: list, oracle: list) -> dict:
        started = time.time()
        jobs = [("replay", payload), ("smoke", payload.get("normals"))] + [("try", r) for r in variants + oracle]
        out, failure = self.run_jobs(jobs)
        if out is None:
            return {"ok": False, "stage": "reset", "reset": failure, "error": failure.get("error") or "reset failed"}
        replay, smoke, tried = out[0], out[1], out[2:]
        pair = [observation(t["attack"]) for t in tried[len(variants):]]
        return {
            "ok": True,
            "ms": elapsed_ms(started),
            "replay": replay,
            "smoke": smoke,
            "variants": tried[:len(variants)],
            "oracle": dict(zip(("true", "false"), pair)),
        }

    def check_file(self, rel: str, spec: dict) -> str:
        if not is_allowed_patch_path(rel):
            return f"path not allowed: {rel}"
        target = self.cfg.app_dir / rel
        if not target.is_file():
            return f"no such file: {rel}"
        if hashlib.sha256(target.read_bytes()).hexdigest() != spec.get("base_sha256"):
            return f"base mismatch: {rel}"
        if not isinstance(spec.get("content"), str):
            return f"missing content: {rel}"
        return ""

    def check_files(self, files: dict) -> str:
        if not files:
            return "no files"
        for rel, spec in files.items():
            problem = self.check_file(rel, spec)
            if problem:
                return problem
        return ""

    @contextmanager
    def staged(self, files: dict) -> Iterator[None]:
        originals = {rel: (self.cfg.app_dir / rel).read_bytes() for rel in files}
        shutil.rmtree(self.src_backup_path, ignore_errors=True)
        for rel, data in originals.items():
            saved = self.src_backup_path / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(data)
        shutil.rmtree(self.backup_path, ignore_errors=True)
        shutil.copytree(self.build_path, self.backup_path, symlinks=True)
        try:
            yield
        finally:
            with self.app.hold():
                for rel, data in originals.items():
                    (self.cfg.app_dir / rel).write_bytes(data)
                shutil.rmtree(self.src_backup_path, ignore_errors=True)
                shutil.rmtree(self.build_path, ignore_errors=True)
                if self.backup_path.exists():
                    self.backup_path.rename(self.build_path)
                self.app.rebuild()

    def build(self, files: dict) -> dict:
        started = time.time()
        with self.app.hold():
            for rel, spec in files.items():
                (self.cfg.app_dir / rel).write_text(spec["content"])
            proc = subprocess.run(self.cfg.build_cmd, shell=True, cwd=self.cfg.app_dir, capture_output=True, text=True, timeout=300)
            self.app.rebuild()
        return {"ok": proc.returncode == 0, "ms": elapsed_ms(started), "log": (proc.stdout + proc.stderr)[-2000:]}

    def patch(self, payload: dict) -> dict:
        files = payload.get("files") or {}
        with self.lock:
            self.drop_current()
            return self._patch(payload, files)

    def _patch(self, payload: dict, files: dict) -> dict:
        started = time.time()
        self.recover_staged()
        problem = self.check_files(files)
        if problem:
            return {"ok": False, "stage": "validate", "error": problem}
        variants = request_list(payload.get("variants"), MAX_VARIANTS)
        oracle = oracle_pair(payload.get("oracle"))
        before = self.verify_stage(payload, variants, oracle)
        if not before["ok"]:
            return dict(before, phase="before")
        with self.staged(files):
            build_info = self.build(files)
            if not build_info["ok"]:
                return {"ok": True, "build": build_info, "replay_before": before["replay"], "smoke_before": before["smoke"]}
            after = self.verify_stage(payload, variants, oracle)
            if not after["ok"]:
                return dict(after, phase="after", build=build_info)
            return {
                "ok": True,
                "ms": elapsed_ms(started),
                "timings": {"before_ms": before["ms"], "build_ms": build_info["ms"], "after_ms": after["ms"]},
                "build": build_info,
                "replay_before": before["replay"],
                "replay": after["replay"],
                "smoke_before": before["smoke"],
                "smoke_after": after["smoke"],
                "variants": {"before": before["variants"], "after": after["variants"]},
                "oracle": {"before": before["oracle"], "after": after["oracle"]} if oracle else {},
            }


SERVER_MAX_THREADS = 32
SERVER_IDLE_SECONDS = 30


def make_handler(runner: Runner):
    cfg = runner.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer-runner"
        sys_version = ""
        timeout = SERVER_IDLE_SECONDS

        def log_message(self, fmt, *args):
            pass

        def reply(self, status: int, obj) -> None:
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def not_found(self) -> None:
            self.close_connection = True
            self.reply(404, {"error": "not found"})

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            if not cfg.secret_sha256 or not header.startswith(BEARER):
                return False
            digest = hashlib.sha256(header[len(BEARER):].encode()).hexdigest()
            return hmac.compare_digest(digest, cfg.secret_sha256)

        def read_json(self):
            raw = self.headers.get("Content-Length")
            if not raw:
                return {}
            length = int(raw)
            if length < 0:
                raise ValueError("negative Content-Length")
            if length > MAX_BODY:
                raise PayloadTooLarge("body too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self):
            if not self.authorized() or self.path != "/health":
                return self.not_found()
            return self.reply(200, {"ok": True, "target_ready": runner.app.ready()})

        def do_POST(self):
            if not self.authorized():
                return self.not_found()
            try:
                payload = self.read_json()
            except PayloadTooLarge:
                self.close_connection = True
                return self.reply(413, {"error": "body too large"})
            except ValueError:
                self.close_connection = True
                return self.reply(400, {"error": "bad json"})
            if not isinstance(payload, dict):
                return self.reply(400, {"error": "bad json"})
            route = self.POST_ROUTES.get(self.path)
            if route is None:
                return self.not_found()
            return route(self, payload)

        def post_reset(self, payload: dict) -> None:
            with runner.lock:
                return self.reply(200, runner.reset())

        def post_replay(self, payload: dict) -> None:
            if "request" not in payload:
                return self.reply(400, {"error": "missing request"})
            return self.reply(200, runner.replay(payload))

        def post_patch(self, payload: dict) -> None:
            if "request" not in payload or "files" not in payload:
                return self.reply(400, {"error": "missing request or files"})
            return self.reply(200, runner.patch(payload))

        POST_ROUTES = {
            "/reset": post_reset,
            "/replay": post_replay,
            "/patch": post_patch,
        }

    return Handler


class RunnerServer(ThreadingHTTPServer):
    daemon_threads = True
    busy_response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 17\r\nRetry-After: 1\r\nConnection: close\r\n\r\n{\"error\":\"busy\"}\n"

    def __init__(self, address, handler, max_threads: int = SERVER_MAX_THREADS):
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

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)


def server_threads(env=os.environ) -> int:
    return max(1, int(env.get("RUNNER_MAX_THREADS", str(SERVER_MAX_THREADS))))


def stop_on_signal(signum, frame):
    raise SystemExit(0)


def main():
    cfg = Config()
    runner = Runner(cfg)
    server = RunnerServer((cfg.bind, cfg.port), make_handler(runner), server_threads())
    signal.signal(signal.SIGTERM, stop_on_signal)
    try:
        runner.start()
        print(json.dumps({"runner": "listening", "host": cfg.bind, "port": cfg.port, "pool": cfg.pool_size}), flush=True)
        server.serve_forever()
    finally:
        runner.close()


if __name__ == "__main__":
    sys.exit(main())
