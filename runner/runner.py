from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

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

BEARER = "Bearer "
JSON_HEADERS = {"Content-Type": "application/json"}
POLL_SECONDS = 0.25
ERROR_CHARS = 300
MAX_VARIANTS = 4
MAX_BODY = 4 * 1024 * 1024
BUSY = {"ok": False, "stage": "busy"}


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


class Target:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def call(self, method: str, path: str, headers: dict | None = None, body: bytes | None = None, timeout: float = 30) -> dict:
        conn = http.client.HTTPConnection(self.cfg.host, self.cfg.port_target, timeout=timeout)
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
    return not rel.startswith("/") and ".." not in Path(rel).parts and rel.startswith(PATCH_PREFIXES)


class Runner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.target = Target(cfg)
        self.lock = threading.Lock()
        self.canary = empty_canary()
        self.recover_staged()

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

    def reset(self) -> dict:
        started = time.time()
        before = self.service_started()
        proc = subprocess.run(self.cfg.reset_cmd, shell=True, capture_output=True, text=True, timeout=120)
        error = reset_error(proc.stdout)
        restarted = True if before is None or error else self.wait_restarted(before)
        ok = proc.returncode == 0 and not error and restarted and self.target.wait_ready()
        self.canary = plant_canary(self.target) if ok else empty_canary()
        return {
            "ok": ok,
            "ms": elapsed_ms(started),
            "restarted": restarted,
            "error": error,
            "canary_planted": self.canary["planted"],
            "stderr": proc.stderr[-ERROR_CHARS:],
        }

    def send(self, req: dict) -> dict:
        body = req.get("body")
        data = body.encode() if isinstance(body, str) else None
        r = self.target.call(req.get("method", "GET"), req.get("path", "/"), clean_headers(req.get("headers")), data)
        r["canary_hits"] = find_canaries(r["body"] + json.dumps(r["headers"]), self.canary["strings"])
        r["body"] = r["body"][:PREVIEW]
        return r

    def replay(self, payload: dict) -> dict:
        if not self.lock.acquire(timeout=self.cfg.busy_wait):
            return dict(BUSY)
        try:
            return self._replay(payload)
        finally:
            self.lock.release()

    def _needs_reset(self, payload: dict) -> bool:
        return payload.get("reset", True) or not self.canary["planted"]

    def _replay(self, payload: dict) -> dict:
        reset = None
        if self._needs_reset(payload):
            reset = self.reset()
            if not reset["ok"]:
                return {"ok": False, "stage": "reset", "reset": reset}
        s0 = self.target.solved()
        control = self.send(payload["control"]) if payload.get("control") else None
        s1 = self.target.solved()
        attack = self.send(payload["request"])
        s2 = self.target.solved()
        return {
            "ok": True,
            "reset": reset,
            "control": control,
            "control_solved": newly_solved(s0, s1),
            "attack": attack,
            "attack_solved": newly_solved(s1, s2),
        }

    def try_all(self, requests: list) -> list:
        out = []
        prev = self.target.solved()
        for i, req in enumerate(requests):
            attack = self.send(req)
            now = self.target.solved()
            solved = newly_solved(prev, now)
            out.append({"attack": attack, "attack_solved": solved})
            if solved and i + 1 < len(requests):
                if not self.reset()["ok"]:
                    break
                prev = self.target.solved()
            else:
                prev = now
        return out

    def smoke(self) -> dict:
        login = json.dumps({"email": self.canary.get("email", ""), "password": self.canary.get("password", "")}).encode()
        checks = [
            ("version", "GET", self.cfg.ready_path, None),
            ("search", "GET", "/rest/products/search?q=apple", None),
            ("login", "POST", "/rest/user/login", login),
        ]
        out = {}
        for name, method, path, body in checks:
            r = self.target.call(method, path, dict(JSON_HEADERS) if body else {}, body)
            out[name] = {"status": r.get("status"), "count": result_count(r["body"])}
        return out

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
            for rel, data in originals.items():
                (self.cfg.app_dir / rel).write_bytes(data)
            shutil.rmtree(self.src_backup_path, ignore_errors=True)
            shutil.rmtree(self.build_path, ignore_errors=True)
            if self.backup_path.exists():
                self.backup_path.rename(self.build_path)
            self.reset()

    def build(self, files: dict) -> dict:
        started = time.time()
        for rel, spec in files.items():
            (self.cfg.app_dir / rel).write_text(spec["content"])
        proc = subprocess.run(self.cfg.build_cmd, shell=True, cwd=self.cfg.app_dir, capture_output=True, text=True, timeout=300)
        return {"ok": proc.returncode == 0, "ms": elapsed_ms(started), "log": (proc.stdout + proc.stderr)[-2000:]}

    def patch(self, payload: dict) -> dict:
        files = payload.get("files") or {}
        with self.lock:
            return self._patch(payload, files)

    def _patch(self, payload: dict, files: dict) -> dict:
        self.recover_staged()
        problem = self.check_files(files)
        if problem:
            return {"ok": False, "stage": "validate", "error": problem}
        first = self.reset()
        if not first["ok"]:
            return {"ok": False, "stage": "reset", "reset": first}
        before = self.smoke()
        variants = [v for v in (payload.get("variants") or []) if isinstance(v, dict)][:MAX_VARIANTS]
        tried = {"before": self.try_all(variants)}
        with self.staged(files):
            build_info = self.build(files)
            if not build_info["ok"]:
                return {"ok": True, "build": build_info, "smoke_before": before}
            result = self._replay(dict(payload, reset=True))
            replayed = bool(result.get("ok"))
            after = self.smoke() if replayed else {}
            tried["after"] = self.try_all(variants) if replayed else []
            return {"ok": True, "build": build_info, "replay": result, "smoke_before": before, "smoke_after": after, "variants": tried}


def make_handler(runner: Runner):
    cfg = runner.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer-runner"
        sys_version = ""

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
            return self.reply(200, {"ok": True, "target_ready": runner.target.ready()})

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


def main():
    cfg = Config()
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(Runner(cfg)))
    server.daemon_threads = True
    print(json.dumps({"runner": "listening", "port": cfg.port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
