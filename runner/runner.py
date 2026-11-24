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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
                "ms": int((time.time() - started) * 1000),
            }
        except (OSError, http.client.HTTPException) as exc:
            return {"status": 0, "error": str(exc)[:300], "body": "", "headers": {}, "ms": int((time.time() - started) * 1000)}
        finally:
            conn.close()

    def ready(self) -> bool:
        return self.call("GET", self.cfg.ready_path, timeout=3).get("status") == 200

    def wait_ready(self) -> bool:
        deadline = time.time() + self.cfg.ready_timeout
        while time.time() < deadline:
            if self.ready():
                return True
            time.sleep(0.25)
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
    out = {}
    for k, v in (raw or {}).items():
        lk = k.lower()
        if lk in DROP_HEADERS or lk.startswith(DROP_PREFIXES):
            continue
        out[k] = v
    return out


def plant_canary(target: Target) -> dict:
    tag = secrets.token_hex(6)
    email = f"canary-{tag}@bouncer.test"
    password = f"Canary-{secrets.token_hex(8)}!"
    body = json.dumps({"email": email, "password": password, "passwordRepeat": password, "securityQuestion": None, "securityAnswer": ""}).encode()
    r = target.call("POST", "/api/Users", {"Content-Type": "application/json"}, body)
    md5 = hashlib.md5(password.encode()).hexdigest()
    return {"planted": r.get("status") in (200, 201), "strings": [email, md5], "email": email, "password": password}


def find_canaries(text: str, canaries: list) -> list:
    return [c for c in canaries if c and c in text]


class Runner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.target = Target(cfg)
        self.lock = threading.Lock()
        self.canary = {"planted": False, "strings": []}

    def service_started(self) -> str | None:
        if not self.cfg.service:
            return None
        try:
            out = subprocess.run(["sprite-env", "services", "get", self.cfg.service], capture_output=True, text=True, timeout=10).stdout
            return json.loads(out)["state"].get("started_at")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return None

    def reset(self) -> dict:
        started = time.time()
        before = self.service_started()
        proc = subprocess.run(self.cfg.reset_cmd, shell=True, capture_output=True, text=True, timeout=120)
        error = ""
        for raw in proc.stdout.splitlines():
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if msg.get("type") == "error":
                error = str(msg.get("data"))[:300]
        restarted = True
        if before is not None and not error:
            deadline = time.time() + self.cfg.ready_timeout
            restarted = False
            while time.time() < deadline:
                now = self.service_started()
                if now and now != before:
                    restarted = True
                    break
                time.sleep(0.25)
        ok = proc.returncode == 0 and not error and restarted and self.target.wait_ready()
        self.canary = plant_canary(self.target) if ok else {"planted": False, "strings": []}
        return {
            "ok": ok,
            "ms": int((time.time() - started) * 1000),
            "restarted": restarted,
            "error": error,
            "canary_planted": self.canary["planted"],
            "stderr": proc.stderr[-300:],
        }

    def send(self, req: dict) -> dict:
        body = req.get("body")
        data = body.encode() if isinstance(body, str) else None
        r = self.target.call(req.get("method", "GET"), req.get("path", "/"), clean_headers(req.get("headers")), data)
        r["canary_hits"] = find_canaries(r["body"] + json.dumps(r["headers"]), self.canary["strings"])
        r["body"] = r["body"][:PREVIEW]
        return r

    def replay(self, payload: dict) -> dict:
        with self.lock:
            return self._replay(payload)

    def _replay(self, payload: dict) -> dict:
        reset = None
        if payload.get("reset", True) or not self.canary["planted"]:
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
            "control_solved": {k: v for k, v in s1.items() if k not in s0},
            "attack": attack,
            "attack_solved": {k: v for k, v in s2.items() if k not in s1},
        }


    def try_all(self, requests: list) -> list:
        out = []
        prev = self.target.solved()
        for req in requests:
            attack = self.send(req)
            now = self.target.solved()
            out.append({"attack": attack, "attack_solved": {k: v for k, v in now.items() if k not in prev}})
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
            r = self.target.call(method, path, {"Content-Type": "application/json"} if body else {}, body)
            count = None
            try:
                data = json.loads(r["body"])
                if isinstance(data.get("data"), list):
                    count = len(data["data"])
                elif "authentication" in data:
                    count = 1
            except (ValueError, AttributeError):
                pass
            out[name] = {"status": r.get("status"), "count": count}
        return out

    def check_files(self, files: dict) -> str:
        if not files:
            return "no files"
        for rel, spec in files.items():
            if rel.startswith("/") or ".." in Path(rel).parts or not rel.startswith(PATCH_PREFIXES):
                return f"path not allowed: {rel}"
            target = self.cfg.app_dir / rel
            if not target.is_file():
                return f"no such file: {rel}"
            if hashlib.sha256(target.read_bytes()).hexdigest() != spec.get("base_sha256"):
                return f"base mismatch: {rel}"
            if not isinstance(spec.get("content"), str):
                return f"missing content: {rel}"
        return ""

    def patch(self, payload: dict) -> dict:
        files = payload.get("files") or {}
        with self.lock:
            problem = self.check_files(files)
            if problem:
                return {"ok": False, "stage": "validate", "error": problem}
            first = self.reset()
            if not first["ok"]:
                return {"ok": False, "stage": "reset", "reset": first}
            before = self.smoke()
            variants = [v for v in (payload.get("variants") or []) if isinstance(v, dict)][:4]
            tried = {"before": self.try_all(variants)}
            build = self.cfg.app_dir / self.cfg.build_dir
            backup = self.cfg.app_dir / (self.cfg.build_dir + ".bouncer-bak")
            originals = {rel: (self.cfg.app_dir / rel).read_bytes() for rel in files}
            shutil.rmtree(backup, ignore_errors=True)
            shutil.copytree(build, backup, symlinks=True)
            started = time.time()
            try:
                for rel, spec in files.items():
                    (self.cfg.app_dir / rel).write_text(spec["content"])
                proc = subprocess.run(self.cfg.build_cmd, shell=True, cwd=self.cfg.app_dir, capture_output=True, text=True, timeout=300)
                build_info = {"ok": proc.returncode == 0, "ms": int((time.time() - started) * 1000), "log": (proc.stdout + proc.stderr)[-2000:]}
                if not build_info["ok"]:
                    return {"ok": True, "build": build_info, "smoke_before": before}
                result = self._replay(dict(payload, reset=True))
                after = self.smoke() if result.get("ok") else {}
                tried["after"] = self.try_all(variants) if result.get("ok") else []
                return {"ok": True, "build": build_info, "replay": result, "smoke_before": before, "smoke_after": after, "variants": tried}
            finally:
                for rel, data in originals.items():
                    (self.cfg.app_dir / rel).write_bytes(data)
                shutil.rmtree(build, ignore_errors=True)
                backup.rename(build)
                self.reset()


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

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            if not cfg.secret_sha256 or not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(hashlib.sha256(header[7:].encode()).hexdigest(), cfg.secret_sha256)

        def do_GET(self):
            if not self.authorized():
                return self.reply(404, {"error": "not found"})
            if self.path == "/health":
                return self.reply(200, {"ok": True, "target_ready": runner.target.ready()})
            return self.reply(404, {"error": "not found"})

        def do_POST(self):
            if not self.authorized():
                return self.reply(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.reply(400, {"error": "bad json"})
            if self.path == "/reset":
                with runner.lock:
                    return self.reply(200, runner.reset())
            if self.path == "/replay":
                if "request" not in payload:
                    return self.reply(400, {"error": "missing request"})
                return self.reply(200, runner.replay(payload))
            if self.path == "/patch":
                if "request" not in payload or "files" not in payload:
                    return self.reply(400, {"error": "missing request or files"})
                return self.reply(200, runner.patch(payload))
            return self.reply(404, {"error": "not found"})

    return Handler


def main():
    cfg = Config()
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(Runner(cfg)))
    server.daemon_threads = True
    print(json.dumps({"runner": "listening", "port": cfg.port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
