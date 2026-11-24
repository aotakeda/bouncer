from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CHALLENGES = {
    "loginAdminChallenge": {"name": "Login Admin", "difficulty": 2, "category": "Injection"},
    "errorHandlingChallenge": {"name": "Error Handling", "difficulty": 1, "category": "Security Misconfiguration"},
}


class Juice:
    def __init__(self, app_dir: str = ""):
        self.app_dir = Path(app_dir) if app_dir else None
        self.reset()

    def mode(self, name: str) -> str:
        if not self.app_dir:
            return "vuln"
        f = self.app_dir / "build" / f"{name}.mode"
        return f.read_text().strip() if f.exists() else "vuln"

    def reset(self):
        self.fixed = {n: self.mode(n) == "fixed" for n in ("login", "search")}
        self.solved = set()
        self.users = [{"email": "admin@juice-sh.op", "md5": hashlib.md5(b"admin123").hexdigest()}]


def juice_handler(state: Juice):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def out(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parts = urlsplit(self.path)
            if parts.path == "/rest/admin/application-version":
                return self.out(200, {"version": "fake"})
            if parts.path == "/api/Challenges":
                return self.out(200, {"data": [dict(key=k, solved=k in state.solved, **v) for k, v in CHALLENGES.items()]})
            if parts.path == "/rest/products/search":
                q = parse_qs(parts.query).get("q", [""])[0]
                if "union" in q.lower() and not state.fixed["search"]:
                    return self.out(200, {"data": [{"name": u["email"], "description": u["md5"]} for u in state.users]})
                if q == "apple":
                    return self.out(200, {"data": [{"name": "Apple Juice"}]})
                if "'" in q:
                    state.solved.add("errorHandlingChallenge")
                    return self.out(500, {"error": "SQLITE_ERROR"})
                return self.out(200, {"data": []})
            return self.out(200, {"page": parts.path})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if self.path == "/__reset":
                state.reset()
                return self.out(200, {"ok": True})
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            if self.path == "/api/Users":
                state.users.append({"email": body.get("email"), "md5": hashlib.md5(body.get("password", "").encode()).hexdigest()})
                return self.out(201, {"status": "success"})
            if self.path == "/rest/user/login":
                md5 = hashlib.md5(str(body.get("password", "")).encode()).hexdigest()
                if any(u["email"] == body.get("email") and u["md5"] == md5 for u in state.users):
                    return self.out(200, {"authentication": {"token": "fake-user-token"}})
                email = str(body.get("email", ""))
                if ("' or 1=1" in email or "admin@juice-sh.op'--" in email) and not state.fixed["login"]:
                    state.solved.add("loginAdminChallenge")
                    return self.out(200, {"authentication": {"token": "fake-admin-token"}})
                return self.out(401, {"error": "Invalid email or password."})
            return self.out(404, {})

    return H


def jev_handler():
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            state = json.loads(self.rfile.read(n))["state"].lower()
            if "'" in state or "union" in state or "sqlmap" in state:
                mal, act = 0.97, "block"
            elif "wp-login" in state:
                mal, act = 0.7, "ignore"
            else:
                mal, act = 0.1, "ignore"
            data = json.dumps({"model": "fake-jev", "answers": {"malicious": {"type": "noul", "noul": mal}, "action": {"type": "choice", "choice": act, "confidence": 0.8, "probabilities": {act: 0.8}}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


SERVER_TS = """import { login } from './routes/login'
import { searchProducts } from './routes/search'
app.post('/rest/user/login', login())
app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
"""


def github_handler(app_dir: Path):
    calls = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def out(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if self.path == "/__calls":
                return self.out(200, calls)
            path = urlsplit(self.path).path
            prefix = "/repos/aotakeda/juice-shop/contents/"
            if path.startswith(prefix):
                rel = path[len(prefix):]
                text = SERVER_TS if rel == "server.ts" else (app_dir / rel).read_text()
                return self.out(200, {"sha": "blob-" + rel, "content": base64.b64encode(text.encode()).decode()})
            if path == "/repos/aotakeda/juice-shop/git/ref/heads/master":
                return self.out(200, {"object": {"sha": "base-sha"}})
            if path == "/repos/aotakeda/juice-shop/pulls":
                return self.out(200, [
                    {"html_url": "https://github.com/aotakeda/juice-shop/pull/1", "head": {"ref": c["body"]["head"], "repo": {"full_name": "aotakeda/juice-shop"}}}
                    for c in calls if c["path"].endswith("/pulls")
                ])
            return self.out(404, {})

        def do_POST(self):
            body = self.body()
            calls.append({"method": "POST", "path": self.path, "body": body})
            if self.path.endswith("/git/refs"):
                return self.out(201, {"ref": body["ref"]})
            if self.path.endswith("/pulls"):
                return self.out(201, {"html_url": "https://github.com/aotakeda/juice-shop/pull/1", "number": 1})
            return self.out(404, {})

        def do_PUT(self):
            body = self.body()
            body["text"] = base64.b64decode(body.get("content", "")).decode()
            calls.append({"method": "PUT", "path": self.path, "body": body})
            return self.out(201, {"content": {}})

    return H


def claude_handler():
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n))
            ok = self.headers.get("anthropic-version") and req.get("output_config", {}).get("format", {}).get("type") == "json_schema"
            text = req["messages"][0]["content"]
            schema = req.get("output_config", {}).get("format", {}).get("schema", {})
            if "variants" in schema.get("properties", {}):
                patch = {"variants": [
                    {"path": "/rest/user/login", "body": json.dumps({"email": "' or 1=1-- variant", "password": "z"}), "idea": "same trick, other comment"},
                    {"path": "/rest/user/login", "body": json.dumps({"email": "admin@juice-sh.op'--", "password": "z"}), "idea": "target admin by email"},
                    {"path": "/api/Users", "body": "{}", "idea": "other endpoint"},
                ]}
            else:
                line = next((l for l in text.splitlines() if "VULN" in l), "")
                patch = {"title": "Use bound parameters", "summary": "Stops the injection.", "edits": [{"search": line, "replace": line.replace("VULN", "replacements")}] if line else []}
            reply = {"model": req["model"], "stop_reason": "end_turn" if ok else "refusal", "content": [{"type": "text", "text": json.dumps(patch)}], "usage": {}}
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


def main():
    kind, port = sys.argv[1], int(sys.argv[2])
    extra = sys.argv[3] if len(sys.argv) > 3 else ""
    if kind == "juice":
        handler = juice_handler(Juice(extra))
    elif kind == "github":
        handler = github_handler(Path(extra))
    elif kind == "claude":
        handler = claude_handler()
    else:
        handler = jev_handler()
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    main()
