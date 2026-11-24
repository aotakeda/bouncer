from __future__ import annotations

import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CHALLENGES = {
    "loginAdminChallenge": {"name": "Login Admin", "difficulty": 2, "category": "Injection"},
    "errorHandlingChallenge": {"name": "Error Handling", "difficulty": 1, "category": "Security Misconfiguration"},
}


class Juice:
    def __init__(self):
        self.reset()

    def reset(self):
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
                if "union" in q.lower():
                    return self.out(200, {"data": [{"name": u["email"], "description": u["md5"]} for u in state.users]})
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
                if "' or 1=1" in str(body.get("email", "")):
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


def main():
    kind, port = sys.argv[1], int(sys.argv[2])
    handler = juice_handler(Juice()) if kind == "juice" else jev_handler()
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    main()
