from __future__ import annotations

import http.client
import json
import os
import socket
import time
import urllib.error
import urllib.request

SPRITE_SOCK = "/.sprite/api.sock"


def post_json(url: str, payload, timeout: float = 30, headers: dict | None = None) -> tuple:
    data = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method="POST", headers=hdrs)
    return _send(req, timeout)


def request(url: str, method: str = "GET", payload=None, timeout: float = 30, headers: dict | None = None) -> tuple:
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"Content-Type": "application/json"} if data is not None else {}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    return _send(req, timeout)


def _send(req, timeout: float) -> tuple:
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": str(exc)[:300]}, time.time() - started
    try:
        parsed = json.loads(body) if body else {}
    except ValueError:
        parsed = {"raw": body[:2000]}
    return status, parsed, time.time() - started


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 5):
        super().__init__("sprite", timeout=timeout)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def sprite_api(method: str, path: str, payload=None) -> int:
    if not os.path.exists(SPRITE_SOCK):
        return 0
    conn = _UnixConnection(SPRITE_SOCK)
    try:
        body = json.dumps(payload).encode() if payload is not None else None
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except OSError:
        return 0
    finally:
        conn.close()


def hold_awake(name: str, seconds: int) -> int:
    return sprite_api("PUT", f"/v1/tasks/{name}", {"expire": f"{seconds}s"})


def release_awake(name: str) -> int:
    return sprite_api("DELETE", f"/v1/tasks/{name}")
