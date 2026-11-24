from __future__ import annotations

import http.client
import json
import os
import socket
import time
import urllib.error
import urllib.request

SPRITE_SOCK = "/.sprite/api.sock"
JSON_HEADERS = {"Content-Type": "application/json"}
ERROR_DETAIL_CHARS = 300


def bare_path(path: str) -> str:
    return path.split("?", 1)[0]


def clip(value, limit: int) -> str:
    return str(value)[:limit]


def bearer(token: str) -> dict | None:
    return {"Authorization": f"Bearer {token}"} if token else None


def encode_json(payload) -> bytes | None:
    return json.dumps(payload).encode() if payload is not None else None


def post_json(url: str, payload, timeout: float = 30, headers: dict | None = None) -> tuple:
    return _send(_build(url, "POST", json.dumps(payload).encode(), headers), timeout)


def request(url: str, method: str = "GET", payload=None, timeout: float = 30, headers: dict | None = None) -> tuple:
    return _send(_build(url, method, encode_json(payload), headers), timeout)


def _build(url: str, method: str, data: bytes | None, headers: dict | None) -> urllib.request.Request:
    hdrs = dict(JSON_HEADERS) if data is not None else {}
    hdrs.update(headers or {})
    return urllib.request.Request(url, data=data, method=method, headers=hdrs)


def _send(req: urllib.request.Request, timeout: float) -> tuple:
    started = time.time()
    try:
        status, body = _read(req, timeout)
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": str(exc)[:300]}, time.time() - started
    return status, _parse(body), time.time() - started


def _read(req: urllib.request.Request, timeout: float) -> tuple[int, str]:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def _parse(body: str):
    if not body:
        return {}
    try:
        return json.loads(body)
    except ValueError:
        return {"raw": body[:2000]}


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
        conn.request(method, path, body=encode_json(payload), headers=JSON_HEADERS)
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
