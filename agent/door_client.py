from __future__ import annotations

import time
from urllib.parse import quote

from . import net
from .labels import Decision

ENDPOINTS = {Decision.BLOCK: "blocklist", Decision.TARPIT: "tarpit"}


class DoorClient:
    def __init__(self, url: str, token: str = ""):
        self.url = url.rstrip("/")
        self.headers = net.bearer(token)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def put(self, kind: Decision, ip: str, seconds: int, reason: str) -> bool:
        status, _, _ = net.request(
            f"{self.url}/_bouncer/{ENDPOINTS[kind]}",
            "PUT",
            {ip: {"until": time.time() + seconds, "reason": reason}},
            timeout=15,
            headers=self.headers,
        )
        return status == 200

    def snapshot(self, timeout: float = 3) -> dict:
        if not self.enabled:
            return {"block": {}, "tarpit": {}}
        status, body, _ = net.request(
            f"{self.url}/_bouncer/blocklist",
            "GET",
            timeout=timeout,
            headers=self.headers,
        )
        if status == 200 and isinstance(body, dict):
            return {"block": body.get("block") or {}, "tarpit": body.get("tarpit") or {}}
        return {"block": {}, "tarpit": {}}

    def delete(self, kind: Decision, ip: str) -> bool:
        if not self.enabled or not ip:
            return False
        status, _, _ = net.request(
            f"{self.url}/_bouncer/{ENDPOINTS[kind]}/{quote(ip, safe='')}",
            "DELETE",
            timeout=10,
            headers=self.headers,
        )
        return status == 200

    def unblock(self, ip: str) -> bool:
        if not self.enabled or not ip:
            return False
        b_ok = self.delete(Decision.BLOCK, ip)
        t_ok = self.delete(Decision.TARPIT, ip)
        return b_ok or t_ok
