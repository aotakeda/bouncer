from __future__ import annotations

import time

from . import net
from .labels import Decision

ENDPOINTS = {Decision.BLOCK: "blocklist", Decision.TARPIT: "tarpit"}
SHIELD_ENDPOINT = "shield"
EMPTY_SNAPSHOT = {"block": {}, "tarpit": {}, "shield": {}}


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

    def put_shield(self, route: str, seconds: int, reason: str) -> bool:
        if not self.enabled:
            return False
        status, _, _ = net.request(
            f"{self.url}/_bouncer/{SHIELD_ENDPOINT}",
            "PUT",
            {route: {"until": time.time() + seconds, "reason": reason}},
            timeout=15,
            headers=self.headers,
        )
        return status == 200

    def snapshot(self, timeout: float = 3) -> dict:
        if not self.enabled:
            return dict(EMPTY_SNAPSHOT)
        status, body, _ = net.request(
            f"{self.url}/_bouncer/blocklist",
            "GET",
            timeout=timeout,
            headers=self.headers,
        )
        if status == 200 and isinstance(body, dict):
            return {kind: body.get(kind) or {} for kind in EMPTY_SNAPSHOT}
        return dict(EMPTY_SNAPSHOT)

    def _delete(self, endpoint: str, target: str) -> bool:
        if not self.enabled or not target:
            return False
        status, body, _ = net.request(
            f"{self.url}/_bouncer/{endpoint}",
            "DELETE",
            {"target": target},
            timeout=10,
            headers=self.headers,
        )
        return status == 200 and isinstance(body, dict) and body.get("ok") is True

    def delete(self, kind: Decision, ip: str) -> bool:
        return self._delete(ENDPOINTS[kind], ip)

    def delete_shield(self, route: str) -> bool:
        return self._delete(SHIELD_ENDPOINT, route)

    def unblock(self, ip: str) -> bool:
        if not self.enabled or not ip:
            return False
        b_ok = self.delete(Decision.BLOCK, ip)
        t_ok = self.delete(Decision.TARPIT, ip)
        return b_ok or t_ok
