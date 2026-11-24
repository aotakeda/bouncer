from __future__ import annotations

import time

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
