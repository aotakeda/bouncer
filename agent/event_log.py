from __future__ import annotations

import json
import os
import queue
import threading
import time
from collections import deque
from pathlib import Path

from .redact import redact_text

TSV_COLUMNS = ["ts", "ip", "method", "path", "kind", "jev_malicious", "jev_action", "jev_confidence", "decision", "replay_verdict", "evidence", "line"]


def tsv_row(r: dict) -> str:
    jev = r.get("jev") or {}
    rep = r.get("replay") or {}
    row = [
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.get("ts", time.time()))),
        r.get("ip", ""),
        r.get("method") or "",
        redact_text(r.get("path", ""))[:300],
        r.get("kind", ""),
        str(jev.get("malicious", "")),
        str(jev.get("action", "")),
        str(jev.get("confidence", "")),
        r.get("decision", ""),
        rep.get("verdict", ""),
        json.dumps(rep.get("evidence", {}), separators=(",", ":")) if rep else "",
        redact_text(r.get("line", "")),
    ]
    return "\t".join(str(c).replace("\t", " ").replace("\n", " ") for c in row) + "\n"


class DecisionLog:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        if not path.exists():
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write("\t".join(TSV_COLUMNS) + "\n")
        path.chmod(0o600)

    def write(self, record: dict) -> None:
        row = tsv_row(record)
        with self.lock:
            with self.path.open("a") as f:
                f.write(row)

    def tail(self, n: int) -> list:
        with self.lock:
            with self.path.open() as f:
                lines = deque(f, maxlen=n + 1)
        rows = [line.rstrip("\n").split("\t") for line in lines]
        return [dict(zip(TSV_COLUMNS, r)) for r in rows if len(r) == len(TSV_COLUMNS) and r != TSV_COLUMNS][-n:]


class Feed:
    def __init__(self, keep: int = 300):
        self.recent: deque = deque(maxlen=keep)
        self.listeners: list = []
        self.lock = threading.Lock()

    def subscribe(self, size: int = 500) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=size)
        with self.lock:
            self.listeners.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.listeners.remove(q)

    def publish(self, item: dict) -> None:
        with self.lock:
            self.recent.append(item)
        self.notify(item)

    def notify(self, item: dict) -> None:
        with self.lock:
            listeners = list(self.listeners)
        for q in listeners:
            try:
                q.put_nowait(item)
            except queue.Full:
                pass

    def latest(self, n: int) -> list:
        with self.lock:
            return list(self.recent)[-n:]
