from __future__ import annotations

import threading
import time
from collections import deque


class FairInbox:
    def __init__(self, per_key: int, total: int):
        self.per_key = per_key
        self.total = total
        self.queues: dict = {}
        self.order: deque = deque()
        self.size = 0
        self.busy = 0
        self.cond = threading.Condition()

    def put(self, key: str, item) -> bool:
        with self.cond:
            q = self.queues.get(key)
            if self.size >= self.total or (q is not None and len(q) >= self.per_key):
                return False
            if q is None:
                q = self.queues[key] = deque()
                self.order.append(key)
            q.append(item)
            self.size += 1
            self.cond.notify_all()
            return True

    def get(self):
        with self.cond:
            while not self.size:
                self.cond.wait()
            key = self.order.popleft()
            q = self.queues[key]
            item = q.popleft()
            self.size -= 1
            self.busy += 1
            if q:
                self.order.append(key)
            else:
                del self.queues[key]
            return item

    def done(self) -> None:
        with self.cond:
            self.busy = max(0, self.busy - 1)
            self.cond.notify_all()

    def empty(self) -> bool:
        with self.cond:
            return not self.size

    def wait_idle(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        with self.cond:
            while self.size or self.busy:
                left = deadline - time.time()
                if left <= 0:
                    return False
                self.cond.wait(left)
            return True
