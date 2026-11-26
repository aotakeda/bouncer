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
        self.working: dict = {}
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
        me = threading.get_ident()
        with self.cond:
            if self.working.pop(me, None) is not None:
                self.cond.notify_all()
            key = self._free_key()
            while key is None:
                self.cond.wait()
                key = self._free_key()
            q = self.queues[key]
            item = q.popleft()
            self.size -= 1
            self.busy += 1
            self.working[me] = key
            if q:
                self.order.append(key)
            else:
                del self.queues[key]
            return item

    def _free_key(self):
        held = set(self.working.values())
        index = next((i for i, key in enumerate(self.order) if key not in held), None)
        if index is None:
            return None
        key = self.order[index]
        del self.order[index]
        return key

    def done(self) -> None:
        with self.cond:
            self.working.pop(threading.get_ident(), None)
            self.busy = max(0, self.busy - 1)
            self.cond.notify_all()

    def empty(self) -> bool:
        with self.cond:
            return not self.size

    def only_me(self) -> bool:
        with self.cond:
            return not self.size and self.busy <= 1

    def wait_idle(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        with self.cond:
            while self.size or self.busy:
                left = deadline - time.time()
                if left <= 0:
                    return False
                self.cond.wait(left)
            return True
