from __future__ import annotations

from enum import Enum


class Label(str, Enum):
    def __str__(self) -> str:
        return self.value

    @classmethod
    def parse(cls, value, default):
        try:
            return cls(value)
        except ValueError:
            return default


class Verdict(Label):
    PROVEN = "PROVEN"
    MINOR = "MINOR"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    NOT_RUN = "NOT_RUN"


class EventKind(Label):
    REQUEST = "request"
    REFUSED = "refused"
    TARPITTED = "tarpitted"
    HONEYPOT = "honeypot"
    CANARY_REUSE = "canary_reuse"
    SHIELDED = "shielded"
    FIX = "fix"


class Decision(Label):
    IGNORE = "ignore"
    WATCH = "watch"
    TARPIT = "tarpit"
    BLOCK = "block"
    REPLAY = "replay"
    FIX = "fix"
    ERROR = "error"
    WOULD_TARPIT = "would_tarpit"
    WOULD_BLOCK = "would_block"

    @property
    def listed(self) -> bool:
        return self in (Decision.BLOCK, Decision.TARPIT)

    def for_owner(self) -> Decision:
        return Decision("would_" + self.value) if self.listed else self


class FixStatus(Label):
    QUEUED = "queued"
    QUEUE_FULL = "queue_full"
    WORKING = "working"
    READY = "ready"
    PR_OPENED = "pr_opened"
    PR_EXISTS = "pr_exists"
    PR_FAILED = "pr_failed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"
    ERROR = "error"
    INTERRUPTED = "interrupted"
