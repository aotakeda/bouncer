from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import parse_qs

from .labels import Decision

SUSPICIOUS = re.compile(
    r"""(['`<>;$]|%27|%22|%3c|%3e|\.\./|\.\.%2f|--|/\*|\bunion\b|\bselect\b|\bsleep\(|\bor\s+1=1|\$ne|\$where|\$gt|etc/passwd|<script|onerror=|javascript:|\{\{|\$\{)""",
    re.IGNORECASE,
)
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|zgrab|masscan|nmap|dirbuster|gobuster|ffuf|wpscan|acunetix|python-requests|go-http-client|curl/|wget/|libwww", re.IGNORECASE)
PROBE_PATH = re.compile(r"\.(php|asp|aspx|jsp|cgi)\b|/wp-|/\.git|/\.env|/phpmyadmin|/cgi-bin|/actuator|/boaform|/HNAP1|/vendor/", re.IGNORECASE)

PREFILTERED = "prefiltered"
DEDUPED = "deduped"
JEV_ACTIONS = (Decision.IGNORE, Decision.WATCH, Decision.TARPIT, Decision.REPLAY, Decision.BLOCK)


@dataclass(frozen=True)
class Thresholds:
    replay: float = 0.9
    min_list_confidence: float = 0.5
    min_list_malicious: float = 0.8
    failed_attack_malicious: float = 0.7
    dedupe_seconds: float = 600


class Signals(NamedTuple):
    suspicious: bool
    scanner: bool
    probe: bool
    failed: bool

    @property
    def interesting(self) -> bool:
        return self.suspicious or self.scanner or self.probe or self.failed


class Screening(NamedTuple):
    skipped: str
    signals: Signals | None


def shape(event: dict) -> str:
    path = event.get("path", "")
    bare, _, query = path.partition("?")
    keys = ",".join(sorted(parse_qs(query, keep_blank_values=True).keys()))
    return f"{event.get('method')} {bare}?{keys}"


def request_text(event: dict) -> str:
    return f"{event.get('path', '')} {event.get('body', '')}"


def read_signals(event: dict, suspicious: bool) -> Signals:
    return Signals(
        suspicious=suspicious,
        scanner=bool(SCANNER_UA.search(event.get("ua", ""))),
        probe=bool(PROBE_PATH.search(event.get("path", ""))),
        failed=(event.get("status") or 0) >= 400,
    )


def malicious(triage: dict) -> float:
    return triage.get("malicious") or 0


class DecisionPolicy:
    def __init__(self, thresholds: Thresholds):
        self.thresholds = thresholds
        self.seen: dict = {}

    def screen(self, event: dict, ip: str, ts: float) -> Screening:
        if event.get("path", "").startswith("/socket.io/"):
            return Screening(PREFILTERED, None)
        text = request_text(event)
        suspicious = bool(SUSPICIOUS.search(text))
        key = (ip, shape(event), hashlib.sha256(text.encode()).hexdigest() if suspicious else "")
        if self._is_duplicate(key, ts):
            return Screening(DEDUPED, None)
        signals = read_signals(event, suspicious)
        if not signals.interesting:
            return Screening(PREFILTERED, None)
        self.seen[key] = {"ts": ts, "count": 1}
        return Screening("", signals)

    def _is_duplicate(self, key: tuple, ts: float) -> bool:
        prior = self.seen.get(key)
        if not prior or ts - prior["ts"] >= self.thresholds.dedupe_seconds:
            return False
        prior["count"] += 1
        return True

    def choose(self, triage: dict, signals: Signals) -> Decision:
        if not triage.get("ok"):
            return Decision.REPLAY if signals.suspicious and not signals.probe else Decision.WATCH
        action = Decision.parse(triage.get("action"), Decision.WATCH)
        if action not in JEV_ACTIONS:
            return Decision.WATCH
        t = self.thresholds
        if action.listed and (triage.get("confidence") or 0) < t.min_list_confidence and malicious(triage) < t.min_list_malicious:
            return Decision.WATCH
        if action.listed and malicious(triage) >= t.replay and not signals.probe:
            return Decision.REPLAY
        return action

    def after_failed_replay(self, triage: dict) -> Decision:
        return Decision.TARPIT if malicious(triage) >= self.thresholds.failed_attack_malicious else Decision.WATCH
