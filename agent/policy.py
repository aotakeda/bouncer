from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import parse_qs, unquote, unquote_plus

from .labels import Decision
from .net import bare_path

SUSPICIOUS = re.compile(
    r"""(['`<>;$]|%27|%22|%3c|%3e|\x00|\.\./|\.\.%2f|--|/\*|\bunion\b|\bselect\b|\bsleep\(|\bor\s+1=1|etc/passwd|<script|[\s"'/<]on[a-z]+\s*=|javascript:|\{\{|\$\{)""",
    re.IGNORECASE,
)
ATTACK = re.compile(
    r"""(\bunion\b[\s\S]{0,80}\bselect\b|\bor\b\s*['"]?\s*\d+\s*=\s*\d+|'\s*(or|and|\)|;|--|#)|--\s|/\*|\bsleep\s*\(|\bbenchmark\s*\(|\.\./|<script|onerror\s*=|javascript:|\$where|\$ne\b|\$gt\b|etc/passwd)""",
    re.IGNORECASE,
)
ATTACK_MORE = re.compile(
    r"""(--(?:$|["'}\]),;&#])|\x00|[\s"'/<]on[a-z]+\s*=|java\s*script\s*:|\$(gte|lt|lte|regex|nin|or|in|exists|elemmatch)\b)""",
    re.IGNORECASE,
)
JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
JWT = re.compile(r"eyJ[\w-]+\.[\w-]*\.[\w-]*")
TOKEN_HEADERS = ("authorization", "cookie")
DOOR_FLAGS = ("truncated", "attack_shaped", "decode_failed")
NORMALIZE_ROUNDS = 4
DIGITS = re.compile(r"\d+")
SPACES = re.compile(r"\s+")
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|zgrab|masscan|nmap|dirbuster|gobuster|ffuf|wpscan|acunetix|python-requests|go-http-client|curl/|wget/|libwww", re.IGNORECASE)
PROBE_PATH = re.compile(r"\.(php|asp|aspx|jsp|cgi)\b|/wp-|/\.git|/\.env|/phpmyadmin|/cgi-bin|/actuator|/boaform|/HNAP1|/vendor/", re.IGNORECASE)
FOREIGN_FETCH_SITES = ("cross-site", "same-site")
BROWSER_UA = re.compile(r"^mozilla/", re.IGNORECASE)

PREFILTERED = "prefiltered"
DEDUPED = "deduped"
VARIANT_DEDUPED = "deduped_variant"
MAX_VARIANTS = 5
REPEAT_PROVEN = "repeat_proven"
MAX_SEEN = 10000
JEV_ACTIONS = (Decision.IGNORE, Decision.WATCH, Decision.TARPIT, Decision.REPLAY, Decision.BLOCK)


@dataclass(frozen=True)
class Thresholds:
    replay: float = 0.9
    min_list_confidence: float = 0.5
    min_list_malicious: float = 0.8
    failed_attack_malicious: float = 0.7
    dedupe_seconds: float = 600
    max_variants: int = MAX_VARIANTS
    proven_seconds: float = 86400
    probe_paths: int = 5
    foreign_block_after: int = 3
    foreign_seconds: float = 600


class Signals(NamedTuple):
    suspicious: bool
    scanner: bool
    probe: bool
    failed: bool
    attack: bool = False

    @property
    def interesting(self) -> bool:
        return self.suspicious or self.scanner or self.probe or self.failed


class Screening(NamedTuple):
    skipped: str
    signals: Signals | None
    probes: int = 0


def shape(event: dict) -> str:
    path = event.get("path", "")
    bare, _, query = path.partition("?")
    keys = ",".join(sorted(parse_qs(query, keep_blank_values=True).keys()))
    return f"{event.get('method')} {bare}?{keys}"


def request_text(event: dict) -> str:
    return f"{event.get('path', '')} {event.get('body', '')}"


def normalize(text: str, plus: bool = True) -> str:
    out = str(text)
    for _ in range(NORMALIZE_ROUNDS):
        decoded = JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), unquote_plus(out) if plus else unquote(out))
        if decoded == out:
            break
        out = decoded
    return out.lower().replace("/**/", " ")


def screened_text(event: dict) -> str:
    form = "form-urlencoded" in str(event.get("ctype") or "").lower()
    return f"{normalize(event.get('path', ''))} {normalize(event.get('body', ''), plus=form)}"


def skeleton(event: dict) -> str:
    return hashlib.sha256(SPACES.sub(" ", DIGITS.sub("0", screened_text(event))).strip().encode()).hexdigest()


def is_suspicious(event: dict) -> bool:
    return bool(SUSPICIOUS.search(request_text(event)) or SUSPICIOUS.search(screened_text(event)))


def header(event: dict, name: str) -> str:
    headers = event.get("headers")
    if not isinstance(headers, dict):
        return ""
    return " ".join(str(v) for k, v in headers.items() if str(k).lower() == name)


def unsigned_jwt(token: str) -> bool:
    head, _, rest = token.partition(".")
    signature = rest.partition(".")[2]
    if not signature:
        return True
    try:
        alg = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))).get("alg")
    except (ValueError, binascii.Error, AttributeError):
        return False
    return str(alg).strip().lower() in ("none", "")


def forged_token(event: dict) -> bool:
    return any(unsigned_jwt(t) for name in TOKEN_HEADERS for t in JWT.findall(header(event, name)))


def flagged_by_door(event: dict) -> bool:
    return any(event.get(flag) is True for flag in DOOR_FLAGS)


def looks_like_attack(event: dict) -> bool:
    text = screened_text(event)
    return bool(ATTACK.search(text) or ATTACK_MORE.search(text)) or event.get("attack_shaped") is True or forged_token(event)


def read_signals(event: dict, suspicious: bool) -> Signals:
    attack = looks_like_attack(event)
    return Signals(
        suspicious=suspicious or attack or flagged_by_door(event),
        scanner=bool(SCANNER_UA.search(event.get("ua", ""))),
        probe=bool(PROBE_PATH.search(event.get("path", ""))),
        failed=(event.get("status") or 0) >= 400,
        attack=attack,
    )


def worth_triage(event: dict) -> bool:
    return read_signals(event, is_suspicious(event)).suspicious


def fetch_header(event: dict, field: str, name: str) -> str:
    value = event.get(field)
    return (value if isinstance(value, str) else header(event, name)).strip().lower()


def browser_fetch(event: dict) -> bool:
    if fetch_header(event, "fetch_site", "sec-fetch-site") not in FOREIGN_FETCH_SITES:
        return False
    if not fetch_header(event, "fetch_mode", "sec-fetch-mode") or not fetch_header(event, "fetch_dest", "sec-fetch-dest"):
        return False
    ua = str(event.get("ua") or "")
    return bool(BROWSER_UA.search(ua)) and not SCANNER_UA.search(ua)


def valid_proven_row(row) -> bool:
    if not isinstance(row, list) or len(row) != 4 or not all(isinstance(v, str) for v in row[:3]):
        return False
    return isinstance(row[3], (int, float)) and not isinstance(row[3], bool)


def malicious(triage: dict) -> float:
    value = triage.get("malicious")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def confidence(triage: dict) -> float:
    value = triage.get("confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


class DecisionPolicy:
    def __init__(self, thresholds: Thresholds):
        self.thresholds = thresholds
        self.lock = threading.RLock()
        self.seen: dict = {}
        self.proven: dict = {}
        self.variants: dict = {}
        self.probes: dict = {}
        self.foreign: dict = {}

    @staticmethod
    def key(event: dict, ip: str) -> tuple:
        forged = forged_token(event)
        text = request_text(event) + (" " + " ".join(header(event, name) for name in TOKEN_HEADERS) if forged else "")
        return (ip, shape(event), hashlib.sha256(text.encode()).hexdigest() if forged or is_suspicious(event) else "")

    def mark_proven(self, event: dict, ip: str, ts: float) -> None:
        key = self.key(event, ip)
        with self.lock:
            if len(self.proven) >= MAX_SEEN:
                cutoff = ts - self.thresholds.proven_seconds
                self.proven = {k: v for k, v in self.proven.items() if v > cutoff}
                if len(self.proven) >= MAX_SEEN:
                    self.proven = dict(sorted(self.proven.items(), key=lambda kv: kv[1])[-(MAX_SEEN // 2):])
            self.proven[key] = ts

    def proven_rows(self, now: float) -> list:
        cutoff = now - self.thresholds.proven_seconds
        with self.lock:
            return [[*key, ts] for key, ts in self.proven.items() if ts > cutoff]

    def restore_proven(self, rows, now: float) -> int:
        if not isinstance(rows, list):
            return 0
        cutoff = now - self.thresholds.proven_seconds
        kept = {tuple(row[:3]): float(row[3]) for row in rows if valid_proven_row(row) and cutoff < row[3] <= now + 60}
        kept = dict(sorted(kept.items(), key=lambda kv: kv[1])[-MAX_SEEN:])
        with self.lock:
            for key, ts in kept.items():
                self.proven[key] = max(ts, self.proven.get(key, ts))
        return len(kept)

    def forget(self, ip: str) -> None:
        with self.lock:
            self.seen = {k: v for k, v in self.seen.items() if k[0] != ip}
            self.variants = {k: v for k, v in self.variants.items() if k[0] != ip}
            self.probes.pop(ip, None)
            self.foreign.pop(ip, None)

    def foreign_strike(self, ip: str, ts: float) -> int:
        cutoff = ts - self.thresholds.foreign_seconds
        with self.lock:
            strikes = [t for t in self.foreign.pop(ip, []) if t > cutoff] + [ts]
            if len(self.foreign) >= MAX_SEEN:
                self.foreign = {k: v for k, v in self.foreign.items() if v and v[-1] > cutoff}
                if len(self.foreign) >= MAX_SEEN:
                    self.foreign = dict(sorted(self.foreign.items(), key=lambda kv: kv[1][-1])[-(MAX_SEEN // 2):])
            self.foreign[ip] = strikes[-max(1, self.thresholds.foreign_block_after):]
            return len(strikes)

    def _proven_ip(self, ip: str, ts: float) -> bool:
        return any(k[0] == ip and ts - v < self.thresholds.proven_seconds for k, v in self.proven.items())

    @staticmethod
    def quiet_socket(event: dict) -> bool:
        path = str(event.get("path", ""))
        low = normalize(path)
        return path.startswith("/socket.io/") and ".." not in low and "\x00" not in low and not flagged_by_door(event)

    def plain(self, event: dict, ip: str) -> bool:
        if self.quiet_socket(event):
            return True
        key = self.key(event, ip)
        with self.lock:
            if key in self.proven:
                return False
        return not read_signals(event, is_suspicious(event)).interesting

    def screen(self, event: dict, ip: str, ts: float) -> Screening:
        if self.quiet_socket(event):
            return Screening(PREFILTERED, None)
        suspicious = is_suspicious(event)
        key = self.key(event, ip)
        signals = read_signals(event, suspicious)
        with self.lock:
            proven_at = self.proven.get(key)
            if proven_at is not None and ts - proven_at < self.thresholds.proven_seconds:
                return Screening(REPEAT_PROVEN, signals)
            if self._is_duplicate(key, ts):
                return Screening(DEDUPED, None)
            if not signals.interesting:
                return Screening(PREFILTERED, None)
            if signals.suspicious and not self._proven_ip(ip, ts) and self._is_variant(event, ip, ts):
                return Screening(VARIANT_DEDUPED, None)
            probes = self._count_probe(event, ip, ts) if signals.probe else 0
            if len(self.seen) >= MAX_SEEN:
                self._prune(ts)
            self.seen[key] = {"ts": ts, "count": 1}
            return Screening("", signals, probes)

    def _count_probe(self, event: dict, ip: str, ts: float) -> int:
        entry = self.probes.get(ip)
        if not entry or ts - entry["ts"] >= self.thresholds.dedupe_seconds:
            if len(self.probes) >= MAX_SEEN:
                cutoff = ts - self.thresholds.dedupe_seconds
                self.probes = {k: v for k, v in self.probes.items() if v["ts"] > cutoff}
                if len(self.probes) >= MAX_SEEN:
                    self.probes = dict(sorted(self.probes.items(), key=lambda kv: kv[1]["ts"])[-(MAX_SEEN // 2):])
            entry = self.probes[ip] = {"ts": ts, "paths": set()}
        if len(entry["paths"]) < max(self.thresholds.probe_paths, 1) * 4:
            entry["paths"].add(bare_path(str(event.get("path", ""))).lower())
        return len(entry["paths"])

    def _is_variant(self, event: dict, ip: str, ts: float) -> bool:
        route = (ip, shape(event))
        entry = self.variants.get(route)
        if not entry or ts - entry["ts"] >= self.thresholds.dedupe_seconds:
            if len(self.variants) >= MAX_SEEN:
                cutoff = ts - self.thresholds.dedupe_seconds
                self.variants = {k: v for k, v in self.variants.items() if v["ts"] > cutoff}
                if len(self.variants) >= MAX_SEEN:
                    self.variants = dict(sorted(self.variants.items(), key=lambda kv: kv[1]["ts"])[-(MAX_SEEN // 2):])
            entry = self.variants[route] = {"ts": ts, "shapes": set()}
        sig = skeleton(event)
        if sig in entry["shapes"] or len(entry["shapes"]) >= self.thresholds.max_variants:
            return True
        entry["shapes"].add(sig)
        return False

    def _prune(self, ts: float) -> None:
        cutoff = ts - self.thresholds.dedupe_seconds
        self.seen = {k: v for k, v in self.seen.items() if v["ts"] > cutoff}
        if len(self.seen) >= MAX_SEEN:
            keep = sorted(self.seen.items(), key=lambda kv: kv[1]["ts"])[-(MAX_SEEN // 2):]
            self.seen = dict(keep)

    def _is_duplicate(self, key: tuple, ts: float) -> bool:
        prior = self.seen.get(key)
        if not prior or ts - prior["ts"] >= self.thresholds.dedupe_seconds:
            return False
        prior["count"] += 1
        return True

    def choose(self, triage: dict, signals: Signals, probes: int = 0) -> Decision:
        decision = self._from_jev(triage, signals)
        if signals.attack and not signals.probe and decision in (Decision.IGNORE, Decision.WATCH, Decision.TARPIT):
            return Decision.REPLAY
        if signals.suspicious or not (signals.probe or signals.scanner):
            return decision
        if signals.probe and self.many_probes(probes):
            return Decision.TARPIT if decision in (Decision.IGNORE, Decision.WATCH, Decision.TARPIT) else decision
        if signals.probe:
            return Decision.IGNORE
        return Decision.WATCH if decision.listed else decision

    def many_probes(self, probes: int) -> bool:
        return self.thresholds.probe_paths > 0 and probes >= self.thresholds.probe_paths

    def _from_jev(self, triage: dict, signals: Signals) -> Decision:
        if not triage.get("ok"):
            return Decision.REPLAY if signals.suspicious and not signals.probe else Decision.WATCH
        action = Decision.parse(triage.get("action"), Decision.WATCH)
        if action not in JEV_ACTIONS:
            return Decision.WATCH
        t = self.thresholds
        score = malicious(triage)
        if action.listed and confidence(triage) < t.min_list_confidence and score < t.min_list_malicious:
            return Decision.WATCH
        if action == Decision.BLOCK and signals.probe:
            return Decision.TARPIT
        if action == Decision.BLOCK:
            if score >= t.replay or score >= t.min_list_malicious or signals.suspicious:
                return Decision.REPLAY
            return Decision.TARPIT
        if action == Decision.TARPIT and score >= t.replay and not signals.probe:
            return Decision.REPLAY
        return action

    def after_failed_replay(self, triage: dict) -> Decision:
        return Decision.TARPIT if malicious(triage) >= self.thresholds.failed_attack_malicious else Decision.WATCH
