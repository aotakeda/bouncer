from __future__ import annotations

import calendar
import re
import time
from urllib.parse import unquote_plus

from . import persona
from .config import Config
from .labels import Decision, EventKind, FixStatus, Verdict
from .net import route_path
from .store import KEPT_INCIDENTS, SIGNAL_STATES, Store

TSV_TIME = "%Y-%m-%dT%H:%M:%SZ"
JEV_NAME = "Jev System One"
FOREIGN_NOTE = "Sent from another site's page, so the visitor may not be the attacker"
FOREIGN_STRIKES_NOTE = "after {n} attacks sent from other sites' pages"
SEVERITIES = ("critical", "high", "medium", "low", "info")
ATTACK_PATTERNS = (
    ("SQL injection", re.compile(r"union\s+(all\s+)?select|'\s*(or|and)\s+[\w'\"]+\s*=|'\)+|'\s*--|;\s*drop\s|sleep\(\d", re.I)),
    ("Cross-site scripting", re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*iframe", re.I)),
    ("Path traversal", re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)),
    ("Command injection", re.compile(r";\s*(cat|ls|id|whoami|curl|wget)\b|\$\(|`[^`]+`", re.I)),
)
FIX_PILLS = {
    FixStatus.QUEUED: ("Fix queued", "now"),
    FixStatus.WORKING: ("Fixing", "now"),
    FixStatus.READY: ("Patch ready", "done"),
    FixStatus.PR_OPENED: ("PR open", "done"),
    FixStatus.PR_EXISTS: ("PR open", "done"),
}


def stored_text(value: str) -> str | None:
    return None if value in ("", "None") else value


def stored_number(value: str) -> float | None:
    text = stored_text(value)
    return None if text is None else float(text)


def attack_type(event: dict) -> str:
    text = unquote_plus(f"{event.get('path', '')} {event.get('body', '')}")
    for name, pattern in ATTACK_PATTERNS:
        if pattern.search(text):
            return name
    return "Exploit"


def severity(kind, decision, verdict, malicious) -> str:
    if verdict == Verdict.PROVEN:
        return "critical"
    if kind == EventKind.CANARY_REUSE:
        return "high"
    if decision in (Decision.BLOCK, Decision.WOULD_BLOCK):
        return "medium"
    if decision in (Decision.TARPIT, Decision.WOULD_TARPIT) or kind == EventKind.HONEYPOT:
        return "low"
    if isinstance(malicious, (int, float)) and malicious >= 0.8:
        return "medium"
    if isinstance(malicious, (int, float)) and malicious >= 0.5:
        return "low"
    return "info"


def foreign_strikes_note(incident: dict) -> str:
    strikes = incident.get("foreign_strikes")
    if isinstance(strikes, bool) or not isinstance(strikes, int) or strikes <= 0:
        return ""
    return FOREIGN_STRIKES_NOTE.format(n=strikes)


def fix_view(fix: dict | None) -> dict | None:
    if not fix:
        return None
    url = fix.get("pr_url") or ""
    variants = (fix.get("verify") or {}).get("variants") or []
    return {
        "status": fix.get("status"),
        "line": fix.get("line"),
        "file": fix.get("file"),
        "summary": fix.get("summary"),
        "diff": (fix.get("diff") or "")[:6000],
        "variants": [{k: v.get(k) for k in ("idea", "before", "after")} for v in variants],
        "pr_url": url if url.startswith("https://github.com/") else "",
    }


def fix_pill(fix: dict | None) -> tuple:
    if not fix:
        return ("", "todo")
    status = FixStatus.parse(fix.get("status"), None)
    if status in FIX_PILLS:
        return FIX_PILLS[status]
    return ("Fix failed", "fail")


def fix_steps(fix: dict | None, fixes_enabled: bool) -> list:
    if not fix:
        return [{"label": "Patch", "state": "todo", "note": "Fixes are off" if not fixes_enabled else "Not started"}]
    status = FixStatus.parse(fix.get("status"), None)
    ts = fix.get("ts")
    if status in (FixStatus.QUEUED, FixStatus.WORKING):
        return [{"label": "Writing and testing a patch", "state": "now", "ts": ts, "note": fix.get("file") or ""}]
    if status == FixStatus.READY:
        return [
            {"label": "Patch written and tested", "state": "done", "ts": ts, "note": fix.get("file") or ""},
            {"label": "Pull request", "state": "todo", "note": "Not opened (dry run)"},
        ]
    if status in (FixStatus.PR_OPENED, FixStatus.PR_EXISTS):
        return [
            {"label": "Patch written and tested", "state": "done", "ts": ts, "note": fix.get("file") or ""},
            {"label": "Pull request opened", "state": "done", "ts": ts, "note": "Waiting for your review"},
        ]
    return [{"label": "Patch", "state": "fail", "ts": ts, "note": str(fix.get("line") or status or "")[:200]}]


class Views:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store

    def mask(self, ip: str) -> str:
        return "you (owner)" if self.cfg.is_owner(ip) else ip

    def feed_row(self, r: dict) -> dict:
        jev = r.get("jev") or {}
        rep = r.get("replay") or {}
        return {
            "ts": r.get("ts"),
            "ip": self.mask(r.get("ip", "")),
            "method": r.get("method"),
            "path": (r.get("path") or "")[:200],
            "decision": r.get("decision"),
            "line": r.get("line"),
            "malicious": jev.get("malicious"),
            "jev_action": jev.get("action"),
            "confidence": jev.get("confidence"),
            "verdict": rep.get("verdict"),
            "why": rep.get("why"),
            "rid": r.get("rid"),
            "kind": r.get("kind"),
            "severity": severity(r.get("kind"), r.get("decision"), rep.get("verdict"), jev.get("malicious")),
        }

    def stored_feed_row(self, row: dict) -> dict:
        return {
            "ts": calendar.timegm(time.strptime(row["ts"], TSV_TIME)),
            "ip": self.mask(row["ip"]),
            "method": row["method"],
            "path": row["path"][:200],
            "decision": row["decision"],
            "line": row["line"],
            "malicious": stored_number(row["jev_malicious"]),
            "jev_action": stored_text(row["jev_action"]),
            "confidence": stored_number(row["jev_confidence"]),
            "verdict": stored_text(row["replay_verdict"]),
            "why": None,
            "kind": row["kind"],
            "severity": severity(row["kind"], row["decision"], stored_text(row["replay_verdict"]), stored_number(row["jev_malicious"])),
        }

    def incident(self, incident: dict) -> dict:
        return {
            "ts": incident["ts"],
            "ip": self.mask(incident["ip"]),
            "path": incident["event"].get("path"),
            "why": incident["replay"].get("why"),
            "fix": fix_view(incident.get("fix")),
        }

    def lists(self, snapshot: dict, viewer_ip: str = "") -> list:
        now = time.time()
        rows = []
        for kind in ("block", "tarpit"):
            for ip, entry in (snapshot.get(kind) or {}).items():
                rows.append({
                    "kind": kind,
                    "ip": ip,
                    "label": self.mask(ip),
                    "yours": bool(viewer_ip and ip == viewer_ip),
                    "left": max(0, int(entry.get("until", 0) - now)),
                    "reason": str(entry.get("reason", ""))[:120],
                })
        return rows

    def shields(self, snapshot: dict) -> list:
        now = time.time()
        rows = []
        for route, entry in (snapshot.get("shield") or {}).items():
            left = int(entry.get("until", 0) - now)
            if left > 0:
                rows.append({"route": route, "left": left, "reason": str(entry.get("reason", ""))[:120]})
        return sorted(rows, key=lambda r: r["route"])

    def blocked_step(self, blocked: bool, ts, unblocked_note: str = "", blocked_note: str = "") -> dict:
        if blocked:
            return {"label": f"Client blocked for {self.cfg.block_seconds // 60} min", "state": "done", "ts": ts, "note": blocked_note}
        return {"label": "Client not blocked", "state": "todo", "ts": ts, "note": unblocked_note}

    def proven_signals(self, fixes_on: bool, shields: dict | None = None) -> list:
        groups: dict = {}
        for incident in self.store.incidents[-KEPT_INCIDENTS:]:
            event = incident.get("event") or {}
            key = f"proven:{event.get('method') or ''} {route_path(event.get('path') or '')}"
            groups.setdefault(key, []).append(incident)
        shields = shields or {}
        return [self.proven_signal(key, items, fixes_on, shields.get(key.removeprefix("proven:"))) for key, items in groups.items()]

    def proven_signal(self, key: str, items: list, fixes_on: bool, shield: dict | None = None) -> dict:
        latest = items[-1]
        event = latest.get("event") or {}
        replay = latest.get("replay") or {}
        jev = latest.get("jev") or {}
        fix = latest.get("fix")
        steps = [
            {"label": f"Flagged by {JEV_NAME}", "state": "done" if jev.get("ok") else "todo", "ts": event.get("ts"), "note": f"{round(jev['malicious'] * 100)}% attack" if isinstance(jev.get("malicious"), (int, float)) else ""},
            {"label": "Proven on the stunt double", "state": "bad", "ts": latest["ts"], "note": replay.get("why") or ""},
            self.blocked_step(latest.get("blocked", True), latest["ts"], FOREIGN_NOTE if latest.get("foreign") else "Owner or door unavailable", foreign_strikes_note(latest)),
            *([{"label": "Route shielded until the fix is merged", "state": "done", "ts": latest["ts"], "note": "attack-shaped requests get 403"}] if shield else []),
            *([{"label": "Route not shielded", "state": "todo", "ts": latest["ts"], "note": "Your own traffic, so it would have been shielded for anyone else"}] if latest.get("would_shield") and not shield else []),
            *fix_steps(fix, fixes_on),
        ]
        pill, pill_state = fix_pill(fix)
        return {
            "id": key,
            "kind": "proven",
            "severity": "critical",
            "status": self.store.signal_status(key, latest["ts"], "open"),
            "title": f"{attack_type(event)} on {event.get('method') or ''} {route_path(event.get('path') or '')}".strip(),
            "summary": replay.get("why") or "",
            "method": event.get("method"),
            "path": (event.get("path") or "")[:2000],
            "body": str(event.get("body") or "")[:2000],
            "ip": self.mask(latest["ip"]),
            "raw_ip": latest["ip"],
            "first": items[0]["ts"],
            "last": latest["ts"],
            "count": len(items),
            "rids": [i.get("rid") for i in items if i.get("rid")],
            "jev": {k: jev.get(k) for k in ("malicious", "action", "confidence")} if jev.get("ok") else None,
            "fix_label": pill,
            "fix_state": pill_state,
            "fix": fix_view(fix),
            "shield": shield,
            "steps": steps,
        }

    def catch_signal(self, catch: dict) -> dict:
        key = f"caught:{catch['ip']}"
        steps = []
        if catch.get("took"):
            steps.append({"label": "Took the bait keys from the fake .env", "state": "done", "ts": catch["took"], "note": ""})
        steps.append({"label": f"Used the bait keys on {catch['path']}", "state": "bad", "ts": catch["ts"], "note": f"{catch.get('count', 1)} times" if catch.get("count", 1) > 1 else ""})
        steps.append(self.blocked_step(catch.get("blocked", True), catch["ts"]))
        return {
            "id": key,
            "kind": "caught",
            "severity": "high",
            "status": self.store.signal_status(key, catch.get("last", catch["ts"]), "resolved"),
            "title": "Bait keys from the fake .env were used",
            "summary": "No real credentials were exposed. The client was caught using decoy keys.",
            "method": catch.get("method"),
            "path": catch["path"],
            "body": "",
            "ip": self.mask(catch["ip"]),
            "raw_ip": catch["ip"],
            "first": catch["ts"],
            "last": catch.get("last", catch["ts"]),
            "count": catch.get("count", 1),
            "rids": [catch["rid"]] if catch.get("rid") else [],
            "jev": None,
            "fix_label": "",
            "fix_state": "todo",
            "fix": None,
            "steps": steps,
        }

    def signals(self, fixes_on: bool, shields: list | None = None) -> list:
        by_route = {s["route"]: s for s in shields or []}
        with self.store.lock:
            items = self.proven_signals(fixes_on, by_route) + [self.catch_signal(c) for c in self.store.catches]
        rank = {s: i for i, s in enumerate(SIGNAL_STATES)}
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(items, key=lambda s: (rank[s["status"]], order[s["severity"]], -s["last"]))

    def state(self, recent: list, door_lists: dict, viewer_ip: str, fixes_on: bool) -> dict:
        store = self.store
        with store.lock:
            stats = dict(store.stats)
            shame = [{"path": p, "count": c, "caption": persona.shame_caption(p, c)} for p, c in store.shame.most_common(10)]
            incidents = [self.incident(i) for i in store.incidents[-KEPT_INCIDENTS:]]
            traffic = sorted([k * 60, *v] for k, v in store.traffic.items())
        shields = self.shields(door_lists)
        return {
            "stats": stats,
            "recent": recent,
            "shame": shame,
            "incidents": incidents,
            "signals": self.signals(fixes_on, shields),
            "traffic": traffic,
            "lists": self.lists(door_lists, viewer_ip),
            "shields": shields,
            "fix_mode": self.cfg.fix_mode if fixes_on else "off",
            "now": time.time(),
        }
