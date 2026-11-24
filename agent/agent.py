from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import queue
import sys
import threading
import time
from collections import Counter
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from . import net, persona
from .door_client import DoorClient
from .event_log import DecisionLog, Feed
from .fix import Claude, Fixer, GitHub
from .jev import Jev
from .labels import Decision, EventKind, FixStatus, Verdict
from .net import bare_path
from .policy import DecisionPolicy, Signals, Thresholds
from .replay import Replayer

DEFAULT_APP_DESCRIPTION = "OWASP Juice Shop, an Angular + Express + SQLite online juice store with a REST API under /rest and /api. Not WordPress, no PHP."
FIX_MODES = ("dry_run", "pr")
COUNTED_ONLY_KINDS = (EventKind.REFUSED, EventKind.TARPITTED)
QUIET_VERDICT_LINES = {Verdict.INCONCLUSIVE: "inconclusive", Verdict.MINOR: "minor"}
AWAKE_TASK = "bouncer-incident"
RESTORED_FEED_ROWS = 300
KEPT_INCIDENTS = 20
TSV_TIME = "%Y-%m-%dT%H:%M:%SZ"
KEPT_SHAME = 200
KEPT_VISITS = 200
KEPT_IPS = 2000
MAX_BODY = 4 * 1024 * 1024
SAVE_SECONDS = 30
UNFINISHED_FIX = (FixStatus.QUEUED, FixStatus.WORKING)
INTERRUPTED_LINE = "Fix was cut short by a restart. The next proven attack on this hole starts it again."

TEXT = "text/plain"
HTML = "text/html; charset=utf-8"
JSON = "application/json"
COOKIE_NAME = "bouncer"


class BadRequest(Exception):
    pass


class PayloadTooLarge(Exception):
    pass


class Config:
    def __init__(self, env: Mapping[str, str] = os.environ):
        self.port = int(env.get("AGENT_PORT", "8080"))
        self.data_dir = Path(env.get("AGENT_DATA_DIR", "./agent-data"))
        self.events_sha256 = env.get("AGENT_EVENTS_SHA256", "")
        self.dash_sha256 = env.get("AGENT_DASH_SHA256", "")
        self.jev_url = env.get("JEV_URL", "")
        self.runner_url = env.get("RUNNER_URL", "")
        self.door_url = env.get("DOOR_URL", "").rstrip("/")
        self.door_token = env.get("DOOR_TOKEN", "")
        self.runner_token = env.get("RUNNER_TOKEN", "")
        self.owner_ips = {ip.strip() for ip in env.get("OWNER_IPS", "").split(",") if ip.strip()}
        self.block_seconds = int(env.get("BLOCK_SECONDS", "900"))
        self.tarpit_seconds = int(env.get("TARPIT_SECONDS", "600"))
        self.dedupe_seconds = int(env.get("DEDUPE_SECONDS", "600"))
        self.replay_threshold = float(env.get("REPLAY_THRESHOLD", "0.9"))
        self.min_list_confidence = float(env.get("MIN_LIST_CONFIDENCE", "0.5"))
        self.min_list_malicious = float(env.get("MIN_LIST_MALICIOUS", "0.8"))
        self.failed_attack_malicious = float(env.get("FAILED_ATTACK_MALICIOUS", "0.7"))
        self.fix_mode = env.get("FIX_MODE", "off")
        self.anthropic_url = env.get("ANTHROPIC_URL", "")
        self.github_url = env.get("GITHUB_URL", "")
        self.github_repo = env.get("GITHUB_REPO", "aotakeda/juice-shop")
        self.github_branch = env.get("GITHUB_BRANCH", "master")
        self.fix_model = env.get("FIX_MODEL", "claude-opus-5-5")
        self.fix_per_hour = int(env.get("FIX_PER_HOUR", "3"))
        self.app_description = env.get("APP_DESCRIPTION", DEFAULT_APP_DESCRIPTION)

    @property
    def fixes_enabled(self) -> bool:
        return self.fix_mode in FIX_MODES and bool(self.anthropic_url and self.github_url and self.runner_url)

    @property
    def thresholds(self) -> Thresholds:
        return Thresholds(
            replay=self.replay_threshold,
            min_list_confidence=self.min_list_confidence,
            min_list_malicious=self.min_list_malicious,
            failed_attack_malicious=self.failed_attack_malicious,
            dedupe_seconds=self.dedupe_seconds,
        )


def build_fixer(cfg: Config) -> Fixer | None:
    if not cfg.fixes_enabled:
        return None
    return Fixer(
        cfg.fix_mode,
        Claude(cfg.anthropic_url, cfg.fix_model),
        GitHub(cfg.github_url, cfg.github_repo, cfg.github_branch),
        cfg.runner_url,
        cfg.runner_token,
        max_per_hour=cfg.fix_per_hour,
    )


def utc_clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(ts))


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


def queued_fix(status: FixStatus) -> dict:
    return {"status": status, "line": "Fix queued." if status == FixStatus.QUEUED else f"No fix attempt: {status}."}


def stored_text(value: str) -> str | None:
    return None if value in ("", "None") else value


def stored_number(value: str) -> float | None:
    text = stored_text(value)
    return None if text is None else float(text)


def valid_incident(item) -> bool:
    if not isinstance(item, dict) or not isinstance(item.get("ts"), (int, float)) or not isinstance(item.get("ip"), str):
        return False
    fix = item.get("fix")
    return isinstance(item.get("event"), dict) and isinstance(item.get("replay"), dict) and (fix is None or isinstance(fix, dict))


def settled(incident: dict) -> dict:
    fix = incident.get("fix") or {}
    if fix.get("status") in UNFINISHED_FIX:
        incident["fix"] = {"status": FixStatus.INTERRUPTED, "line": INTERRUPTED_LINE}
    return incident


def stored_counts(value) -> dict:
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}


class Brain:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.log = DecisionLog(cfg.data_dir / "decisions.tsv")
        self.feed = Feed()
        self.policy = DecisionPolicy(cfg.thresholds)
        self.door = DoorClient(cfg.door_url, cfg.door_token)
        self.jev = Jev(cfg.jev_url, cfg.app_description) if cfg.jev_url else None
        self.replayer = Replayer(cfg.runner_url, cfg.runner_token) if cfg.runner_url else None
        self.fixer = build_fixer(cfg)
        self.inbox: queue.Queue = queue.Queue(maxsize=20000)
        self.per_ip: dict = {}
        self.honeypot_visits: dict = {}
        self.shame: Counter = Counter()
        self.stats: Counter = Counter()
        self.incidents: list = []
        self.incidents_path = cfg.data_dir / "incidents.json"
        self.counters_path = cfg.data_dir / "counters.json"
        self.state_lock = threading.RLock()
        self.save_lock = threading.Lock()
        self.counters_saved = 0.0
        self._lists_cache: tuple[float, dict] = (0.0, {"block": {}, "tarpit": {}})
        self._restore_feed()
        self._restore_incidents()
        self._restore_counters()
        self.kind_handlers = {
            EventKind.HONEYPOT: self._on_honeypot,
            EventKind.CANARY_REUSE: self._on_canary_reuse,
        }
        self.verdict_handlers = {
            Verdict.PROVEN: self._on_proven,
            Verdict.NOT_REPRODUCED: self._on_not_reproduced,
            Verdict.INCONCLUSIVE: self._on_quiet_verdict,
            Verdict.MINOR: self._on_quiet_verdict,
        }
        threading.Thread(target=self._work, daemon=True).start()

    def _restore_feed(self):
        try:
            stored = self.log.tail(RESTORED_FEED_ROWS)
        except Exception:
            return
        for row in stored:
            try:
                self.feed.recent.append(self._feed_row(row))
            except Exception:
                continue

    def _feed_row(self, row: dict) -> dict:
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
        }

    def _restore_incidents(self):
        try:
            loaded = json.loads(self.incidents_path.read_text())
            if not isinstance(loaded, list) or not all(valid_incident(i) for i in loaded):
                return
        except Exception:
            return
        self.incidents = [settled(i) for i in loaded[-KEPT_INCIDENTS:]]

    def _restore_counters(self):
        try:
            loaded = json.loads(self.counters_path.read_text())
            stats, shame, visits = (stored_counts(loaded.get(k)) for k in ("stats", "shame", "honeypot_visits"))
        except Exception:
            return
        self.stats.update(stats)
        self.shame.update(shame)
        self.honeypot_visits.update(visits)

    def _counters(self) -> dict:
        with self.state_lock:
            visits = sorted(self.honeypot_visits.items(), key=lambda kv: kv[1])[-KEPT_VISITS:]
            return {"stats": dict(self.stats), "shame": dict(self.shame.most_common(KEPT_SHAME)), "honeypot_visits": dict(visits)}

    def _incidents_snapshot(self) -> list:
        with self.state_lock:
            return [dict(i, fix=dict(i["fix"]) if isinstance(i.get("fix"), dict) else i.get("fix")) for i in self.incidents[-KEPT_INCIDENTS:]]

    def _write_json(self, path: Path, data) -> None:
        with self.save_lock:
            try:
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, default=str))
                tmp.replace(path)
            except Exception:
                with self.state_lock:
                    self.stats["save_failed"] += 1

    def _save_incidents(self):
        self._write_json(self.incidents_path, self._incidents_snapshot())

    def _save_counters(self):
        self.counters_saved = time.time()
        self._write_json(self.counters_path, self._counters())

    def submit(self, events: list):
        for e in events:
            try:
                self.inbox.put_nowait(e)
            except queue.Full:
                with self.state_lock:
                    self.stats["dropped"] += 1

    def _work(self):
        while True:
            event = self.inbox.get()
            net.hold_awake(AWAKE_TASK, 300)
            try:
                self.handle(event)
            except Exception as exc:
                self.emit({"ts": time.time(), "ip": event.get("ip"), "path": event.get("path"), "decision": Decision.ERROR, "line": f"agent error: {exc}"[:300]})
            if self.inbox.empty():
                self._save_counters()
                net.release_awake(AWAKE_TASK)
            elif time.time() - self.counters_saved >= SAVE_SECONDS:
                self._save_counters()

    def history(self, ip: str) -> str:
        with self.state_lock:
            items = list(self.per_ip.get(ip, [])[-5:])
        return "; ".join(f"{d['method']} {d['path'][:80]} -> {d['decision']}" for d in items)

    def handle(self, event: dict):
        with self.state_lock:
            self.stats["events"] += 1
        record = self._record(event)
        kind = record["kind"]
        if kind in COUNTED_ONLY_KINDS:
            with self.state_lock:
                self.stats[kind] += 1
            return
        self.kind_handlers.get(kind, self._on_request)(event, record)

    @staticmethod
    def _record(event: dict) -> dict:
        return {
            "ts": event.get("ts", time.time()),
            "ip": event.get("ip", "?"),
            "method": event.get("method"),
            "path": event.get("path", ""),
            "kind": EventKind.parse(event.get("kind", EventKind.REQUEST), EventKind.REQUEST),
            "ua": event.get("ua", ""),
        }

    def _on_honeypot(self, event: dict, record: dict):
        with self.state_lock:
            self.honeypot_visits[record["ip"]] = record["ts"]
            self.shame[record["path"]] += 1
        self._list_and_decide(record, Decision.TARPIT, "took the honeypot .env", persona.line("honeypot", record["path"]))

    def _on_canary_reuse(self, event: dict, record: dict):
        line = persona.line("canary_reuse", record["path"]) + self._honeypot_story(record["ip"])
        self._list_and_decide(record, Decision.BLOCK, "reused honeypot credentials", line)

    def _honeypot_story(self, ip: str) -> str:
        with self.state_lock:
            if ip in self.honeypot_visits:
                ts = self.honeypot_visits[ip]
                return f" Keys were taken from the fake .env by this same client at {utc_clock(ts)} UTC."
            if not self.honeypot_visits:
                return ""
            origin_ip, origin_ts = max(self.honeypot_visits.items(), key=lambda kv: kv[1])
        return f" Keys were last taken from the fake .env by {self.mask(origin_ip)} at {utc_clock(origin_ts)} UTC."

    def _on_request(self, event: dict, record: dict):
        screening = self.policy.screen(event, record["ip"], record["ts"])
        if screening.skipped:
            with self.state_lock:
                self.stats[screening.skipped] += 1
            return
        signals = screening.signals
        if signals.probe:
            with self.state_lock:
                self.shame[bare_path(record["path"])] += 1
        triage = self._triage(event, record["ip"])
        record["jev"] = triage
        decision = self.policy.choose(triage, signals)
        if decision == Decision.REPLAY and self.replayer:
            return self._replay(event, record, triage)
        self._act(record, decision, signals)

    def _triage(self, event: dict, ip: str) -> dict:
        if not self.jev:
            return {"ok": False, "error": "jev not configured"}
        return self.jev.triage(event, self.history(ip))

    def _act(self, record: dict, decision: Decision, signals: Signals):
        path = record["path"]
        if decision.listed:
            return self._list_and_decide(record, decision, f"jev: {decision}", persona.line(decision, path))
        if decision == Decision.IGNORE:
            kind = "ignore_probe" if signals.probe or signals.scanner else "ignore"
            return self.decide(record, Decision.IGNORE, line=persona.line(kind, path))
        return self.decide(record, Decision.WATCH, line=persona.line("watch", path))

    def _replay(self, event: dict, record: dict, triage: dict):
        self.decide(record, Decision.REPLAY, line=persona.line("replay", record["path"]))
        result = self.replayer.run(event)
        record = {**record, "replay": result}
        handler = self.verdict_handlers.get(result["verdict"], self._on_jammed)
        handler(event, record, triage)

    def _on_proven(self, event: dict, record: dict, triage: dict):
        ip, result = record["ip"], record["replay"]
        self.set_list(Decision.BLOCK, ip, "proven exploit: " + result["why"][:120])
        incident = {"ts": time.time(), "ip": ip, "event": event, "replay": result}
        if self.fixer:
            incident["fix"] = queued_fix(FixStatus.QUEUED)
        with self.state_lock:
            self.incidents.append(incident)
            if len(self.incidents) > KEPT_INCIDENTS:
                self.incidents = self.incidents[-KEPT_INCIDENTS:]
        self.decide(record, Decision.BLOCK, line=persona.line("proven", record["path"]))
        if self.fixer:
            status = self.fixer.submit(incident, self.fix_report)
            if status != FixStatus.QUEUED:
                with self.state_lock:
                    incident["fix"] = queued_fix(status)
        self._save_incidents()

    def _on_not_reproduced(self, event: dict, record: dict, triage: dict):
        line = persona.line("not_reproduced", record["path"])
        decision = self.policy.after_failed_replay(triage)
        if decision.listed:
            return self._list_and_decide(record, decision, "failed attack attempt", line)
        self.decide(record, decision, line=line)

    def _on_quiet_verdict(self, event: dict, record: dict, triage: dict):
        kind = QUIET_VERDICT_LINES[record["replay"]["verdict"]]
        self.decide(record, Decision.WATCH, line=persona.line(kind, record["path"]))

    def _on_jammed(self, event: dict, record: dict, triage: dict):
        self.decide(record, Decision.WATCH, line=f"Back room is jammed ({record['replay'].get('why')}). Watching instead.")

    def _list_and_decide(self, record: dict, decision: Decision, reason: str, line: str):
        self.set_list(decision, record["ip"], reason)
        self.decide(record, decision, line=line)

    def list_seconds(self, kind: Decision) -> int:
        return self.cfg.block_seconds if kind == Decision.BLOCK else self.cfg.tarpit_seconds

    def fix_report(self, incident: dict, fix: dict):
        with self.state_lock:
            incident["fix"] = fix
        self._save_incidents()
        event = incident["event"]
        record = {"ts": time.time(), "ip": incident["ip"], "method": event.get("method"), "path": event.get("path", ""), "kind": EventKind.FIX}
        record["replay"] = {"verdict": str(fix.get("status", "")).upper(), "evidence": {k: fix[k] for k in ("file", "pr_url") if fix.get(k)}}
        self.decide(record, Decision.FIX, line=fix.get("line", ""))

    def set_list(self, kind: Decision, ip: str, reason: str) -> bool:
        if self.is_owner(ip) or not self.door.enabled:
            return False
        ok = self.door.put(kind, ip, self.list_seconds(kind), reason)
        with self.state_lock:
            self.stats[f"{kind}_sent" if ok else f"{kind}_failed"] += 1
            if ok:
                self._lists_cache = (0.0, {"block": {}, "tarpit": {}})
        return ok

    def unblock(self, ip: str) -> bool:
        if not self.door.enabled or not ip:
            return False
        ok = self.door.unblock(ip)
        if ok:
            with self.state_lock:
                self.stats["unblocked"] += 1
                self._lists_cache = (0.0, {"block": {}, "tarpit": {}})
        return ok

    def is_owner(self, ip: str | None) -> bool:
        return ip in self.cfg.owner_ips

    def mask(self, ip: str) -> str:
        return "you (owner)" if self.is_owner(ip) else ip

    def decide(self, record: dict, decision: Decision, line: str):
        if self.is_owner(record.get("ip")) and decision.listed:
            line = f"That's you, boss. Anyone else gets a {decision} here. ({line})"
            decision = decision.for_owner()
        record = {**record, "decision": decision, "line": line}
        with self.state_lock:
            self.stats[decision] += 1
            self._remember(record)
        self.log.write(record)
        self.emit(record)

    def _remember(self, record: dict):
        ip = record["ip"]
        if ip not in self.per_ip and len(self.per_ip) >= KEPT_IPS:
            self.per_ip.pop(next(iter(self.per_ip)))
        self.per_ip[ip] = (self.per_ip.get(ip, []) + [record])[-20:]

    def public_view(self, r: dict) -> dict:
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
        }

    def emit(self, record: dict):
        self.feed.publish(self.public_view(record))

    def incident_view(self, incident: dict) -> dict:
        return {
            "ts": incident["ts"],
            "ip": self.mask(incident["ip"]),
            "path": incident["event"].get("path"),
            "why": incident["replay"].get("why"),
            "fix": fix_view(incident.get("fix")),
        }

    def _door_snapshot(self) -> dict:
        now = time.time()
        with self.state_lock:
            cached_at, snap = self._lists_cache
            if cached_at and now - cached_at < 3.0:
                return snap
        fresh = self.door.snapshot(timeout=3)
        with self.state_lock:
            self._lists_cache = (time.time(), fresh)
        return fresh

    def active_lists(self, viewer_ip: str = "") -> list:
        snap = self._door_snapshot()
        now = time.time()
        rows = []
        for kind in ("block", "tarpit"):
            for ip, entry in (snap.get(kind) or {}).items():
                rows.append({
                    "kind": kind,
                    "ip": ip,
                    "label": self.mask(ip),
                    "yours": bool(viewer_ip and ip == viewer_ip),
                    "left": max(0, int(entry.get("until", 0) - now)),
                    "reason": str(entry.get("reason", ""))[:120],
                })
        return rows

    def state(self, viewer_ip: str = "") -> dict:
        with self.state_lock:
            stats = dict(self.stats)
            shame = [{"path": p, "count": c, "caption": persona.shame_caption(p, c)} for p, c in self.shame.most_common(10)]
            incidents = [self.incident_view(i) for i in self.incidents[-KEPT_INCIDENTS:]]
        return {
            "stats": stats,
            "recent": self.feed.latest(100),
            "shame": shame,
            "incidents": incidents,
            "lists": self.active_lists(viewer_ip),
        }

DASHBOARD = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Bouncer</title><style>
:root{--bg:#0e0e12;--fg:#ececf1;--mute:#8b8b99;--card:#18181f;--line:#26262f;--red:#ff5d5d;--amber:#ffb547;--green:#4ade80;--blue:#7aa2ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 ui-sans-serif,system-ui,-apple-system,sans-serif}
header{padding:20px 16px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{margin:0;font-size:22px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute);margin:0 0 10px}
main{display:grid;grid-template-columns:2fr 1fr;gap:16px;padding:16px;max-width:1200px;margin:auto}@media(max-width:800px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stats{display:flex;gap:18px;flex-wrap:wrap;color:var(--mute)}.stats b{color:var(--fg);font-size:18px;display:block}
.ev{border-top:1px solid var(--line);padding:10px 0}.ev:first-child{border-top:0}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;margin-right:6px;background:var(--line)}
.block{background:var(--red);color:#000}.tarpit{background:var(--amber);color:#000}.replay,.QUEUED,.WORKING{background:var(--blue);color:#000}.ignore{background:#2a2a33}.watch,.MINOR,.INCONCLUSIVE{background:#3a3a46}.would_block,.would_tarpit{background:#3a3a46;outline:1px dashed var(--red)}
.PROVEN,.ERROR{background:var(--red);color:#000}.fix,.READY,.PR_OPENED,.PR_EXISTS{background:var(--green);color:#000}.FAILED,.PR_FAILED,.RATE_LIMITED,.INTERRUPTED{background:var(--amber);color:#000}
pre{font:12px/1.4 ui-monospace,monospace;background:#0b0b0f;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:360px}.add{color:var(--green)}.del{color:var(--red)}a{color:var(--blue)}.NOT_REPRODUCED{background:var(--green);color:#000}
code{font:12px ui-monospace,monospace;color:var(--mute);word-break:break-all}.line{margin:4px 0 0}.meta{color:var(--mute);font-size:12px}
button.btn{font:12px inherit;padding:3px 9px;border-radius:6px;border:1px solid var(--line);background:#26262f;color:var(--fg);cursor:pointer;float:right}button.btn:hover{border-color:var(--blue)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin-right:6px;vertical-align:middle}.dot.off{background:var(--amber)}
</style></head><body><header><h1>Bouncer</h1><span class=meta>Personal security agent at the door of a deliberately vulnerable OWASP Juice Shop</span><span class=meta style="margin-left:auto"><span class=dot id=dot></span><span id=conn>live</span></span></header>
<main><section class=card><h2>Tonight at the door</h2><div class=stats id=stats></div><div id=feed></div></section>
<aside><div class="card"><h2>On the list</h2><div id=lists></div></div><div class="card" style="margin-top:16px"><h2>Wall of shame</h2><div id=shame></div></div><div class="card" style="margin-top:16px"><h2>Proven break-ins</h2><div id=inc></div></div></aside></main>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=ts=>new Date(ts*1000).toLocaleTimeString();
function ev(e){const pct=v=>v==null?'':Math.round(v*100)+'%';return `<div class=ev><span class="tag ${esc(e.decision)}">${esc(e.decision)}</span>${e.verdict?`<span class="tag ${esc(e.verdict)}">${esc(e.verdict)}</span>`:''}<span class=meta>${t(e.ts)} · ${esc(e.ip)}${e.malicious!=null?` · Jev: attack ${pct(e.malicious)}, says ${esc(e.jev_action)} (${pct(e.confidence)} sure)`:''}</span><div><code>${esc(e.method)} ${esc(e.path)}</code></div><p class=line>${esc(e.line)}${e.why?` <span class=meta>(${esc(e.why)})</span>`:''}</p></div>`}
const colour=d=>esc(d).split('\\n').map(l=>l.startsWith('+')&&!l.startsWith('+++')?`<span class=add>${l}</span>`:l.startsWith('-')&&!l.startsWith('---')?`<span class=del>${l}</span>`:l).join('\\n');
const afterTag=v=>v.after==='PROVEN'?['PROVEN','still works']:v.after==='ERROR'?['ERROR','error']:v.after==='NOT_RUN'?['','not run']:['READY','blocked'];
function fx(f){if(!f)return '';return `<p class=line><span class="tag ${esc((f.status||'').toUpperCase())}">fix: ${esc(f.status)}</span>${esc(f.line)}${f.pr_url?` <a href="${esc(f.pr_url)}" target=_blank rel=noopener>pull request</a>`:''}</p>${f.summary?`<p class="line meta">${esc(f.summary)}</p>`:''}${f.diff?`<details><summary class=meta>patch for ${esc(f.file)}</summary><pre>${colour(f.diff)}</pre></details>`:''}${(f.variants||[]).length?`<details><summary class=meta>${f.variants.length} other ways in, tried before and after</summary>${f.variants.map(v=>{const [cls,lbl]=afterTag(v);return `<p class="line meta"><span class="tag ${v.before==='PROVEN'?'PROVEN':''}">${v.before==='PROVEN'?'worked':'not shown'}</span> &rarr; <span class="tag ${cls}">${lbl}</span> ${esc(v.idea)}</p>`}).join('')}</details>`:''}`}
const feed=document.getElementById('feed'),dot=document.getElementById('dot'),conn=document.getElementById('conn');
let lastShame='',lastInc='',lastLists='';
async function unblock(ip){const r=await fetch('api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});if(r.status===401)return location.reload();sync()}
function render(s){const st=s.stats||{};document.getElementById('stats').innerHTML=[['events','seen'],['prefiltered','waved through'],['replay','replayed'],['block','bounced'],['tarpit','slow-laned'],['refused','refused at door']].map(([k,l])=>`<div><b>${st[k]||0}</b>${l}</div>`).join('');
const listsKey=JSON.stringify(s.lists||[]);if(listsKey!==lastLists){lastLists=listsKey;document.getElementById('lists').innerHTML=(s.lists||[]).map(x=>`<div class=ev><button class=btn data-ip="${esc(x.ip)}">Unblock</button><span class="tag ${esc(x.kind)}">${esc(x.kind)}</span><code>${esc(x.label)}</code>${x.yours?' <span class=meta>(you)</span>':''}<div class=meta>${x.left}s left · ${esc(x.reason)}</div></div>`).join('')||'<p class=meta>Door is open. Nobody blocked.</p>';document.querySelectorAll('#lists button[data-ip]').forEach(b=>b.onclick=()=>unblock(b.dataset.ip))}
const shameKey=JSON.stringify(s.shame||[]);if(shameKey!==lastShame){lastShame=shameKey;document.getElementById('shame').innerHTML=(s.shame||[]).map(x=>`<div class=ev><code>${esc(x.path)}</code><p class=line>${esc(x.caption)}</p></div>`).join('')||'<p class=meta>Nobody embarrassing yet.</p>'}
const incKey=JSON.stringify(s.incidents||[]);if(incKey!==lastInc){lastInc=incKey;document.getElementById('inc').innerHTML=(s.incidents||[]).map(x=>`<div class=ev><span class=meta>${t(x.ts)} · ${esc(x.ip)}</span><div><code>${esc(x.path)}</code></div><p class=line>${esc(x.why)}</p>${fx(x.fix)}</div>`).join('')||'<p class=meta>No proven break-ins.</p>'}}
async function sync(init=false){const r=await fetch('api/state');if(r.status===401)return location.reload();const s=await r.json();render(s);if(init)feed.innerHTML=(s.recent||[]).slice().reverse().map(ev).join('')}
sync(true);
const es=new EventSource('stream');
let wasOff=false;
es.onopen=()=>{dot.className='dot';conn.textContent='live';if(wasOff){wasOff=false;sync(true)}};
es.onerror=()=>{wasOff=true;dot.className='dot off';conn.textContent='reconnecting...'};
es.onmessage=m=>{feed.insertAdjacentHTML('afterbegin',ev(JSON.parse(m.data)));while(feed.children.length>150)feed.lastElementChild.remove();sync()};
</script></body></html>"""

LOGIN = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Bouncer</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e0e12;color:#ececf1;font:16px system-ui,sans-serif}form{display:flex;gap:8px;padding:16px}input,button{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #333;background:#18181f;color:inherit}</style></head>
<body><form method=post action=login><input type=password name=passphrase placeholder="What's the password?" autofocus><button>Let me in</button></form></body></html>"""


def sha_matches(secret: str, expected_sha: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), expected_sha)


def make_handler(brain: Brain):
    cfg = brain.cfg
    not_found = (404, b"not found", TEXT)

    def cookie_value() -> str:
        return hmac.new(cfg.dash_sha256.encode(), b"bouncer-dashboard", hashlib.sha256).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def reply(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def bearer_ok(self, expected_sha: str) -> bool:
            scheme, _, token = self.headers.get("Authorization", "").partition(" ")
            if not expected_sha or scheme != "Bearer" or not token:
                return False
            return sha_matches(token, expected_sha)

        def dash_ok(self) -> bool:
            if not cfg.dash_sha256:
                return False
            cookies = dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p)
            return hmac.compare_digest(cookies.get(COOKIE_NAME, ""), cookie_value())

        def client_ip(self) -> str:
            return self.headers.get("Sprite-Client-Ip") or self.client_address[0]

        def body(self) -> bytes:
            raw = self.headers.get("Content-Length")
            if not raw:
                return b""
            try:
                n = int(raw)
            except ValueError as exc:
                raise BadRequest("invalid Content-Length") from exc
            if n < 0:
                raise BadRequest("negative Content-Length")
            if n > MAX_BODY:
                raise PayloadTooLarge("body too large")
            return self.rfile.read(n) if n > 0 else b""

        def post_events(self, data: bytes):
            if not self.bearer_ok(cfg.events_sha256):
                return self.reply(*not_found)
            try:
                payload = json.loads(data)
                events = payload.get("events", []) if isinstance(payload, dict) else None
            except ValueError:
                return self.reply(400, b"bad json", TEXT)
            if not isinstance(events, list):
                return self.reply(400, b"bad json", TEXT)
            brain.submit(events)
            return self.reply(202, json.dumps({"accepted": len(events)}).encode(), JSON)

        def post_login(self, data: bytes):
            given = parse_qs(data.decode("utf-8", "replace")).get("passphrase", [""])[0]
            if cfg.dash_sha256 and sha_matches(given, cfg.dash_sha256):
                cookie = f"{COOKIE_NAME}={cookie_value()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800"
                return self.reply(303, b"", TEXT, {"Location": "./", "Set-Cookie": cookie})
            time.sleep(1)
            return self.reply(401, LOGIN.encode(), HTML)

        def post_unblock(self, data: bytes):
            if not self.dash_ok():
                return self.reply(401, b"unauthorized", TEXT)
            if "application/json" not in self.headers.get("Content-Type", "").lower():
                return self.reply(415, b"expected application/json", TEXT)
            try:
                payload = json.loads(data or b"{}")
            except ValueError:
                return self.reply(400, b"bad json", TEXT)
            if not isinstance(payload, dict):
                return self.reply(400, b"bad json", TEXT)
            ip = payload.get("ip")
            if not ip or ip == "self":
                ip = self.client_ip()
            if not isinstance(ip, str) or any(c.isspace() or c == "/" for c in ip):
                return self.reply(400, b"bad ip", TEXT)
            ok = brain.unblock(ip)
            return self.reply(200, json.dumps({"ok": ok, "ip": ip}).encode(), JSON)

        def healthz(self):
            return self.reply(200, b"ok", TEXT)

        def login_page(self):
            return self.reply(200, LOGIN.encode(), HTML)

        def dashboard(self):
            return self.reply(200, DASHBOARD.encode(), HTML)

        def api_state(self):
            return self.reply(200, json.dumps(brain.state(self.client_ip())).encode(), JSON)

        def stream(self):
            q = brain.feed.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                self._pump(q)
            except OSError:
                pass
            finally:
                brain.feed.unsubscribe(q)

        def _pump(self, q: queue.Queue):
            while True:
                try:
                    item = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()

        PUBLIC_GET_ROUTES = {"/healthz": healthz}
        PRIVATE_GET_ROUTES = {"/": dashboard, "/api/state": api_state, "/stream": stream}
        POST_ROUTES = {"/events": post_events, "/login": post_login, "/api/unblock": post_unblock}

        def do_POST(self):
            try:
                data = self.body()
            except BadRequest:
                self.close_connection = True
                return self.reply(400, b"bad request", TEXT)
            except PayloadTooLarge:
                self.close_connection = True
                return self.reply(413, b"payload too large", TEXT)
            route = self.POST_ROUTES.get(bare_path(self.path))
            if not route:
                return self.reply(*not_found)
            return route(self, data)

        def do_GET(self):
            path = bare_path(self.path)
            public = self.PUBLIC_GET_ROUTES.get(path)
            if public:
                return public(self)
            if not self.dash_ok():
                if path == "/":
                    return self.login_page()
                if path in self.PRIVATE_GET_ROUTES:
                    return self.reply(401, b"unauthorized", TEXT)
                return self.reply(*not_found)
            route = self.PRIVATE_GET_ROUTES.get(path)
            if not route:
                return self.reply(*not_found)
            return route(self)

    return Handler


def main():
    cfg = Config()
    brain = Brain(cfg)
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(brain))
    server.daemon_threads = True
    print(json.dumps({"agent": "listening", "port": cfg.port, "jev": bool(cfg.jev_url), "runner": bool(cfg.runner_url), "door": bool(cfg.door_url)}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
