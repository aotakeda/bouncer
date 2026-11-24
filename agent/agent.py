from __future__ import annotations

import itertools
import json
import queue
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from . import net, persona
from .claude import Claude
from .config import Config
from .door_client import DoorClient
from .event_log import DecisionLog, Feed
from .fix import Fixer
from .github import GitHub
from .jev import Jev
from .labels import Decision, EventKind, FixStatus, Verdict
from .net import bare_path
from .policy import DecisionPolicy, Signals
from .replay import Replayer
from .store import Store
from .views import Views
from .web import make_handler

COUNTED_ONLY_KINDS = (EventKind.REFUSED, EventKind.TARPITTED)
QUIET_VERDICT_LINES = {Verdict.INCONCLUSIVE: "inconclusive", Verdict.MINOR: "minor"}
AWAKE_TASK = "bouncer-incident"
RESTORED_FEED_ROWS = 300
SAVE_SECONDS = 30
LISTS_CACHE_SECONDS = 3.0
NO_LISTS_CACHE: tuple[float, dict] = (0.0, {})
KIND_OUTCOMES = {EventKind.REFUSED: "blocked", EventKind.TARPITTED: "slowed"}
DECISION_OUTCOMES = {Decision.BLOCK: "blocked", Decision.TARPIT: "slowed"}


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


def event_time(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return time.time()
    try:
        time.gmtime(value)
    except (ValueError, OverflowError, OSError):
        return time.time()
    return value


def queued_fix(status: FixStatus) -> dict:
    return {"status": status, "line": "Fix queued." if status == FixStatus.QUEUED else f"No fix attempt: {status}."}


class Brain:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.log = DecisionLog(cfg.data_dir / "decisions.tsv")
        self.feed = Feed()
        self.store = Store(cfg.data_dir)
        self.views = Views(cfg, self.store)
        self.policy = DecisionPolicy(cfg.thresholds)
        self.door = DoorClient(cfg.door_url, cfg.door_token)
        self.jev = Jev(cfg.jev_url, cfg.app_description) if cfg.jev_url else None
        self.replayer = Replayer(cfg.runner_url, cfg.runner_token) if cfg.runner_url else None
        self.fixer = build_fixer(cfg)
        self.inbox: queue.Queue = queue.Queue(maxsize=20000)
        self.rids = itertools.count(1)
        self.rid_prefix = format(int(time.time()), "x")
        self.lists_lock = threading.Lock()
        self.lists_cache = NO_LISTS_CACHE
        self._restore_feed()
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
        previous = None
        for index, row in enumerate(stored):
            try:
                view = self.views.stored_feed_row(row)
            except Exception:
                continue
            same = previous and previous["decision"] == Decision.REPLAY and all(previous[k] == view[k] for k in ("ip", "method", "path"))
            view["rid"] = previous["rid"] if same else f"r{index}"
            self.feed.recent.append(view)
            previous = view

    def submit(self, events: list):
        for e in events:
            if not isinstance(e, dict):
                self.store.count("malformed")
                continue
            try:
                self.inbox.put_nowait(e)
            except queue.Full:
                self.store.count("dropped")

    def _work(self):
        while True:
            event = self.inbox.get()
            net.hold_awake(AWAKE_TASK, 300)
            try:
                self.handle(event)
            except Exception as exc:
                self._report_error(event, exc)
            if self.inbox.empty():
                self.store.save_counters()
                net.release_awake(AWAKE_TASK)
            elif time.time() - self.store.counters_saved >= SAVE_SECONDS:
                self.store.save_counters()

    def _report_error(self, event: dict, exc: Exception):
        ip, path = event.get("ip"), event.get("path")
        self.emit({
            "ts": time.time(),
            "ip": ip if isinstance(ip, str) else "?",
            "path": path if isinstance(path, str) else "",
            "decision": Decision.ERROR,
            "line": f"agent error: {exc}"[:300],
        })

    def history(self, ip: str) -> str:
        return "; ".join(f"{d['method']} {d['path'][:80]} -> {d['decision']}" for d in self.store.recent(ip, 5))

    def handle(self, event: dict):
        self.store.count("events")
        record = self._record(event)
        record["rid"] = f"{self.rid_prefix}-{next(self.rids)}"
        kind = record["kind"]
        if kind in COUNTED_ONLY_KINDS:
            self.store.count(kind)
            self.store.count_traffic(record["ts"], KIND_OUTCOMES[kind])
            return
        decision = self.kind_handlers.get(kind, self._on_request)(event, record)
        self.store.count_traffic(record["ts"], DECISION_OUTCOMES.get(decision, "allowed"))

    @staticmethod
    def _record(event: dict) -> dict:
        return {
            "ts": event_time(event.get("ts")),
            "ip": event.get("ip", "?"),
            "method": event.get("method"),
            "path": event.get("path", ""),
            "kind": EventKind.parse(event.get("kind", EventKind.REQUEST), EventKind.REQUEST),
            "ua": event.get("ua", ""),
        }

    def _on_honeypot(self, event: dict, record: dict) -> Decision:
        self.store.visit_honeypot(record["ip"], record["ts"])
        self.store.shame_path(record["path"])
        return self._list_and_decide(record, Decision.TARPIT, "took the honeypot .env", persona.line("honeypot", record["path"]))

    def _on_canary_reuse(self, event: dict, record: dict) -> Decision:
        line = persona.line("canary_reuse", record["path"]) + self._honeypot_story(record["ip"])
        blocked = self.set_list(Decision.BLOCK, record["ip"], "reused honeypot credentials")
        self.store.remember_catch(record, blocked)
        return self.decide(record, Decision.BLOCK, line=line)

    def _honeypot_story(self, ip: str) -> str:
        origin = self.store.honeypot_origin(ip)
        if not origin:
            return ""
        origin_ip, ts = origin
        if origin_ip == ip:
            return f" Keys were taken from the fake .env by this same client at {utc_clock(ts)} UTC."
        return f" Keys were last taken from the fake .env by {self.views.mask(origin_ip)} at {utc_clock(ts)} UTC."

    def _on_request(self, event: dict, record: dict) -> Decision | None:
        screening = self.policy.screen(event, record["ip"], record["ts"])
        if screening.skipped:
            self.store.count(screening.skipped)
            return None
        signals = screening.signals
        if signals.probe:
            self.store.shame_path(bare_path(record["path"]))
        triage = self._triage(event, record["ip"])
        record["jev"] = triage
        decision = self.policy.choose(triage, signals)
        if decision == Decision.REPLAY and self.replayer:
            return self._replay(event, record, triage)
        return self._act(record, decision, signals)

    def _triage(self, event: dict, ip: str) -> dict:
        if not self.jev:
            return {"ok": False, "error": "jev not configured"}
        return self.jev.triage(event, self.history(ip))

    def _act(self, record: dict, decision: Decision, signals: Signals) -> Decision:
        path = record["path"]
        if decision.listed:
            return self._list_and_decide(record, decision, f"jev: {decision}", persona.line(decision, path))
        if decision == Decision.IGNORE:
            kind = "ignore_probe" if signals.probe or signals.scanner else "ignore"
            return self.decide(record, Decision.IGNORE, line=persona.line(kind, path))
        return self.decide(record, Decision.WATCH, line=persona.line("watch", path))

    def _replay(self, event: dict, record: dict, triage: dict) -> Decision:
        self.decide(record, Decision.REPLAY, line=persona.line("replay", record["path"]))
        result = self.replayer.run(event)
        record = {**record, "replay": result}
        handler = self.verdict_handlers.get(result["verdict"], self._on_jammed)
        return handler(event, record, triage)

    def _on_proven(self, event: dict, record: dict, triage: dict) -> Decision:
        ip, result = record["ip"], record["replay"]
        blocked = self.set_list(Decision.BLOCK, ip, "proven exploit: " + result["why"][:120])
        incident = {"ts": time.time(), "ip": ip, "event": event, "replay": result, "jev": triage, "blocked": blocked, "rid": record.get("rid")}
        if self.fixer:
            incident["fix"] = queued_fix(FixStatus.QUEUED)
        self.store.add_incident(incident)
        decision = self.decide(record, Decision.BLOCK, line=persona.line("proven", record["path"]))
        if self.fixer:
            status = self.fixer.submit(incident, self.fix_report)
            if status != FixStatus.QUEUED:
                self.store.set_fix(incident, queued_fix(status))
        self.store.save_incidents()
        return decision

    def _on_not_reproduced(self, event: dict, record: dict, triage: dict) -> Decision:
        line = persona.line("not_reproduced", record["path"])
        decision = self.policy.after_failed_replay(triage)
        if decision.listed:
            return self._list_and_decide(record, decision, "failed attack attempt", line)
        return self.decide(record, decision, line=line)

    def _on_quiet_verdict(self, event: dict, record: dict, triage: dict) -> Decision:
        kind = QUIET_VERDICT_LINES[record["replay"]["verdict"]]
        return self.decide(record, Decision.WATCH, line=persona.line(kind, record["path"]))

    def _on_jammed(self, event: dict, record: dict, triage: dict) -> Decision:
        return self.decide(record, Decision.WATCH, line=f"Back room is jammed ({record['replay'].get('why')}). Watching instead.")

    def _list_and_decide(self, record: dict, decision: Decision, reason: str, line: str) -> Decision:
        self.set_list(decision, record["ip"], reason)
        return self.decide(record, decision, line=line)

    def list_seconds(self, kind: Decision) -> int:
        return self.cfg.block_seconds if kind == Decision.BLOCK else self.cfg.tarpit_seconds

    def fix_report(self, incident: dict, fix: dict):
        self.store.set_fix(incident, {**fix, "ts": time.time()})
        self.store.save_incidents()
        event = incident["event"]
        record = {"ts": time.time(), "ip": incident["ip"], "method": event.get("method"), "path": event.get("path", ""), "kind": EventKind.FIX}
        record["replay"] = {"verdict": str(fix.get("status", "")).upper(), "evidence": {k: fix[k] for k in ("file", "pr_url") if fix.get(k)}}
        self.decide(record, Decision.FIX, line=fix.get("line", ""))

    def set_list(self, kind: Decision, ip: str, reason: str) -> bool:
        if self.cfg.is_owner(ip) or not self.door.enabled:
            return False
        ok = self.door.put(kind, ip, self.list_seconds(kind), reason)
        self.store.count(f"{kind}_sent" if ok else f"{kind}_failed")
        if ok:
            self._forget_lists()
        return ok

    def unblock(self, ip: str) -> bool:
        if not self.door.enabled or not ip:
            return False
        ok = self.door.unblock(ip)
        if ok:
            self.store.count("unblocked")
            self._forget_lists()
        return ok

    def decide(self, record: dict, decision: Decision, line: str) -> Decision:
        if self.cfg.is_owner(record.get("ip")) and decision.listed:
            line = f"That's you, boss. Anyone else gets a {decision} here. ({line})"
            decision = decision.for_owner()
        record = {**record, "decision": decision, "line": line}
        self.store.count(decision)
        self.store.remember(record)
        self.log.write(record)
        self.emit(record)
        return decision

    def emit(self, record: dict):
        self.feed.publish(self.views.feed_row(record))

    def _forget_lists(self):
        with self.lists_lock:
            self.lists_cache = NO_LISTS_CACHE

    def _door_snapshot(self) -> dict:
        with self.lists_lock:
            cached_at, snap = self.lists_cache
            if cached_at and time.time() - cached_at < LISTS_CACHE_SECONDS:
                return snap
        fresh = self.door.snapshot(timeout=3)
        with self.lists_lock:
            self.lists_cache = (time.time(), fresh)
        return fresh

    def state(self, viewer_ip: str = "") -> dict:
        return self.views.state(self.feed.latest(300), self._door_snapshot(), viewer_ip, bool(self.fixer))


def main():
    cfg = Config()
    brain = Brain(cfg)
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(brain))
    server.daemon_threads = True
    print(json.dumps({"agent": "listening", "port": cfg.port, "jev": bool(cfg.jev_url), "runner": bool(cfg.runner_url), "door": bool(cfg.door_url)}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
