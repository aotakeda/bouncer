from __future__ import annotations

import itertools
import json
import sys
import threading
import time

from . import net, persona
from .claude import Claude
from .config import Config
from .door_client import DoorClient
from .event_log import DecisionLog, Feed
from .fix import Fixer
from .github import GitHub
from .inbox import FairInbox
from .jev import Jev
from .labels import Decision, EventKind, FixStatus, Verdict
from .net import bare_path, route_path
from .policy import PREFILTERED, REPEAT_PROVEN, DecisionPolicy, Screening, browser_fetch, worth_triage
from .replay import Replayer
from .store import Store
from .views import Views
from .web import AgentServer, make_handler

SLOWED_REFUSAL = 429
QUIET_VERDICT_LINES = {Verdict.INCONCLUSIVE: "inconclusive", Verdict.MINOR: "minor"}
AWAKE_TASK = "bouncer-incident"
RESTORED_FEED_ROWS = 300
SAVE_SECONDS = 30
LISTS_CACHE_SECONDS = 3.0
NO_LISTS_CACHE: tuple[float, dict] = (0.0, {})
KIND_OUTCOMES = {EventKind.REFUSED: "blocked", EventKind.TARPITTED: "slowed", EventKind.SHIELDED: "blocked"}
DECISION_OUTCOMES = {Decision.BLOCK: "blocked", Decision.TARPIT: "slowed"}
REFUSED_KINDS = (EventKind.REFUSED, EventKind.SHIELDED)
DROP_LOG_EVERY = 100
RETRY_KEY = "__retry__"
REPEAT_LINE = "Same trick that already worked in the back room. No second test needed. Out."
SHIELDED_LINE = "The door already turned it away: this route is shielded until the fix is merged. It would have worked, so they're out."
CROSS_SITE_HONEYPOT_LINE = "Fake .env fetched from inside another site's page. Probably an innocent browser being used as a puppet. Not slowing it down."
UNTAKEN_BAIT_LINE = "Bait value showed up, but this client never took the bait. Could be someone's browser being used against them. Not blocking."
FLOOD_LINE = "Too many requests to check at once. Slow lane while I work through the pile."
FOREIGN_LINE = "Sent from another site's page, so the visitor may not be the attacker. Not blocking or slowing it."
OWNER_SHIELD_LINE = "Your own traffic, so the route was not shielded."
FOREIGN_LIMIT_REASON = "kept attacking from other sites' pages"
CROSS_SITE_REUSE_LINE = "Bait value sent from inside another site's page. Probably an innocent browser being used as a puppet. Not blocking."


def trusted_fetch(event: dict) -> bool:
    return not browser_fetch(event)


def foreign_fetch(event: dict) -> bool:
    return browser_fetch(event)


def foreign_limit_line(strikes: int, seconds: float) -> str:
    return f"Another site's page again: {strikes} times from this client in {int(seconds)}s. Puppet or not, it's out."


def traffic_outcome(kind: EventKind, decision: Decision | None) -> str:
    if kind in REFUSED_KINDS:
        return KIND_OUTCOMES[kind]
    return DECISION_OUTCOMES.get(decision) or KIND_OUTCOMES.get(kind, "allowed")


def build_fixer(cfg: Config) -> Fixer | None:
    if not cfg.fixes_enabled:
        return None
    return Fixer(
        cfg.fix_mode,
        Claude(cfg.anthropic_url, cfg.fix_model, cfg.app_description),
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
        self.proven_lock = threading.Lock()
        self.policy.restore_proven(self.store.load_proven(), time.time())
        self.door = DoorClient(cfg.door_url, cfg.door_token)
        self.jev = Jev(cfg.jev_url, cfg.app_description) if cfg.jev_url else None
        self.replayer = Replayer(cfg.runner_url, cfg.runner_token) if cfg.runner_url else None
        self.fixer = build_fixer(cfg)
        self.inbox = FairInbox(cfg.pending_per_ip, cfg.pending_total)
        self.flooding: set = set()
        self.flood_lock = threading.Lock()
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
        self.replay_lock = threading.Lock()
        self.awake_lock = threading.Lock()
        self.awake_busy = 0
        for _ in range(cfg.workers):
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
            ip = e.get("ip") if isinstance(e.get("ip"), str) else "?"
            if self._count_quietly(e, ip) or self.inbox.put(ip, e):
                continue
            self._drop(ip, self.inbox.size < self.inbox.total)

    def _count_quietly(self, event: dict, ip: str) -> bool:
        kind = EventKind.parse(event.get("kind", EventKind.REQUEST), None)
        if self._counted_only(kind, event):
            outcome, name = KIND_OUTCOMES[kind], kind
        elif kind == EventKind.REQUEST and self._plain(event, ip):
            outcome, name = "allowed", PREFILTERED
        else:
            return False
        self.store.count("events")
        self.store.count(name)
        self.store.count_traffic(event_time(event.get("ts")), outcome)
        return True

    def _counted_only(self, kind, event: dict) -> bool:
        if kind == EventKind.REFUSED:
            return True
        if kind != EventKind.TARPITTED:
            return False
        if event.get("status") == SLOWED_REFUSAL:
            return True
        try:
            return not worth_triage(event)
        except Exception:
            return False

    def _plain(self, event: dict, ip: str) -> bool:
        try:
            return self.policy.plain(event, ip)
        except Exception:
            return False

    def _drop(self, ip: str, per_ip: bool):
        self.store.count("dropped")
        self.store.count("dropped_per_ip" if per_ip else "dropped_queue_full")
        if self.store.stats["dropped"] % DROP_LOG_EVERY == 1:
            print(json.dumps({"agent": "dropped events", "dropped": self.store.stats["dropped"], "reason": "per_ip" if per_ip else "queue_full"}), file=sys.stderr, flush=True)
        if per_ip:
            with self.flood_lock:
                self.flooding.add(ip)

    def _work(self):
        while True:
            event = self.inbox.get()
            try:
                self._work_one(event)
            finally:
                self.inbox.done()

    def _work_one(self, event: dict):
        with self.awake_lock:
            self.awake_busy += 1
        net.hold_awake(AWAKE_TASK, 300)
        try:
            self.handle(event)
        except Exception as exc:
            self._report_error(event, exc)
        with self.awake_lock:
            self.awake_busy -= 1
            last = not self.awake_busy and self.inbox.only_me()
            if last:
                net.release_awake(AWAKE_TASK)
        if last or time.time() - self.store.counters_saved >= SAVE_SECONDS:
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
        if RETRY_KEY in event:
            retry = event[RETRY_KEY]
            self._replay(retry["event"], retry["record"], retry["triage"], retry["attempt"])
            return
        self.store.count("events")
        record = self._record(event)
        record["rid"] = f"{self.rid_prefix}-{next(self.rids)}"
        kind = record["kind"]
        if self._counted_only(kind, event):
            self.store.count(kind)
            self.store.count_traffic(record["ts"], KIND_OUTCOMES[kind])
            return
        if kind == EventKind.TARPITTED:
            self.store.count(kind)
            self.store.count("tarpitted_triaged")
        self._slow_flooder(record)
        decision = self.kind_handlers.get(kind, self._on_request)(event, record)
        self.store.count_traffic(record["ts"], traffic_outcome(kind, decision))

    def _slow_flooder(self, record: dict):
        with self.flood_lock:
            if record["ip"] not in self.flooding:
                return
            self.flooding.discard(record["ip"])
        self._list_and_decide(dict(record), Decision.TARPIT, "flooded the triage queue", FLOOD_LINE)

    @staticmethod
    def _record(event: dict) -> dict:
        return {
            "ts": event_time(event.get("ts")),
            "ip": event.get("ip", "?"),
            "method": event.get("method"),
            "path": event.get("path", ""),
            "kind": EventKind.parse(event.get("kind", EventKind.REQUEST), EventKind.REQUEST),
            "ua": event.get("ua", ""),
            "foreign": foreign_fetch(event),
        }

    def _on_honeypot(self, event: dict, record: dict) -> Decision:
        if record.get("foreign"):
            self.store.shame_path(record["path"])
            return self.decide(record, Decision.WATCH, line=CROSS_SITE_HONEYPOT_LINE)
        self.store.visit_honeypot(record["ip"], record["ts"])
        self.store.shame_path(record["path"])
        line = persona.line("honeypot", record["path"])
        if event.get("took_bait") and trusted_fetch(event):
            self.store.count("tarpit_by_door")
            return self.decide(record, Decision.TARPIT, line=line)
        return self._list_and_decide(record, Decision.TARPIT, "took the honeypot .env", line)

    def _on_canary_reuse(self, event: dict, record: dict) -> Decision:
        origin = self.store.honeypot_origin(record["ip"])
        took = bool(event.get("took_bait")) or bool(origin and origin[0] == record["ip"])
        reason, line = "reused honeypot credentials", persona.line("canary_reuse", record["path"]) + self._honeypot_story(record["ip"])
        if not took:
            return self.decide(record, Decision.WATCH, line=UNTAKEN_BAIT_LINE)
        strikes = self._foreign_strikes(record)
        if strikes and strikes < self.cfg.foreign_block_after:
            return self.decide(record, Decision.WATCH, line=CROSS_SITE_REUSE_LINE)
        if strikes:
            reason, line = f"{FOREIGN_LIMIT_REASON}: {reason}", f"{line} {foreign_limit_line(strikes, self.cfg.foreign_seconds)}"
        record = {**record, "foreign": False}
        if event.get("took_bait") and trusted_fetch(event):
            self.store.count("block_by_door")
            blocked = self.door.enabled and not self.cfg.is_owner(record["ip"])
        else:
            blocked = self.set_list(Decision.BLOCK, record["ip"], reason)
        self.store.remember_catch(record, blocked)
        return self.decide(record, Decision.BLOCK, line=line)

    def _foreign_strikes(self, record: dict) -> int:
        if not record.get("foreign"):
            return 0
        strikes = self.policy.foreign_strike(record["ip"], record["ts"])
        self.store.count("foreign_limit" if strikes >= self.cfg.foreign_block_after else "foreign_excused")
        return strikes

    def _block_on_proof(self, record: dict, reason: str, line: str) -> Decision:
        strikes = self._foreign_strikes(record)
        if strikes >= self.cfg.foreign_block_after:
            record = {**record, "foreign": False}
            reason, line = f"{FOREIGN_LIMIT_REASON}: {reason}", f"{line} {foreign_limit_line(strikes, self.cfg.foreign_seconds)}"
        return self._list_and_decide(record, Decision.BLOCK, reason, line)

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
        if screening.skipped == REPEAT_PROVEN:
            self.store.count(REPEAT_PROVEN)
            return self._block_on_proof(record, "repeated a proven exploit", REPEAT_LINE)
        if screening.skipped:
            self.store.count(screening.skipped)
            return None
        signals = screening.signals
        if signals.probe:
            self.store.shame_path(bare_path(record["path"]))
        triage = self._triage(event, record["ip"])
        record["jev"] = triage
        decision = self.policy.choose(triage, signals, screening.probes)
        if decision == Decision.REPLAY and self.replayer:
            return self._replay(event, record, triage)
        return self._act(record, decision, screening)

    def _triage(self, event: dict, ip: str) -> dict:
        if not self.jev:
            return {"ok": False, "error": "jev not configured"}
        return self.jev.triage(event, self.history(ip))

    def _act(self, record: dict, decision: Decision, screening: Screening) -> Decision:
        path, signals = record["path"], screening.signals
        if decision.listed:
            many = decision == Decision.TARPIT and signals.probe and self.policy.many_probes(screening.probes)
            reason = f"probed {screening.probes} paths" if many else f"jev: {decision}"
            return self._list_and_decide(record, decision, reason, persona.line(decision, path))
        if decision == Decision.IGNORE:
            kind = "ignore_probe" if signals.probe else "ignore"
            return self.decide(record, Decision.IGNORE, line=persona.line(kind, path))
        return self.decide(record, Decision.WATCH, line=persona.line("watch", path))

    def _replay(self, event: dict, record: dict, triage: dict, attempt: int = 0) -> Decision:
        if not attempt:
            self.decide(record, Decision.REPLAY, line=persona.line("replay", record["path"]))
        with self.replay_lock:
            result = self.replayer.run(event)
        replayed = {**record, "replay": result, "attempt": attempt}
        handler = self.verdict_handlers.get(result["verdict"], self._on_jammed)
        return handler(event, replayed, triage)

    def _shield(self, record: dict, why: str) -> bool:
        if self.cfg.shield_seconds <= 0 or not self.door.enabled:
            return False
        if self.cfg.is_owner(record.get("ip")):
            self.store.count("would_shield")
            return False
        route = f"{record.get('method')} {route_path(record['path'])}"
        ok = self.door.put_shield(route, self.cfg.shield_seconds, "proven exploit: " + why[:120])
        self.store.count("shield_sent" if ok else "shield_failed")
        if ok:
            self._forget_lists()
        return ok

    def _remember_proven(self, event: dict, ip: str, ts: float):
        with self.proven_lock:
            self.policy.mark_proven(event, ip, ts)
            self.store.save_proven(self.policy.proven_rows(time.time()))

    def _on_proven(self, event: dict, record: dict, triage: dict) -> Decision:
        ip, result = record["ip"], record["replay"]
        self._remember_proven(event, ip, record["ts"])
        self._shield(record, result["why"])
        strikes = self._foreign_strikes(record)
        foreign = 0 < strikes < self.cfg.foreign_block_after
        reason = "proven exploit: " + result["why"][:120]
        if strikes and not foreign:
            reason = f"{FOREIGN_LIMIT_REASON}: {reason}"
            record = {**record, "foreign": False}
        blocked = False if foreign else self.set_list(Decision.BLOCK, ip, reason)
        incident = {"ts": time.time(), "ip": ip, "event": event, "replay": result, "jev": triage, "blocked": blocked, "rid": record.get("rid")}
        if foreign:
            incident["foreign"] = True
            self.store.count("foreign_proven")
        elif strikes:
            incident["foreign_strikes"] = strikes
        if self.cfg.is_owner(ip) and self.cfg.shield_seconds > 0 and self.door.enabled:
            incident["would_shield"] = True
        if self.fixer:
            incident["fix"] = queued_fix(FixStatus.QUEUED)
        self.store.add_incident(incident)
        line = SHIELDED_LINE if record.get("kind") == EventKind.SHIELDED else persona.line("proven", record["path"])
        if incident.get("would_shield"):
            line = f"{line} {OWNER_SHIELD_LINE}"
        if incident.get("foreign_strikes"):
            line = f"{line} {foreign_limit_line(strikes, self.cfg.foreign_seconds)}"
        base = {k: v for k, v in record.items() if k != "attempt"}
        decision = self.decide(base, Decision.WATCH, line=f"{line} {FOREIGN_LINE}") if foreign else self.decide(base, Decision.BLOCK, line=line)
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
        attempt = record.get("attempt", 0)
        if record["replay"].get("busy") and attempt < self.cfg.busy_retries:
            base = {k: v for k, v in record.items() if k not in ("replay", "attempt")}
            payload = {RETRY_KEY: {"event": event, "record": base, "triage": triage, "attempt": attempt + 1}}
            timer = threading.Timer(self.cfg.busy_retry_seconds, self.inbox.put, args=(record["ip"], payload))
            timer.daemon = True
            timer.start()
            self.store.count("replay_retry")
            slow = self.policy.after_failed_replay(triage)
            line = f"Back room is busy testing a fix. Trying again in {int(self.cfg.busy_retry_seconds)}s."
            if slow.listed and not attempt:
                return self._list_and_decide(base, slow, "waiting for proof", line + " Slow lane until then.")
            return self.decide(base, Decision.WATCH, line=line)
        return self.decide(record, Decision.WATCH, line=f"Back room is jammed ({record['replay'].get('why')}). Watching instead.")

    def _list_and_decide(self, record: dict, decision: Decision, reason: str, line: str) -> Decision:
        if record.get("foreign"):
            self.store.count("foreign_not_listed")
            return self.decide(record, Decision.WATCH, line=f"{line} {FOREIGN_LINE}")
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
            self.policy.forget(ip)
            if self.store.forget_honeypot(ip):
                self.store.count("bait_forgotten")
            with self.flood_lock:
                self.flooding.discard(ip)
            self._forget_lists()
            self.feed.notify({"kind": "state", "what": "lists"})
        return ok

    def unshield(self, route: str) -> bool:
        if not self.door.enabled or not route:
            return False
        ok = self.door.delete_shield(route)
        if ok:
            self.store.count("unshielded")
            self._forget_lists()
            self.feed.notify({"kind": "state", "what": "lists"})
        return ok

    def set_signal_status(self, key: str, status: str) -> bool:
        ok = self.store.set_signal_status(key, status)
        if ok:
            self.feed.notify({"kind": "state", "what": "signal", "id": key})
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
    server = AgentServer((cfg.host, cfg.port), make_handler(brain))
    print(json.dumps({"agent": "listening", "host": cfg.host, "port": cfg.port, "workers": cfg.workers, "jev": bool(cfg.jev_url), "runner": bool(cfg.runner_url), "door": bool(cfg.door_url)}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
