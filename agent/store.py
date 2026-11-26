from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter
from pathlib import Path

from .labels import FixStatus
from .redact import redact_incident, redact_text

KEPT_INCIDENTS = 20
KEPT_SHAME = 200
KEPT_VISITS = 200
KEPT_IPS = 2000
KEPT_PER_IP = 20
KEPT_CATCHES = 20
KEPT_SIGNAL_STATES = 500
MAX_COUNTED_KEYS = 2000
TRAFFIC_KEEP_MINUTES = 7 * 24 * 60
OUTCOME_SLOTS = ("allowed", "slowed", "blocked")
SIGNAL_STATES = ("open", "reviewing", "resolved")
UNFINISHED_FIX = (FixStatus.QUEUED, FixStatus.WORKING)
INTERRUPTED_LINE = "Fix was cut short by a restart. The next proven attack on this hole starts it again."


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


def valid_catch(item) -> bool:
    return isinstance(item, dict) and isinstance(item.get("ts"), (int, float)) and isinstance(item.get("ip"), str) and isinstance(item.get("path"), str)


def valid_signal_state(item) -> bool:
    return isinstance(item, dict) and item.get("status") in SIGNAL_STATES and isinstance(item.get("ts"), (int, float))


def stored_traffic(value) -> dict:
    if not isinstance(value, dict):
        return {}
    out = {}
    for k, v in value.items():
        if isinstance(v, list) and len(v) == len(OUTCOME_SLOTS) and all(isinstance(n, int) and not isinstance(n, bool) for n in v):
            try:
                out[int(k)] = list(v)
            except ValueError:
                continue
    return out


def stored_counts(value) -> dict:
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}


class Store:
    def __init__(self, data_dir: Path):
        self.lock = threading.RLock()
        self.save_lock = threading.Lock()
        self.stats: Counter = Counter()
        self.shame: Counter = Counter()
        self.honeypot_visits: dict = {}
        self.per_ip: dict = {}
        self.incidents: list = []
        self.catches: list = []
        self.signal_states: dict = {}
        self.traffic: dict = {}
        self.counters_saved = 0.0
        self.incidents_path = data_dir / "incidents.json"
        self.catches_path = data_dir / "catches.json"
        self.signal_states_path = data_dir / "triage.json"
        self.counters_path = data_dir / "counters.json"
        self.proven_path = data_dir / "proven.json"
        self._restore_incidents()
        self._restore_catches()
        self._restore_signal_states()
        self._restore_counters()

    def _restore_incidents(self):
        try:
            loaded = json.loads(self.incidents_path.read_text())
            if not isinstance(loaded, list) or not all(valid_incident(i) for i in loaded):
                return
        except Exception:
            return
        self.incidents = [settled(i) for i in loaded[-KEPT_INCIDENTS:]]

    def _restore_catches(self):
        try:
            loaded = json.loads(self.catches_path.read_text())
        except Exception:
            return
        if isinstance(loaded, list):
            self.catches = [c for c in loaded if valid_catch(c)][-KEPT_CATCHES:]

    def _restore_signal_states(self):
        try:
            loaded = json.loads(self.signal_states_path.read_text())
        except Exception:
            return
        if isinstance(loaded, dict):
            self.signal_states = {k: v for k, v in loaded.items() if isinstance(k, str) and valid_signal_state(v)}

    def _restore_counters(self):
        try:
            loaded = json.loads(self.counters_path.read_text())
            stats, shame, visits = (stored_counts(loaded.get(k)) for k in ("stats", "shame", "honeypot_visits"))
            traffic = stored_traffic(loaded.get("traffic"))
        except Exception:
            return
        self.stats.update(stats)
        self.shame.update(shame)
        self.honeypot_visits.update(visits)
        self.traffic.update(traffic)

    def load_proven(self) -> list:
        try:
            loaded = json.loads(self.proven_path.read_text())
        except Exception:
            return []
        return loaded if isinstance(loaded, list) else []

    def save_proven(self, rows: list) -> None:
        self._write_json(self.proven_path, rows)

    def _write_json(self, path: Path, data) -> None:
        with self.save_lock:
            try:
                tmp = path.with_suffix(".tmp")
                with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                    f.write(json.dumps(data, default=str))
                tmp.chmod(0o600)
                tmp.replace(path)
            except Exception:
                self.count("save_failed")

    def _counters(self) -> dict:
        with self.lock:
            visits = sorted(self.honeypot_visits.items(), key=lambda kv: kv[1])[-KEPT_VISITS:]
            traffic = {str(k): list(v) for k, v in self.traffic.items()}
            shame = {redact_text(k): v for k, v in self.shame.most_common(KEPT_SHAME)}
            return {"stats": dict(self.stats), "shame": shame, "honeypot_visits": dict(visits), "traffic": traffic}

    def save_counters(self):
        self.counters_saved = time.time()
        self._write_json(self.counters_path, self._counters())

    def save_incidents(self):
        with self.lock:
            data = [redact_incident(i) for i in self.incidents[-KEPT_INCIDENTS:]]
        self._write_json(self.incidents_path, data)

    def _save_catches(self):
        with self.lock:
            data = [dict(c, path=redact_text(c["path"])) for c in self.catches[-KEPT_CATCHES:]]
        self._write_json(self.catches_path, data)

    def _save_signal_states(self):
        with self.lock:
            data = dict(sorted(self.signal_states.items(), key=lambda kv: kv[1]["ts"])[-KEPT_SIGNAL_STATES:])
        self._write_json(self.signal_states_path, data)

    def count(self, name: str):
        with self.lock:
            self.stats[name] += 1

    def shame_path(self, path: str):
        with self.lock:
            if path not in self.shame and len(self.shame) >= MAX_COUNTED_KEYS:
                self.shame = Counter(dict(self.shame.most_common(MAX_COUNTED_KEYS // 2)))
            self.shame[path] += 1

    def count_traffic(self, ts, outcome: str):
        when = ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else time.time()
        minute = int(when // 60)
        with self.lock:
            if minute not in self.traffic:
                cutoff = int(time.time() // 60) - TRAFFIC_KEEP_MINUTES
                for old in [m for m in self.traffic if m < cutoff]:
                    del self.traffic[old]
                self.traffic[minute] = [0] * len(OUTCOME_SLOTS)
            self.traffic[minute][OUTCOME_SLOTS.index(outcome)] += 1

    def visit_honeypot(self, ip: str, ts):
        with self.lock:
            if ip not in self.honeypot_visits and len(self.honeypot_visits) >= MAX_COUNTED_KEYS:
                self.honeypot_visits = dict(sorted(self.honeypot_visits.items(), key=lambda kv: kv[1])[-(MAX_COUNTED_KEYS // 2):])
            self.honeypot_visits[ip] = ts

    def forget_honeypot(self, ip: str) -> bool:
        with self.lock:
            return self.honeypot_visits.pop(ip, None) is not None

    def honeypot_origin(self, ip: str) -> tuple | None:
        with self.lock:
            if ip in self.honeypot_visits:
                return ip, self.honeypot_visits[ip]
            if not self.honeypot_visits:
                return None
            return max(self.honeypot_visits.items(), key=lambda kv: kv[1])

    def remember(self, record: dict):
        ip = record["ip"]
        with self.lock:
            history = self.per_ip.pop(ip, [])
            if len(self.per_ip) >= KEPT_IPS:
                self.per_ip.pop(next(iter(self.per_ip)))
            self.per_ip[ip] = (history + [record])[-KEPT_PER_IP:]

    def recent(self, ip: str, n: int) -> list:
        with self.lock:
            return list(self.per_ip.get(ip, [])[-n:])

    def add_incident(self, incident: dict):
        with self.lock:
            self.incidents.append(incident)
            if len(self.incidents) > KEPT_INCIDENTS:
                self.incidents = self.incidents[-KEPT_INCIDENTS:]

    def set_fix(self, incident: dict, fix: dict):
        with self.lock:
            incident["fix"] = fix

    def remember_catch(self, record: dict, blocked: bool):
        ip = record["ip"]
        ts = record["ts"] if isinstance(record["ts"], (int, float)) else time.time()
        with self.lock:
            took = self.honeypot_visits.get(ip)
            for catch in reversed(self.catches):
                if catch["ip"] == ip:
                    catch.update(last=ts, count=catch.get("count", 1) + 1, blocked=blocked, rid=record["rid"])
                    break
            else:
                self.catches.append({"ts": ts, "last": ts, "ip": ip, "method": record.get("method"), "path": record["path"], "took": took, "blocked": blocked, "count": 1, "rid": record["rid"]})
                self.catches = self.catches[-KEPT_CATCHES:]
        self._save_catches()

    def signal_status(self, key: str, last_seen: float, default: str) -> str:
        with self.lock:
            saved = self.signal_states.get(key)
        if not saved:
            return default
        if saved["status"] == "resolved" and default == "open" and last_seen > saved["ts"]:
            return "open"
        return saved["status"]

    def set_signal_status(self, key: str, status: str) -> bool:
        if status not in SIGNAL_STATES or not isinstance(key, str) or not key or len(key) > 300:
            return False
        with self.lock:
            self.signal_states[key] = {"status": status, "ts": time.time()}
        self._save_signal_states()
        return True
