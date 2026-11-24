from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import net

PROVEN = "PROVEN"
MINOR = "MINOR"
NOT_REPRODUCED = "NOT_REPRODUCED"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"

STATEFUL_HEADERS = ("authorization", "cookie")
KEEP_HEADERS = ("content-type", "accept", "authorization", "cookie", "x-user-email")


def control_value(key: str, value):
    if isinstance(value, str):
        return "control@bouncer.test" if "mail" in key.lower() else "control"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return 1
    if isinstance(value, dict):
        return {k: control_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [control_value(key, v) for v in value]
    return value


def control_path(path: str) -> str:
    parts = urlsplit(path)
    if not parts.query:
        return path
    query = urlencode([(k, "apple") for k, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit(("", "", parts.path, query, ""))


def control_body(body: str | None, ctype: str | None) -> str | None:
    if not body:
        return body
    if ctype and "json" in ctype:
        try:
            return json.dumps(control_value("", json.loads(body)))
        except ValueError:
            return "{}"
    if ctype and "form" in ctype:
        return urlencode([(k, "control") for k, _ in parse_qsl(body, keep_blank_values=True)])
    return "control"


def build_request(event: dict) -> dict:
    headers = {}
    if event.get("ctype"):
        headers["Content-Type"] = event["ctype"]
    for k, v in (event.get("headers") or {}).items():
        if k.lower() in KEEP_HEADERS:
            headers[k] = v
    req = {"method": event.get("method", "GET"), "path": event.get("path", "/"), "headers": headers}
    if event.get("body") is not None:
        req["body"] = event["body"]
    return req


def build_control(req: dict) -> dict:
    ctype = req["headers"].get("Content-Type")
    ctrl = {"method": req["method"], "path": control_path(req["path"]), "headers": dict(req["headers"])}
    if "body" in req:
        ctrl["body"] = control_body(req["body"], ctype)
    return ctrl


def is_stateful(req: dict) -> bool:
    return any(k.lower() in STATEFUL_HEADERS for k in req["headers"]) or req["method"] in ("PUT", "PATCH", "DELETE")


def interpret(req: dict, result: dict) -> dict:
    if not result.get("ok"):
        return {"verdict": ERROR, "why": f"runner failed at {result.get('stage', 'call')}", "evidence": {}}
    attack = result["attack"]
    control = result.get("control") or {}
    solved = result.get("attack_solved", {})
    major = {k: v for k, v in solved.items() if (v.get("difficulty") or 0) >= 2}
    leaked = [c for c in attack.get("canary_hits", []) if c not in (control.get("canary_hits") or [])]
    evidence = {
        "attack_status": attack.get("status"),
        "control_status": control.get("status"),
        "solved": {k: v.get("name") for k, v in solved.items()},
        "canaries_leaked": len(leaked),
        "reset_ms": (result.get("reset") or {}).get("ms"),
    }
    if major or leaked:
        why = []
        if major:
            why.append("solved " + ", ".join(f"{v.get('name')} (difficulty {v.get('difficulty')})" for v in major.values()))
        if leaked:
            why.append(f"leaked {len(leaked)} canary strings the control did not")
        return {"verdict": PROVEN, "why": "; ".join(why), "evidence": evidence}
    if solved:
        return {"verdict": MINOR, "why": "only tripped " + ", ".join(v.get("name") or k for k, v in solved.items()), "evidence": evidence}
    if is_stateful(req):
        return {"verdict": INCONCLUSIVE, "why": "request carries a session or changes state; one replay cannot prove it safe", "evidence": evidence}
    return {"verdict": NOT_REPRODUCED, "why": "no challenge solved and no canary leaked", "evidence": evidence}


class Replayer:
    def __init__(self, runner_url: str, token: str = ""):
        self.runner_url = runner_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else None

    def run(self, event: dict) -> dict:
        req = build_request(event)
        payload = {"reset": True, "request": req, "control": build_control(req)}
        status, body, elapsed = net.post_json(self.runner_url + "/replay", payload, timeout=120, headers=self.headers)
        if status != 200:
            return {"verdict": ERROR, "why": f"runner returned HTTP {status}", "evidence": {"body": str(body)[:300]}, "seconds": round(elapsed, 2)}
        out = interpret(req, body)
        out["seconds"] = round(elapsed, 2)
        out["request"] = req
        return out
