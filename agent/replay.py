from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import net
from .labels import Verdict

STATEFUL_HEADERS = ("authorization", "cookie")
STATEFUL_METHODS = ("PUT", "PATCH", "DELETE")
KEEP_HEADERS = ("content-type", "accept", "authorization", "cookie", "x-user-email")

SESSION_COOKIE = re.compile(r"(?:^|;)\s*[\w.-]*(?:session|sess|sid|token|auth|jwt|login|user)[\w.-]*\s*=\s*[^;\s]{8,}", re.IGNORECASE)
CREDENTIAL = re.compile(r"^\s*(?:bearer|basic|token|digest)\s+\S{8,}|^\s*\S{16,}\s*$", re.IGNORECASE)
JWT = re.compile(r"eyJ[\w-]+\.[\w-]*\.[\w-]*")

CONTROL_TEXT = "control"
MAJOR_DIFFICULTY = 2


def control_value(key: str, value):
    if isinstance(value, str):
        return "control@bouncer.test" if "mail" in key.lower() else CONTROL_TEXT
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return 1
    if isinstance(value, dict):
        return {k: control_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [control_value(key, v) for v in value]
    return value


def _replace_values(query: str, value: str) -> str:
    return urlencode([(k, value) for k, _ in parse_qsl(query, keep_blank_values=True)])


def control_path(path: str) -> str:
    parts = urlsplit(path)
    if not parts.query:
        return path
    return urlunsplit(("", "", parts.path, _replace_values(parts.query, "apple"), ""))


def control_body(body: str | None, ctype: str | None) -> str | None:
    if not body:
        return body
    ctype = ctype or ""
    if "json" in ctype:
        try:
            return json.dumps(control_value("", json.loads(body)))
        except ValueError:
            return "{}"
    if "form" in ctype:
        return _replace_values(body, CONTROL_TEXT)
    return CONTROL_TEXT


def build_request(event: dict) -> dict:
    headers = {}
    if event.get("ctype"):
        headers["Content-Type"] = event["ctype"]
    headers.update({k: v for k, v in (event.get("headers") or {}).items() if k.lower() in KEEP_HEADERS})
    req = {"method": event.get("method", "GET"), "path": event.get("path", "/"), "headers": headers}
    if event.get("body") is not None:
        req["body"] = event["body"]
    if event.get("truncated"):
        req["truncated"] = True
    return req


def build_control(req: dict) -> dict:
    ctrl = {"method": req["method"], "path": control_path(req["path"]), "headers": dict(req["headers"])}
    if "body" in req:
        ctrl["body"] = control_body(req["body"], req["headers"].get("Content-Type"))
    return ctrl


def carries_session(name: str, value) -> bool:
    value = str(value or "")
    if JWT.search(value):
        return True
    if name == "cookie":
        return bool(SESSION_COOKIE.search(value))
    return bool(CREDENTIAL.search(value))


def is_stateful(req: dict) -> bool:
    if req["method"] in STATEFUL_METHODS:
        return True
    return any(k.lower() in STATEFUL_HEADERS and carries_session(k.lower(), v) for k, v in req["headers"].items())


def _outcome(verdict: Verdict, why: str, evidence: dict) -> dict:
    return {"verdict": verdict, "why": why, "evidence": evidence}


def _proven_reasons(major: dict, leaked: list, reflected: bool = False) -> list:
    why = []
    if major:
        why.append("solved " + ", ".join(f"{v.get('name')} (difficulty {v.get('difficulty')})" for v in major.values()))
    if leaked:
        why.append(f"leaked {len(leaked)} canary strings the control did not")
    if reflected:
        why.append("sent the injected markup back unescaped in an HTML page")
    return why


def interpret(req: dict, result: dict) -> dict:
    if not result.get("ok") and result.get("stage") == "busy":
        return {**_outcome(Verdict.ERROR, "back room busy testing a fix", {}), "busy": True}
    if not result.get("ok"):
        return _outcome(Verdict.ERROR, f"runner failed at {result.get('stage', 'call')}", {})
    attack = result["attack"]
    control = result.get("control") or {}
    solved = result.get("attack_solved", {})
    major = {k: v for k, v in solved.items() if (v.get("difficulty") or 0) >= MAJOR_DIFFICULTY}
    control_hits = control.get("canary_hits") or []
    leaked = [c for c in attack.get("canary_hits", []) if c not in control_hits]
    reflected = bool(attack.get("reflected")) and not control.get("reflected")
    evidence = {
        "attack_status": attack.get("status"),
        "control_status": control.get("status"),
        "solved": {k: v.get("name") for k, v in solved.items()},
        "canaries_leaked": len(leaked),
        "reflected": reflected,
        "reset_ms": (result.get("reset") or {}).get("ms"),
    }
    if not attack.get("status"):
        return _outcome(Verdict.ERROR, f"target did not answer: {attack.get('error') or 'status 0'}", evidence)
    if major or leaked or reflected:
        return _outcome(Verdict.PROVEN, "; ".join(_proven_reasons(major, leaked, reflected)), evidence)
    if solved:
        return _outcome(Verdict.MINOR, "only tripped " + ", ".join(v.get("name") or k for k, v in solved.items()), evidence)
    if req.get("truncated"):
        return _outcome(Verdict.INCONCLUSIVE, "request body was cut at the door; one replay cannot prove it safe", evidence)
    if is_stateful(req):
        return _outcome(Verdict.INCONCLUSIVE, "request carries a session or changes state; one replay cannot prove it safe", evidence)
    return _outcome(Verdict.NOT_REPRODUCED, "no challenge solved and no canary leaked", evidence)


class Replayer:
    def __init__(self, runner_url: str, token: str = ""):
        self.runner_url = runner_url.rstrip("/")
        self.headers = net.bearer(token)

    def run(self, event: dict) -> dict:
        req = build_request(event)
        payload = {"reset": True, "request": req, "control": build_control(req)}
        status, body, elapsed = net.post_json(self.runner_url + "/replay", payload, timeout=120, headers=self.headers)
        seconds = round(elapsed, 2)
        if status != 200 or not isinstance(body, dict):
            return {"verdict": Verdict.ERROR, "why": f"runner returned HTTP {status}", "evidence": {"body": str(body)[:300]}, "seconds": seconds}
        return {**interpret(req, body), "seconds": seconds, "request": req}
