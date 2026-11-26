from __future__ import annotations

import re
from urllib.parse import unquote_plus

from .policy import unsigned_jwt

MASK = "[redacted]"
SECRET_NAME = re.compile(
    r"pass|pwd|secret|token|totp|answer|jwt|auth(?!or)|session|cookie|api[_-]?key|credential|signature|private[_-]?key"
    r"|(?:^|[_.\[-])(?:key|code|sig|sid|otp)\]?$",
    re.IGNORECASE,
)
JSON_FIELD = re.compile(r'"((?:[^"\\]|\\.)*)"(\s*:\s*)("(?:[^"\\]|\\.)*"?|[^,{}\[\]\s"]+)')
PAIR_FIELD = re.compile(r"(^|[?&;])([^=&;?#\s\"']+)=([^&;#\s\"]*)")
JWT_TOKEN = re.compile(r"(eyJ[\w-]+)\.[\w-]*(?:\.[\w-]*)?")
AUTH_HEADERS = {"authorization", "proxy-authorization"}
COOKIE_HEADERS = {"cookie", "set-cookie"}
TEXT_FIELDS = ("path", "body", "ua", "query", "referer")


def secret_name(name: str) -> bool:
    try:
        name = unquote_plus(name)
    except Exception:
        pass
    return bool(SECRET_NAME.search(name))


def _json_field(m: re.Match) -> str:
    if not secret_name(m.group(1)):
        return m.group(0)
    return f'"{m.group(1)}"{m.group(2)}"{MASK}"'


def _pair_field(m: re.Match) -> str:
    if not m.group(3) or not secret_name(m.group(2)):
        return m.group(0)
    return f"{m.group(1)}{m.group(2)}={MASK}"


def _jwt(m: re.Match) -> str:
    note = ", unsigned" if unsigned_jwt(m.group(0)) else ""
    return f"{m.group(1)}.[redacted jwt{note}]"


def redact_text(text) -> str:
    if not isinstance(text, str) or not text:
        return text
    out = JSON_FIELD.sub(_json_field, text)
    out = PAIR_FIELD.sub(_pair_field, out)
    return JWT_TOKEN.sub(_jwt, out)


def redact_header(name: str, value) -> str:
    text = str(value)
    lower = str(name).lower()
    if lower in AUTH_HEADERS:
        scheme, sep, rest = text.strip().partition(" ")
        if sep and scheme.isalpha() and len(scheme) <= 16:
            return f"{scheme} {MASK}"
        return MASK
    if lower in COOKIE_HEADERS:
        parts = []
        for part in text.split(";"):
            key, eq, _ = part.partition("=")
            parts.append(f"{key}={MASK}" if eq else part)
        return ";".join(parts)
    if secret_name(lower):
        return MASK
    return redact_text(text)


def redact_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return headers
    return {k: redact_header(k, v) for k, v in headers.items()}


def redact_event(event) -> dict:
    if not isinstance(event, dict):
        return event
    out = dict(event)
    for key in TEXT_FIELDS:
        if isinstance(out.get(key), str):
            out[key] = redact_text(out[key])
    if "headers" in out:
        out["headers"] = redact_headers(out["headers"])
    return out


def redact_replay(replay) -> dict:
    if not isinstance(replay, dict):
        return replay
    out = dict(replay)
    if isinstance(out.get("request"), dict):
        out["request"] = redact_event(out["request"])
    evidence = out.get("evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get("body"), str):
        out["evidence"] = dict(evidence, body=redact_text(evidence["body"]))
    return out


def redact_incident(incident: dict) -> dict:
    out = dict(incident, event=redact_event(incident.get("event")), replay=redact_replay(incident.get("replay")))
    if isinstance(incident.get("fix"), dict):
        out["fix"] = dict(incident["fix"])
    return out
