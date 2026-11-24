from __future__ import annotations

from . import net

ACTIONS = {
    "ignore": "normal traffic, or a probe for software this app does not run",
    "watch": "unusual but probably harmless; keep an eye on this client",
    "tarpit": "a scanner or bot fishing around; slow it down to waste its time",
    "replay": "a real attempt against a route this app has; check in a sandbox whether it works",
    "block": "clearly hostile and persistent; refuse this client for a while",
}


def describe(event: dict) -> str:
    parts = [f"{event.get('method')} {event.get('path')}", f"status={event.get('status')}"]
    if event.get("ua"):
        parts.append(f"ua={event['ua'][:200]}")
    if event.get("ctype"):
        parts.append(f"content-type={event['ctype']}")
    if event.get("body"):
        parts.append(f"body={event['body'][:1500]}")
    return " ".join(parts)


class Jev:
    def __init__(self, url: str, app_description: str, model: str = "jev-latest"):
        self.url = url
        self.app_description = app_description
        self.model = model

    def triage(self, event: dict, history: str = "") -> dict:
        state = f"App: {self.app_description}\nRequest: {describe(event)}"
        if history:
            state += f"\nSame client recently: {history}"
        payload = {
            "model": self.model,
            "state": state,
            "questions": {
                "malicious": {"type": "noul", "instructions": "Is this request an attack attempt against this app?"},
                "action": {"type": "choice", "instructions": "What should a cautious security agent do with this client?", "criteria": ACTIONS},
            },
        }
        status, body, elapsed = net.post_json(self.url, payload, timeout=20)
        if status != 200 or "answers" not in body:
            return {"ok": False, "error": body, "status": status, "seconds": round(elapsed, 3)}
        answers = body["answers"]
        action = answers.get("action", {})
        return {
            "ok": True,
            "model": body.get("model"),
            "malicious": answers.get("malicious", {}).get("noul"),
            "action": action.get("choice"),
            "confidence": action.get("confidence"),
            "probabilities": action.get("probabilities", {}),
            "seconds": round(elapsed, 3),
        }
