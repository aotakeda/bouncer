from __future__ import annotations

from . import net

ACTIONS = {
    "ignore": "normal traffic, or a probe for software this app does not run",
    "watch": "unusual but probably harmless; keep an eye on this client",
    "tarpit": "a scanner or bot fishing around; slow it down to waste its time",
    "replay": "a real attempt against a route this app has; check in a sandbox whether it works",
    "block": "clearly hostile and persistent; refuse this client for a while",
}

QUESTIONS = {
    "malicious": {"type": "noul", "instructions": "Is this request an attack attempt against this app?"},
    "action": {"type": "choice", "instructions": "What should a cautious security agent do with this client?", "criteria": ACTIONS},
}


def one_line(value, limit: int) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")[:limit]


def describe(event: dict) -> str:
    parts = [f"{one_line(event.get('method', ''), 20)} {one_line(event.get('path', ''), 500)}", f"status={event.get('status')}"]
    if event.get("ua"):
        parts.append(f"ua={one_line(event['ua'], 200)}")
    if event.get("ctype"):
        parts.append(f"content-type={one_line(event['ctype'], 120)}")
    if event.get("body"):
        parts.append(f"body={one_line(event['body'], 1500)}")
    return " ".join(parts)


def parse_answers(body: dict, elapsed: float) -> dict:
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


class Jev:
    def __init__(self, url: str, app_description: str, model: str = "jev-latest"):
        self.url = url
        self.app_description = app_description
        self.model = model

    def prompt_state(self, event: dict, history: str = "") -> str:
        state = f"App: {self.app_description}\nRequest: {describe(event)}"
        if history:
            state += f"\nSame client recently: {history}"
        return state

    def triage(self, event: dict, history: str = "") -> dict:
        payload = {"model": self.model, "state": self.prompt_state(event, history), "questions": QUESTIONS}
        status, body, elapsed = net.post_json(self.url, payload, timeout=20)
        if status != 200 or "answers" not in body:
            return {"ok": False, "error": body, "status": status, "seconds": round(elapsed, 3)}
        return parse_answers(body, elapsed)
