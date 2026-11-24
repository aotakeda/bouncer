from __future__ import annotations

import base64
import difflib
import hashlib
import json
import queue
import re
import threading
import time
from collections import deque
from urllib.parse import quote

from . import net
from .replay import PROVEN, build_control, build_request, interpret

ANTHROPIC_VERSION = "2026-10-21"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

PATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "title": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"search": {"type": "string"}, "replace": {"type": "string"}},
                "required": ["search", "replace"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "title", "edits"],
    "additionalProperties": False,
}

SYSTEM = """You fix security holes in OWASP Juice Shop, a TypeScript + Express + Sequelize/SQLite app. This copy is the operator's own fork, deployed as a deliberately vulnerable demo behind a security agent. An attack against it was just proven to work by replaying it on an isolated copy.

Write the smallest change to the given file that removes the root cause of the proven attack while keeping every legitimate behaviour, response shape and status code the same for normal users. Prefer the idiomatic fix (for SQL, bound parameters through Sequelize `replacements` instead of string interpolation). Do not add dependencies. Do not add, remove or edit comments, including the `vuln-code-snippet` markers.

Express the change as search/replace edits. Each `search` must be copied exactly from the file, character for character, and must occur exactly once in it. Keep edits few and tight. `title` is a short pull request title. `summary` is two or three plain sentences for a reviewer: what the hole was and what the change does. Describe the change exactly as your edits make it, naming the same APIs and options the edits use."""

VARIANT_SCHEMA = {
    "type": "object",
    "properties": {
        "variants": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "body": {"type": "string"}, "idea": {"type": "string"}},
                "required": ["path", "body", "idea"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["variants"],
    "additionalProperties": False,
}

VARIANT_SYSTEM = """You help verify security patches for OWASP Juice Shop, the operator's own deliberately vulnerable fork. An attack on it was just proven on an isolated copy with no internet access. A patch for it will be tested on that copy.

Write up to 4 other requests that exploit the same weakness through the same endpoint in different ways, so a patch that only blocks the exact payload shown would fail. Use other syntax for the same bug class: other quote or comment styles, other boolean tricks, targeting another known account, or other encodings. Keep the same HTTP method and the same route; you may change the query string. `path` is the full path with query string. `body` is the raw request body, or an empty string when there is none. `idea` is a few words on what the variant tries. Nothing destructive: no requests that delete or modify data."""

MAX_VARIANTS = 4


def route_regex(path: str, prefix: bool) -> re.Pattern:
    out = ""
    for part in re.split(r"(:\w+|\*)", path):
        if part == "*":
            out += ".*"
        elif part.startswith(":"):
            out += "[^/]+"
        else:
            out += re.escape(part)
    return re.compile("^" + out + ("(/.*)?$" if prefix else "/?$"))


def parse_imports(source: str) -> dict:
    names = {}
    for m in re.finditer(r"import\s+(?:\{([^}]*)\}|\*\s+as\s+(\w+)|(\w+))\s+from\s+'\./routes/([\w/.-]+)'", source):
        target = "routes/" + m.group(4) + ("" if m.group(4).endswith(".ts") else ".ts")
        if m.group(1):
            for item in m.group(1).split(","):
                item = item.strip()
                if item:
                    names[item.split(" as ")[-1].strip()] = target
        else:
            names[m.group(2) or m.group(3)] = target
    return names


def locate_route(server_source: str, method: str, path: str) -> str:
    names = parse_imports(server_source)
    bare = path.split("?", 1)[0]
    method = method.lower()
    exact, loose = [], []
    for m in re.finditer(r"app\.(get|post|put|patch|delete|all|use)\(\s*'([^']+)'(.*)", server_source):
        verb, route, rest = m.groups()
        if verb not in (method, "all", "use"):
            continue
        if not route_regex(route, prefix=verb == "use").match(bare):
            continue
        for ident in re.findall(r"\b(\w+)\s*(?:\.\s*\w+\s*)?\(", rest):
            if ident in names:
                (exact if verb == method else loose).append(names[ident])
                break
    hits = exact or loose
    return hits[0] if hits else ""


def apply_edits(source: str, edits: list) -> tuple:
    out = source
    for i, e in enumerate(edits):
        count = out.count(e["search"])
        if count != 1:
            return None, f"edit {i + 1}: search text occurs {count} times, must occur exactly once"
        out = out.replace(e["search"], e["replace"], 1)
    if out == source:
        return None, "edits change nothing"
    return out, ""


def unified_diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), f"a/{path}", f"b/{path}"))


class GitHub:
    def __init__(self, base_url: str, repo: str, branch: str):
        self.base = base_url.rstrip("/")
        self.repo = repo
        self.branch = branch
        self.headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "bouncer-agent"}

    def call(self, method: str, path: str, payload=None) -> tuple:
        status, body, _ = net.request(f"{self.base}/repos/{self.repo}{path}", method, payload, timeout=30, headers=self.headers)
        return status, body

    def file(self, path: str) -> dict:
        status, body = self.call("GET", f"/contents/{quote(path)}?ref={quote(self.branch)}")
        if status != 200 or "content" not in body:
            return {}
        return {"path": path, "sha": body["sha"], "text": base64.b64decode(body["content"]).decode("utf-8")}

    def open_pr_url(self, prefix: str) -> str:
        status, body = self.call("GET", "/pulls?state=open&per_page=100")
        if status != 200 or not isinstance(body, list):
            return ""
        for pr in body:
            head = pr.get("head") or {}
            if (head.get("ref") or "").startswith(prefix) and ((head.get("repo") or {}).get("full_name") or self.repo) == self.repo:
                return pr.get("html_url") or ""
        return ""

    def open_pr(self, branch: str, path: str, blob_sha: str, content: str, title: str, body: str) -> dict:
        status, ref = self.call("GET", f"/git/ref/heads/{quote(self.branch)}")
        if status != 200:
            return {"ok": False, "step": "base ref", "status": status}
        status, out = self.call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]})
        if status != 201:
            return {"ok": False, "step": "branch", "status": status, "detail": str(out)[:300]}
        payload = {"message": title, "content": base64.b64encode(content.encode()).decode(), "sha": blob_sha, "branch": branch}
        status, out = self.call("PUT", f"/contents/{quote(path)}", payload)
        if status not in (200, 201):
            return {"ok": False, "step": "commit", "status": status, "detail": str(out)[:300]}
        status, out = self.call("POST", "/pulls", {"title": title, "head": branch, "base": self.branch, "body": body})
        if status != 201:
            return {"ok": False, "step": "pull request", "status": status, "detail": str(out)[:300]}
        return {"ok": True, "url": out.get("html_url"), "number": out.get("number")}


class Claude:
    def __init__(self, base_url: str, model: str):
        self.url = base_url.rstrip("/") + "/v1/messages"
        self.model = model

    def patch(self, prompt: str) -> dict:
        out = self.ask(SYSTEM, prompt, PATCH_SCHEMA, "high")
        if out["ok"]:
            out["patch"] = out.pop("data")
        return out

    def variants(self, prompt: str) -> dict:
        out = self.ask(VARIANT_SYSTEM, prompt, VARIANT_SCHEMA, "medium")
        if out["ok"]:
            out["variants"] = (out.pop("data") or {}).get("variants") or []
        return out

    def ask(self, system: str, prompt: str, schema: dict, effort: str) -> dict:
        payload = {
            "model": self.model,
            "max_tokens": 16000,
            "system": system,
            "fallbacks": "default",
            "output_config": {"effort": effort, "format": {"type": "json_schema", "schema": schema}},
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {"anthropic-version": ANTHROPIC_VERSION, "anthropic-beta": FALLBACK_BETA}
        status, body, elapsed = net.post_json(self.url, payload, timeout=600, headers=headers)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}: {str(body)[:300]}", "seconds": round(elapsed, 1)}
        stop = body.get("stop_reason")
        if stop != "end_turn":
            return {"ok": False, "error": f"stopped: {stop}", "seconds": round(elapsed, 1)}
        text = "".join(b.get("text", "") for b in body.get("content", []) if b.get("type") == "text")
        try:
            data = json.loads(text)
        except ValueError:
            return {"ok": False, "error": "reply was not JSON", "seconds": round(elapsed, 1)}
        return {"ok": True, "data": data, "model": body.get("model"), "usage": body.get("usage", {}), "seconds": round(elapsed, 1)}


def clean_variants(req: dict, raw: list) -> list:
    bare = req.get("path", "/").split("?", 1)[0]
    seen = {(req.get("path"), req.get("body") or "")}
    out = []
    for v in raw or []:
        path, body = str(v.get("path") or ""), str(v.get("body") or "")
        if not path.startswith("/") or path.split("?", 1)[0] != bare or len(path) > 2000 or len(body) > 4000:
            continue
        if (path, body) in seen:
            continue
        seen.add((path, body))
        variant = {"method": req.get("method", "GET"), "path": path, "headers": dict(req.get("headers") or {}), "idea": str(v.get("idea") or "")[:120]}
        if body or "body" in req:
            variant["body"] = body
        out.append(variant)
        if len(out) >= MAX_VARIANTS:
            break
    return out


def describe_attack(req: dict, why: str) -> str:
    lines = [f"{req.get('method')} {req.get('path')}"]
    for k, v in (req.get("headers") or {}).items():
        lines.append(f"{k}: {v}")
    if req.get("body"):
        lines.append("")
        lines.append(str(req["body"])[:3000])
    return "\n".join(lines) + f"\n\nReplay result: {why}"


def variant_table(variants: list, verify: dict) -> list:
    control = ((verify.get("replay") or {}).get("control")) or {}
    rows = []
    for i, v in enumerate(variants):
        verdicts = {}
        for stage in ("before", "after"):
            runs = (verify.get("variants") or {}).get(stage) or []
            run = runs[i] if i < len(runs) else None
            verdicts[stage] = interpret(v, {"ok": True, "control": control, **run})["verdict"] if run else "NOT_RUN"
        shown = v["path"] + (" " + v["body"] if v.get("body") else "")
        rows.append({"idea": v.get("idea", ""), "request": shown[:300], **verdicts})
    return rows


def branch_prefix(path: str) -> str:
    return "bouncer/fix-" + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") + "-"


def smoke_diff(before: dict, after: dict) -> list:
    return [f"{k}: {before.get(k)} -> {after.get(k)}" for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)]


class Fixer:
    def __init__(self, mode: str, claude: Claude, github: GitHub, runner_url: str, runner_token: str = "", max_per_hour: int = 3, attempts: int = 2):
        self.mode = mode
        self.claude = claude
        self.github = github
        self.runner_url = runner_url.rstrip("/")
        self.runner_headers = {"Authorization": f"Bearer {runner_token}"} if runner_token else None
        self.max_per_hour = max_per_hour
        self.attempts = attempts
        self.jobs: queue.Queue = queue.Queue(maxsize=50)
        self.started: deque = deque()
        self.files: dict = {}
        self.results: dict = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._work, daemon=True).start()

    def take_slot(self) -> bool:
        now = time.time()
        with self.lock:
            while self.started and now - self.started[0] > 3600:
                self.started.popleft()
            if len(self.started) >= self.max_per_hour:
                return False
            self.started.append(now)
            return True

    def submit(self, incident: dict, report) -> str:
        try:
            self.jobs.put_nowait((incident, report))
        except queue.Full:
            return "queue_full"
        return "queued"

    def _work(self):
        while True:
            incident, report = self.jobs.get()
            net.hold_awake("bouncer-fix", 900)
            try:
                result = self.fix(incident, lambda status, line: report(incident, {"status": status, "line": line}))
            except Exception as exc:
                result = {"status": "error", "line": f"fix step crashed: {exc}"[:300]}
            report(incident, result)
            if self.jobs.empty():
                net.release_awake("bouncer-fix")

    def runner_patch(self, payload: dict) -> dict:
        status, body, _ = net.post_json(self.runner_url + "/patch", payload, timeout=600, headers=self.runner_headers)
        if status != 200:
            return {"ok": False, "stage": "http", "error": f"runner HTTP {status}: {str(body)[:300]}"}
        return body

    def fix(self, incident: dict, progress) -> dict:
        event = incident["event"]
        req = (incident.get("replay") or {}).get("request") or build_request(event)
        why = (incident.get("replay") or {}).get("why", "")
        control_status = ((incident.get("replay") or {}).get("evidence") or {}).get("control_status")
        server = self.github.file("server.ts")
        if not server:
            return {"status": "failed", "line": "Could not read server.ts from the repo."}
        path = locate_route(server["text"], req.get("method", "GET"), req.get("path", "/"))
        if not path:
            return {"status": "failed", "line": f"No route file found for {req.get('method')} {req.get('path', '').split('?')[0]}."}
        with self.lock:
            known = self.files.get(path)
            if known == "working":
                return {"status": "skipped", "file": path, "line": f"Already working on {path}."}
            if known in ("ready", "pr_opened"):
                return self.known(path)
            self.files[path] = "working"
        url = self.github.open_pr_url(branch_prefix(path))
        if url:
            self.files[path] = "pr_opened"
            self.results[path] = {"status": "pr_opened", "file": path, "pr_url": url}
            return self.known(path)
        original = self.github.file(path)
        if not original:
            self.files[path] = "failed"
            return {"status": "failed", "file": path, "line": f"Could not read {path} from the repo."}
        if not self.take_slot():
            self.files.pop(path, None)
            return {"status": "rate_limited", "file": path, "line": f"Hit the limit of {self.max_per_hour} fix attempts an hour. {path} stays as it is for now."}
        progress("working", f"Calling the carpenter for {path}.")
        base_sha = hashlib.sha256(original["text"].encode()).hexdigest()
        prompt = f"Proven attack:\n{describe_attack(req, why)}\n\nFile `{path}`:\n```ts\n{original['text']}\n```"
        asked = self.claude.variants(f"Proven attack:\n{describe_attack(req, why)}")
        variants = clean_variants(req, asked.get("variants") if asked.get("ok") else [])
        feedback = ""
        attempts = []
        for attempt in range(1, self.attempts + 1):
            answer = self.claude.patch(prompt + feedback)
            if not answer["ok"]:
                attempts.append({"attempt": attempt, "problem": answer["error"]})
                break
            patch = answer["patch"]
            new_text, problem = apply_edits(original["text"], patch.get("edits") or [])
            verify = {}
            if not problem:
                verify = self.runner_patch({"files": {path: {"content": new_text, "base_sha256": base_sha}}, "request": req, "control": build_control(req), "variants": variants})
                problem = self.judge(req, verify, control_status, variants)
            attempts.append({"attempt": attempt, "problem": problem, "claude_seconds": answer["seconds"], "model": answer.get("model")})
            if not problem:
                diff = unified_diff(path, original["text"], new_text)
                result = {
                    "status": "ready",
                    "file": path,
                    "title": patch["title"],
                    "summary": patch["summary"],
                    "diff": diff,
                    "attempts": attempts,
                    "verify": {
                        "build_ms": verify["build"]["ms"],
                        "after": interpret(req, verify["replay"])["verdict"],
                        "smoke": verify["smoke_after"],
                        "variants": variant_table(variants, verify),
                    },
                }
                return self.ship(incident, result, original, new_text, req, why)
            feedback = f"\n\nYour previous edits were:\n{json.dumps(patch.get('edits'), indent=1)[:6000]}\n\nThey failed: {problem}\nTry again."
        self.files[path] = "failed"
        last = attempts[-1]["problem"] if attempts else "no attempt"
        return {"status": "failed", "file": path, "attempts": attempts, "line": f"Couldn't fix {path} safely: {last}"[:400]}

    def known(self, path: str) -> dict:
        prev = self.results.get(path) or {}
        keep = {k: prev[k] for k in ("file", "title", "summary", "diff", "pr_url", "verify") if prev.get(k)}
        if prev.get("pr_url"):
            return dict(keep, status="pr_exists", line=f"Same hole as before. {path} already has a pull request waiting for the owner.")
        return dict(keep, status="ready", line=f"Same hole as before. The patch for {path} is already tested and waiting.")

    def judge(self, req: dict, verify: dict, control_status, variants: list | None = None) -> str:
        problem = self.judge_main(req, verify, control_status)
        if problem:
            return problem
        for row in variant_table(variants or [], verify):
            if row["after"] == PROVEN:
                return f"a variant of the attack still works after the patch ({row['idea']}): {row['request']}"[:600]
        return ""

    def judge_main(self, req: dict, verify: dict, control_status) -> str:
        if not verify.get("ok"):
            return f"replay box error at {verify.get('stage')}: {verify.get('error') or verify.get('reset')}"[:600]
        build = verify.get("build") or {}
        if not build.get("ok"):
            return "TypeScript build failed:\n" + build.get("log", "")[-1500:]
        replay = verify.get("replay") or {}
        verdict = interpret(req, replay)
        if verdict["verdict"] == PROVEN:
            return "the attack still works after the patch: " + verdict["why"]
        if verdict["verdict"] == "ERROR":
            return "replay after the patch failed: " + verdict["why"]
        now_control = (replay.get("control") or {}).get("status")
        if control_status is not None and now_control != control_status:
            return f"normal request changed: control status {control_status} -> {now_control}"
        changed = smoke_diff(verify.get("smoke_before") or {}, verify.get("smoke_after") or {})
        if changed:
            return "legitimate behaviour changed: " + "; ".join(changed)
        return ""

    def ship(self, incident: dict, result: dict, original: dict, new_text: str, req: dict, why: str) -> dict:
        path = result["file"]
        body = self.pr_body(incident, result, req, why)
        result["pr_body"] = body
        if self.mode != "pr":
            self.files[path] = "ready"
            self.results[path] = result
            result["line"] = f"Patch for {path} holds up on the stunt double. Dry run, so no pull request opened."
            return result
        branch = branch_prefix(path) + time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        pr = self.github.open_pr(branch, path, original["sha"], new_text, result["title"], body)
        result["pr"] = pr
        if pr.get("ok"):
            self.files[path] = "pr_opened"
            self.results[path] = result
            result["status"] = "pr_opened"
            result["pr_url"] = pr.get("url")
            result["line"] = f"Fixed the lock on {path}. Pull request is up for the owner to review."
        else:
            self.files[path] = "failed"
            result["status"] = "pr_failed"
            result["line"] = f"Patch works but the pull request failed at {pr.get('step')} (HTTP {pr.get('status')})."
        return result

    def pr_body(self, incident: dict, result: dict, req: dict, why: str) -> str:
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(incident.get("ts", time.time())))
        smoke = result["verify"]["smoke"]
        rows = "\n".join(f"| {k} | {v.get('status')} | {v.get('count') if v.get('count') is not None else ''} |" for k, v in smoke.items())
        body_excerpt = str(req.get("body") or "")[:800]
        return f"""{result['summary']}

### What happened
At {when} a request to `{req.get('method')} {req.get('path', '').split('?')[0]}` was replayed on an isolated copy of this app and it worked: {why}.

```
{req.get('method')} {req.get('path', '')[:500]}
{body_excerpt}
```

### How this patch was checked
On the isolated copy, Bouncer applied this patch, rebuilt the server ({result['verify']['build_ms']} ms), replayed the same attack and a harmless control request, then rolled the copy back.

- Attack after the patch: **{result['verify']['after']}**
- Normal checks after the patch, all matching the unpatched app:

| check | status | items |
|---|---|---|
{rows}
{self.variant_section(result['verify'].get('variants') or [])}
Opened by Bouncer. Review before merging.
"""

    @staticmethod
    def variant_section(rows: list) -> str:
        if not rows:
            return ""
        label = {PROVEN: "worked", "NOT_RUN": "not run", "MINOR": "minor only", "INCONCLUSIVE": "unclear"}
        lines = "\n".join(
            f"| {r['idea'].replace('|', '/')} | `{r['request'][:120].replace('|', '/').replace('`', '')}` | {label.get(r['before'], 'not shown')} | {label.get(r['after'], 'blocked')} |"
            for r in rows
        )
        return f"""
Other ways into the same hole, written by Claude and tried on the copy before and after the patch:

| idea | request | before | after |
|---|---|---|---|
{lines}
"""
