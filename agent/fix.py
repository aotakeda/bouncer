from __future__ import annotations

import difflib
import hashlib
import json
import queue
import re
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, NamedTuple

from . import net
from .claude import Claude
from .github import GitHub
from .labels import FixStatus, Verdict
from .net import ERROR_DETAIL_CHARS, bare_path, clip
from .pr_text import pr_body
from .replay import build_control, build_request, interpret
from .route_finder import locate_route

BRANCH_PREFIX = "bouncer/fix-"
PROBLEM_CHARS = 600
KNOWN_RESULT_FIELDS = ("file", "title", "summary", "diff", "pr_url", "verify")
MAX_VARIANTS = 4
VARIANTS_FAILED = "Claude's variant request failed, so only the original attack was replayed."
VARIANTS_EMPTY = "Claude offered no usable variants, so only the original attack was replayed."


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


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def is_variant_in_scope(path: str, body: str, bare: str) -> bool:
    if not path.startswith("/") or bare_path(path) != bare:
        return False
    return len(path) <= 2000 and len(body) <= 4000


def clean_variants(req: dict, raw: list) -> list:
    bare = bare_path(req.get("path", "/"))
    seen = {(req.get("path"), req.get("body") or "")}
    out = []
    for v in raw or []:
        path, body = str(v.get("path") or ""), str(v.get("body") or "")
        if not is_variant_in_scope(path, body, bare) or (path, body) in seen:
            continue
        seen.add((path, body))
        variant = {"method": req.get("method", "GET"), "path": path, "headers": dict(req.get("headers") or {}), "idea": clip(v.get("idea") or "", 120)}
        if body or "body" in req:
            variant["body"] = body
        out.append(variant)
        if len(out) >= MAX_VARIANTS:
            break
    return out


def untrusted_block(tag: str, text: str) -> str:
    safe = text.replace(f"</{tag}>", f"<\\/{tag}>")
    return f"<{tag}>\n{safe}\n</{tag}>"


def describe_attack(req: dict, why: str) -> str:
    lines = [f"{req.get('method')} {req.get('path')}"]
    lines.extend(f"{k}: {v}" for k, v in (req.get("headers") or {}).items())
    if req.get("body"):
        lines.append("")
        lines.append(clip(req["body"], 3000))
    return untrusted_block("untrusted_http_request", "\n".join(lines)) + f"\n\nReplay result: {why}"


def stage_verdict(variant: dict, verify: dict, stage: str, index: int, control: dict) -> Verdict:
    runs = (verify.get("variants") or {}).get(stage) or []
    run = runs[index] if index < len(runs) else None
    if not run:
        return Verdict.NOT_RUN
    return interpret(variant, {"ok": True, "control": control, **run})["verdict"]


def variant_table(variants: list, verify: dict) -> list:
    control = ((verify.get("replay") or {}).get("control")) or {}
    rows = []
    for i, v in enumerate(variants):
        verdicts = {stage: stage_verdict(v, verify, stage, i, control) for stage in ("before", "after")}
        shown = v["path"] + (" " + v["body"] if v.get("body") else "")
        rows.append({"idea": v.get("idea", ""), "request": shown[:300], **verdicts})
    return rows


def branch_prefix(path: str) -> str:
    return BRANCH_PREFIX + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") + "-"


def smoke_diff(before: dict, after: dict) -> list:
    return [f"{k}: {before.get(k)} -> {after.get(k)}" for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)]


def retry_feedback(patch: dict, problem: str) -> str:
    edits = json.dumps(patch.get("edits"), indent=1)[:6000]
    return f"\n\nYour previous edits were:\n{edits}\n\nThey failed: {problem}\nTry again."


@dataclass
class FixJob:
    incident: dict
    req: dict
    why: str
    control_status: int | None
    path: str = ""
    original: dict = field(default_factory=dict)
    variants: list = field(default_factory=list)
    variants_note: str = ""

    @classmethod
    def from_incident(cls, incident: dict) -> FixJob:
        replay = incident.get("replay") or {}
        return cls(
            incident=incident,
            req=replay.get("request") or build_request(incident["event"]),
            why=replay.get("why", ""),
            control_status=(replay.get("evidence") or {}).get("control_status"),
        )

    @property
    def method(self) -> str:
        return self.req.get("method", "GET")

    @property
    def text(self) -> str:
        return self.original["text"]

    @property
    def base_sha(self) -> str:
        return sha256_hex(self.text)

    def attack_prompt(self) -> str:
        return f"Proven attack:\n{describe_attack(self.req, self.why)}"

    def patch_prompt(self) -> str:
        return f"{self.attack_prompt()}\n\nFile `{self.path}`:\n```ts\n{self.text}\n```"

    def verify_payload(self, new_text: str) -> dict:
        return {"files": {self.path: {"content": new_text, "base_sha256": self.base_sha}}, "request": self.req, "control": build_control(self.req), "variants": self.variants}


class PatchTry(NamedTuple):
    new_text: str | None
    verify: dict
    problem: str


def ready_result(job: FixJob, patch: dict, new_text: str, attempts: list, verify: dict) -> dict:
    return {
        "status": FixStatus.READY,
        "file": job.path,
        "title": patch["title"],
        "summary": patch["summary"],
        "diff": unified_diff(job.path, job.text, new_text),
        "attempts": attempts,
        "verify": {
            "build_ms": verify["build"]["ms"],
            "after": interpret(job.req, verify["replay"])["verdict"],
            "smoke": verify["smoke_after"],
            "variants": variant_table(job.variants, verify),
            "variants_note": job.variants_note,
        },
    }


def with_note(line: str, note: str) -> str:
    return f"{line} {note}" if note else line


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self.started: deque = deque()
        self.lock = threading.Lock()

    def take(self) -> bool:
        now = time.time()
        with self.lock:
            while self.started and now - self.started[0] > self.window:
                self.started.popleft()
            if len(self.started) >= self.limit:
                return False
            self.started.append(now)
            return True


Progress = Callable[[FixStatus, str], None]


class Fixer:
    def __init__(self, mode: str, claude: Claude, github: GitHub, runner_url: str, runner_token: str = "", max_per_hour: int = 3, attempts: int = 2):
        self.mode = mode
        self.claude = claude
        self.github = github
        self.runner_url = runner_url.rstrip("/")
        self.runner_headers = net.bearer(runner_token)
        self.max_per_hour = max_per_hour
        self.limiter = RateLimiter(max_per_hour, 3600)
        self.attempts = attempts
        self.jobs: queue.Queue = queue.Queue(maxsize=50)
        self.files: dict = {}
        self.results: dict = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._work, daemon=True).start()

    def take_slot(self) -> bool:
        return self.limiter.take()

    def submit(self, incident: dict, report) -> FixStatus:
        try:
            self.jobs.put_nowait((incident, report))
        except queue.Full:
            return FixStatus.QUEUE_FULL
        return FixStatus.QUEUED

    def _work(self):
        while True:
            incident, report = self.jobs.get()
            net.hold_awake("bouncer-fix", 900)
            self._report(incident, report, self._run_job(incident, report))
            if self.jobs.empty():
                net.release_awake("bouncer-fix")

    @staticmethod
    def _report(incident: dict, report, result: dict) -> None:
        try:
            report(incident, result)
        except Exception as exc:
            print(json.dumps({"fix": "report failed", "status": str(result.get("status")), "error": clip(exc, ERROR_DETAIL_CHARS)}), file=sys.stderr, flush=True)

    def _run_job(self, incident: dict, report) -> dict:
        try:
            return self.fix(incident, lambda status, line: report(incident, {"status": status, "line": line}))
        except Exception as exc:
            return {"status": FixStatus.ERROR, "line": f"fix step crashed: {exc}"[:ERROR_DETAIL_CHARS]}

    def runner_patch(self, payload: dict) -> dict:
        status, body, _ = net.post_json(self.runner_url + "/patch", payload, timeout=600, headers=self.runner_headers)
        if status != 200:
            return {"ok": False, "stage": "http", "error": f"runner HTTP {status}: {clip(body, ERROR_DETAIL_CHARS)}"}
        return body

    def _set_file(self, path: str, status: FixStatus | None, result: dict | None = None) -> None:
        with self.lock:
            if status is None:
                self.files.pop(path, None)
            else:
                self.files[path] = status
            if result is not None:
                self.results[path] = result

    def fix(self, incident: dict, progress: Progress) -> dict:
        job = FixJob.from_incident(incident)
        server = self.github.file("server.ts")
        if not server:
            return {"status": FixStatus.FAILED, "line": "Could not read server.ts from the repo."}
        job.path = locate_route(server["text"], job.method, job.req.get("path", "/"))
        if not job.path:
            return {"status": FixStatus.FAILED, "line": f"No route file found for {job.req.get('method')} {bare_path(job.req.get('path', ''))}."}
        claimed = self._claim(job.path)
        if claimed:
            return claimed
        try:
            return self._fix_claimed(job, progress)
        except Exception:
            self._set_file(job.path, None)
            raise

    def _fix_claimed(self, job: FixJob, progress: Progress) -> dict:
        existing = self._reuse_open_pr(job.path)
        if existing:
            return existing
        job.original = self.github.file(job.path)
        if not job.original:
            self._set_file(job.path, FixStatus.FAILED)
            return {"status": FixStatus.FAILED, "file": job.path, "line": f"Could not read {job.path} from the repo."}
        if not self.take_slot():
            self._set_file(job.path, None)
            return {"status": FixStatus.RATE_LIMITED, "file": job.path, "line": f"Hit the limit of {self.max_per_hour} fix attempts an hour. {job.path} stays as it is for now."}
        progress(FixStatus.WORKING, f"Calling the carpenter for {job.path}.")
        return self._attempt_patches(job)

    def _claim(self, path: str) -> dict | None:
        with self.lock:
            known = self.files.get(path)
            if known == FixStatus.WORKING:
                return {"status": FixStatus.SKIPPED, "file": path, "line": f"Already working on {path}."}
            if known in (FixStatus.READY, FixStatus.PR_OPENED):
                return self.known(path)
            self.files[path] = FixStatus.WORKING
        return None

    def _reuse_open_pr(self, path: str) -> dict | None:
        url = self.github.open_pr_url(branch_prefix(path))
        if not url:
            return None
        self._set_file(path, FixStatus.PR_OPENED, {"status": FixStatus.PR_OPENED, "file": path, "pr_url": url})
        return self.known(path)

    def _ask_variants(self, job: FixJob) -> list:
        asked = self.claude.variants(job.attack_prompt())
        variants = clean_variants(job.req, asked.get("variants") if asked.get("ok") else [])
        if not asked.get("ok"):
            job.variants_note = VARIANTS_FAILED
        elif not variants:
            job.variants_note = VARIANTS_EMPTY
        return variants

    def _attempt_patches(self, job: FixJob) -> dict:
        prompt = job.patch_prompt()
        job.variants = self._ask_variants(job)
        feedback = ""
        attempts = []
        for attempt in range(1, self.attempts + 1):
            answer = self.claude.patch(prompt + feedback)
            if not answer["ok"]:
                attempts.append({"attempt": attempt, "problem": answer["error"]})
                break
            patch = answer["patch"]
            tried = self._try_patch(job, patch)
            attempts.append({"attempt": attempt, "problem": tried.problem, "claude_seconds": answer["seconds"], "model": answer.get("model")})
            if not tried.problem:
                return self.ship(job, ready_result(job, patch, tried.new_text, attempts, tried.verify), tried.new_text)
            feedback = retry_feedback(patch, tried.problem)
        return self._give_up(job.path, attempts)

    def _try_patch(self, job: FixJob, patch: dict) -> PatchTry:
        new_text, problem = apply_edits(job.text, patch.get("edits") or [])
        if problem:
            return PatchTry(new_text, {}, problem)
        verify = self.runner_patch(job.verify_payload(new_text))
        return PatchTry(new_text, verify, self.judge(job.req, verify, job.control_status, job.variants))

    def _give_up(self, path: str, attempts: list) -> dict:
        self._set_file(path, FixStatus.FAILED)
        last = attempts[-1]["problem"] if attempts else "no attempt"
        return {"status": FixStatus.FAILED, "file": path, "attempts": attempts, "line": f"Couldn't fix {path} safely: {last}"[:400]}

    def known(self, path: str) -> dict:
        prev = self.results.get(path) or {}
        keep = {k: prev[k] for k in KNOWN_RESULT_FIELDS if prev.get(k)}
        if prev.get("pr_url"):
            return dict(keep, status=FixStatus.PR_EXISTS, line=f"Same hole as before. {path} already has a pull request waiting for the owner.")
        return dict(keep, status=FixStatus.READY, line=f"Same hole as before. The patch for {path} is already tested and waiting.")

    def judge(self, req: dict, verify: dict, control_status, variants: list | None = None) -> str:
        problem = self.judge_main(req, verify, control_status)
        if problem:
            return problem
        for row in variant_table(variants or [], verify):
            if row["after"] == Verdict.PROVEN:
                return f"a variant of the attack still works after the patch ({row['idea']}): {row['request']}"[:PROBLEM_CHARS]
            if row["after"] == Verdict.ERROR:
                return f"a variant of the attack errored after the patch ({row['idea']}): {row['request']}"[:PROBLEM_CHARS]
        return ""

    def judge_main(self, req: dict, verify: dict, control_status) -> str:
        if not verify.get("ok"):
            return f"replay box error at {verify.get('stage')}: {verify.get('error') or verify.get('reset')}"[:PROBLEM_CHARS]
        build = verify.get("build") or {}
        if not build.get("ok"):
            return "TypeScript build failed:\n" + build.get("log", "")[-1500:]
        replay = verify.get("replay") or {}
        verdict = interpret(req, replay)
        if verdict["verdict"] == Verdict.PROVEN:
            return "the attack still works after the patch: " + verdict["why"]
        if verdict["verdict"] == Verdict.ERROR:
            return "replay after the patch failed: " + verdict["why"]
        now_control = (replay.get("control") or {}).get("status")
        if control_status is not None and now_control != control_status:
            return f"normal request changed: control status {control_status} -> {now_control}"
        changed = smoke_diff(verify.get("smoke_before") or {}, verify.get("smoke_after") or {})
        if changed:
            return "legitimate behaviour changed: " + "; ".join(changed)
        return ""

    def ship(self, job: FixJob, result: dict, new_text: str) -> dict:
        path = job.path
        result["pr_body"] = pr_body(job, result)
        if self.mode != "pr":
            result["line"] = with_note(f"Patch for {path} holds up on the stunt double. Dry run, so no pull request opened.", job.variants_note)
            self._set_file(path, FixStatus.READY, result)
            return result
        branch = branch_prefix(path) + time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        pr = self.github.open_pr(branch, path, job.original["sha"], new_text, result["title"], result["pr_body"])
        result["pr"] = pr
        if not pr.get("ok"):
            result["status"] = FixStatus.PR_FAILED
            result["line"] = f"Patch works but the pull request failed at {pr.get('step')} (HTTP {pr.get('status')})."
            self._set_file(path, FixStatus.FAILED)
            return result
        result["status"] = FixStatus.PR_OPENED
        result["pr_url"] = pr.get("url")
        result["line"] = with_note(f"Fixed the lock on {path}. Pull request is up for the owner to review.", job.variants_note)
        self._set_file(path, FixStatus.PR_OPENED, result)
        return result
