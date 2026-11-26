from __future__ import annotations

import difflib
import hashlib
import json
import queue
import re
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Callable, NamedTuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import net
from .claude import Claude
from .github import GitHub
from .labels import FixStatus, Verdict
from .net import ERROR_DETAIL_CHARS, bare_path, clip
from .policy import JWT, unsigned_jwt
from .pr_text import pr_body, pr_title
from .replay import build_control, build_request, interpret, is_stateful
from .route_finder import locate_route

BRANCH_PREFIX = "bouncer/fix-"
PROBLEM_CHARS = 600
KNOWN_RESULT_FIELDS = ("file", "title", "summary", "diff", "pr_url", "verify")
MAX_VARIANTS = 4
VARIANTS_FAILED = "Claude's variant request failed, so only the original attack was replayed."
VARIANTS_EMPTY = "Claude offered no usable variants, so only the original attack was replayed."
ORACLE_MISSING = "Claude offered no usable true/false request pair, so no blind-injection check was run."
APOSTROPHE_TEXT = "O'Reilly"
APOSTROPHE_EMAIL = "o'reilly@bouncer.test"
NORMAL_PLAIN = "route plain"
NORMAL_APOSTROPHE = "route apostrophe"
NORMAL_LIKE = {NORMAL_APOSTROPHE: NORMAL_PLAIN}
SERVER_ERROR = 500
MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "tsconfig.json", ".npmrc"}
IMPORT_LIKE = re.compile(
    r"""\bimport\s*(?:type\s+)?(?:[\w$*{}\s,]+?\s*from\s*)?['"`][^'"`]+['"`]"""
    r"""|\bexport\s+[^;\n]*?\bfrom\s*['"`][^'"`]+['"`]"""
    r"""|\bimport\s*\(|\brequire\s*\(|\brequire\.resolve\b"""
)
SECRET_HEADERS = ("authorization", "cookie")
REQUEST_TAG = re.compile(r"<(\s*/?\s*[\w-]*request)", re.IGNORECASE)


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


def same_route_request(req: dict, path: str, body: str) -> dict:
    out = {"method": req.get("method", "GET"), "path": path, "headers": dict(req.get("headers") or {})}
    if body or "body" in req:
        out["body"] = body
    return out


def clean_variants(req: dict, raw: list) -> list:
    bare = bare_path(req.get("path", "/"))
    seen = {(req.get("path"), req.get("body") or "")}
    out = []
    for v in raw or []:
        if not isinstance(v, dict):
            continue
        path, body = str(v.get("path") or ""), str(v.get("body") or "")
        if not is_variant_in_scope(path, body, bare) or (path, body) in seen:
            continue
        seen.add((path, body))
        out.append(dict(same_route_request(req, path, body), idea=clip(v.get("idea") or "", 120)))
        if len(out) >= MAX_VARIANTS:
            break
    return out


def clean_oracle(req: dict, raw) -> dict:
    if not isinstance(raw, dict):
        return {}
    bare = bare_path(req.get("path", "/"))
    sides = {}
    for side in ("true", "false"):
        path, body = str(raw.get(f"{side}_path") or ""), str(raw.get(f"{side}_body") or "")
        if not is_variant_in_scope(path, body, bare):
            return {}
        sides[side] = same_route_request(req, path, body)
    if (sides["true"]["path"], sides["true"].get("body")) == (sides["false"]["path"], sides["false"].get("body")):
        return {}
    return dict(sides, idea=clip(raw.get("idea") or "", 120))


def legit_value(key: str, value, text: str, email: str):
    if isinstance(value, str):
        return email if "mail" in key.lower() else text
    if isinstance(value, dict):
        return {k: legit_value(k, v, text, email) for k, v in value.items()}
    if isinstance(value, list):
        return [legit_value(key, v, text, email) for v in value]
    return value


def legit_pairs(query: str, text: str, email: str) -> str:
    return urlencode([(k, email if "mail" in k.lower() else text) for k, _ in parse_qsl(query, keep_blank_values=True)])


def legit_body(body, ctype: str, text: str, email: str):
    if not body:
        return body
    if "json" in ctype:
        try:
            return json.dumps(legit_value("", json.loads(body), text, email))
        except ValueError:
            return "{}"
    if "form" in ctype:
        return legit_pairs(body, text, email)
    return text


def legit_request(req: dict, text: str, email: str) -> dict:
    parts = urlsplit(req.get("path", "/"))
    path = urlunsplit(("", "", parts.path, legit_pairs(parts.query, text, email), "")) if parts.query else req.get("path", "/")
    headers = dict(req.get("headers") or {})
    out = {"method": req.get("method", "GET"), "path": path, "headers": headers}
    if "body" in req:
        ctype = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
        out["body"] = legit_body(req["body"], ctype.lower(), text, email)
    return out


def normal_requests(req: dict) -> list:
    attack = (req.get("path"), req.get("body"))
    plain = build_control(req)
    out = []
    if (plain["path"], plain.get("body")) != attack:
        out.append({"name": NORMAL_PLAIN, "request": plain})
    quoted = legit_request(req, APOSTROPHE_TEXT, APOSTROPHE_EMAIL)
    if (quoted["path"], quoted.get("body")) not in (attack, (plain["path"], plain.get("body"))):
        out.append({"name": NORMAL_APOSTROPHE, "request": quoted})
    return out


def import_lines(text: str) -> Counter:
    return Counter(re.sub(r"\s+", " ", m.group(0)) for m in IMPORT_LIKE.finditer(text))


def new_imports(before: str, after: str) -> list:
    return sorted((import_lines(after) - import_lines(before)).keys())


def dependency_problem(path: str, before: str, after: str) -> str:
    if path.rsplit("/", 1)[-1].lower() in MANIFESTS:
        return f"{path} is a dependency manifest; patches may only change the route file"
    added = new_imports(before, after)
    if added:
        return "the patch adds an import or require, which is not allowed: " + "; ".join(added)[:300]
    return ""


def neutralize(text: str) -> str:
    return REQUEST_TAG.sub(lambda m: "&lt;" + m.group(1), str(text))


def untrusted_block(tag: str, text: str) -> str:
    return f"<{tag}>\n{neutralize(text)}\n</{tag}>"


def redact(name: str, value) -> str:
    if str(name).lower() not in SECRET_HEADERS:
        return str(value)
    text = str(value)
    note = ", holds an unsigned JWT" if any(unsigned_jwt(t) for t in JWT.findall(text)) else ""
    return f"[redacted, {len(text)} chars{note}]"


def describe_attack(req: dict, why: str) -> str:
    lines = [f"{req.get('method')} {req.get('path')}"]
    lines.extend(f"{k}: {redact(k, v)}" for k, v in (req.get("headers") or {}).items())
    if req.get("body"):
        lines.append("")
        lines.append(clip(req["body"], 3000))
    return untrusted_block("untrusted_http_request", "\n".join(lines)) + f"\n\nReplay result: {neutralize(why)}"


STAGE_REPLAY = {"before": "replay_before", "after": "replay"}


def stage_verdict(variant: dict, verify: dict, stage: str, index: int, control: dict) -> Verdict:
    runs = (verify.get("variants") or {}).get(stage) or []
    run = runs[index] if index < len(runs) else None
    if not isinstance(run, dict) or not isinstance(run.get("attack"), dict):
        return Verdict.NOT_RUN
    return interpret(variant, {"ok": True, "control": control, **run})["verdict"]


def stage_control(verify: dict, stage: str) -> dict:
    return ((verify.get(STAGE_REPLAY[stage]) or {}).get("control")) or {}


def variant_table(variants: list, verify: dict) -> list:
    rows = []
    for i, v in enumerate(variants):
        verdicts = {stage: stage_verdict(v, verify, stage, i, stage_control(verify, stage)) for stage in ("before", "after")}
        shown = v["path"] + (" " + v["body"] if v.get("body") else "")
        rows.append({"idea": v.get("idea", ""), "request": shown[:300], **verdicts})
    return rows


def answered(obs) -> bool:
    return isinstance(obs, dict) and bool(obs.get("status"))


def told_apart(pair: dict) -> bool:
    t, f = pair.get("true"), pair.get("false")
    if not (answered(t) and answered(f)):
        return False
    return any(t.get(k) != f.get(k) for k in ("status", "count", "fingerprint"))


def describe_pair(pair: dict) -> str:
    def one(obs):
        count = obs.get("count")
        return f"{obs.get('status')}" + (f" with {count} items" if count is not None else "")

    return f"true got {one(pair['true'])}, false got {one(pair['false'])}"


def oracle_outcome(oracle: dict, verify: dict) -> dict:
    if not oracle:
        return {"state": "none"}
    got = verify.get("oracle") or {}
    before, after = got.get("before") or {}, got.get("after") or {}
    if not all(answered(stage.get(side)) for stage in (before, after) for side in ("true", "false")):
        return {"state": "not_run"}
    if not told_apart(before):
        return {"state": "no_signal", "before": describe_pair(before)}
    if told_apart(after):
        return {"state": "leaks", "before": describe_pair(before), "after": describe_pair(after)}
    return {"state": "closed", "before": describe_pair(before), "after": describe_pair(after)}


def status_of(obs: dict):
    return obs.get("status") if isinstance(obs, dict) else None


def normal_problem(name: str, before: dict, after: dict, after_all: dict) -> str:
    if not answered(before):
        return f"{name}: no answer from the unpatched copy"
    if not answered(after):
        return f"{name}: no answer after the patch"
    if before["status"] >= SERVER_ERROR:
        like = after_all.get(NORMAL_LIKE.get(name, ""))
        if answered(like) and after["status"] != like["status"]:
            return f"{name}: crashed before the patch ({before['status']}) and now gets {after['status']}, but the same request with a plain value gets {like['status']}"
        return ""
    if after["status"] != before["status"]:
        return f"{name}: status {before['status']} -> {after['status']}"
    if after.get("count") != before.get("count"):
        return f"{name}: items {before.get('count')} -> {after.get('count')}"
    if after.get("fingerprint") != before.get("fingerprint"):
        return f"{name}: same status {after['status']} but the response body changed"
    return ""


def smoke_diff(before: dict, after: dict) -> list:
    out = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if not isinstance(b, dict) or not isinstance(a, dict):
            out.append(f"{name}: not run {'before' if not isinstance(b, dict) else 'after'} the patch")
            continue
        problem = normal_problem(name, b, a, after)
        if problem:
            out.append(problem)
    return out


def normal_rows(before: dict, after: dict) -> list:
    rows = []
    for name in sorted(set(before) & set(after)):
        b, a = before[name], after[name]
        crashed = (status_of(b) or 0) >= SERVER_ERROR
        rows.append({
            "name": name,
            "before": status_of(b),
            "after": status_of(a),
            "items": a.get("count"),
            "body": "not compared, the unpatched app crashed" if crashed else ("same" if a.get("fingerprint") == b.get("fingerprint") else "changed"),
        })
    return rows


def branch_prefix(path: str) -> str:
    return BRANCH_PREFIX + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") + "-"


def retry_feedback(patch: dict, problem: str) -> str:
    edits = json.dumps(patch.get("edits"), indent=1)[:6000]
    return neutralize(f"\n\nYour previous edits were:\n{edits}\n\nThey failed: {problem}\nTry again.")


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
    oracle: dict = field(default_factory=dict)
    oracle_note: str = ""

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
        payload = {
            "files": {self.path: {"content": new_text, "base_sha256": self.base_sha}},
            "request": self.req,
            "control": build_control(self.req),
            "variants": self.variants,
            "normals": normal_requests(self.req),
        }
        if self.oracle:
            payload["oracle"] = {"true": self.oracle["true"], "false": self.oracle["false"]}
        return payload


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
            "before": interpret(job.req, verify["replay_before"])["verdict"],
            "after": interpret(job.req, verify["replay"])["verdict"],
            "checks": normal_rows(verify.get("smoke_before") or {}, verify.get("smoke_after") or {}),
            "variants": variant_table(job.variants, verify),
            "variants_note": job.variants_note,
            "oracle": dict(oracle_outcome(job.oracle, verify), idea=job.oracle.get("idea", "")),
            "oracle_note": job.oracle_note,
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
        if is_stateful(job.req):
            self._set_file(job.path, None)
            return {"status": FixStatus.SKIPPED, "file": job.path, "line": f"This attack needs a login session or changes data, so a patch can't be proven safe on the replay server. {job.path} needs a fix by hand."}
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
            if known == FixStatus.READY:
                return self.known(path)
            self.files[path] = FixStatus.WORKING
        return None

    def _known_pr_is_open(self, path: str) -> str:
        prev = self.results.get(path) or {}
        number = (prev.get("pr") or {}).get("number")
        if not number or not prev.get("pr_url"):
            return ""
        return prev["pr_url"] if self.github.pr_state(number) == "open" else ""

    def _reuse_open_pr(self, path: str) -> dict | None:
        url = self._known_pr_is_open(path) or self.github.open_pr_url(branch_prefix(path))
        if url is None:
            self._set_file(path, None)
            return {"status": FixStatus.FAILED, "file": path, "line": f"Couldn't check GitHub for an open pull request on {path}, so no new one was opened. The next proven attack will try again."}
        if not url:
            with self.lock:
                self.results.pop(path, None)
            return None
        prev = self.results.get(path) or {}
        kept = prev if prev.get("pr_url") == url else {"status": FixStatus.PR_OPENED, "file": path, "pr_url": url}
        self._set_file(path, FixStatus.PR_OPENED, kept)
        return self.known(path)

    def _ask_variants(self, job: FixJob) -> list:
        asked = self.claude.variants(job.attack_prompt())
        variants = clean_variants(job.req, asked.get("variants") if asked.get("ok") else [])
        job.oracle = clean_oracle(job.req, asked.get("oracle")) if asked.get("ok") else {}
        if not asked.get("ok"):
            job.variants_note = VARIANTS_FAILED
        elif not variants:
            job.variants_note = VARIANTS_EMPTY
        if not job.oracle:
            job.oracle_note = ORACLE_MISSING
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
        if not problem:
            problem = dependency_problem(job.path, job.text, new_text)
        if problem:
            return PatchTry(new_text, {}, problem)
        verify = self.runner_patch(job.verify_payload(new_text))
        return PatchTry(new_text, verify, self.judge(job.req, verify, job.control_status, job.variants, job.oracle))

    def _give_up(self, path: str, attempts: list) -> dict:
        self._set_file(path, FixStatus.FAILED)
        last = attempts[-1]["problem"] if attempts else "no attempt"
        return {"status": FixStatus.FAILED, "file": path, "attempts": attempts, "line": f"Couldn't fix {path} safely: {last}"[:400]}

    def known(self, path: str) -> dict:
        prev = self.results.get(path) or {}
        keep = {k: prev[k] for k in KNOWN_RESULT_FIELDS if prev.get(k)}
        if prev.get("pr_url"):
            return dict(keep, status=FixStatus.PR_EXISTS, line=f"Another fix for {path} is already open and waiting for the owner, so no second pull request was opened. It may not cover this attack; check again once it is merged.")
        return dict(keep, status=FixStatus.READY, line=f"A patch for {path} is already tested and waiting from an earlier attack, so no new patch was written. It may not cover this attack.")

    def judge(self, req: dict, verify: dict, control_status, variants: list | None = None, oracle: dict | None = None) -> str:
        problem = self.judge_main(req, verify, control_status)
        if problem:
            return problem
        for row in variant_table(variants or [], verify):
            if row["after"] == Verdict.PROVEN:
                return f"a variant of the attack still works after the patch ({row['idea']}): {row['request']}"[:PROBLEM_CHARS]
            if row["after"] == Verdict.ERROR:
                return f"a variant of the attack errored after the patch ({row['idea']}): {row['request']}"[:PROBLEM_CHARS]
            if row["after"] != Verdict.NOT_REPRODUCED:
                return f"a variant of the attack was {row['after']} after the patch, not a clean no effect ({row['idea']}): {row['request']}"[:PROBLEM_CHARS]
        return self.judge_oracle(oracle or {}, verify)

    @staticmethod
    def judge_oracle(oracle: dict, verify: dict) -> str:
        outcome = oracle_outcome(oracle, verify)
        if outcome["state"] == "not_run":
            return "the true/false request pair was not run on both the unpatched and the patched copy"
        if outcome["state"] == "leaks":
            return f"blind injection still works after the patch: a true/false request pair still gets different answers ({outcome['after']}). Fix the root cause with bound parameters or proper escaping, not a keyword blocklist."[:PROBLEM_CHARS]
        return ""

    def judge_main(self, req: dict, verify: dict, control_status) -> str:
        if not verify.get("ok"):
            where = " ".join(str(x) for x in (verify.get("phase"), verify.get("stage")) if x)
            return f"replay box error at {where}: {verify.get('error') or verify.get('reset')}"[:PROBLEM_CHARS]
        build = verify.get("build") or {}
        if not build.get("ok"):
            return "TypeScript build failed:\n" + build.get("log", "")[-1500:]
        before = interpret(req, verify.get("replay_before") or {"ok": False, "stage": "missing"})
        if before["verdict"] != Verdict.PROVEN:
            return f"the original attack did not work on the unpatched copy in this run ({before['verdict']}: {before['why']}), so the test proves nothing"[:PROBLEM_CHARS]
        replay = verify.get("replay") or {}
        verdict = interpret(req, replay)
        if verdict["verdict"] == Verdict.PROVEN:
            return "the attack still works after the patch: " + verdict["why"]
        if verdict["verdict"] == Verdict.ERROR:
            return "replay after the patch failed: " + verdict["why"]
        if verdict["verdict"] != Verdict.NOT_REPRODUCED:
            return f"the attack after the patch was {verdict['verdict']}, not a clean no effect: {verdict['why']}"[:PROBLEM_CHARS]
        now_control = (replay.get("control") or {}).get("status")
        if control_status is not None and now_control != control_status:
            return f"normal request changed: control status {control_status} -> {now_control}"
        before_smoke, after_smoke = verify.get("smoke_before"), verify.get("smoke_after")
        if not before_smoke or not after_smoke:
            return "normal requests were not run on both the unpatched and the patched copy"
        changed = smoke_diff(before_smoke, after_smoke)
        if changed:
            return ("legitimate behaviour changed: " + "; ".join(changed))[:PROBLEM_CHARS]
        return ""

    def ship(self, job: FixJob, result: dict, new_text: str) -> dict:
        path = job.path
        result["pr_body"] = pr_body(job, result)
        if self.mode != "pr":
            result["line"] = with_note(f"Patch for {path} holds up on the stunt double. Dry run, so no pull request opened.", job.variants_note)
            self._set_file(path, FixStatus.READY, result)
            return result
        branch = branch_prefix(path) + time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        pr = self.github.open_pr(branch, path, job.original["sha"], new_text, pr_title(result["title"]), result["pr_body"])
        result["pr"] = pr
        if not pr.get("ok"):
            result["status"] = FixStatus.PR_FAILED
            cleanup = {True: " The branch was deleted.", False: f" The branch {branch} could not be deleted; remove it by hand."}.get(pr.get("branch_deleted"), "")
            result["line"] = f"Patch works but the pull request failed at {pr.get('step')} (HTTP {pr.get('status')}).{cleanup}"
            self._set_file(path, FixStatus.FAILED)
            return result
        result["status"] = FixStatus.PR_OPENED
        result["pr_url"] = pr.get("url")
        result["line"] = with_note(f"Fixed the lock on {path}. Pull request is up for the owner to review.", job.variants_note)
        self._set_file(path, FixStatus.PR_OPENED, result)
        return result
