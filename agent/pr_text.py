from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

from .labels import Verdict
from .net import bare_path, clip

if TYPE_CHECKING:
    from .fix import FixJob

VARIANT_LABELS = {
    Verdict.PROVEN: "worked",
    Verdict.NOT_REPRODUCED: "no effect",
    Verdict.NOT_RUN: "not run",
    Verdict.MINOR: "minor only",
    Verdict.INCONCLUSIVE: "unclear",
    Verdict.ERROR: "error",
}


REQUEST_CHARS = 120
OWN_LINKS = ("https://github.com/aotakeda/", "http://github.com/aotakeda/")
ZWJ = "\u200d"
MD_LINK = re.compile(r"!?\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?[^)]*\)")
URL = re.compile(r"\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>()\[\]`|]+", re.IGNORECASE)
MENTION = re.compile(r"(?<![\w`])@(?=[a-z0-9])", re.IGNORECASE)
ISSUE_REF = re.compile(r"(?<=[\w/])#(?=\d)|(?<![\w&])#(?=\d)|\bGH-(?=\d)", re.IGNORECASE)
FENCE = re.compile(r"`{3,}|~{3,}")
LEGEND = "_minor only_: the request only tripped a minor side effect, such as an error page, and leaked nothing. _not run_: the copy did not get to try it. _unclear_: the result could not be read. _blocked_: it worked before the patch and fails after it. _didn't work before either_: it did not work even on the unpatched copy, so it says nothing about the patch."
WARNING = "Generated from an attacker-supplied request. Review the whole diff, not just the tests."
NOT_EVIDENCE = "didn't work before either"
NORMAL_RULE = "Each normal request must get the same status, item count and response body after the patch as before it. Timestamps, tokens, ids and the test account's values are masked before the bodies are compared. One change is allowed: a request that crashed the unpatched app with a server error (5xx) may now get an answer, and on the patched route it must get the same status as the same request with a plain value."
ORACLE_TEXT = {
    "closed": "A true/false pair of requests ({idea}) got different answers on the unpatched copy ({before}) and identical answers after the patch ({after}), so the injection point no longer leaks data one bit at a time.",
    "no_signal": "A true/false pair of requests ({idea}) got the same answer even on the unpatched copy ({before}), so it says nothing about blind injection.",
}


def own_link(url: str) -> bool:
    return url.lower().startswith(OWN_LINKS)


def defang(url: str) -> str:
    if own_link(url):
        return url
    return url.replace("://", "[:]//", 1).replace(".", "[.]")


def safe_text(text) -> str:
    out = str(text).replace("\r", " ").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out = MD_LINK.sub(lambda m: m.group(0) if own_link(m.group(2)) else f"{m.group(1)} ({m.group(2)})", out)
    out = URL.sub(lambda m: defang(m.group(0)), out)
    out = MENTION.sub("@" + ZWJ, out)
    out = ISSUE_REF.sub(lambda m: m.group(0) + ZWJ, out)
    return FENCE.sub(lambda m: "".join("\\" + c for c in m.group(0)), out)


def table_cell(text) -> str:
    return safe_text(text).replace("\n", " ").replace("|", "\\|").replace("`", "\\`")


def shorten(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit - 1]
    cut = re.sub(r"%[0-9a-fA-F]?$", "", cut)
    return cut + "…"


def code_span(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def blank(value) -> str:
    return "" if value is None else str(value)


def check_rows(checks: list) -> str:
    return "\n".join(f"| {table_cell(c.get('name'))} | {blank(c.get('before'))} | {blank(c.get('after'))} | {blank(c.get('items'))} | {table_cell(c.get('body') or '')} |" for c in checks)


def after_label(row: dict) -> str:
    if row["after"] == Verdict.NOT_REPRODUCED:
        return "blocked" if row["before"] == Verdict.PROVEN else NOT_EVIDENCE
    return VARIANT_LABELS.get(row["after"], "unclear")


def variant_row(row: dict) -> str:
    request = shorten(str(row["request"]).replace("\r", " ").replace("\n", " "), REQUEST_CHARS).replace("`", "'").replace("|", "\\|")
    before = VARIANT_LABELS.get(row["before"], "unclear")
    return f"| {table_cell(row['idea'])} | `{request}` | {before} | {after_label(row)} |"


def evidence_line(rows: list) -> str:
    proven = sum(1 for r in rows if r["before"] == Verdict.PROVEN)
    if proven == len(rows):
        return f"All {len(rows)} worked on the unpatched copy and fail after the patch."
    return f"{proven} of {len(rows)} worked on the unpatched copy and fail after the patch. The others did not work even before the patch, so they are not evidence that the patch works."


def variant_section(rows: list, note: str = "") -> str:
    if not rows:
        return f"\n{safe_text(note)}\n" if note else ""
    lines = "\n".join(variant_row(r) for r in rows)
    return f"""
Other ways into the same hole, written by Claude and tried on the copy before and after the patch. {evidence_line(rows)}

| idea | request | before | after |
|---|---|---|---|
{lines}

{LEGEND}
"""


def oracle_section(oracle: dict, note: str = "") -> str:
    template = ORACLE_TEXT.get((oracle or {}).get("state"))
    if not template:
        return f"\n{safe_text(note)}\n" if note else ""
    idea = safe_text(oracle.get("idea") or "written by Claude").replace("\n", " ")
    return "\n" + template.format(idea=idea, before=safe_text(oracle.get("before", "")), after=safe_text(oracle.get("after", ""))) + "\n"


def code_fence(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def pr_body(job: FixJob, result: dict) -> str:
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job.incident.get("ts", time.time())))
    verify = result["verify"]
    method, path = job.req.get("method"), job.req.get("path", "")
    body_excerpt = clip(job.req.get("body") or "", 800)
    fenced = f"{method} {path[:500]}\n{body_excerpt}"
    fence = code_fence(fenced)
    return f"""{safe_text(result['summary'])}

> {WARNING}

### What happened
At {when} a request to {code_span(f"{method} {bare_path(path)}".replace(chr(10), " "))} was replayed on an isolated copy of this app and it worked: {safe_text(job.why)}.

{fence}
{fenced}
{fence}

### How this patch was checked
On the isolated copy, Bouncer replayed the attack on the unpatched app, applied this patch, rebuilt the server ({verify['build_ms']} ms), replayed the same attack and the same normal requests, then rolled the copy back.

- Attack before the patch, in the same run: **{verify.get('before', Verdict.PROVEN)}**
- Attack after the patch: **{verify['after']}**
- Normal requests before and after the patch:

| check | before | after | items | body |
|---|---|---|---|---|
{check_rows(verify.get('checks') or [])}

{NORMAL_RULE}
{variant_section(verify.get('variants') or [], verify.get('variants_note') or "")}{oracle_section(verify.get('oracle') or {}, verify.get('oracle_note') or "")}
> {WARNING}

Opened by Bouncer. Review before merging.
"""


def pr_title(title) -> str:
    return safe_text(title).replace("\n", " ")[:200]
