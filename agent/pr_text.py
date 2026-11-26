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
LEGEND = "_minor only_: the request only tripped a minor side effect, such as an error page, and leaked nothing. _not run_: the copy did not get to try it. _unclear_: the result could not be read. _blocked_: it worked before the patch and fails after it."
WARNING = "Generated from an attacker-supplied request. Review the whole diff, not just the tests."


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


def smoke_rows(smoke: dict) -> str:
    return "\n".join(f"| {k} | {v.get('status')} | {v.get('count') if v.get('count') is not None else ''} |" for k, v in smoke.items())


def variant_row(row: dict) -> str:
    request = shorten(str(row["request"]).replace("\r", " ").replace("\n", " "), REQUEST_CHARS).replace("`", "'").replace("|", "\\|")
    before = VARIANT_LABELS.get(row["before"], "unclear")
    blocked = row["before"] == Verdict.PROVEN and row["after"] == Verdict.NOT_REPRODUCED
    after = "blocked" if blocked else VARIANT_LABELS.get(row["after"], "unclear")
    return f"| {table_cell(row['idea'])} | `{request}` | {before} | {after} |"


def variant_section(rows: list, note: str = "") -> str:
    if not rows:
        return f"\n{safe_text(note)}\n" if note else ""
    lines = "\n".join(variant_row(r) for r in rows)
    return f"""
Other ways into the same hole, written by Claude and tried on the copy before and after the patch:

| idea | request | before | after |
|---|---|---|---|
{lines}

{LEGEND}
"""


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
On the isolated copy, Bouncer applied this patch, rebuilt the server ({verify['build_ms']} ms), replayed the same attack and a harmless control request, then rolled the copy back.

- Attack after the patch: **{verify['after']}**
- Normal checks after the patch, all matching the unpatched app:

| check | status | items |
|---|---|---|
{smoke_rows(verify['smoke'])}
{variant_section(verify.get('variants') or [], verify.get('variants_note') or "")}
{WARNING}

Opened by Bouncer. Review before merging.
"""


def pr_title(title) -> str:
    return safe_text(title).replace("\n", " ")[:200]
