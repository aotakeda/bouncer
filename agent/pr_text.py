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


def table_cell(text: str) -> str:
    return text.replace("|", "/")


def smoke_rows(smoke: dict) -> str:
    return "\n".join(f"| {k} | {v.get('status')} | {v.get('count') if v.get('count') is not None else ''} |" for k, v in smoke.items())


def variant_row(row: dict) -> str:
    request = table_cell(row["request"][:120]).replace("`", "")
    before = VARIANT_LABELS.get(row["before"], "unclear")
    blocked = row["before"] == Verdict.PROVEN and row["after"] == Verdict.NOT_REPRODUCED
    after = "blocked" if blocked else VARIANT_LABELS.get(row["after"], "unclear")
    return f"| {table_cell(row['idea'])} | `{request}` | {before} | {after} |"


def variant_section(rows: list, note: str = "") -> str:
    if not rows:
        return f"\n{note}\n" if note else ""
    lines = "\n".join(variant_row(r) for r in rows)
    return f"""
Other ways into the same hole, written by Claude and tried on the copy before and after the patch:

| idea | request | before | after |
|---|---|---|---|
{lines}
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
    return f"""{result['summary']}

### What happened
At {when} a request to `{method} {bare_path(path)}` was replayed on an isolated copy of this app and it worked: {job.why}.

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
Opened by Bouncer. Review before merging.
"""
