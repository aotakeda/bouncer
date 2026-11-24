from __future__ import annotations

import base64
from urllib.parse import quote

from . import net
from .net import ERROR_DETAIL_CHARS, clip


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
            if self._is_own_branch(pr, prefix):
                return pr.get("html_url") or ""
        return ""

    def _is_own_branch(self, pr: dict, prefix: str) -> bool:
        head = pr.get("head") or {}
        if not (head.get("ref") or "").startswith(prefix):
            return False
        repo = head.get("repo")
        return isinstance(repo, dict) and repo.get("full_name") == self.repo

    def open_pr(self, branch: str, path: str, blob_sha: str, content: str, title: str, body: str) -> dict:
        status, ref = self.call("GET", f"/git/ref/heads/{quote(self.branch)}")
        if status != 200:
            return {"ok": False, "step": "base ref", "status": status}
        status, out = self.call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]})
        if status != 201:
            return self._step_failed("branch", status, out)
        payload = {"message": title, "content": base64.b64encode(content.encode()).decode(), "sha": blob_sha, "branch": branch}
        status, out = self.call("PUT", f"/contents/{quote(path)}", payload)
        if status not in (200, 201):
            return self._step_failed("commit", status, out)
        status, out = self.call("POST", "/pulls", {"title": title, "head": branch, "base": self.branch, "body": body})
        if status != 201:
            return self._step_failed("pull request", status, out)
        return {"ok": True, "url": out.get("html_url"), "number": out.get("number")}

    @staticmethod
    def _step_failed(step: str, status: int, out) -> dict:
        return {"ok": False, "step": step, "status": status, "detail": clip(out, ERROR_DETAIL_CHARS)}
