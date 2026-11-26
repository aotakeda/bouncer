from __future__ import annotations

import base64
from urllib.parse import quote

from . import net
from .net import ERROR_DETAIL_CHARS, clip

PAGE_SIZE = 100
MAX_PAGES = 10


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

    def open_pr_url(self, prefix: str) -> str | None:
        for page in range(1, MAX_PAGES + 1):
            status, body = self.call("GET", f"/pulls?state=open&per_page={PAGE_SIZE}&page={page}")
            if status != 200 or not isinstance(body, list):
                return None
            for pr in body:
                if isinstance(pr, dict) and self._is_own_branch(pr, prefix):
                    return pr.get("html_url") or f"https://github.com/{self.repo}/pull/{pr.get('number')}"
            if len(body) < PAGE_SIZE:
                return ""
        return None

    def pr_state(self, number) -> str | None:
        status, body = self.call("GET", f"/pulls/{int(number)}")
        if status != 200 or not isinstance(body, dict) or "state" not in body:
            return None
        if body.get("merged") or body.get("merged_at"):
            return "merged"
        return str(body["state"])

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
            return self._drop_branch(branch, self._step_failed("commit", status, out))
        status, out = self.call("POST", "/pulls", {"title": title, "head": branch, "base": self.branch, "body": body})
        if status != 201:
            return self._drop_branch(branch, self._step_failed("pull request", status, out))
        return {"ok": True, "url": out.get("html_url"), "number": out.get("number")}

    def _drop_branch(self, branch: str, failed: dict) -> dict:
        status, _ = self.call("DELETE", f"/git/refs/heads/{quote(branch)}")
        failed["branch_deleted"] = status in (200, 204)
        return failed

    @staticmethod
    def _step_failed(step: str, status: int, out) -> dict:
        return {"ok": False, "step": step, "status": status, "detail": clip(out, ERROR_DETAIL_CHARS)}
