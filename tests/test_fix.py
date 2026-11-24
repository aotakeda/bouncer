from __future__ import annotations

import unittest

from agent.fix import VARIANTS_FAILED, apply_edits, branch_prefix, clean_variants, locate_route, pr_body, smoke_diff, Fixer, FixJob
from agent.labels import FixStatus

SERVER = """import { login } from './routes/login'
import { searchProducts } from './routes/search'
import * as basket from './routes/basket'
import { getUserProfile, updateUserProfile as upd } from './routes/userProfile'
  app.post('/rest/passkey/login-options', utils.asyncHandler(passkey.loginOptions))
  app.post('/rest/user/login', login())
  app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
  app.get('/rest/basket/:id', basket.retrieveBasket())
  app.use('/profile', upd())
"""


class LocateRoute(unittest.TestCase):
    def test_named_import(self):
        self.assertEqual(locate_route(SERVER, "POST", "/rest/user/login"), "routes/login.ts")

    def test_wrapped_handler_and_query(self):
        self.assertEqual(locate_route(SERVER, "GET", "/rest/products/search?q=x'--"), "routes/search.ts")

    def test_namespace_import_with_param(self):
        self.assertEqual(locate_route(SERVER, "GET", "/rest/basket/7"), "routes/basket.ts")

    def test_aliased_use_prefix(self):
        self.assertEqual(locate_route(SERVER, "POST", "/profile/image"), "routes/userProfile.ts")

    def test_method_must_match(self):
        self.assertEqual(locate_route(SERVER, "GET", "/rest/user/login"), "")


class ApplyEdits(unittest.TestCase):
    def test_applies_unique_edit(self):
        out, problem = apply_edits("a = '${x}'\n", [{"search": "'${x}'", "replace": "?"}])
        self.assertEqual((out, problem), ("a = ?\n", ""))

    def test_rejects_ambiguous_or_missing(self):
        self.assertIn("2 times", apply_edits("x x", [{"search": "x", "replace": "y"}])[1])
        self.assertIn("0 times", apply_edits("x", [{"search": "z", "replace": "y"}])[1])
        self.assertEqual(apply_edits("x", [])[1], "edits change nothing")


class Judge(unittest.TestCase):
    req = {"method": "POST", "path": "/rest/user/login", "headers": {}}
    smoke = {"login": {"status": 200, "count": 1}, "search": {"status": 200, "count": 1}}

    def verify(self, attack_solved=None, control=401, after=None, build_ok=True):
        return {
            "ok": True,
            "build": {"ok": build_ok, "ms": 10, "log": "error TS2304"},
            "replay": {"ok": True, "control": {"status": control, "canary_hits": []}, "attack": {"status": 401, "canary_hits": []}, "attack_solved": attack_solved or {}},
            "smoke_before": self.smoke,
            "smoke_after": after or self.smoke,
        }

    def judge(self, verify):
        return Fixer.judge(Fixer.__new__(Fixer), self.req, verify, 401)

    def test_good_patch_passes(self):
        self.assertEqual(self.judge(self.verify()), "")

    def test_compile_failure(self):
        self.assertIn("build failed", self.judge(self.verify(build_ok=False)))

    def test_attack_still_works(self):
        self.assertIn("still works", self.judge(self.verify(attack_solved={"loginAdminChallenge": {"name": "Login Admin", "difficulty": 2}})))

    def test_control_changed(self):
        self.assertIn("control status 401 -> 500", self.judge(self.verify(control=500)))

    def test_legit_login_broken(self):
        broken = {"login": {"status": 401, "count": None}, "search": {"status": 200, "count": 1}}
        self.assertIn("legitimate behaviour changed", self.judge(self.verify(after=broken)))
        self.assertEqual(smoke_diff(self.smoke, self.smoke), [])


class Variants(unittest.TestCase):
    req = {"method": "POST", "path": "/rest/user/login", "headers": {"Content-Type": "application/json"}, "body": "{}"}

    def test_keeps_only_same_route_and_new_requests(self):
        raw = [
            {"path": "/rest/user/login", "body": '{"email":"a"}', "idea": "x"},
            {"path": "/rest/user/login", "body": "{}", "idea": "same as original"},
            {"path": "/api/Users", "body": "{}", "idea": "other route"},
            {"path": "/rest/user/login", "body": '{"email":"a"}', "idea": "duplicate"},
        ]
        out = clean_variants(self.req, raw)
        self.assertEqual([v["idea"] for v in out], ["x"])
        self.assertEqual((out[0]["method"], out[0]["headers"]), ("POST", {"Content-Type": "application/json"}))

    def test_variant_that_still_works_fails_the_patch(self):
        variants = clean_variants(self.req, [{"path": "/rest/user/login", "body": '{"email":"a"}', "idea": "other quote"}])
        verify = Judge.verify(Judge())
        still = {"attack": {"status": 200, "canary_hits": []}, "attack_solved": {"loginAdminChallenge": {"name": "Login Admin", "difficulty": 2}}}
        blocked = {"attack": {"status": 401, "canary_hits": []}, "attack_solved": {}}
        verify["variants"] = {"before": [still], "after": [still]}
        self.assertIn("variant of the attack still works", Fixer.judge(Fixer.__new__(Fixer), self.req, verify, 401, variants))
        verify["variants"] = {"before": [still], "after": [blocked]}
        self.assertEqual(Fixer.judge(Fixer.__new__(Fixer), self.req, verify, 401, variants), "")


class StubGitHub:
    def __init__(self, open_url=""):
        self.open_url = open_url

    def file(self, path):
        text = SERVER if path == "server.ts" else "query(`x = '${x}'`)\n"
        return {"path": path, "sha": "blob", "text": text}

    def open_pr_url(self, prefix):
        return self.open_url if prefix == branch_prefix("routes/login.ts") else ""


class StubClaude:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = 0

    def variants(self, prompt):
        return {"ok": False, "error": "skip"}

    def patch(self, prompt):
        self.calls += 1
        if not self.ok:
            return {"ok": False, "error": "down", "seconds": 0}
        return {"ok": True, "seconds": 0, "patch": {"title": "t", "summary": "s", "edits": [{"search": "'${x}'", "replace": ":x"}]}}


class Dedupe(unittest.TestCase):
    login = {"ip": "1.2.3.4", "event": {}, "replay": {"request": {"method": "POST", "path": "/rest/user/login", "headers": {}, "body": "{}"}}}
    search = {"ip": "1.2.3.4", "event": {}, "replay": {"request": {"method": "GET", "path": "/rest/products/search?q=x", "headers": {}}}}

    def fixer(self, github, claude, per_hour=3):
        f = Fixer("dry_run", claude, github, "http://runner", max_per_hour=per_hour)
        f.runner_patch = lambda payload: Judge.verify(Judge(), control=None)
        return f

    def test_open_pr_on_github_is_reused_without_calling_claude(self):
        claude = StubClaude()
        f = self.fixer(StubGitHub("https://github.com/aotakeda/juice-shop/pull/1"), claude, per_hour=1)
        out = f.fix(self.login, lambda *a: None)
        self.assertEqual((out["status"], out["pr_url"], claude.calls), ("pr_exists", "https://github.com/aotakeda/juice-shop/pull/1", 0))
        self.assertTrue(f.take_slot())

    def test_repeat_returns_known_patch_without_using_a_slot(self):
        claude = StubClaude()
        f = self.fixer(StubGitHub(), claude, per_hour=1)
        first = f.fix(self.login, lambda *a: None)
        again = f.fix(self.login, lambda *a: None)
        self.assertEqual((first["status"], again["status"], claude.calls), ("ready", "ready", 1))
        self.assertEqual(again["diff"], first["diff"])
        self.assertIn("already tested", again["line"])
        self.assertIn(VARIANTS_FAILED, first["line"])

    def test_limit_counts_only_real_attempts(self):
        f = self.fixer(StubGitHub(), StubClaude(ok=False), per_hour=1)
        self.assertEqual(f.fix(self.login, lambda *a: None)["status"], "failed")
        out = f.fix(self.search, lambda *a: None)
        self.assertEqual((out["status"], out["file"]), ("rate_limited", "routes/search.ts"))
        self.assertNotIn("routes/search.ts", f.files)

    def test_crash_releases_the_file(self):
        f = self.fixer(StubGitHub(), CrashingClaude())
        first = f._run_job(self.login, lambda *a: None)
        again = f._run_job(self.login, lambda *a: None)
        self.assertEqual(first["status"], FixStatus.ERROR)
        self.assertNotEqual(again["status"], FixStatus.SKIPPED)


class CrashingClaude(StubClaude):
    def variants(self, prompt):
        raise RuntimeError("boom")


class PrBody(unittest.TestCase):
    def test_backticks_in_attack_stay_inside_the_fence(self):
        req = {"method": "POST", "path": "/rest/user/login", "headers": {}, "body": "x\n```\n# injected heading"}
        job = FixJob(incident={"ts": 0}, req=req, why="w", control_status=401)
        result = {"summary": "s", "verify": {"build_ms": 1, "after": "NOT_REPRODUCED", "smoke": {}, "variants": []}}
        body = pr_body(job, result)
        self.assertIn("````\nPOST /rest/user/login\nx\n```\n# injected heading\n````", body)


if __name__ == "__main__":
    unittest.main()
