from __future__ import annotations

import unittest

from agent.fix import apply_edits, locate_route, smoke_diff, Fixer

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
        return Fixer.judge(None, self.req, verify, 401)

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


if __name__ == "__main__":
    unittest.main()
