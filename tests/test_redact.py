from __future__ import annotations

import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from agent import jev as jev_mod
from agent.fix import FixJob
from agent.labels import FixStatus
from agent.redact import MASK, redact_event, redact_header, redact_incident, redact_text
from agent.store import Store

UNSIGNED = "eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIn0."
SIGNED = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
SQLI = "' OR 1=1--"


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class RedactText(unittest.TestCase):
    def test_json_secret_fields_are_masked_and_the_payload_stays(self):
        body = json.dumps({"email": SQLI, "password": "hunter2", "nested": {"authToken": "abc", "author": "Ann"}, "pin": 1})
        out = redact_text(body)
        self.assertNotIn("hunter2", out)
        self.assertNotIn('"abc"', out)
        self.assertIn(SQLI, out)
        self.assertIn('"author": "Ann"', out)
        self.assertEqual(json.loads(out)["password"], MASK)
        self.assertEqual(json.loads(out)["nested"]["authToken"], MASK)

    def test_truncated_json_still_masks_secrets(self):
        out = redact_text('{"email":"a@b.c","password":"hunter2-and-more')
        self.assertNotIn("hunter2", out)
        self.assertIn('"email":"a@b.c"', out)

    def test_form_body_and_query_string(self):
        self.assertEqual(redact_text("email=x%27+OR+1%3D1--&passwd=hunter2"), f"email=x%27+OR+1%3D1--&passwd={MASK}")
        path = f"/rest/products/search?q={SQLI}&api_key=k123&token=t456&page=2"
        out = redact_text(path)
        self.assertIn(f"q={SQLI}", out)
        self.assertIn("page=2", out)
        self.assertNotIn("k123", out)
        self.assertNotIn("t456", out)

    def test_sql_comparisons_are_not_mistaken_for_pairs(self):
        self.assertEqual(redact_text("q=1' AND 1=1--"), "q=1' AND 1=1--")

    def test_jwts_keep_only_their_header(self):
        out = redact_text(f"token in body {SIGNED} and {UNSIGNED}")
        self.assertNotIn("eyJpZCI6MX0", out)
        self.assertNotIn("eyJlbWFpbCI6", out)
        self.assertIn("eyJhbGciOiJub25lIn0.[redacted jwt, unsigned]", out)
        self.assertIn("eyJhbGciOiJIUzI1NiJ9.[redacted jwt]", out)

    def test_headers(self):
        self.assertEqual(redact_header("Authorization", f"Bearer {SIGNED}"), f"Bearer {MASK}")
        self.assertEqual(redact_header("authorization", "opaque-token-value"), MASK)
        self.assertEqual(redact_header("Cookie", "token=abc; language=en"), f"token={MASK}; language={MASK}")
        self.assertEqual(redact_header("X-Api-Key", "k"), MASK)
        self.assertEqual(redact_header("Accept", "*/*"), "*/*")
        self.assertEqual(redact_header("X-User-Email", "a@b.c"), "a@b.c")

    def test_event_is_copied_not_changed(self):
        event = {"method": "POST", "path": "/login?session=s1", "body": '{"password":"p"}', "headers": {"Cookie": "a=b"}, "ua": "curl"}
        before = json.dumps(event, sort_keys=True)
        out = redact_event(event)
        self.assertEqual(json.dumps(event, sort_keys=True), before)
        self.assertEqual(out["path"], f"/login?session={MASK}")
        self.assertEqual(out["headers"]["Cookie"], f"a={MASK}")
        self.assertNotIn('"p"', out["body"])


class JevPrompt(unittest.TestCase):
    def test_jev_sees_the_payload_but_not_the_password(self):
        seen = []

        def fake_post(url, payload, timeout=30, headers=None):
            seen.append(payload)
            return 500, {}, 0.1

        old = jev_mod.net.post_json
        jev_mod.net.post_json = fake_post
        self.addCleanup(setattr, jev_mod.net, "post_json", old)
        event = {"method": "POST", "path": "/rest/user/login?token=t-secret", "status": 401, "body": json.dumps({"email": SQLI, "password": "hunter2"}), "ctype": "application/json"}
        jev_mod.Jev("http://jev", "shop").triage(event, "GET /x?api_key=k-secret -> watch")
        state = seen[0]["state"]
        self.assertIn(SQLI, state)
        for secret in ("hunter2", "t-secret", "k-secret"):
            self.assertNotIn(secret, state)
        self.assertIn("hunter2", event["body"])


class StoreOnDisk(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def incident(self):
        event = {"method": "POST", "path": "/rest/user/login?session=s-secret", "body": json.dumps({"email": SQLI, "password": "hunter2"}), "ctype": "application/json", "headers": {"Authorization": f"Bearer {SIGNED}", "Cookie": "token=c-secret"}}
        req = {"method": "POST", "path": event["path"], "headers": {"Content-Type": "application/json", "Authorization": f"Bearer {SIGNED}", "Cookie": "token=c-secret"}, "body": event["body"]}
        replay = {"verdict": "PROVEN", "why": "solved Login Admin", "evidence": {"control_status": 401}, "request": req}
        return {"ts": 1.0, "ip": "203.0.113.7", "event": event, "replay": replay, "jev": {"ok": True}, "fix": {"status": FixStatus.WORKING}}

    def test_incidents_are_redacted_on_disk_only_and_private(self):
        store = Store(self.tmp)
        incident = self.incident()
        store.add_incident(incident)
        store.save_incidents()
        text = store.incidents_path.read_text()
        for secret in ("hunter2", "s-secret", "c-secret", "eyJpZCI6MX0"):
            self.assertNotIn(secret, text)
        self.assertIn(json.dumps(SQLI)[1:-1], text)
        self.assertEqual(mode(store.incidents_path), 0o600)
        self.assertIn("hunter2", incident["event"]["body"])
        self.assertEqual(incident["replay"]["request"]["headers"]["Cookie"], "token=c-secret")
        job = FixJob.from_incident(incident)
        self.assertEqual(job.req["headers"]["Authorization"], f"Bearer {SIGNED}")

    def test_reloaded_incidents_stay_usable(self):
        store = Store(self.tmp)
        store.add_incident(self.incident())
        store.save_incidents()
        again = Store(self.tmp)
        self.assertEqual(len(again.incidents), 1)
        loaded = again.incidents[0]
        self.assertEqual(loaded["fix"]["status"], FixStatus.INTERRUPTED)
        job = FixJob.from_incident(loaded)
        self.assertEqual(job.req["headers"]["Cookie"], f"token={MASK}")
        self.assertIn(SQLI, job.req["body"])

    def test_every_store_file_is_private(self):
        store = Store(self.tmp)
        store.shame_path("/ftp?token=sh-secret")
        store.save_counters()
        store.remember_catch({"ip": "203.0.113.7", "ts": 1.0, "path": "/x?password=c-secret", "rid": "r"}, True)
        store.set_signal_status("proven:x", "resolved")
        store.save_proven([["ip", "shape", "h", 1.0]])
        for path in (store.counters_path, store.catches_path, store.signal_states_path, store.proven_path):
            self.assertEqual(mode(path), 0o600, path.name)
        self.assertNotIn("sh-secret", store.counters_path.read_text())
        self.assertNotIn("c-secret", store.catches_path.read_text())
        self.assertEqual(store.catches[0]["path"], "/x?password=c-secret")

    def test_redact_incident_copies_the_fix(self):
        incident = self.incident()
        out = redact_incident(incident)
        out["fix"]["status"] = "changed"
        self.assertEqual(incident["fix"]["status"], FixStatus.WORKING)


if __name__ == "__main__":
    unittest.main()
