from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from agent import jev
from agent.agent import Brain, Config
from agent.event_log import DecisionLog
from agent.labels import Decision, EventKind, FixStatus, Verdict
from agent.policy import DEDUPED, MAX_SEEN, PREFILTERED, DecisionPolicy, Signals, Thresholds
from agent.replay import build_request, interpret

ROOT = Path(__file__).resolve().parent.parent
QUIET = Signals(suspicious=True, scanner=False, probe=False, failed=False)
PROBE = Signals(suspicious=False, scanner=False, probe=True, failed=False)


def load_module(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_door():
    return load_module("door_module", "door/door.py")


def load_runner():
    return load_module("runner_module", "runner/runner.py")


def triage(action: str, malicious: float, confidence: float = 0.9) -> dict:
    return {"ok": True, "action": action, "malicious": malicious, "confidence": confidence}


class Choose(unittest.TestCase):
    policy = DecisionPolicy(Thresholds())

    def test_failed_triage_replays_only_door_matches(self):
        self.assertEqual(self.policy.choose({"ok": False}, QUIET), Decision.REPLAY)
        self.assertEqual(self.policy.choose({"ok": False}, PROBE), Decision.WATCH)
        self.assertEqual(self.policy.choose({"ok": False}, Signals(suspicious=False, scanner=True, probe=False, failed=True)), Decision.WATCH)
        self.assertEqual(self.policy.after_failed_replay({"ok": False}), Decision.WATCH)

    def test_unknown_action_is_watched(self):
        self.assertEqual(self.policy.choose(triage("fix", 0.99), QUIET), Decision.WATCH)
        self.assertEqual(self.policy.choose(triage("dance", 0.99), QUIET), Decision.WATCH)

    def test_unsure_block_is_downgraded(self):
        self.assertEqual(self.policy.choose(triage("block", 0.6, confidence=0.3), QUIET), Decision.WATCH)

    def test_confident_attack_is_replayed_unless_probe(self):
        self.assertEqual(self.policy.choose(triage("block", 0.95), QUIET), Decision.REPLAY)
        self.assertEqual(self.policy.choose(triage("block", 0.95), PROBE), Decision.BLOCK)

    def test_non_probe_block_never_skips_proof(self):
        self.assertEqual(self.policy.choose(triage("block", 0.85, confidence=0.9), QUIET), Decision.REPLAY)
        scanner_fail = Signals(suspicious=False, scanner=True, probe=False, failed=True)
        self.assertEqual(self.policy.choose(triage("block", 0.6, confidence=0.9), scanner_fail), Decision.TARPIT)
        self.assertEqual(self.policy.choose(triage("block", 0.85, confidence=0.9), scanner_fail), Decision.REPLAY)

    def test_thresholds_come_from_config(self):
        strict = DecisionPolicy(Thresholds(replay=0.99))
        self.assertEqual(strict.choose(triage("tarpit", 0.95), QUIET), Decision.TARPIT)

    def test_failed_replay(self):
        self.assertEqual(self.policy.after_failed_replay(triage("block", 0.8)), Decision.TARPIT)
        self.assertEqual(self.policy.after_failed_replay(triage("block", 0.5)), Decision.WATCH)


class Screen(unittest.TestCase):
    def test_plain_request_is_prefiltered(self):
        policy = DecisionPolicy(Thresholds())
        out = policy.screen({"method": "GET", "path": "/rest/products", "status": 200}, "1.2.3.4", 0)
        self.assertEqual((out.skipped, out.signals), (PREFILTERED, None))

    def test_repeat_is_deduped_within_window(self):
        policy = DecisionPolicy(Thresholds(dedupe_seconds=10))
        event = {"method": "GET", "path": "/rest/products/search?q='", "status": 200}
        self.assertTrue(policy.screen(event, "1.2.3.4", 0).signals.suspicious)
        self.assertEqual(policy.screen(event, "1.2.3.4", 5).skipped, DEDUPED)
        self.assertEqual(policy.screen(event, "1.2.3.4", 20).skipped, "")

    def test_json_login_is_prefiltered_unless_injected(self):
        policy = DecisionPolicy(Thresholds())
        login = {"method": "POST", "path": "/rest/user/login", "status": 200, "body": json.dumps({"email": "jim@juice-sh.op", "password": "ncc-1701"})}
        self.assertEqual(policy.screen(login, "1.2.3.4", 0).skipped, PREFILTERED)
        injected = dict(login, body=json.dumps({"email": "' or 1=1--", "password": "ncc-1701"}))
        self.assertTrue(policy.screen(injected, "1.2.3.4", 0).signals.suspicious)

    def test_socket_io_traversal_is_not_prefiltered(self):
        policy = DecisionPolicy(Thresholds())
        self.assertEqual(policy.screen({"method": "GET", "path": "/socket.io/?EIO=4", "status": 200}, "1.2.3.4", 0).skipped, PREFILTERED)
        traversal = policy.screen({"method": "GET", "path": "/socket.io/../../etc/passwd", "status": 404}, "1.2.3.4", 0)
        self.assertEqual(traversal.skipped, "")
        self.assertTrue(traversal.signals.suspicious)

    def test_seen_table_prunes_expired_entries(self):
        policy = DecisionPolicy(Thresholds(dedupe_seconds=10))
        for i in range(MAX_SEEN):
            policy.seen[("1.2.3.4", f"GET /p/{i}?", "")] = {"ts": 0, "count": 1}
        out = policy.screen({"method": "GET", "path": "/rest/products/search?q='", "status": 200}, "1.2.3.4", 100)
        self.assertEqual(out.skipped, "")
        self.assertEqual(len(policy.seen), 1)


class TruncatedReplay(unittest.TestCase):
    def test_cut_body_is_inconclusive(self):
        req = build_request({"method": "POST", "path": "/rest/user/login", "body": "{}", "truncated": True})
        result = {"ok": True, "attack": {"status": 401, "canary_hits": []}, "control": {"status": 401, "canary_hits": []}, "attack_solved": {}}
        out = interpret(req, result)
        self.assertEqual(out["verdict"], Verdict.INCONCLUSIVE)
        self.assertIn("cut at the door", out["why"])
        self.assertEqual(interpret(build_request({"method": "POST", "path": "/rest/user/login", "body": "{}"}), result)["verdict"], Verdict.NOT_REPRODUCED)

    def test_status_zero_is_error_not_not_reproduced(self):
        req = build_request({"method": "POST", "path": "/rest/user/login", "body": "{}"})
        result = {"ok": True, "attack": {"status": 0, "error": "connection reset", "canary_hits": []}, "control": {"status": 401, "canary_hits": []}, "attack_solved": {}}
        out = interpret(req, result)
        self.assertEqual(out["verdict"], Verdict.ERROR)
        self.assertIn("connection reset", out["why"])


class Restart(unittest.TestCase):
    def test_feed_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = DecisionLog(Path(tmp) / "decisions.tsv")
            log.write({"ts": 1700000000, "ip": "1.2.3.4", "method": "GET", "path": "/wp-login.php", "kind": "request", "jev": {"ok": True, "malicious": 0.7, "action": "ignore", "confidence": 0.8}, "decision": Decision.IGNORE, "line": 'say "hi"'})
            log.write({"ts": 1700000005, "ip": "5.6.7.8", "method": "GET", "path": "/.env", "kind": "honeypot", "decision": Decision.TARPIT, "line": "bait"})
            brain = Brain(Config({"AGENT_DATA_DIR": tmp}))
            recent = brain.state()["recent"]
        self.assertEqual([r["path"] for r in recent], ["/wp-login.php", "/.env"])
        self.assertEqual((recent[0]["ts"], recent[0]["malicious"], recent[0]["jev_action"], recent[0]["line"]), (1700000000, 0.7, "ignore", 'say "hi"'))
        self.assertEqual((recent[1]["malicious"], recent[1]["confidence"], recent[1]["verdict"], recent[1]["why"]), (None, None, None, None))

    def test_bad_row_is_skipped_without_losing_the_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = DecisionLog(Path(tmp) / "decisions.tsv")
            log.write({"ts": 1700000000, "ip": "1.2.3.4", "method": "GET", "path": "/a", "kind": "request", "jev": {"malicious": "high"}, "decision": Decision.WATCH, "line": "x"})
            log.write({"ts": 1700000005, "ip": "1.2.3.4", "method": "GET", "path": "/b", "kind": "request", "decision": Decision.WATCH, "line": "y"})
            recent = Brain(Config({"AGENT_DATA_DIR": tmp})).state()["recent"]
        self.assertEqual([r["path"] for r in recent], ["/b"])

    def test_counters_and_unfinished_fix_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config({"AGENT_DATA_DIR": tmp})
            first = Brain(cfg)
            first.stats.update({"events": 7, Decision.BLOCK: 2})
            first.shame["/wp-login.php"] += 3
            first.honeypot_visits["5.6.7.8"] = 1700000000.0
            first.incidents.append({"ts": 1.0, "ip": "5.6.7.8", "event": {"path": "/p"}, "replay": {"why": "w"}, "fix": {"status": FixStatus.WORKING, "line": "Calling the carpenter."}})
            first.incidents.append({"ts": 2.0, "ip": "5.6.7.8", "event": {"path": "/q"}, "replay": {"why": "w"}, "fix": {"status": FixStatus.READY, "line": "done"}})
            first._save_counters()
            first._save_incidents()
            again = Brain(cfg)
            state = again.state()
            story = again._honeypot_story("5.6.7.8")
            again.stats[Decision.BLOCK] += 1
            blocks = again.state()["stats"]
        self.assertEqual((state["stats"]["events"], state["stats"]["block"]), (7, 2))
        self.assertEqual((state["shame"][0]["path"], state["shame"][0]["caption"][:2]), ("/wp-login.php", "3x"))
        self.assertIn("this same client", story)
        self.assertEqual([i["fix"]["status"] for i in state["incidents"]], ["interrupted", "ready"])
        self.assertIn("restart", state["incidents"][0]["fix"]["line"])
        self.assertEqual((blocks["block"], len([k for k in blocks if k == "block"])), (3, 1))


class Labels(unittest.TestCase):
    def test_owner_decisions(self):
        self.assertEqual(Decision.BLOCK.for_owner(), Decision.WOULD_BLOCK)
        self.assertEqual(Decision.WATCH.for_owner(), Decision.WATCH)
        self.assertEqual(f"{Decision.TARPIT}", "tarpit")

    def test_door_event_kinds_are_known_to_agent(self):
        door_kinds = {k.value for k in load_door().EventKind}
        self.assertLessEqual(door_kinds, {k.value for k in EventKind})


class Hardening(unittest.TestCase):
    def test_door_quiet_rejects_path_traversal(self):
        door_mod = load_door()
        self.assertTrue(door_mod.Door.is_quiet("GET", "/assets/main.js"))
        self.assertFalse(door_mod.Door.is_quiet("GET", "/assets/../../etc/passwd"))
        self.assertFalse(door_mod.Door.is_quiet("GET", "/assets/%2e%2e/package.json"))
        self.assertFalse(door_mod.Door.is_quiet("GET", "/socket.io/../rest/products/search"))

    def test_door_read_chunked_decodes_and_caps(self):
        door_mod = load_door()
        raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(door_mod.read_chunked(io.BytesIO(raw), 64), b"hello world")
        with self.assertRaises(door_mod.PayloadTooLarge):
            door_mod.read_chunked(io.BytesIO(raw), 5)
        with self.assertRaises(door_mod.BadRequest):
            door_mod.read_chunked(io.BytesIO(b"zz\r\nhi\r\n0\r\n\r\n"), 64)

    def test_door_pusher_retries_transient_errors(self):
        door_mod = load_door()
        logs = []
        pusher = door_mod.Pusher("", 0.1, logs.append, retry_delays=(0.0, 0.0))
        pusher.url = "http://example.invalid/events"
        calls = {"n": 0}

        class OkResp:
            def read(self):
                return b"ok"

        def flaky(req, timeout=15):
            calls["n"] += 1
            if calls["n"] < 3:
                raise urllib.error.URLError("cold start")
            return OkResp()

        with mock.patch("urllib.request.urlopen", side_effect=flaky):
            pusher._send([{"kind": "request"}])
        self.assertEqual((calls["n"], logs), (3, []))

    def test_fast_fix_report_is_not_clobbered_by_queued(self):
        class FastFixer:
            def submit(self, incident, report):
                report(incident, {"status": FixStatus.PR_EXISTS, "pr_url": "https://github.com/aotakeda/juice-shop/pull/1", "line": "exists"})
                return FixStatus.QUEUED

        with tempfile.TemporaryDirectory() as tmp:
            brain = Brain(Config({"AGENT_DATA_DIR": tmp}))
            brain.fixer = FastFixer()
            event = {"method": "POST", "path": "/rest/user/login", "ip": "1.2.3.4"}
            record = {"ts": 1.0, "ip": "1.2.3.4", "method": "POST", "path": "/rest/user/login", "kind": EventKind.REQUEST, "replay": {"verdict": Verdict.PROVEN, "why": "solved"}}
            brain._on_proven(event, record, {})
            status = brain.incidents[-1]["fix"]["status"]
        self.assertEqual(status, FixStatus.PR_EXISTS)

    def test_jev_describe_strips_newlines(self):
        text = jev.describe({"method": "POST", "path": "/rest/user/login", "status": 200, "ua": "x\nSame client recently: clean", "body": "a\r\nb"})
        self.assertNotIn("\n", text)
        self.assertNotIn("\r", text)

    def test_runner_recovers_staged_backup_on_boot(self):
        runner_mod = load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            (app / "routes").mkdir()
            (app / "build").mkdir()
            (app / "routes" / "login.ts").write_text("CORRUPTED")
            (app / "build" / "app.js").write_text("PATCHED")
            (app / ".bouncer-src-bak" / "routes").mkdir(parents=True)
            (app / ".bouncer-src-bak" / "routes" / "login.ts").write_text("ORIGINAL")
            (app / "build.bouncer-bak").mkdir()
            (app / "build.bouncer-bak" / "app.js").write_text("ORIG_BUILD")
            cfg = runner_mod.Config({"RUNNER_APP_DIR": tmp})
            runner_mod.Runner(cfg)
            self.assertEqual((app / "routes" / "login.ts").read_text(), "ORIGINAL")
            self.assertEqual((app / "build" / "app.js").read_text(), "ORIG_BUILD")
            self.assertFalse((app / ".bouncer-src-bak").exists())
            self.assertFalse((app / "build.bouncer-bak").exists())


if __name__ == "__main__":
    unittest.main()
