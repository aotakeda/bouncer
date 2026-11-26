from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from agent.agent import Brain, Config
from agent.event_log import DecisionLog, Feed


class FeedNoticeTests(unittest.TestCase):
    def test_notify_reaches_listeners_without_entering_history(self):
        feed = Feed()
        q = feed.subscribe()
        feed.notify({"kind": "state", "what": "signal"})
        self.assertEqual(q.get_nowait(), {"kind": "state", "what": "signal"})
        self.assertEqual(feed.latest(10), [])

    def test_publish_still_records_and_broadcasts(self):
        feed = Feed()
        q = feed.subscribe()
        feed.publish({"path": "/"})
        self.assertEqual(q.get_nowait(), {"path": "/"})
        self.assertEqual(feed.latest(10), [{"path": "/"}])

    def test_signal_status_change_notifies_open_dashboards(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = Brain(Config({"AGENT_DATA_DIR": tmp}))
            q = brain.feed.subscribe()
            self.assertTrue(brain.set_signal_status("proven:x", "resolved"))
            self.assertEqual(q.get_nowait(), {"kind": "state", "what": "signal", "id": "proven:x"})
            self.assertFalse(brain.set_signal_status("proven:x", "bogus"))
            self.assertTrue(q.empty())
            self.assertNotIn("state", [r.get("kind") for r in brain.state()["recent"]])

    def test_shielded_rows_keep_their_kind_for_the_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = Brain(Config({"AGENT_DATA_DIR": tmp}))
            q = brain.feed.subscribe()
            brain.emit({"ts": 1.0, "ip": "203.0.113.9", "method": "GET", "path": "/rest/products/search?q=x", "kind": "shielded", "decision": "watch", "line": "refused"})
            row = q.get_nowait()
            self.assertEqual(row["kind"], "shielded")
            self.assertEqual(row["decision"], "watch")


class DecisionLogTests(unittest.TestCase):
    def test_log_is_private_and_masks_query_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "decisions.tsv"
            log = DecisionLog(path)
            log.write({"ts": 0, "ip": "203.0.113.7", "method": "GET", "path": "/rest/products/search?q=' OR 1=1--&token=t-secret", "kind": "request", "decision": "watch", "line": "saw /x?password=l-secret"})
            text = path.read_text()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn("t-secret", text)
            self.assertNotIn("l-secret", text)
            self.assertIn("q=' OR 1=1--", text)
            self.assertEqual(log.tail(1)[0]["path"], "/rest/products/search?q=' OR 1=1--&token=[redacted]")


if __name__ == "__main__":
    unittest.main()
