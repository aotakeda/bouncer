from __future__ import annotations

import tempfile
import unittest

from agent.agent import Brain, Config
from agent.event_log import Feed


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


if __name__ == "__main__":
    unittest.main()
