from __future__ import annotations

import unittest

from agent import persona


class Lines(unittest.TestCase):
    def test_same_request_gets_same_line(self):
        self.assertEqual(persona.line("ignore_probe", "/wp-login.php"), persona.line("ignore_probe", "/wp-login.php?x=1"))
        self.assertIn(persona.line("block", "/rest/user/login"), persona.LINES["block"])

    def test_lines_vary_across_paths(self):
        picks = {persona.line("ignore_probe", f"/probe-{i}") for i in range(40)}
        self.assertGreater(len(picks), 1)


if __name__ == "__main__":
    unittest.main()
