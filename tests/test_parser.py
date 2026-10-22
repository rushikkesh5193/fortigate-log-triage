import unittest

from helpers import ROOT  # noqa: F401  (sets sys.path)
from triage.parser import parse_files, parse_line


class ParserTests(unittest.TestCase):
    def test_bare_and_quoted_values(self):
        e = parse_line('date=2026-10-20 time=09:14:03 srcip=10.0.0.1 srcport=5000 action="deny" msg="two words here"')
        self.assertEqual(e["srcip"], "10.0.0.1")
        self.assertEqual(e["srcport"], "5000")
        self.assertEqual(e["action"], "deny")
        self.assertEqual(e["msg"], "two words here")
        self.assertEqual((e["_ts"].hour, e["_ts"].minute, e["_ts"].second), (9, 14, 3))

    def test_escaped_quotes_and_backslashes(self):
        e = parse_line(r'date=2026-10-20 time=09:14:03 msg="said \"hi\" at C:\\temp"')
        self.assertEqual(e["msg"], 'said "hi" at C:\\temp')

    def test_empty_quoted_value(self):
        e = parse_line('date=2026-10-20 time=09:14:03 user="" action="login"')
        self.assertEqual(e["user"], "")
        self.assertEqual(e["action"], "login")

    def test_rejects_non_records(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("# a comment"))
        self.assertIsNone(parse_line("just some text"))
        self.assertIsNone(parse_line('time=09:14:03 srcip=1.2.3.4'))               # no date
        self.assertIsNone(parse_line('date=2026-13-45 time=09:14:03 srcip=1.2.3.4'))  # impossible date
        self.assertIsNone(parse_line('date=2026-10-20 time=25:00:00 srcip=1.2.3.4'))  # impossible time

    def test_files_sorted_and_malformed_counted(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.log")
            with open(p, "w") as fh:
                fh.write("# header\n"
                         "date=2026-10-20 time=10:00:00 n=2\n"
                         "garbage line\n"
                         "date=2026-10-20 time=09:00:00 n=1\n"
                         "\n"
                         "date=2026-10-20 time=09:00:00 n=1b\n")
            events, bad = parse_files([p])
        self.assertEqual(bad, 1)
        self.assertEqual([e["n"] for e in events], ["1", "1b", "2"])   # time-ordered, stable within a second


if __name__ == "__main__":
    unittest.main()
