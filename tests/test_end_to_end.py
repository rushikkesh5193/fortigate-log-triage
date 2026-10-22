"""End-to-end check: generate a synthetic day with known injected incidents, run the real CLI, compare with truth.

The detectors and thresholds were written before this data, but the data generator and detectors were developed
together by the same author, so a pass shows the pipeline works - it is not a measure of real-world accuracy.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from helpers import ROOT
from tools.gen_logs import generate


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = cls.tmp.name
        generate(cls.d, seed=7, sessions=18000)
        with open(os.path.join(cls.d, "truth.json")) as fh:
            cls.truth = json.load(fh)["injected"]
        cls.run1 = cls.run_cli("out1")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_cli(cls, name):
        out = os.path.join(cls.d, name)
        res = subprocess.run([sys.executable, "-m", "triage", os.path.join(cls.d, "sample.log"), "--out-dir", out],
                             cwd=ROOT, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        with open(os.path.join(out, "incidents.json")) as fh:
            return json.load(fh)

    def test_every_injected_incident_found_with_right_severity_and_nothing_else(self):
        want = {(t["category"], t["src"]): t["severity"] for t in self.truth if t["expect"] == "detect"}
        got = {(i["category"], i["src"]): i["severity"] for i in self.run1["incidents"]}
        self.assertEqual(got, want)

    def test_known_limitation_low_and_slow_scan_is_missed(self):
        missed = [t["src"] for t in self.truth if t["expect"] == "miss"]
        self.assertEqual(missed, ["203.0.113.60"])
        self.assertNotIn("203.0.113.60", [i["src"] for i in self.run1["incidents"]])

    def test_benign_noise_raises_nothing(self):
        srcs = {i["src"] for i in self.run1["incidents"]}
        self.assertNotIn("10.10.5.50", srcs)      # authorised scanner
        self.assertNotIn("10.10.30.5", srcs)      # backup job
        self.assertNotIn("10.10.1.5", srcs)       # admin typo

    def test_queue_is_sorted_by_severity_and_ids_are_unique(self):
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sev = [order[i["severity"]] for i in self.run1["incidents"]]
        self.assertEqual(sev, sorted(sev, reverse=True))
        ids = [i["id"] for i in self.run1["incidents"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_malformed_line_counted_not_fatal(self):
        self.assertEqual(self.run1["meta"]["malformed"], 1)

    def test_output_is_deterministic(self):
        again = self.run_cli("out2")
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.run1, sort_keys=True))

    def test_report_markdown_has_queue_and_evidence(self):
        with open(os.path.join(self.d, "out1", "report.md")) as fh:
            md = fh.read()
        self.assertIn("## Queue", md)
        self.assertIn("Recommended L1 action", md)
        self.assertIn("```", md)

    def test_missing_input_file_exits_nonzero(self):
        res = subprocess.run([sys.executable, "-m", "triage", "/nonexistent.log"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
