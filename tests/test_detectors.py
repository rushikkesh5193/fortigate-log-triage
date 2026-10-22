import unittest

from helpers import cfg, new, parse_rows, sec
from triage.detectors import (detect_bruteforce, detect_exfil, detect_exposure, detect_ips, detect_malware,
                              detect_scan)


def scan_events(g, n, src="203.0.113.5", start=0, role="wan", gap=1, action="deny", hosts=1):
    for i in range(n):
        g.traffic(sec(start + i * gap), src, role, f"10.10.20.{1 + i % hosts}", "dmz", 1000 + i, action)


class ScanTests(unittest.TestCase):
    def test_threshold_boundary(self):
        g = new(); scan_events(g, 14)
        self.assertEqual(detect_scan(parse_rows(g), cfg()), [])
        g = new(); scan_events(g, 15)
        out = detect_scan(parse_rows(g), cfg())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].count, 15)

    def test_quiet_gap_splits_campaigns(self):
        g = new(); scan_events(g, 10); scan_events(g, 10, start=500)       # two bursts of 10 targets each
        self.assertEqual(detect_scan(parse_rows(g), cfg()), [])

    def test_accepted_traffic_is_not_a_scan(self):
        g = new(); scan_events(g, 30, action="accept")
        self.assertEqual(detect_scan(parse_rows(g), cfg()), [])

    def test_allowlisted_scanner_ignored(self):
        g = new(); scan_events(g, 40, src="10.10.5.50", role="lan")
        self.assertEqual(detect_scan(parse_rows(g), cfg()), [])

    def test_external_vs_internal_severity_and_kind(self):
        g = new(); scan_events(g, 30, src="203.0.113.5", role="wan")
        ext = detect_scan(parse_rows(g), cfg())[0]
        g = new(); scan_events(g, 30, src="10.10.1.9", role="lan", hosts=30)
        internal = detect_scan(parse_rows(g), cfg())[0]
        self.assertEqual((ext.severity, internal.severity), ("medium", "high"))
        self.assertIn("port scan", ext.title)
        self.assertIn("host sweep", internal.title)


def fails(g, n, src="203.0.113.9", users=("admin",), start=0, step=10):
    for i in range(n):
        g.admin_login(sec(start + i * step), src, users[i % len(users)], False)


class BruteforceTests(unittest.TestCase):
    def test_threshold_boundary(self):
        g = new(); fails(g, 4)
        self.assertEqual(detect_bruteforce(parse_rows(g), cfg()), [])
        g = new(); fails(g, 5)
        out = detect_bruteforce(parse_rows(g), cfg())
        self.assertEqual((len(out), out[0].severity), (1, "medium"))

    def test_many_failures_is_high(self):
        g = new(); fails(g, 20)
        self.assertEqual(detect_bruteforce(parse_rows(g), cfg())[0].severity, "high")

    def test_success_after_failures_is_critical(self):
        g = new(); fails(g, 6); g.admin_login(sec(6 * 10 + 20), "203.0.113.9", "admin", True)
        out = detect_bruteforce(parse_rows(g), cfg())
        self.assertEqual((out[0].severity, out[0].details["successful_login_after"]), ("critical", True))

    def test_success_from_other_ip_does_not_escalate(self):
        g = new(); fails(g, 6); g.admin_login(sec(80), "10.10.1.5", "netadmin", True)
        self.assertEqual(detect_bruteforce(parse_rows(g), cfg())[0].severity, "medium")

    def test_spray_vs_brute_force_labels(self):
        g = new(); fails(g, 12, users=("a", "b", "c", "d", "e", "f"))        # 2 tries per account
        self.assertIn("spraying", detect_bruteforce(parse_rows(g), cfg())[0].title)
        g = new(); fails(g, 40, users=("a", "b", "c"))                       # 13 tries per account
        self.assertNotIn("spraying", detect_bruteforce(parse_rows(g), cfg())[0].title)

    def test_separate_sources_and_quiet_gap(self):
        g = new(); fails(g, 5, src="203.0.113.1"); fails(g, 5, src="203.0.113.2")
        self.assertEqual(len(detect_bruteforce(parse_rows(g), cfg())), 2)
        g = new(); fails(g, 3); fails(g, 3, start=1000)                       # 3 + 3 across a long gap
        self.assertEqual(detect_bruteforce(parse_rows(g), cfg()), [])

    def test_admin_typo_not_flagged(self):
        g = new(); fails(g, 2, src="10.10.1.5", users=("netadmin",)); g.admin_login(sec(40), "10.10.1.5", "netadmin", True)
        self.assertEqual(detect_bruteforce(parse_rows(g), cfg()), [])


class ExposureTests(unittest.TestCase):
    def test_risky_port_accepted_from_wan(self):
        g = new(); g.traffic(sec(0), "203.0.113.7", "wan", "10.10.20.15", "dmz", 3389, "accept")
        out = detect_exposure(parse_rows(g), cfg())
        self.assertEqual((len(out), out[0].severity), (1, "high"))

    def test_denied_https_and_internal_sources_ignored(self):
        g = new()
        g.traffic(sec(0), "203.0.113.7", "wan", "10.10.20.15", "dmz", 3389, "deny")      # denied: policy worked
        g.traffic(sec(1), "203.0.113.7", "wan", "10.10.20.10", "dmz", 443, "accept")     # normal web traffic
        g.traffic(sec(2), "10.10.1.5", "lan", "10.10.30.5", "dmz", 3389, "accept")       # internal admin RDP
        self.assertEqual(detect_exposure(parse_rows(g), cfg()), [])


class ExfilTests(unittest.TestCase):
    def upload(self, total, rcvd=1000, dst="192.0.2.250", n=10):
        g = new()
        for i in range(n):
            g.traffic(sec(i * 60), "10.10.1.42", "lan", dst, "wan", 443, "close", total // n, rcvd // n)
        return parse_rows(g)

    def test_thresholds(self):
        c = cfg()["exfil"]["min_bytes"]
        self.assertEqual(detect_exfil(self.upload(c - 10_000), cfg()), [])                      # just under
        self.assertEqual(detect_exfil(self.upload(c + 10_000), cfg())[0].severity, "medium")    # just over
        self.assertEqual(detect_exfil(self.upload(c * 5 + 10_000), cfg())[0].severity, "high")  # 5x

    def test_normal_download_heavy_traffic_not_flagged(self):
        c = cfg()["exfil"]["min_bytes"]
        self.assertEqual(detect_exfil(self.upload(c * 2, rcvd=c * 2), cfg()), [])               # ratio 1:1

    def test_backup_destination_allowlisted(self):
        c = cfg()["exfil"]["min_bytes"]
        self.assertEqual(detect_exfil(self.upload(c * 6, dst="198.51.100.200"), cfg()), [])


class IpsTests(unittest.TestCase):
    def sev(self, vendor, action):
        g = new(); g.ips(sec(0), "203.0.113.8", "10.10.20.10", "Some.Attack", vendor, action)
        out = detect_ips(parse_rows(g), cfg())
        return out[0].severity if out else None

    def test_severity_table(self):
        self.assertEqual(self.sev("critical", "detected"), "critical")
        self.assertEqual(self.sev("critical", "dropped"), "medium")
        self.assertEqual(self.sev("high", "detected"), "high")
        self.assertEqual(self.sev("high", "blocked"), "low")

    def test_low_and_medium_vendor_severity_ignored(self):
        self.assertIsNone(self.sev("medium", "detected"))
        self.assertIsNone(self.sev("low", "detected"))

    def test_same_attack_same_source_is_one_incident(self):
        g = new()
        for i in range(5):
            g.ips(sec(i), "203.0.113.8", "10.10.20.10", "Some.Attack", "critical", "detected")
        out = detect_ips(parse_rows(g), cfg())
        self.assertEqual((len(out), out[0].count), (1, 5))


class MalwareTests(unittest.TestCase):
    def test_av_incident_attributed_to_the_internal_host(self):
        g = new(); g.virus(sec(0), "192.0.2.77", "10.10.1.77", "W32/Test!tr")
        out = [i for i in detect_malware(parse_rows(g), cfg()) if i.category == "malware"]
        self.assertEqual((out[0].src, out[0].severity), ("10.10.1.77", "high"))

    def test_blocklist_allowed_vs_denied(self):
        g = new(); g.traffic(sec(0), "10.10.1.8", "lan", "203.0.113.250", "wan", 8443, "close")
        self.assertEqual(detect_malware(parse_rows(g), cfg())[0].severity, "critical")
        g = new(); g.traffic(sec(0), "10.10.1.8", "lan", "203.0.113.250", "wan", 8443, "deny")
        self.assertEqual(detect_malware(parse_rows(g), cfg())[0].severity, "medium")

    def test_non_blocklisted_destination_ignored(self):
        g = new(); g.traffic(sec(0), "10.10.1.8", "lan", "192.0.2.10", "wan", 443, "close")
        self.assertEqual(detect_malware(parse_rows(g), cfg()), [])


if __name__ == "__main__":
    unittest.main()
