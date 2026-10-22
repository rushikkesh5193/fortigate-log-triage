#!/usr/bin/env python3
"""Generate a synthetic day of FortiGate-style logs with known, injected incidents.

IMPORTANT: these logs are SYNTHETIC. They follow the FortiOS key=value layout (field names such as srcintfrole,
sentbyte, logdesc, severity) as I understand it from Fortinet's public documentation, but they were not exported
from a real device, and exact logid values / field sets vary by FortiOS version. All external addresses come from
the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so nothing here points at a
real third party.

Output: <out>/sample.log and <out>/truth.json (what was injected, and what the detectors are expected to do).
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta

DAY = datetime(2026, 10, 20)
EPOCH = datetime(1970, 1, 1)
DEV, DEVID = "FGT-HQ-01", "FGT60F0000000001"
UNQUOTED = {"date", "time", "srcip", "dstip"}
INTF = {"lan": "port1", "dmz": "port2", "wan": "wan1"}
SERVICE = {443: "HTTPS", 80: "HTTP", 53: "DNS", 25: "SMTP", 3389: "RDP", 445: "SMB", 23: "TELNET", 22: "SSH", 1433: "MS-SQL"}
LOG4J = "Apache.Log4j.Error.Log.Remote.Code.Execution"


def fmt(rec):
    parts = []
    for k, v in rec.items():
        if isinstance(v, int) or k in UNQUOTED:
            parts.append(f"{k}={v}")
        else:
            parts.append('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"')))
    return " ".join(parts)


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.rows = []        # (timestamp, record)
        self.truth = []
        self.sid = 100000

    # -- record builders ---------------------------------------------------------------------------------
    def _base(self, ts, logid, typ, sub, level):
        return {"date": ts.strftime("%Y-%m-%d"), "time": ts.strftime("%H:%M:%S"), "devname": DEV, "devid": DEVID,
                "logid": logid, "type": typ, "subtype": sub, "level": level, "vd": "root",
                "eventtime": int((ts - EPOCH).total_seconds() * 1e9)}

    def traffic(self, ts, src, srcrole, dst, dstrole, dport, action, sent=0, rcvd=0, dur=0, proto=6):
        self.sid += 1
        rec = self._base(ts, "0000000013", "traffic", "forward", "notice")
        rec.update(srcip=src, srcport=self.r.randint(1025, 65000), srcintf=INTF[srcrole], srcintfrole=srcrole,
                   dstip=dst, dstport=dport, dstintf=INTF[dstrole], dstintfrole=dstrole, sessionid=self.sid, proto=proto,
                   action=action, policyid=0 if action == "deny" else 1, policytype="policy",
                   service=SERVICE.get(dport, f"tcp/{dport}"), duration=dur, sentbyte=sent, rcvdbyte=rcvd)
        self.rows.append((ts, rec))

    def admin_login(self, ts, src, user, ok):
        rec = self._base(ts, "0100032001" if ok else "0100032002", "event", "system", "information" if ok else "alert")
        rec.update(logdesc="Admin login successful" if ok else "Admin login failed", user=user, ui=f"https({src})",
                   action="login", status="success" if ok else "failed", **({} if ok else {"reason": "passwd_invalid"}),
                   msg=f"Administrator {user} {'logged in successfully' if ok else 'login failed'} from https({src})")
        self.rows.append((ts, rec))

    def ips(self, ts, src, dst, attack, severity, action):
        rec = self._base(ts, "0419016384", "utm", "ips", "alert")
        rec.update(srcip=src, dstip=dst, action=action, severity=severity, attack=attack, direction="incoming",
                   msg=f"web_misc: {attack}.")
        self.rows.append((ts, rec))

    def virus(self, ts, server, client, virus):
        rec = self._base(ts, "0211008192", "utm", "virus", "warning")
        rec.update(srcip=server, dstip=client, action="blocked", virus=virus, direction="incoming", dtype="Virus",
                   filename="invoice_update.exe", msg=f"File is infected with {virus}.")
        self.rows.append((ts, rec))

    # -- scenarios ---------------------------------------------------------------------------------------
    def at(self, hh, mm, ss=0):
        return DAY + timedelta(hours=hh, minutes=mm, seconds=ss)

    def baseline(self, n_sessions):
        r = self.r
        users = [f"10.10.1.{i}" for i in range(10, 110)]
        ext = [f"192.0.2.{i}" for i in range(1, 101)]
        weights = [1] * 7 + [4, 8, 10, 10, 9, 8, 9, 10, 10, 8, 5, 3] + [2] * 5   # hour-of-day shape (24 values)
        for _ in range(n_sessions):
            ts = DAY + timedelta(hours=r.choices(range(24), weights)[0], minutes=r.randint(0, 59), seconds=r.randint(0, 59))
            u = r.choice(users)
            if r.random() < 0.005:        # occasional policy denies (sparse, so no burst forms)
                self.traffic(ts, u, "lan", r.choice(ext), "wan", r.choice([22, 25, 6881]), "deny")
                continue
            port = r.choices([443, 80, 53, 25], [70, 10, 15, 5])[0]
            sent = int(r.lognormvariate(9.5, 1.0))
            self.traffic(ts, u, "lan", r.choice(ext), "wan", port, "close", sent, int(sent * r.uniform(2, 40)),
                         r.randint(1, 120), 17 if port == 53 else 6)
        for _ in range(1500):             # legitimate inbound HTTPS to the DMZ web server
            ts = DAY + timedelta(seconds=r.randint(0, 86399))
            self.traffic(ts, f"192.0.2.{r.randint(101, 199)}", "wan", "10.10.20.10", "dmz", 443, "close",
                         r.randint(500, 3000), r.randint(5000, 90000), r.randint(1, 60))
        for hh in (8, 10, 12, 15, 17, 18):  # normal admin logins by the network admin
            self.admin_login(self.at(hh, self.r.randint(0, 59)), "10.10.1.5", "netadmin", True)

    def benign_noise(self):
        r = self.r
        t = self.at(9, 3)                 # admin mistypes the password twice, then succeeds (below threshold)
        self.admin_login(t, "10.10.1.5", "netadmin", False)
        self.admin_login(t + timedelta(seconds=14), "10.10.1.5", "netadmin", False)
        self.admin_login(t + timedelta(seconds=40), "10.10.1.5", "netadmin", True)
        for i in range(300):              # authorised vulnerability scanner (allowlisted in config)
            self.traffic(self.at(22, 0) + timedelta(seconds=i), "10.10.5.50", "lan", f"10.10.30.{r.randint(1, 60)}", "dmz",
                         r.choice([21, 22, 23, 80, 135, 445, 1433, 3389]), "deny")
        for i in range(6):                # nightly backup to an approved cloud destination (allowlisted)
            self.traffic(self.at(1, 0) + timedelta(minutes=10 * i), "10.10.30.5", "dmz", "198.51.100.200", "wan", 443,
                         "close", 50_000_000, 40_000, 300)

    def inject(self):
        r = self.r

        def truth(cat, sev, src, expect="detect", note=""):
            self.truth.append({"category": cat, "severity": sev, "src": src, "expect": expect, "note": note})

        # 1 external port scan of the DMZ web server
        for i, port in enumerate(r.sample(range(1, 1025), 120)):
            self.traffic(self.at(2, 14) + timedelta(seconds=i), "203.0.113.50", "wan", "10.10.20.10", "dmz", port, "deny")
        truth("scan", "medium", "203.0.113.50", note="external vertical port scan")
        # 2 firewall admin brute force that ends in a successful login
        t = self.at(3, 30)
        for i in range(40):
            self.admin_login(t + timedelta(seconds=i * 15 + r.randint(0, 5)), "203.0.113.77", r.choice(["admin", "root", "administrator"]), False)
        self.admin_login(t + timedelta(seconds=40 * 15 + 70), "203.0.113.77", "admin", True)
        truth("bruteforce", "critical", "203.0.113.77", note="40 failures on 3 accounts, then success (brute force, not spray)")
        # 3 password spraying, no success
        t = self.at(4, 10)
        users = ["admin", "root", "fortinet", "support", "backup", "guest"]
        for i in range(12):
            self.admin_login(t + timedelta(seconds=i * 20), "198.51.100.9", users[i % 6], False)
        truth("bruteforce", "medium", "198.51.100.9", note="spray across 6 accounts")
        # 4 RDP reachable from the internet (accepted)
        for i in range(3):
            self.traffic(self.at(9, 40) + timedelta(minutes=2 * i), "203.0.113.99", "wan", "10.10.20.15", "dmz", 3389, "accept", 5000, 9000, 90)
        truth("exposure", "high", "203.0.113.99", note="RDP accepted from internet")
        # 5 data exfiltration: 660,000,000 bytes (about 629 MiB) uploaded in 30 sessions
        for i in range(30):
            self.traffic(self.at(13, 0) + timedelta(minutes=2 * i), "10.10.1.42", "lan", "192.0.2.250", "wan", 443, "close", 22_000_000, 20_000, 110)
        truth("exfiltration", "high", "10.10.1.42", note="660,000,000-byte upload to unapproved destination")
        # 6 IPS: one critical exploit that got through, one that was blocked
        for i in range(3):
            self.ips(self.at(10, 15, i * 5), "203.0.113.140", "10.10.20.10", LOG4J, "critical", "detected")
        truth("ips", "critical", "203.0.113.140", note="critical exploit NOT blocked")
        for i in range(2):
            self.ips(self.at(10, 20, i * 5), "203.0.113.141", "10.10.20.10", LOG4J, "critical", "dropped")
        truth("ips", "medium", "203.0.113.141", note="critical exploit blocked")
        # 7 antivirus detection for a user's download
        for i in range(2):
            self.virus(self.at(11, 5, i * 20), "192.0.2.77", "10.10.1.77", "W32/Agent.ABC!tr")
        truth("malware", "high", "10.10.1.77", note="malware download blocked")
        # 8 C2 beaconing to a blocklisted address (allowed), and a blocked attempt from another host
        for i in range(12):
            self.traffic(self.at(15, 0) + timedelta(minutes=5 * i, seconds=r.randint(0, 3)), "10.10.1.88", "lan", "203.0.113.250", "wan", 8443, "close", 600, 900, 2)
        truth("c2", "critical", "10.10.1.88", note="beaconing to blocklisted IP, allowed")
        for i in range(3):
            self.traffic(self.at(15, 30, i * 30), "10.10.1.89", "lan", "203.0.113.250", "wan", 8443, "deny")
        truth("c2", "medium", "10.10.1.89", note="blocked attempt to blocklisted IP")
        # 9 internal host sweeping the server VLAN for SMB
        for i in range(60):
            self.traffic(self.at(16, 20) + timedelta(seconds=i), "10.10.1.99", "lan", f"10.10.30.{i + 1}", "dmz", 445, "deny")
        truth("scan", "high", "10.10.1.99", note="internal SMB host sweep")
        # 10 low-and-slow scan: 1 probe per 10 minutes for 12 hours. Deliberately NOT detectable by burst rules.
        for i in range(72):
            self.traffic(self.at(0, 5) + timedelta(minutes=10 * i), "203.0.113.60", "wan", "10.10.20.10", "dmz", 1000 + i, "deny")
        truth("scan", "-", "203.0.113.60", expect="miss", note="low-and-slow scan: known limitation")

    def write(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        self.rows.sort(key=lambda x: x[0])
        with open(os.path.join(outdir, "sample.log"), "w", encoding="utf-8") as fh:
            fh.write("# SYNTHETIC FortiGate-style logs generated by tools/gen_logs.py (not from a real device)\n")
            for _, rec in self.rows:
                fh.write(fmt(rec) + "\n")
            fh.write("this line is deliberately malformed and must be skipped\n")
        with open(os.path.join(outdir, "truth.json"), "w", encoding="utf-8") as fh:
            json.dump({"events": len(self.rows), "injected": self.truth}, fh, indent=2)
        return len(self.rows)


def generate(outdir, seed=7, sessions=18000):
    g = Gen(seed)
    g.baseline(sessions)
    g.benign_noise()
    g.inject()
    return g.write(outdir)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sample")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--sessions", type=int, default=18000)
    a = ap.parse_args()
    print(f"wrote {generate(a.out, a.seed, a.sessions):,} events to {a.out}/sample.log")
