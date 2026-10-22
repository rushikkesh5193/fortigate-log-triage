"""Rule-based detectors. Each takes (events, cfg) and returns a list of Incident.

Design notes
  * Events are grouped per source and split into "bursts" (a new burst starts after a quiet gap), so one
    attacker campaign becomes ONE incident instead of hundreds of alerts - the main job of L1 triage.
  * Severity encodes triage logic, not just the vendor's label: an attack that was blocked is lower priority
    than the same attack that got through; a login success after many failures is an escalation.
  * Authorised scanners and known backup destinations are allowlisted in config (tuning, as in a real SOC).
  * MITRE ATT&CK ids are indicative starting points for the analyst, not a verdict.
"""
import re
from collections import defaultdict
from datetime import timedelta

from .models import Incident

BLOCKED = {"dropped", "blocked", "drop", "block", "reset", "reset_client", "reset_server", "deny"}
COMMUNICATED = {"accept", "close", "client-rst", "server-rst", "timeout"}
_UI_IP = re.compile(r"\(([0-9a-fA-F:.]+)\)")


def _int(e, key):
    try:
        return int(e.get(key, 0))
    except (TypeError, ValueError):
        return 0


def _bursts(items, gap_seconds):
    """Split a time-ordered list of events into runs separated by more than gap_seconds."""
    cur = []
    for e in items:
        if cur and (e["_ts"] - cur[-1]["_ts"]).total_seconds() > gap_seconds:
            yield cur
            cur = []
        cur.append(e)
    if cur:
        yield cur


def _evidence(events, n=3):
    return [e["_raw"] for e in events[:n]]


def detect_scan(events, cfg):
    c, skip = cfg["scan"], set(cfg["allowlist"]["scanners"])
    by_src = defaultdict(list)
    for e in events:
        if e.get("type") == "traffic" and e.get("action") == "deny" and e.get("srcip") and e["srcip"] not in skip:
            by_src[e["srcip"]].append(e)
    out = []
    for src, es in by_src.items():
        for b in _bursts(es, c["gap_seconds"]):
            targets = {(e.get("dstip"), e.get("dstport")) for e in b}
            if len(targets) < c["min_targets"]:
                continue
            hosts = {t[0] for t in targets}
            ports = {t[1] for t in targets}
            kind = "port scan (many ports, few hosts)" if len(ports) > len(hosts) else "host sweep (many hosts, few ports)"
            external = b[0].get("srcintfrole") == "wan"
            out.append(Incident(
                category="scan",
                severity="medium" if external else "high",
                title=f"{kind} from {'external' if external else 'INTERNAL'} host {src}",
                techniques=["T1046"],
                first_seen=b[0]["_ts"], last_seen=b[-1]["_ts"], src=src,
                dst=next(iter(hosts)) if len(hosts) == 1 else f"{len(hosts)} hosts",
                count=len(b),
                details={"distinct_targets": len(targets), "distinct_hosts": len(hosts), "distinct_ports": len(ports)},
                evidence=_evidence(b),
                action=("Internet background scanning is common: confirm the traffic was denied, check the source against threat intel, "
                        "and escalate only if followed by accepted sessions from the same IP." if external else
                        "Internal host scanning the network is a strong sign of compromise or an unapproved scanner: identify the asset "
                        "owner, check for an approved scan window, isolate the host if unexplained and escalate to L2."),
            ))
    return out


def _login_src(e):
    m = _UI_IP.search(e.get("ui", ""))
    return m.group(1) if m else e.get("srcip")


def detect_bruteforce(events, cfg):
    c = cfg["bruteforce"]
    fails, wins = defaultdict(list), defaultdict(list)
    for e in events:
        if e.get("type") != "event":
            continue
        desc, src = e.get("logdesc", "").lower(), _login_src(e)
        if not src:
            continue
        if "admin login failed" in desc:
            fails[src].append(e)
        elif "admin login successful" in desc:
            wins[src].append(e)
    out = []
    for src, es in fails.items():
        for b in _bursts(es, c["gap_seconds"]):
            if len(b) < c["min_failures"]:
                continue
            start, end = b[0]["_ts"], b[-1]["_ts"]
            horizon = end + timedelta(seconds=c["gap_seconds"])
            success = [w for w in wins.get(src, []) if start <= w["_ts"] <= horizon]
            users = sorted({e.get("user", "?") for e in b})
            # Spraying = few attempts per account across MANY accounts; brute force = many attempts on few accounts.
            spray = len(users) >= c["spray_min_users"] and len(b) / len(users) <= c["spray_max_per_account"]
            sev = "critical" if success else ("high" if len(b) >= c["high_failures"] else "medium")
            kind = "password spraying" if spray else "brute force"
            out.append(Incident(
                category="bruteforce", severity=sev,
                title=f"Firewall admin {kind} from {src}" + (" - FOLLOWED BY SUCCESSFUL LOGIN" if success else ""),
                techniques=["T1110.003" if spray else "T1110.001"],
                first_seen=start, last_seen=(success[-1]["_ts"] if success else end), src=src, dst="firewall admin interface",
                count=len(b) + len(success),
                details={"failed_logins": len(b), "accounts_tried": users, "successful_login_after": bool(success)},
                evidence=_evidence(b, 2) + _evidence(success, 1),
                action=("Treat as a possible account compromise: disable or reset the admin account, restrict admin access to trusted IPs, "
                        "review config changes since the login, and escalate to L2 immediately." if success else
                        "Confirm the source is external/untrusted, block it, enforce trusted-host restrictions and MFA on admin access, "
                        "and watch for a later successful login."),
            ))
    return out


def detect_exposure(events, cfg):
    risky = {int(k): v for k, v in cfg["exposure"]["risky_ports"].items()}
    groups = defaultdict(list)
    for e in events:
        if e.get("type") == "traffic" and e.get("action") in COMMUNICATED and e.get("srcintfrole") == "wan":
            port = _int(e, "dstport")
            if port in risky and e.get("action") == "accept":
                groups[(e["srcip"], e["dstip"], port)].append(e)
    out = []
    for (src, dst, port), es in groups.items():
        out.append(Incident(
            category="exposure", severity="high",
            title=f"Internet host {src} reached {risky[port]} ({port}) on {dst} - session ACCEPTED",
            techniques=["T1133"], first_seen=es[0]["_ts"], last_seen=es[-1]["_ts"], src=src, dst=f"{dst}:{port}",
            count=len(es), details={"service": risky[port], "sessions": len(es)}, evidence=_evidence(es),
            action=("Remote-access/file-sharing services should not be reachable from the internet: find the firewall policy that "
                    "allowed it (policyid in the log), confirm with the asset owner, and escalate for an emergency policy change. "
                    "Check the destination host for signs of login attempts or compromise."),
        ))
    return out


def detect_exfil(events, cfg):
    c = cfg["exfil"]
    ok_dst = set(cfg["allowlist"]["backup_destinations"])
    sums = defaultdict(lambda: {"sent": 0, "rcvd": 0, "events": []})
    for e in events:
        if (e.get("type") == "traffic" and e.get("srcintfrole") == "lan" and e.get("dstintfrole") == "wan"
                and e.get("dstip") not in ok_dst and _int(e, "sentbyte") > 0):
            s = sums[(e["srcip"], e["dstip"])]
            s["sent"] += _int(e, "sentbyte")
            s["rcvd"] += _int(e, "rcvdbyte")
            s["events"].append(e)
    out = []
    for (src, dst), s in sums.items():
        ratio = s["sent"] / s["rcvd"] if s["rcvd"] else float("inf")
        if s["sent"] < c["min_bytes"] or ratio < c["min_ratio"]:
            continue
        mib = s["sent"] / (1024 * 1024)
        out.append(Incident(
            category="exfiltration",
            severity="high" if s["sent"] >= c["min_bytes"] * c["high_multiplier"] else "medium",
            title=f"Unusual upload volume: {src} sent {mib:,.0f} MiB to external {dst}",
            techniques=["T1048"], first_seen=s["events"][0]["_ts"], last_seen=s["events"][-1]["_ts"], src=src, dst=dst,
            count=len(s["events"]),
            details={"sent_mib": round(mib, 1), "received_mib": round(s["rcvd"] / (1024 * 1024), 3),
                     "upload_to_download_ratio": None if ratio == float("inf") else round(ratio, 1)},
            evidence=_evidence(s["events"]),
            action=("Check whether the user/host has a legitimate reason (backup, cloud sync, file share) and whether the destination is "
                    "approved. If not, contact the asset owner, consider blocking the destination, and escalate as possible data exfiltration."),
        ))
    return out


def detect_ips(events, cfg):
    wanted = set(cfg["ips"]["severities"])
    groups = defaultdict(list)
    for e in events:
        if e.get("type") == "utm" and e.get("subtype") == "ips" and e.get("severity", "").lower() in wanted:
            groups[(e.get("attack", "?"), e.get("srcip", "?"))].append(e)
    out = []
    for (attack, src), es in groups.items():
        sev_log = es[0].get("severity", "").lower()
        blocked = all(e.get("action", "").lower() in BLOCKED for e in es)
        if sev_log == "critical":
            sev = "medium" if blocked else "critical"
        else:
            sev = "low" if blocked else "high"
        out.append(Incident(
            category="ips", severity=sev,
            title=f"IPS: {attack} from {src} ({'blocked' if blocked else 'NOT blocked'}, vendor severity {sev_log})",
            techniques=["T1190"], first_seen=es[0]["_ts"], last_seen=es[-1]["_ts"], src=src, dst=es[0].get("dstip", "?"),
            count=len(es), details={"attack": attack, "blocked": blocked, "vendor_severity": sev_log}, evidence=_evidence(es),
            action=("Blocked by the firewall: record it, check the source reputation, and watch for the same source reaching other services."
                    if blocked else
                    "The attack was detected but not blocked: check the target host's logs for exploitation, confirm the signature action "
                    "in the IPS profile, and escalate to L2 for possible compromise."),
        ))
    return out


def detect_malware(events, cfg):
    out = []
    # 1) antivirus detections: group by the affected internal host
    av = defaultdict(list)
    for e in events:
        if e.get("type") == "utm" and e.get("subtype") == "virus" and e.get("virus"):
            host = e.get("dstip") if e.get("direction") == "incoming" else e.get("srcip")
            av[(host, e["virus"])].append(e)
    for (host, virus), es in av.items():
        blocked = all(e.get("action", "").lower() in BLOCKED for e in es)
        out.append(Incident(
            category="malware", severity="high" if blocked else "critical",
            title=f"Malware signature {virus} on/for host {host} ({'blocked' if blocked else 'NOT blocked'})",
            techniques=["T1204"], first_seen=es[0]["_ts"], last_seen=es[-1]["_ts"], src=host, dst=es[0].get("srcip", "?"),
            count=len(es), details={"virus": virus, "blocked": blocked}, evidence=_evidence(es),
            action=("Blocked at the gateway, but the host tried to fetch malware: identify the user, check the endpoint AV/EDR for the "
                    "same family and for the file on disk, and review how the download was triggered (phishing link, browsing)."
                    if blocked else
                    "Malware was not blocked: isolate the endpoint, collect the file hash, and escalate to L2 for incident response."),
        ))
    # 2) traffic to known-bad destinations (threat-intel blocklist)
    bad = set(cfg.get("blocklist", []))
    groups = defaultdict(list)
    for e in events:
        if e.get("type") == "traffic" and e.get("dstip") in bad and e.get("srcintfrole") in ("lan", "dmz"):
            groups[(e["srcip"], e["dstip"])].append(e)
    for (src, dst), es in groups.items():
        talked = [e for e in es if e.get("action") in COMMUNICATED]
        out.append(Incident(
            category="c2", severity="critical" if talked else "medium",
            title=(f"Internal host {src} COMMUNICATED with known-bad {dst}" if talked
                   else f"Internal host {src} attempted contact with known-bad {dst} (denied)"),
            techniques=["T1071"], first_seen=es[0]["_ts"], last_seen=es[-1]["_ts"], src=src, dst=dst, count=len(es),
            details={"sessions_allowed": len(talked), "attempts_denied": len(es) - len(talked),
                     "distinct_ports": sorted({e.get("dstport") for e in es})},
            evidence=_evidence(es),
            action=("Possible command-and-control: isolate the host, capture memory/disk per procedure, block the destination, "
                    "and escalate to L2/IR now." if talked else
                    "The connection was denied, but the host is trying to reach a known-bad address: check the endpoint for malware "
                    "and look for other destinations the host contacted."),
        ))
    return out


DETECTORS = [detect_scan, detect_bruteforce, detect_exposure, detect_exfil, detect_ips, detect_malware]
