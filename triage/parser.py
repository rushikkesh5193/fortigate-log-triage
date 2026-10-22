"""Parser for FortiGate-style key=value syslog lines.

    date=2026-10-20 time=09:14:03 devname="FGT-HQ-01" type="traffic" srcip=10.10.1.5 action="deny" ...

Values are either bare tokens or double-quoted strings (which may contain spaces and escaped quotes).
Lines without a valid date/time pair are counted as malformed and skipped rather than crashing the run.
"""
import re
from datetime import datetime

_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_UNESC = re.compile(r'\\(["\\])')


def parse_line(line):
    """Return a dict of fields (plus '_ts' datetime and '_raw'), or None if the line is not a log record."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    rec = {}
    for key, val in _KV.findall(line):
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = _UNESC.sub(r"\1", val[1:-1])
        rec[key] = val
    if "date" not in rec or "time" not in rec:
        return None
    try:
        rec["_ts"] = datetime.strptime(rec["date"] + " " + rec["time"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    rec["_raw"] = line
    return rec


def parse_files(paths):
    """Parse one or more files. Returns (events sorted by time, malformed_line_count)."""
    events, malformed = [], 0
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                rec = parse_line(line)
                if rec is None:
                    malformed += 1
                else:
                    events.append(rec)
    events.sort(key=lambda e: e["_ts"])  # stable: same-second events keep file order
    return events, malformed
