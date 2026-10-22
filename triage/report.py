import json
from collections import Counter

from .models import SEV_ORDER


def rank(incidents):
    """Order by severity (highest first), then time; assign stable ticket ids."""
    incidents = sorted(incidents, key=lambda i: (-SEV_ORDER[i.severity], i.first_seen, i.category, i.src))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{inc.first_seen:%Y%m%d}-{n:03d}"
    return incidents


def to_json(incidents, meta):
    def one(i):
        return {"id": i.id, "category": i.category, "severity": i.severity, "title": i.title, "mitre": i.techniques,
                "first_seen": i.first_seen.isoformat(sep=" "), "last_seen": i.last_seen.isoformat(sep=" "),
                "src": i.src, "dst": i.dst, "event_count": i.count, "details": i.details,
                "recommended_action": i.action, "evidence": i.evidence}
    return json.dumps({"meta": meta, "incidents": [one(i) for i in incidents]}, indent=2, sort_keys=True)


def to_markdown(incidents, meta):
    sev = Counter(i.severity for i in incidents)
    cat = Counter(i.category for i in incidents)
    lines = [
        "# Security Log Triage Report", "",
        f"- Input files: {', '.join(meta['files'])}",
        f"- Events parsed: {meta['events']:,} (malformed lines skipped: {meta['malformed']})",
        f"- Incidents raised: {len(incidents)}  "
        f"(critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']})", "",
        "## Queue (work top to bottom)", "",
        "| Ticket | Severity | Category | First seen | Source | Summary |", "|---|---|---|---|---|---|",
    ]
    for i in incidents:
        lines.append(f"| {i.id} | {i.severity.upper()} | {i.category} | {i.first_seen:%Y-%m-%d %H:%M:%S} | {i.src} | {i.title} |")
    lines += ["", "## Incident tickets", ""]
    for i in incidents:
        lines += [
            f"### {i.id} - {i.severity.upper()} - {i.title}", "",
            f"- **Category:** {i.category}   **MITRE ATT&CK (indicative):** {', '.join(i.techniques)}",
            f"- **Window:** {i.first_seen:%Y-%m-%d %H:%M:%S} to {i.last_seen:%H:%M:%S}   **Events:** {i.count}",
            f"- **Source:** {i.src}   **Target:** {i.dst}",
            f"- **Details:** {json.dumps(i.details, sort_keys=True)}",
            f"- **Recommended L1 action:** {i.action}", "", "Evidence (first log lines):", "", "```",
            *i.evidence, "```", "",
        ]
    lines += ["---", f"Categories: {dict(sorted(cat.items()))}", ""]
    return "\n".join(lines)
