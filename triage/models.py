from dataclasses import dataclass, field
from datetime import datetime

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Incident:
    category: str          # scan | bruteforce | exposure | exfiltration | ips | malware | c2
    severity: str          # critical | high | medium | low
    title: str
    techniques: list       # indicative MITRE ATT&CK technique ids
    first_seen: datetime
    last_seen: datetime
    src: str               # attacker / affected host (see per-detector notes)
    dst: str
    count: int             # number of log events behind the incident
    details: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)   # a few raw log lines
    action: str = ""       # recommended L1 action
    id: str = ""
