"""FortiGate-format log triage: parse firewall logs, raise prioritised incident tickets."""
import json
import os

from .detectors import DETECTORS
from .parser import parse_files
from .report import rank, to_json, to_markdown

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "config.json")


def load_config(path=None):
    with open(path or DEFAULT_CONFIG, "r", encoding="utf-8") as fh:
        return json.load(fh)


def analyse(events, cfg):
    incidents = []
    for det in DETECTORS:
        incidents.extend(det(events, cfg))
    return rank(incidents)


def run(paths, cfg=None):
    cfg = cfg or load_config()
    events, malformed = parse_files(paths)
    incidents = analyse(events, cfg)
    meta = {"files": [os.path.basename(p) for p in paths], "events": len(events), "malformed": malformed}
    return incidents, meta
