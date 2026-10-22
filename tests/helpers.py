import copy
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from datetime import datetime, timedelta  # noqa: E402

from tools.gen_logs import Gen, fmt  # noqa: E402
from triage import load_config  # noqa: E402
from triage.parser import parse_line  # noqa: E402

T0 = datetime(2026, 10, 20, 12, 0, 0)


def cfg():
    return copy.deepcopy(load_config())


def parse_rows(gen):
    """Turn what a Gen built into parsed events, going through the real text format and parser."""
    gen.rows.sort(key=lambda x: x[0])
    return [parse_line(fmt(rec)) for _, rec in gen.rows]


def new():
    return Gen(seed=1)


def sec(n):
    return T0 + timedelta(seconds=n)
