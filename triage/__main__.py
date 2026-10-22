import argparse
import os
import sys

from . import load_config, run
from .report import to_json, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m triage", description="Triage FortiGate-format firewall logs.")
    ap.add_argument("logs", nargs="+", help="one or more log files")
    ap.add_argument("--config", help="JSON config (thresholds, allowlists, blocklist)")
    ap.add_argument("--out-dir", default="out", help="where to write report.md and incidents.json")
    args = ap.parse_args(argv)

    for p in args.logs:
        if not os.path.isfile(p):
            print(f"error: no such file: {p}", file=sys.stderr)
            return 2
    incidents, meta = run(args.logs, load_config(args.config))
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(to_markdown(incidents, meta))
    with open(os.path.join(args.out_dir, "incidents.json"), "w", encoding="utf-8") as fh:
        fh.write(to_json(incidents, meta))
    print(f"parsed {meta['events']:,} events ({meta['malformed']} malformed) -> {len(incidents)} incidents")
    for i in incidents:
        print(f"  {i.id}  {i.severity.upper():8s} {i.title}")
    print(f"wrote {args.out_dir}/report.md and {args.out_dir}/incidents.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
