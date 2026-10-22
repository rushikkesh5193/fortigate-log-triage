#!/usr/bin/env bash
# Generate a synthetic day of FortiGate-style logs, triage it, and run the tests.
set -eu
cd "$(dirname "$0")/.."
OUT=${OUT:-demo}
python3 tools/gen_logs.py --out "$OUT" --seed 7
python3 -m triage "$OUT/sample.log" --out-dir "$OUT/out"
echo
python3 -m unittest discover -s tests 2>&1 | tail -4
