"""Run the complete relslice test suite under isolated Python."""

import os
import subprocess
import sys

TESTS = [
    "test_basic.py",
    "test_hand_root.py",
    "test_attacks.py",
    "test_edge.py",
    "test_tamper_db.py",
    "test_malformed.py",
    "test_selfcheck.py",
    "test_cli.py",
]

HERE = os.path.dirname(os.path.abspath(__file__))
failures = 0
for name in TESTS:
    proc = subprocess.run(
        [sys.executable, "-I", os.path.join(HERE, name)],
        capture_output=True,
        text=True,
    )
    tail = proc.stdout.strip().splitlines()
    summary = tail[-1] if tail else "(no output)"
    print(f"{name:24s} rc={proc.returncode}  {summary}")
    if proc.returncode != 0:
        failures += 1
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
print()
print("ALL PASS" if failures == 0 else f"{failures} SUITE(S) FAILED")
sys.exit(1 if failures else 0)
