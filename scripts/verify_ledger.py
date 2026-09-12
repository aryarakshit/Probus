"""
Independent ledger audit (scripts/verify_ledger.py)

Recomputes every merkle root from the content-addressed objects and round
records, checks the chain of prev_root links, and exits non-zero on any
discrepancy. Anyone holding a copy of ledger/ can run this without trusting
the validator that produced it.

    python scripts/verify_ledger.py [--ledger ledger] [--show 3]
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from neurons.ledger import Ledger


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=None, help="ledger directory (default: ./ledger)")
    ap.add_argument("--show", type=int, default=2, help="print the last N round records")
    args = ap.parse_args()

    ledger = Ledger(args.ledger)
    report = ledger.verify()
    print(f"ledger : {ledger.root}")
    print(f"rounds : {report['rounds']}   objects verified: {report['objects_checked']}")
    print(f"head   : {report['head']}")
    if report["problems"]:
        print("\nPROBLEMS:")
        for p in report["problems"]:
            print("  -", p)
        print("\nVERIFICATION FAILED")
        sys.exit(1)

    if args.show and report["rounds"]:
        files = sorted(os.listdir(ledger.rounds))[-args.show:]
        for fname in files:
            with open(os.path.join(ledger.rounds, fname), encoding="utf-8") as f:
                rec = json.load(f)
            print(f"\n-- height {rec['height']}  task={rec['task']} {rec['constants']}  root={rec['root'][:16]}…")
            for s in rec["submissions"]:
                flag = "BROKEN by " + ",".join(s["broken_by"]) if s["broken_by"] else ("gate-reject" if not s["gate"] else "ok")
                print(f"   {s['hotkey']:<22} rust={str(s['rust_sha256'])[:12]} hidden={s['passed_hidden']}/{s['total_hidden']} final={s['final']:.3f} {flag}")
            for r in rec["reproducers"][:3]:
                blob = ledger.get(r["input_sha256"]) or b""
                print(f"   reproducer {r['input_sha256'][:12]} {r['input_len']}B {blob[:32]!r} -> {r['translator']} ({r['reason']})")
    print("\nVERIFICATION OK")


if __name__ == "__main__":
    main()
