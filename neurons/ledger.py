"""
Verified translation ledger (neurons/ledger.py).

Every validation round leaves a tamper-evident record behind:

  ledger/objects/<sha256>      content-addressed artifacts: the C source, every
                               Rust submission, every valid breaker reproducer
  ledger/rounds/<id>.json      the round record - hashes of the artifacts above,
                               per-submission verdicts, scores and weights
  ledger/chain.jsonl           one line per round: merkle root over the record's
                               leaves, chained to the previous root

The merkle root commits to the whole round; the chain commits to the order.
`scripts/verify_ledger.py` recomputes everything from the objects and fails on
any edit. This is the "continuously generated, verified C-to-Rust dataset" the
subnet exists to produce: (C, Safe Rust, verdict, adversarial inputs) tuples
anyone can audit, not a claim in a README.
"""

import os
import json
import time
import hashlib
from typing import Dict, Any, List, Optional

LEDGER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ledger"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def merkle_root(leaves: List[str]) -> str:
    """Binary merkle tree over hex leaf hashes (last node duplicated on odd levels)."""
    if not leaves:
        return sha256_bytes(b"")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


class Ledger:
    def __init__(self, root: Optional[str] = None):
        self.root = root or LEDGER_DIR
        self.objects = os.path.join(self.root, "objects")
        self.rounds = os.path.join(self.root, "rounds")
        self.chain_path = os.path.join(self.root, "chain.jsonl")
        os.makedirs(self.objects, exist_ok=True)
        os.makedirs(self.rounds, exist_ok=True)

    # --------------------------------------------------------------- objects
    def put(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        path = os.path.join(self.objects, digest)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
        return digest

    def get(self, digest: str) -> Optional[bytes]:
        path = os.path.join(self.objects, digest)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    # ---------------------------------------------------------------- chain
    def last_root(self) -> str:
        if not os.path.exists(self.chain_path):
            return "0" * 64
        last = None
        with open(self.chain_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)
        return last["root"] if last else "0" * 64

    def next_height(self) -> int:
        if not os.path.exists(self.chain_path):
            return 1
        with open(self.chain_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip()) + 1

    @staticmethod
    def leaves_of(record: Dict[str, Any]) -> List[str]:
        """Deterministic leaf order: task, C, each submission, each reproducer, scores."""
        leaves = [sha256_bytes(canonical({"task": record["task"], "constants": record["constants"], "hidden_tests": record["hidden_tests"]}))]
        leaves.append(record["c_sha256"])
        for sub in sorted(record["submissions"], key=lambda s: s["hotkey"]):
            leaves.append(sha256_bytes(canonical(sub)))
        for rep in sorted(record["reproducers"], key=lambda r: (r["translator"], r["breaker"], r["input_sha256"])):
            leaves.append(sha256_bytes(canonical(rep)))
        leaves.append(sha256_bytes(canonical({"scores": record["scores"], "weights": record["weights"]})))
        return leaves

    def commit(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Store a round record, append its root to the chain, return the chain entry."""
        height = self.next_height()
        prev = self.last_root()
        record = dict(record)
        record["height"] = height
        record["prev_root"] = prev
        root = merkle_root(self.leaves_of(record))
        record["root"] = root
        with open(os.path.join(self.rounds, f"{height:06d}.json"), "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, sort_keys=True)
        entry = {"height": height, "root": root, "prev_root": prev, "task": record["task"],
                 "timestamp": record.get("timestamp", time.time()), "chained": sha256_bytes((prev + root).encode())}
        with open(self.chain_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    # ---------------------------------------------------------------- verify
    def verify(self) -> Dict[str, Any]:
        """Recompute every root from stored objects and records. Returns a report."""
        problems: List[str] = []
        entries: List[Dict[str, Any]] = []
        if os.path.exists(self.chain_path):
            with open(self.chain_path, "r", encoding="utf-8") as f:
                entries = [json.loads(l) for l in f if l.strip()]
        prev = "0" * 64
        objects_checked = 0
        for entry in entries:
            path = os.path.join(self.rounds, f"{entry['height']:06d}.json")
            if not os.path.exists(path):
                problems.append(f"height {entry['height']}: record missing"); continue
            with open(path, "r", encoding="utf-8") as f:
                rec = json.load(f)
            if rec.get("prev_root") != prev or entry.get("prev_root") != prev:
                problems.append(f"height {entry['height']}: chain break (expected prev {prev[:12]})")
            root = merkle_root(self.leaves_of(rec))
            if root != rec.get("root") or root != entry.get("root"):
                problems.append(f"height {entry['height']}: merkle root mismatch")
            digests = [rec["c_sha256"]] + [s["rust_sha256"] for s in rec["submissions"]] + [r["input_sha256"] for r in rec["reproducers"]]
            for digest in digests:
                if digest is None:          # a miner that returned nothing has no object to check
                    continue
                blob = self.get(digest)
                if blob is None:
                    problems.append(f"height {entry['height']}: object {digest[:12]} missing")
                elif sha256_bytes(blob) != digest:
                    problems.append(f"height {entry['height']}: object {digest[:12]} corrupted")
                else:
                    objects_checked += 1
            prev = entry.get("root", root)
        return {"ok": not problems, "rounds": len(entries), "objects_checked": objects_checked,
                "head": prev, "problems": problems}

    def stats(self) -> Dict[str, Any]:
        entries = 0
        if os.path.exists(self.chain_path):
            with open(self.chain_path, "r", encoding="utf-8") as f:
                entries = sum(1 for l in f if l.strip())
        n_objects = len(os.listdir(self.objects)) if os.path.exists(self.objects) else 0
        return {"rounds": entries, "objects": n_objects, "head": self.last_root()}
