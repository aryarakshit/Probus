"""
Ledger tests (tests/test_ledger.py): merkle roots, chaining, tamper detection.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.ledger import Ledger, merkle_root, sha256_bytes


def _record(ledger: Ledger, n: int):
    c = ledger.put(f"int main(void) {{ return {n}; }}".encode())
    r = ledger.put(f"fn main() {{ /* {n} */ }}".encode())
    rep = ledger.put(bytes([n]))
    return {
        "round_id": n, "timestamp": 0, "task": "t", "constants": {"k": n},
        "c_sha256": c, "hidden_tests": {"count": 3, "digest": "00"},
        "submissions": [{"hotkey": "a", "rust_sha256": r, "gate": True, "compiled": True,
                         "passed_hidden": 3, "total_hidden": 3, "pre_t": 1.0, "final": 0.0, "broken_by": ["b"]}],
        "reproducers": [{"translator": "a", "breaker": "b", "input_sha256": rep, "input_len": 1,
                         "reason": "stdout mismatch", "c_exit": 0, "rust_exit": 0}],
        "breakers": {"b": {"submitted": 1, "score": 0.5}},
        "scores": {"a": 0.0, "b": 0.5}, "weights": {"0": 0.0, "1": 1.0}, "validator": "v",
    }


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ledger = Ledger(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_merkle_root_is_deterministic(self):
        a = [sha256_bytes(b"1"), sha256_bytes(b"2"), sha256_bytes(b"3")]
        self.assertEqual(merkle_root(a), merkle_root(list(a)))
        self.assertNotEqual(merkle_root(a), merkle_root(a[::-1]))
        self.assertEqual(len(merkle_root([])), 64)

    def test_02_commit_chains_and_verifies(self):
        e1 = self.ledger.commit(_record(self.ledger, 1))
        e2 = self.ledger.commit(_record(self.ledger, 2))
        self.assertEqual(e1["prev_root"], "0" * 64)
        self.assertEqual(e2["prev_root"], e1["root"])
        rep = self.ledger.verify()
        self.assertTrue(rep["ok"], rep)
        self.assertEqual(rep["rounds"], 2)
        self.assertEqual(rep["objects_checked"], 6)

    def test_03_no_submission_has_no_object(self):
        rec = _record(self.ledger, 1)
        rec["submissions"].append({"hotkey": "silent", "rust_sha256": None, "gate": False, "compiled": False,
                                   "passed_hidden": 0, "total_hidden": 3, "pre_t": 0.0, "final": 0.0, "broken_by": []})
        self.ledger.commit(rec)
        self.assertTrue(self.ledger.verify()["ok"])

    def test_04_tampering_is_detected(self):
        self.ledger.commit(_record(self.ledger, 1))
        path = os.path.join(self.tmp, "rounds", "000001.json")
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        rec["scores"]["a"] = 1.0          # try to award the broken translator
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        rep = self.ledger.verify()
        self.assertFalse(rep["ok"])
        self.assertTrue(any("merkle" in p for p in rep["problems"]))
        # corrupt an artifact
        obj = os.path.join(self.tmp, "objects", rec["c_sha256"])
        with open(obj, "wb") as f:
            f.write(b"int main(void) { return 0; }")
        rep = self.ledger.verify()
        self.assertTrue(any("corrupted" in p for p in rep["problems"]))


if __name__ == "__main__":
    unittest.main()
