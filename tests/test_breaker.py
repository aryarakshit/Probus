"""
Breaker miner tests (tests/test_breaker.py)

The breaker must *find* the planted bug in each weak fixture by differential
fuzzing, submit only sanitizer-clean inputs, and shrink the reproducer.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")
os.environ.setdefault("PROBUS_MOCK", "1")

from neurons.miner_breaker import BreakerMiner, parse_args
from neurons.difffuzz import LocalDiff
from protocol import BreakerSynapse
from dataset.tasks import sample_task


class TestBreakerMiner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.breaker = BreakerMiner(parse_args(["--mock", "--fuzz_seconds", "8", "--wallet_hotkey", "t_breaker"]))

    def _attack(self, task_name, seed):
        task = sample_task(task_name, seed=seed)
        syn = BreakerSynapse(c_code=task.c_code, rust_code=task.weak_rust, task_name=task.task_name, num_inputs_requested=8)
        resp = self.breaker.forward(syn)
        return task, resp, self.breaker.last_report

    def test_01_finds_planted_bugs(self):
        expectations = {
            "utf8_validate": 3,    # surrogate ED A0 80
            "leb128_decode": 6,    # overflow bits in the last byte
            "reverse_bytes": 8,    # char vs byte reversal on multibyte input
            "rle_encode": 300,     # run longer than MAX_RUN
        }
        for name, max_len in expectations.items():
            task, resp, report = self._attack(name, seed=1)
            hits = report["divergences"]
            self.assertGreater(len(hits), 0, f"{name}: breaker found no divergence")
            self.assertEqual(resp.input_encoding, "base64")
            self.assertLessEqual(hits[0]["input_len"], max_len, f"{name}: reproducer not minimized: {hits[0]}")
            self.assertIn("divergence", resp.divergence_rationale)

    def test_02_submitted_inputs_are_sanitizer_clean(self):
        task, resp, report = self._attack("kv_normalize", seed=2)
        raw = resp.get_raw_inputs()
        self.assertGreaterEqual(len(raw), 1)
        with LocalDiff(task.c_code) as d:
            self.assertTrue(all(d.is_clean(raw)), "breaker submitted an input the sanitizer build rejects")

    def test_03_correct_translation_is_not_broken(self):
        task = sample_task("base64_encode", seed=4)
        syn = BreakerSynapse(c_code=task.c_code, rust_code=task.reference_rust, task_name=task.task_name, num_inputs_requested=8)
        self.breaker.forward(syn)
        self.assertEqual(self.breaker.last_report["divergences"], [])

    def test_04_non_compiling_candidate_is_reported(self):
        task = sample_task("crc32", seed=4)
        bad = 'fn main() { let x: u32 = "no"; }'
        syn = BreakerSynapse(c_code=task.c_code, rust_code=bad, task_name=task.task_name, num_inputs_requested=4)
        resp = self.breaker.forward(syn)
        self.assertEqual(len(resp.get_raw_inputs()), 4)
        self.assertIn("does not compile", str(self.breaker.last_report["stages"]))


if __name__ == "__main__":
    unittest.main()
