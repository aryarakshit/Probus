"""
Task pool tests (tests/test_tasks.py): every task is UB-free, portable, and its
fixtures are wired correctly. This is the CI proof that the *validator's* side of
the contract is sound before any miner is judged against it.
"""

import os
import sys
import random
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")

from dataset.tasks import sample_task, list_tasks, infer_task, build_task, TASK_DESCRIPTIONS
from dataset.hidden_tests import generate_raw_hidden_tests
from neurons.difffuzz import LocalDiff, default_seeds


class TestTaskPool(unittest.TestCase):
    def test_01_registry(self):
        names = list_tasks()
        self.assertGreaterEqual(len(names), 8)
        for n in names:
            self.assertIn(n, TASK_DESCRIPTIONS)

    def test_02_infer_roundtrip(self):
        for name in list_tasks():
            t = sample_task(name, seed=17)
            got_name, consts = infer_task(t.c_code)
            self.assertEqual(got_name, name)
            self.assertEqual(consts, t.constants)
            stamp = "// probus-task: " + name + "\n"
            self.assertEqual(build_task(name, consts).c_code.replace(stamp, ""), t.c_code.replace(stamp, ""))

    def test_03_every_task_is_sound(self):
        """C builds under ASan/UBSan, reference Rust is byte-exact, weak Rust is genuinely different."""
        for name in list_tasks():
            t = sample_task(name, seed=5)
            with LocalDiff(t.c_code) as d:
                self.assertIsNotNone(d.c_bin, f"{name}: {d.c_error}")
                inputs = generate_raw_hidden_tests(30, seed=5) + default_seeds(t.c_code)
                clean = d.is_clean(inputs)
                self.assertGreaterEqual(sum(clean), len(inputs) - 2, f"{name}: sanitizer rejects hidden inputs")
                valid = [i for i, ok in zip(inputs, clean) if ok]
                self.assertTrue(d.build_rust(t.reference_rust), f"{name} reference: {d.rust_error[:500]}")
                self.assertEqual(d.compare(valid), [], f"{name}: reference diverges")
                self.assertTrue(d.build_rust(t.weak_rust), f"{name} weak: {d.rust_error[:500]}")
                # the breaker sees both sources, so seed from both (crc32's bug hides behind a Rust constant)
                hits = d.fuzz(default_seeds(t.c_code, t.weak_rust), budget_s=6, rng=random.Random(5), want=1, minimize=False)
                self.assertGreater(len(hits), 0, f"{name}: weak fixture is not actually weak")


if __name__ == "__main__":
    unittest.main()
