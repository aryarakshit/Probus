"""
Translator miner tests (tests/test_miner_translation.py)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tests.helpers import install_stub_llm

from neurons.miner_translator import TranslatorMiner, parse_args, extract_rust, local_static_check
from protocol import TranslationSynapse
from dataset.tasks import sample_task


class TestTranslatorMiner(unittest.TestCase):

    def test_01_miner_has_no_answer_key(self):
        """The real miner must not be able to reach the reference solution."""
        src_dir = os.path.join(os.path.dirname(__file__), "..", "neurons")
        for fname in ("miner_translator.py", "llm.py", "difffuzz.py"):
            with open(os.path.join(src_dir, fname), encoding="utf-8") as f:
                src = f.read()
            self.assertNotIn("reference_rust", src, f"{fname} references the answer key")
            self.assertNotIn("weak_rust", src, f"{fname} references a fixture")
            self.assertNotIn("sample_task", src, f"{fname} imports the task generator")

    def test_02_llm_mode_repairs_a_buggy_first_draft(self):
        stub = install_stub_llm(buggy_first=True)
        args = parse_args(["--mock", "--mode", "llm", "--self_fuzz_seconds", "3", "--wallet_hotkey", "t_llm"])
        miner = TranslatorMiner(args)
        task = sample_task("rle_encode", seed=11)
        resp = miner.forward(TranslationSynapse(c_code=task.c_code, task_name=task.task_name))
        self.assertEqual(stub.calls, 2, "self-fuzz should have rejected the first draft and asked for a repair")
        self.assertEqual(resp.repair_attempts, 2)
        self.assertIn("fn main", resp.rust_code)
        self.assertTrue(resp.rust_code.startswith("#![forbid(unsafe_code)]"))
        self.assertIn("self-test clean", resp.compiler_notes)
        self.assertTrue(miner.last_trace[0]["verdict"].startswith("Differential test"))
        self.assertEqual(miner.last_trace[1]["verdict"], "clean")

    def test_03_llm_mode_accepts_a_correct_first_draft(self):
        stub = install_stub_llm(buggy_first=False)
        args = parse_args(["--mock", "--mode", "llm", "--self_fuzz_seconds", "2", "--wallet_hotkey", "t_llm2"])
        miner = TranslatorMiner(args)
        task = sample_task("crc32", seed=3)
        resp = miner.forward(TranslationSynapse(c_code=task.c_code, task_name=task.task_name))
        self.assertEqual(stub.calls, 1)
        self.assertEqual(resp.repair_attempts, 1)

    def test_04_fixtures_track_round_constants(self):
        """weak/cheater fixtures must be rebuilt for the constants in the C the miner received."""
        args = parse_args(["--mock", "--mode", "weak", "--wallet_hotkey", "t_weak"])
        miner = TranslatorMiner(args)
        for seed in (1, 2, 3):
            task = sample_task("reverse_bytes", seed=seed)
            resp = miner.forward(TranslationSynapse(c_code=task.c_code, task_name=task.task_name))
            self.assertIn(str(task.constants["chunk_size"]), resp.rust_code)
        args.mode = "cheater"
        resp = TranslatorMiner(args).forward(TranslationSynapse(c_code=task.c_code, task_name=task.task_name))
        self.assertIn("unsafe", resp.rust_code)

    def test_05_extract_and_static_check(self):
        code = extract_rust("blah\n```rust\nfn main() {}\n```\ntrailing")
        self.assertEqual(code, "#![forbid(unsafe_code)]\nfn main() {}\n")
        self.assertFalse(local_static_check("fn main() { unsafe {} }")[0])
        self.assertFalse(local_static_check('extern "C" { fn f(); }')[0])
        self.assertTrue(local_static_check("use std::process::ExitCode; fn main() -> ExitCode { ExitCode::from(3) }")[0])


if __name__ == "__main__":
    unittest.main()
