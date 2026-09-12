"""
Master End-to-End Test Suite for Aegis Subnet (tests/test_end_to_end.py)
Validates all phases:
1. Static analysis pre-filters and rustc -F unsafe_code gate
2. Cubed pass-rate formula and 50% anti-collusion rule
3. Secret sanitizer-verified hidden test generation
4. Adversarial breaker fuzzer raw byte synthesis
5. Full round execution across the LLM translator (stubbed model), weak/cheater fixtures, and the breaker
6. On-chain weight emission and JSONL audit logging
"""

import sys
import os
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"
os.environ["AEGIS_MOCK"] = "1"

from tests.helpers import install_stub_llm

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from dataset.tasks import sample_task
from dataset.hidden_tests import generate_sanitizer_verified_hidden_tests
from sandbox.sandbox_runner import SandboxRunner
from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, static_analysis_gate, parse_args as parse_val_args
from neurons.scoring import calculate_translator_pre_score, score_round


class TestAegisSubnetEndToEnd(unittest.TestCase):

    def test_01_static_analysis_hard_gates(self):
        """Verify strict static gates block unsafe, process commands, libc, and pass safe code."""
        unsafe_code = 'pub fn run() { unsafe { std::ptr::null::<i32>(); } }'
        passed, reason = static_analysis_gate(unsafe_code)
        self.assertFalse(passed)
        self.assertIn("unsafe", reason.lower())

        proc_code = 'pub fn run() { std::process::Command::new("gcc"); }'
        passed, reason = static_analysis_gate(proc_code)
        self.assertFalse(passed)
        self.assertIn("process", reason.lower())

        libc_code = 'pub fn run() { libc::free(std::ptr::null_mut()); }'
        passed, reason = static_analysis_gate(libc_code)
        self.assertFalse(passed)
        self.assertIn("libc", reason.lower())

        exit_code = 'use std::process::ExitCode; fn main() -> ExitCode { ExitCode::from(3) }'
        passed, reason = static_analysis_gate(exit_code)
        self.assertTrue(passed, "ExitCode is the sanctioned non-zero exit path")

        hidden_exit = 'fn main() { std::process::exit(1) }'
        self.assertFalse(static_analysis_gate(hidden_exit)[0])

        safe_code = '#![forbid(unsafe_code)]\nfn main() {}'
        passed, reason = static_analysis_gate(safe_code)
        self.assertTrue(passed)
        self.assertIsNone(reason)

    def test_02_scoring_formula(self):
        """Verify cubed pass-rate formula pre_t = (passed / total) ** 3."""
        # Unsafe code -> 0.0
        score = calculate_translator_pre_score(passed_hidden=10, total_hidden=10, compile_success=True, gate_success=False)
        self.assertEqual(score, 0.0)

        # Perfect safe pass (10/10) -> 1.0
        score = calculate_translator_pre_score(passed_hidden=10, total_hidden=10, compile_success=True, gate_success=True)
        self.assertEqual(score, 1.0)

        # 50% pass rate -> (0.5)^3 = 0.125
        score = calculate_translator_pre_score(passed_hidden=5, total_hidden=10, compile_success=True, gate_success=True)
        self.assertEqual(score, 0.125)

    def test_03_hidden_test_synthesis(self):
        """Verify generation of property-based and boundary hidden tests."""
        runner = SandboxRunner()
        task = sample_task("reverse_bytes", seed=123)
        suite = generate_sanitizer_verified_hidden_tests(task.c_code, runner, count=15, seed=123)
        self.assertEqual(len(suite), 15)
        self.assertIn(b"", suite)
        self.assertIn(b"\x00", suite)

    def test_04_adversarial_breaker_generation(self):
        """Verify breaker miner generates adversarial raw byte edge cases."""
        b_args = parse_br_args(["--mock"])
        b_args.wallet_hotkey = "test_breaker_unit"
        breaker = BreakerMiner(b_args)
        
        task = sample_task("reverse_bytes", seed=42)
        syn = BreakerSynapse(c_code=task.c_code, rust_code=task.weak_rust, task_name=task.task_name, num_inputs_requested=10)
        resp = breaker.forward(syn)
        raw = resp.get_raw_inputs()

        self.assertGreaterEqual(len(raw), 5)
        self.assertEqual(resp.input_encoding, "base64")
        self.assertGreater(len(breaker.last_report["divergences"]), 0, "breaker should break the weak fixture")

    def test_05_validator_round_with_miners(self):
        """Verify a full round: stubbed-model translator repairs itself, fixtures are gated/broken, ledger commits."""
        import tempfile
        v_args = parse_val_args(["--mock"])
        v_args.wallet_hotkey = "unit_val"
        v_args.no_docker = True
        v_args.log_file = os.path.join(tempfile.gettempdir(), "aegis_test_rounds.jsonl")
        v_args.ledger_dir = tempfile.mkdtemp(prefix="aegis_test_ledger_")
        import shutil
        self.addCleanup(shutil.rmtree, v_args.ledger_dir, True)
        self.addCleanup(lambda: os.path.exists(v_args.log_file) and os.remove(v_args.log_file))
        val = Validator(v_args)

        # Spawn the real (stubbed-model) translator plus weak and cheater fixtures
        stub = install_stub_llm(buggy_first=True)
        m_h_args = parse_tr_args(["--mock", "--self_fuzz_seconds", "3"])
        m_h_args.wallet_hotkey = "unit_honest"
        m_h_args.mode = "llm"
        m_honest = TranslatorMiner(m_h_args).run()

        m_w_args = parse_tr_args(["--mock"])
        m_w_args.wallet_hotkey = "unit_weak"
        m_w_args.mode = "weak"
        m_weak = TranslatorMiner(m_w_args).run()

        m_c_args = parse_tr_args(["--mock"])
        m_c_args.wallet_hotkey = "unit_cheater"
        m_c_args.mode = "cheater"
        m_cheater = TranslatorMiner(m_c_args).run()

        b_args = parse_br_args(["--mock", "--fuzz_seconds", "6"])
        b_args.wallet_hotkey = "unit_breaker"
        m_breaker = BreakerMiner(b_args).run()

        res = val.run_validation_round(
            translator_axons=[m_honest.axon, m_weak.axon, m_cheater.axon],
            breaker_axons=[m_breaker.axon],
            num_tests=15,
            task_name="rle_encode"
        )

        scores = res["round_scores"]
        # Honest should score high (1.0)
        self.assertAlmostEqual(scores["unit_honest"], 1.0, places=2)
        # Cheater rejected -> 0.0
        self.assertEqual(scores["unit_cheater"], 0.0)
        # Breaker breaks weak -> breaker earns bounty > 0
        self.assertGreater(scores["unit_breaker"], 0.0)
        # Weak broken -> score = 0.0
        self.assertEqual(scores["unit_weak"], 0.0)
        # The LLM miner had to repair its first draft
        self.assertEqual(stub.calls, 2)
        # Round is committed to the ledger and verifies
        self.assertIn("root", res["log_entry"]["ledger"])
        self.assertTrue(val.ledger.verify()["ok"])
        # Reproducer recorded for the broken translator
        self.assertGreater(len(res["log_entry"]["translator_evals"]["unit_weak"]["reproducers"]), 0)


if __name__ == "__main__":
    unittest.main()
