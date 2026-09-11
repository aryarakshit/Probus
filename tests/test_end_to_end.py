"""
Master End-to-End Test Suite for C-to-Safe-Rust Subnet (tests/test_end_to_end.py)
Validates all phases, static gate hard stops, sandbox fuzzing, breaker scoring, and weight emissions.
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

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from dataset.hidden_tests import generate_hidden_tests
from sandbox.sandbox_runner import SandboxRunner
from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, static_analysis_gate, calculate_score, parse_args as parse_val_args


class TestC2RustSubnet(unittest.TestCase):

    def test_01_static_analysis_hard_gates(self):
        """Verify strict static gates block unsafe, process commands, libc, and pass safe code."""
        unsafe_code = 'pub fn run() { unsafe { std::ptr::null::<i32>(); } }'
        passed, reason = static_analysis_gate(unsafe_code)
        self.assertFalse(passed)
        self.assertIn("Unsafe", reason)

        proc_code = 'pub fn run() { std::process::Command::new("gcc"); }'
        passed, reason = static_analysis_gate(proc_code)
        self.assertFalse(passed)
        self.assertIn("process", reason.lower())

        libc_code = 'pub fn run() { libc::free(std::ptr::null_mut()); }'
        passed, reason = static_analysis_gate(libc_code)
        self.assertFalse(passed)
        self.assertIn("libc", reason.lower())

        safe_code = '#![forbid(unsafe_code)]\npub fn run(s: &str) -> String { s.chars().rev().collect() }'
        passed, reason = static_analysis_gate(safe_code)
        self.assertTrue(passed)
        self.assertIsNone(reason)

    def test_02_scoring_formula(self):
        """Verify squared pass-rate formula, safety penalty zeroing, and speed bonus cap."""
        # Unsafe code hard reject
        score, _ = calculate_score(pass_rate=1.0, has_unsafe=True, actual_time=1.0)
        self.assertEqual(score, 0.0)

        # Perfect safe fast pass: (1.0)^2 * 1.0 * min(1.2, 1.0 + (10 - 2)/10 * 0.2) = 1.16
        score, bd = calculate_score(pass_rate=1.0, has_unsafe=False, actual_time=2.0, max_time=10.0)
        self.assertGreater(score, 1.0)
        self.assertLessEqual(score, 1.20)

        # Weak translation: pass_rate = 0.5 -> (0.5)^2 * 1.0 * 1.0 = 0.25
        score, _ = calculate_score(pass_rate=0.5, has_unsafe=False, actual_time=10.0, max_time=10.0)
        self.assertEqual(score, 0.25)

    def test_03_hidden_test_synthesis(self):
        """Verify generation of property-based and boundary hidden tests."""
        suite = generate_hidden_tests(count=50, seed=123)
        self.assertEqual(len(suite), 50)
        self.assertIn("", suite)
        self.assertIn("Hello World", suite)

    def test_04_adversarial_breaker_generation(self):
        """Verify breaker miner generates adversarial edge cases."""
        b_args = parse_br_args([])
        b_args.wallet_hotkey = "test_breaker_unit"
        breaker = BreakerMiner(b_args)
        
        c_sample = "void rev(char *s) {}"
        rs_sample = "pub fn rev(s: &str) {}"
        syn = BreakerSynapse(c_code=c_sample, rust_code=rs_sample, function_name="rev", num_inputs_requested=10)
        resp = breaker.forward(syn)
        
        self.assertEqual(len(resp.test_inputs), 10)
        self.assertIn("\x00", resp.test_inputs)

    def test_05_validator_round_with_miners(self):
        """Verify full round execution, static gate slashing, and emission assignment."""
        v_args = parse_val_args([])
        v_args.wallet_hotkey = "unit_val"
        val = Validator(v_args)

        # Spawn honest and cheater miners
        m_h_args = parse_tr_args([])
        m_h_args.wallet_hotkey = "unit_honest"
        m_h_args.mode = "honest"
        m_honest = TranslatorMiner(m_h_args).run()

        m_c_args = parse_tr_args([])
        m_c_args.wallet_hotkey = "unit_cheater"
        m_c_args.mode = "cheater"
        m_cheater = TranslatorMiner(m_c_args).run()

        res = val.run_validation_round(
            translator_axons=[m_honest.axon, m_cheater.axon],
            breaker_axons=None,
            num_tests=20
        )

        round_results = res["round_results"]
        honest_res = next(r for r in round_results if r["hotkey"] == "unit_honest")
        cheater_res = next(r for r in round_results if r["hotkey"] == "unit_cheater")

        self.assertGreater(honest_res["score"], 1.0)
        self.assertEqual(cheater_res["score"], 0.0)
        self.assertEqual(cheater_res["status"], "REJECTED_STATIC_GATE")


if __name__ == "__main__":
    unittest.main()
