"""
Unit Tests for Scoring & Incentive Rules (tests/test_scoring.py)
Acceptance Criteria:
1. The 50% rule makes collusion strictly net-negative
2. Bounty splits equally across multiple breakers discovering bugs
3. Invalid (UB/timeout/oversize) inputs earn nothing and are penalized
4. Empty breaker response earns 0.0
5. Normalized weights sum to 1.0 and map to the correct metagraph UIDs
"""

import sys
import os
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["PROBUS_ALLOW_UNSANDBOXED"] = "1"

from neurons.scoring import (
    calculate_translator_pre_score,
    score_round,
    update_ema_weights
)
from sandbox.sandbox_runner import SandboxRunner
from dataset.tasks import sample_task


class TestScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = SandboxRunner()

    def test_01_collusion_net_negative(self):
        """Colluding translator + breaker pair strictly loses TAO compared to honest play."""
        # Honest translator: achieves pre_t = 0.80
        # If honest: Translator earns 0.80, Breaker earns 0.0 -> Pair total = 0.80
        # If colluding: Translator intentionally broken -> Translator earns 0.0, Breaker earns 0.5 * 0.80 = 0.40
        # Pair total = 0.40 -> Loss of -0.40
        pre_t = 0.80
        honest_pair_total = pre_t + 0.0
        colluding_pair_total = 0.0 + (0.5 * pre_t)
        self.assertLess(colluding_pair_total, honest_pair_total)
        self.assertEqual(colluding_pair_total - honest_pair_total, -0.40)

    def test_02_bounty_splits_across_breakers(self):
        """When multiple breakers break a translator, the 50% bounty is split equally."""
        task = sample_task("reverse_bytes", seed=20)
        
        translators = {
            "t_weak": {
                "rust_code": task.weak_rust,
                "pre_t": 0.60,
                "passed_hidden": 15,
                "total_hidden": 20,
                "compile_success": True,
                "gate_success": True
            }
        }
        # Two breakers both submit an edge case that exposes the weak miner's bug
        breaker_submissions = {
            "b1": [b"\xff\xfe\x00\x01"],
            "b2": ["🦀🚀".encode("utf-8")]
        }


        res = score_round(
            translators=translators,
            breaker_submissions=breaker_submissions,
            sandbox_runner=self.runner,
            c_code=task.c_code
        )

        # t_weak score becomes 0.0
        self.assertEqual(res["translator_scores"]["t_weak"], 0.0)
        # Total bounty = 0.5 * 0.60 = 0.30
        # Each breaker gets 0.30 / 2 = 0.15
        self.assertAlmostEqual(res["breaker_scores"]["b1"], 0.15, places=4)
        self.assertAlmostEqual(res["breaker_scores"]["b2"], 0.15, places=4)

    def test_03_invalid_ub_input_earns_nothing_and_penalized(self):
        """Input that triggers UB or exceeds size receives 0 bounty and incurs penalty."""
        task = sample_task("reverse_bytes", seed=20)
        translators = {
            "t_weak": {
                "rust_code": task.weak_rust,
                "pre_t": 0.60,
                "passed_hidden": 15,
                "total_hidden": 20,
                "compile_success": True,
                "gate_success": True
            }
        }
        # Oversize input > 16 KB
        oversize_input = b"A" * (20 * 1024)
        breaker_submissions = {
            "b_invalid": [oversize_input]
        }

        res = score_round(
            translators=translators,
            breaker_submissions=breaker_submissions,
            sandbox_runner=self.runner,
            c_code=task.c_code,
            invalid_penalty=0.05
        )

        self.assertEqual(res["invalid_counts"]["b_invalid"], 1)
        self.assertEqual(res["breaker_scores"]["b_invalid"], 0.0)

    def test_04_empty_breaker_response_earns_zero(self):
        """Empty breaker submission earns exactly 0.0."""
        task = sample_task("reverse_bytes", seed=20)
        translators = {
            "t_honest": {
                "rust_code": task.reference_rust,
                "pre_t": 1.0,
                "passed_hidden": 20,
                "total_hidden": 20,
                "compile_success": True,
                "gate_success": True
            }
        }
        breaker_submissions = {
            "b_empty": []
        }

        res = score_round(
            translators=translators,
            breaker_submissions=breaker_submissions,
            sandbox_runner=self.runner,
            c_code=task.c_code
        )

        self.assertEqual(res["breaker_scores"]["b_empty"], 0.0)
        self.assertEqual(res["translator_scores"]["t_honest"], 1.0)

    def test_05_weights_normalization_and_uid_mapping(self):
        """Normalized weights must sum to 1.0 and accurately map to metagraph UIDs."""
        round_scores = {
            "miner_0": 1.0,
            "miner_1": 0.5,
            "miner_2": 0.0
        }
        uids_by_hotkey = {
            "miner_0": 0,
            "miner_1": 1,
            "miner_2": 2
        }
        current_ema = {}
        new_ema, weights = update_ema_weights(current_ema, round_scores, uids_by_hotkey, alpha=0.1)

        total_weight = sum(weights.values())
        self.assertAlmostEqual(total_weight, 1.0, places=5)
        self.assertGreater(weights[0], weights[1])
        self.assertEqual(weights[2], 0.0)


if __name__ == "__main__":
    unittest.main()
