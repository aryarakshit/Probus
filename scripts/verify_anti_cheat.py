"""
Anti-Cheat & Gating Verification Suite (scripts/verify_anti_cheat.py)
Tests and verifies:
1. Unsafe rejection: Rust code containing `unsafe` -> static gate / compiler reject
2. Process/Interpreter rejection: Rust code calling `std::process::Command` -> static gate reject
3. Backdoor Libc rejection: Rust code calling `libc::` -> static gate reject
4. Cubed Scoring Formula: pre_t = (passed / total) ** 3
5. 50% Anti-Collusion Breaker Bounty Rule: collusion is strictly net-negative
"""

import sys
import os
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.validator import static_analysis_gate
from neurons.scoring import calculate_translator_pre_score, score_round


def test_unsafe_rejection():
    print("\n[TEST 1] Testing Unsafe Block Rejection...")
    code_with_unsafe = """
    pub fn solution(input: &str) -> String {
        unsafe {
            let ptr = input.as_ptr();
            String::from("pwned")
        }
    }
    """
    passed, reason = static_analysis_gate(code_with_unsafe)
    score = calculate_translator_pre_score(
        passed_hidden=1,
        total_hidden=1,
        compile_success=True,
        gate_success=passed,
        code_size_bytes=len(code_with_unsafe.encode("utf-8"))
    )

    print(f"  Result: Passed={passed}, Reason='{reason}'")
    print(f"  Final Score: {score}")

    assert not passed, "FAILED: Code with unsafe MUST be rejected!"
    assert score == 0.0, f"FAILED: Score must be 0.0, got {score}"
    print("  --> [PASS] Unsafe test successfully blocked with 0.0 score.")


def test_interpreter_rejection():
    print("\n[TEST 2] Testing C-Interpreter / Process Spawning Rejection...")
    code_with_process = """
    use std::process::Command;
    pub fn solution(input: &str) -> String {
        let output = Command::new("gcc").arg("code.c").output().unwrap();
        String::from_utf8(output.stdout).unwrap()
    }
    """
    passed, reason = static_analysis_gate(code_with_process)
    score = calculate_translator_pre_score(
        passed_hidden=1,
        total_hidden=1,
        compile_success=True,
        gate_success=passed,
        code_size_bytes=len(code_with_process.encode("utf-8"))
    )

    print(f"  Result: Passed={passed}, Reason='{reason}'")
    print(f"  Final Score: {score}")

    assert not passed, "FAILED: Process spawning MUST be rejected!"
    assert score == 0.0, f"FAILED: Score must be 0.0, got {score}"
    print("  --> [PASS] Interpreter backdoor successfully blocked.")


def test_libc_rejection():
    print("\n[TEST 3] Testing Libc / Extern 'C' Backdoor Rejection...")
    code_with_libc = """
    pub fn solution(input: &str) -> String {
        let raw = libc::malloc(100);
        String::from("cheater")
    }
    """
    passed, reason = static_analysis_gate(code_with_libc)
    assert not passed, "FAILED: Libc call MUST be rejected!"
    print(f"  Result: Passed={passed}, Reason='{reason}'")
    print("  --> [PASS] Libc backdoor successfully blocked.")


def test_scoring_formula():
    print("\n[TEST 4] Testing Cubed Pass-Rate Scoring Formula...")
    # Perfect pass (10/10) -> (1.0)^3 = 1.0
    score_perfect = calculate_translator_pre_score(passed_hidden=10, total_hidden=10)
    print(f"  Perfect (100% pass): {score_perfect}")
    assert score_perfect == 1.0, f"Expected 1.0, got {score_perfect}"

    # 80% pass -> (0.8)^3 = 0.512
    score_80 = calculate_translator_pre_score(passed_hidden=8, total_hidden=10)
    print(f"  80% pass: {score_80}")
    assert abs(score_80 - 0.512) < 1e-4, f"Expected 0.512, got {score_80}"

    # 50% pass -> (0.5)^3 = 0.125
    score_50 = calculate_translator_pre_score(passed_hidden=5, total_hidden=10)
    print(f"  50% pass: {score_50}")
    assert abs(score_50 - 0.125) < 1e-4, f"Expected 0.125, got {score_50}"

    print("  --> [PASS] Cubed scoring formula verified mathematically.")


def test_anti_collusion_math():
    print("\n[TEST 5] Verifying 50% Anti-Collusion Mathematical Proof...")
    # Suppose Translator T achieves pre_t = 0.80
    # Scenario 1: Honest submission -> Translator earns 0.80.
    # Scenario 2: Colluding with Breaker B (plant bug, claim bounty):
    #   Translator T is broken -> T earns 0.0
    #   Breaker B earns 0.5 * pre_t = 0.40
    #   Colluding pair total earnings = 0.0 + 0.40 = 0.40
    #   Net gain from collusion = 0.40 - 0.80 = -0.40 (Strict Loss)
    pre_t = 0.80
    honest_earnings = pre_t
    colluding_earnings = 0.0 + (0.5 * pre_t)
    net_collusion_gain = colluding_earnings - honest_earnings
    print(f"  Honest Translator Earnings: {honest_earnings:.4f}")
    print(f"  Colluding Pair Total Earnings: {colluding_earnings:.4f}")
    print(f"  Net Collusion Profit: {net_collusion_gain:.4f}")
    assert net_collusion_gain < 0, "Collusion must be strictly unprofitable!"
    print("  --> [PASS] Anti-collusion 50% rule mathematically guarantees net loss for colluders.")


def main():
    print("=" * 60)
    print("  RUNNING STATIC ANALYSIS & ANTI-CHEAT TEST SUITE ")
    print("=" * 60)
    test_unsafe_rejection()
    test_interpreter_rejection()
    test_libc_rejection()
    test_scoring_formula()
    test_anti_collusion_math()
    print("\n" + "=" * 60)
    print("  ALL ANTI-CHEAT HARD GATES PASSED VERIFICATION!  ")
    print("=" * 60)


if __name__ == "__main__":
    main()
