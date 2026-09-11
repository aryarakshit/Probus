"""
Anti-Cheat Verification Suite (scripts/verify_anti_cheat.py)
Tests and verifies all 3 critical anti-cheat barriers:
1. The "Unsafe" Test: Rust code containing `unsafe` -> immediate hard gate reject (< 1s, Score 0.0).
2. The "Interpreter" Test: Rust code calling `std::process::Command` -> hard gate reject.
3. The "Backdoor Libc" Test: Rust code calling `libc::` or external C FFI -> hard gate reject.
4. The "Formula" Test: Verifies squared pass rate, safety penalty, and speed bonus cap.
"""

import sys
import os
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.validator import static_analysis_gate, calculate_score


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
    t_start = time.time()
    passed, reason = static_analysis_gate(code_with_unsafe)
    elapsed = time.time() - t_start
    score, breakdown = calculate_score(0.0, has_unsafe=True, actual_time=elapsed)

    print(f"  Result: Passed={passed}, Reason='{reason}'")
    print(f"  Elapsed: {elapsed:.4f}s (< 1.0s threshold)")
    print(f"  Final Score: {score}")

    assert not passed, "FAILED: Code with unsafe MUST be rejected!"
    assert elapsed < 1.0, f"FAILED: Gate took {elapsed}s, must be < 1.0s"
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
    score, _ = calculate_score(0.0, has_unsafe=True, actual_time=0.1)

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
    print("\n[TEST 4] Testing Squared Pass-Rate Scoring Formula...")
    # Perfect pass (1.0) with fast time (2.0s vs 10.0s max) -> (1.0)^2 * 1.0 * min(1.2, 1.0 + 8/10*0.2) = 1.0 * 1.16 = 1.16
    score_honest, bd_honest = calculate_score(pass_rate=1.0, has_unsafe=False, actual_time=2.0)
    print(f"  Honest (100% pass): Final={score_honest} (Breakdown: {bd_honest})")
    assert score_honest > 1.0, f"Honest score should have speed bonus, got {score_honest}"

    # Weak pass (40% pass) -> (0.40)^2 * 1.0 * 1.0 = 0.16
    score_weak, bd_weak = calculate_score(pass_rate=0.40, has_unsafe=False, actual_time=10.0)
    print(f"  Weak (40% pass): Final={score_weak} (Breakdown: {bd_weak})")
    assert round(score_weak, 2) == 0.16, f"Expected 0.16, got {score_weak}"

    # Cheater (with unsafe penalty) -> 0.0
    score_cheater, bd_cheater = calculate_score(pass_rate=1.0, has_unsafe=True, actual_time=0.5)
    print(f"  Cheater (unsafe penalty): Final={score_cheater} (Breakdown: {bd_cheater})")
    assert score_cheater == 0.0, f"Expected 0.0, got {score_cheater}"

    print("  --> [PASS] Scoring formula verified mathematically.")


def main():
    print("==================================================")
    print("  RUNNING STATIC ANALYSIS & ANTI-CHEAT TEST SUITE ")
    print("==================================================")
    test_unsafe_rejection()
    test_interpreter_rejection()
    test_libc_rejection()
    test_scoring_formula()
    print("\n==================================================")
    print("  ALL ANTI-CHEAT HARD GATES PASSED VERIFICATION!  ")
    print("==================================================")


if __name__ == "__main__":
    main()
