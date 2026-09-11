"""
Unit Test for Breaker Miner (tests/test_breaker.py)
Verifies adversarial edge-case input generation (boundary values, null bytes, unicode).
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from neurons.miner_breaker import BreakerMiner, parse_args
from protocol import BreakerSynapse


def test_breaker_miner():
    print("\n--- Testing Breaker Miner Adversarial Input Generation ---")
    args = parse_args()
    args.wallet_hotkey = "test_breaker"
    breaker = BreakerMiner(args)

    with open("dataset/sample_c_code.c", "r", encoding="utf-8") as f:
        c_code = f.read()

    sample_rust = "pub fn solution(s: &str) -> String { s.chars().rev().collect() }"

    syn = BreakerSynapse(
        c_code=c_code,
        rust_code=sample_rust,
        function_name="reverse_string",
        num_inputs_requested=8
    )
    resp = breaker.forward(syn)

    assert len(resp.test_inputs) >= 5, f"Expected at least 5 adversarial inputs, got {len(resp.test_inputs)}"
    assert "" in resp.test_inputs, "Must test empty string"
    assert "\x00" in resp.test_inputs, "Must test null-byte boundary"
    assert any(ord(c) > 127 for item in resp.test_inputs for c in str(item)), "Must test unicode / emojis"

    print(f"--> Breaker successfully generated {len(resp.test_inputs)} adversarial inputs:")
    for idx, inp in enumerate(resp.test_inputs):
        print(f"    [{idx+1}] {repr(inp)}")
    print(f"--> Rationale: {resp.divergence_rationale}")
    print("\n[SUCCESS] Breaker miner tests passed!")


if __name__ == "__main__":
    test_breaker_miner()
