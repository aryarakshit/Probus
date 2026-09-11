"""
Unit Test for Breaker Miner (tests/test_breaker.py)
Verifies adversarial edge-case input generation (raw boundary values, null bytes, unicode).
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"
os.environ["AEGIS_MOCK"] = "1"


from neurons.miner_breaker import BreakerMiner, parse_args
from protocol import BreakerSynapse
from dataset.tasks import sample_task


def test_breaker_miner():
    print("\n--- Testing Breaker Miner Adversarial Input Generation ---")
    args = parse_args(["--mock"])
    args.wallet_hotkey = "test_breaker"
    breaker = BreakerMiner(args)

    task = sample_task("reverse_bytes", seed=42)

    syn = BreakerSynapse(
        c_code=task.c_code,
        rust_code=task.weak_rust,
        task_name=task.task_name,
        num_inputs_requested=10
    )
    resp = breaker.forward(syn)
    raw_inputs = resp.get_raw_inputs()

    assert len(raw_inputs) >= 5, f"Expected at least 5 adversarial inputs, got {len(raw_inputs)}"
    assert b"" in raw_inputs, "Must test empty input"
    assert b"\x00" in raw_inputs, "Must test null-byte boundary"
    assert any(any(b > 127 for b in item) for item in raw_inputs), "Must test non-ASCII / unicode"

    print(f"--> Breaker successfully generated {len(raw_inputs)} adversarial inputs:")
    for idx, inp in enumerate(raw_inputs):
        print(f"    [{idx+1}] {repr(inp)}")
    print(f"--> Rationale: {resp.divergence_rationale}")
    print("\n[SUCCESS] Breaker miner tests passed!")


if __name__ == "__main__":
    test_breaker_miner()
