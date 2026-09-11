"""
Unit Test for Translator Miner (tests/test_miner_translation.py)
Verifies that translator generates valid whole-program Safe Rust (fn main) and filters unsafe code.
"""

import sys
import os
import re

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"
os.environ["AEGIS_MOCK"] = "1"


from neurons.miner_translator import TranslatorMiner, parse_args
from protocol import TranslationSynapse
from dataset.tasks import sample_task


def test_honest_translation():
    print("\n--- Testing Honest Translator Miner ---")
    args = parse_args(["--mock"])
    args.mode = "honest"
    args.wallet_hotkey = "test_honest"
    miner = TranslatorMiner(args)
    
    task = sample_task("reverse_bytes", seed=42)

    syn = TranslationSynapse(c_code=task.c_code, task_name=task.task_name)
    resp = miner.forward(syn)
    
    assert resp.rust_code is not None, "Rust code must not be None"
    assert "fn main" in resp.rust_code, "Must contain whole program 'fn main()'"
    assert not re.search(r"\bunsafe\s*\{", resp.rust_code), "Safe Rust must NOT contain unsafe blocks"
    assert "#![forbid(unsafe_code)]" in resp.rust_code, "Must declare forbid(unsafe_code)"
    print("--> Honest Miner output successfully verified as 100% Safe Rust with fn main:")
    print(resp.rust_code[:200] + "...")


def test_cheater_translation():
    print("\n--- Testing Cheater Miner ---")
    args = parse_args(["--mock"])
    args.mode = "cheater"
    args.wallet_hotkey = "test_cheater"
    miner = TranslatorMiner(args)

    task = sample_task("reverse_bytes", seed=42)

    syn = TranslationSynapse(c_code=task.c_code, task_name=task.task_name)
    resp = miner.forward(syn)
    assert "unsafe" in resp.rust_code, "Cheater code should contain unsafe for anti-cheat verification"
    print("--> Cheater Miner output confirmed (contains prohibited unsafe block).")


if __name__ == "__main__":
    test_honest_translation()
    test_cheater_translation()
    print("\n[SUCCESS] Miner translation tests passed!")
