"""
Unit Test for Translator Miner (tests/test_miner_translation.py)
Verifies that translator generates valid Safe Rust and filters unsafe code.
"""

import sys
import os
import re

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.miner_translator import TranslatorMiner, parse_args
from protocol import TranslationSynapse


def test_honest_translation():
    print("\n--- Testing Honest Translator Miner ---")
    args = parse_args()
    args.mode = "honest"
    args.wallet_hotkey = "test_honest"
    miner = TranslatorMiner(args)
    
    with open("dataset/sample_c_code.c", "r", encoding="utf-8") as f:
        c_code = f.read()

    syn = TranslationSynapse(c_code=c_code, function_name="reverse_string")
    resp = miner.forward(syn)
    
    assert resp.rust_code is not None, "Rust code must not be None"
    assert "pub fn solution" in resp.rust_code, "Must contain solution entrypoint"
    assert not re.search(r"\bunsafe\s*\{", resp.rust_code), "Safe Rust must NOT contain unsafe blocks"
    assert "#![forbid(unsafe_code)]" in resp.rust_code, "Must declare forbid(unsafe_code)"
    print("--> Honest Miner output successfully verified as 100% Safe Rust:")
    print(resp.rust_code)


def test_cheater_translation():
    print("\n--- Testing Cheater Miner ---")
    args = parse_args()
    args.mode = "cheater"
    args.wallet_hotkey = "test_cheater"
    miner = TranslatorMiner(args)

    with open("dataset/sample_c_code.c", "r", encoding="utf-8") as f:
        c_code = f.read()

    syn = TranslationSynapse(c_code=c_code, function_name="reverse_string")
    resp = miner.forward(syn)
    assert "unsafe" in resp.rust_code, "Cheater code should contain unsafe for anti-cheat verification"
    print("--> Cheater Miner output confirmed (contains prohibited unsafe block).")


if __name__ == "__main__":
    test_honest_translation()
    test_cheater_translation()
    print("\n[SUCCESS] Miner translation tests passed!")
