"""
Unified miner entrypoint (neurons/miner.py)

    python neurons/miner.py --type translator --mode llm --wallet_hotkey t1 --mock
    python neurons/miner.py --type breaker --fuzz_seconds 15 --wallet_hotkey b1 --mock

Everything after --type is handed to that role's own argument parser, so the
flags documented in miner_translator.py / miner_breaker.py apply unchanged.
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.miner_translator import TranslatorMiner, parse_args as parse_translator_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_breaker_args


def main():
    parser = argparse.ArgumentParser(description="Aegis miner", add_help=False)
    parser.add_argument("--type", type=str, choices=["translator", "breaker"], default="translator",
                        help="miner role: translator (C -> Safe Rust) or breaker (adversarial fuzzer)")
    role, rest = parser.parse_known_args()

    if role.type == "breaker":
        miner = BreakerMiner(parse_breaker_args(rest))
    else:
        miner = TranslatorMiner(parse_translator_args(rest))

    miner.run()
    miner.serve_forever()


if __name__ == "__main__":
    main()
