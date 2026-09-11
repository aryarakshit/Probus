"""
Unified Miner Entrypoint (neurons/miner.py)
Dispatches to either Translator Miner or Breaker Miner based on CLI flags.
"""

import sys
import os
import argparse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons.miner_translator import TranslatorMiner, parse_args as parse_translator_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_breaker_args


def main():
    parser = argparse.ArgumentParser(description="Unified C-to-Safe-Rust Subnet Miner")
    parser.add_argument("--type", type=str, choices=["translator", "breaker"], default="translator",
                        help="Miner role: 'translator' (C to Safe Rust) or 'breaker' (adversarial fuzzer)")
    parser.add_argument("--netuid", type=int, default=1, help="Subnet netuid")
    parser.add_argument("--wallet_name", type=str, default="default", help="Bittensor wallet name")
    parser.add_argument("--wallet_hotkey", type=str, default="default", help="Hotkey name")
    parser.add_argument("--axon_port", type=int, default=8091, help="Port to host axon on")
    parser.add_argument("--axon_ip", type=str, default="127.0.0.1", help="IP address for axon")
    parser.add_argument("--subtensor_network", type=str, default="local", help="Network (local/finney/test)")
    parser.add_argument("--mode", type=str, default="honest", choices=["honest", "weak", "cheater", "llm"],
                        help="Translator mode (honest, weak, cheater, llm)")
    parser.add_argument("--strategy", type=str, default="adversarial_fuzz", help="Breaker strategy")
    parser.add_argument("--local_repair", action="store_true", default=True, help="Enable repair loop")
    
    args = parser.parse_args()
    
    if args.type == "breaker":
        miner = BreakerMiner(args)
    else:
        miner = TranslatorMiner(args)
        
    miner.run()


if __name__ == "__main__":
    main()
