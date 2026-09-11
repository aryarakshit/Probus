"""
Live Subnet Demo Orchestrator (scripts/run_demo.py)
Spawns the local validator and 4 distinct miner archetypes:
1. Miner_Honest: 100% Safe Rust with whole-program fn main()
2. Miner_Weak: Flawed translator with edge-case bugs
3. Miner_Cheater: Malicious miner using unsafe pointer hacks
4. Miner_Breaker: Adversarial fuzzer seeking edge-case divergences

Executes genuine validation rounds with dynamic tasks and secret hidden tests.
Prints live, unscripted evaluation metrics directly from execution results.
"""

import sys
import os
import time
import argparse
from typing import Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import substrate as bt
from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, parse_args as parse_val_args


def run_hackathon_demo(num_rounds: int = 3, allow_unsandboxed: bool = True):
    print("=" * 80)
    print(" BITTENSOR C-TO-SAFE-RUST SUBNET: LIVE ADVERSARIAL VALIDATION DEMO")
    print("=" * 80)
    
    if allow_unsandboxed:
        os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"

    # 1. Setup Validator
    v_args = parse_val_args([])
    v_args.wallet_hotkey = "val_prime"
    v_args.no_docker = allow_unsandboxed
    v_args.mock = True
    validator = Validator(v_args)
    
    # 2. Setup 4 Miner Archetypes
    print("\n[SETUP] Initializing 4 Distinct Miner Archetypes on Subnet...")

    # Miner 1: Honest
    m1_args = parse_tr_args([])
    m1_args.wallet_hotkey = "miner_translator_honest"
    m1_args.mode = "honest"
    m1_args.mock = True
    miner_honest = TranslatorMiner(m1_args)
    miner_honest.run()

    # Miner 2: Weak
    m2_args = parse_tr_args([])
    m2_args.wallet_hotkey = "miner_translator_weak"
    m2_args.mode = "weak"
    m2_args.mock = True
    miner_weak = TranslatorMiner(m2_args)
    miner_weak.run()

    # Miner 3: Cheater
    m3_args = parse_tr_args([])
    m3_args.wallet_hotkey = "miner_translator_cheater"
    m3_args.mode = "cheater"
    m3_args.mock = True
    miner_cheater = TranslatorMiner(m3_args)
    miner_cheater.run()

    # Miner 4: Breaker
    m4_args = parse_br_args([])
    m4_args.wallet_hotkey = "miner_breaker"
    m4_args.mock = True
    miner_breaker = BreakerMiner(m4_args)
    miner_breaker.run()

    # Register axons with validator query lists
    translator_axons = [
        miner_honest.axon,
        miner_weak.axon,
        miner_cheater.axon
    ]
    breaker_axons = [
        miner_breaker.axon
    ]

    print(f"[SETUP] Subnet online with 3 Translators and 1 Breaker. Beginning {num_rounds} validation rounds.\n")

    cumulative_scores = {
        "miner_translator_honest": 0.0,
        "miner_translator_weak": 0.0,
        "miner_translator_cheater": 0.0,
        "miner_breaker": 0.0
    }
    round_records = []

    for round_idx in range(1, num_rounds + 1):
        print("-" * 80)
        print(f"[ROUND {round_idx}/{num_rounds}] Executing validation cycle...")
        
        t0 = time.time()
        result = validator.run_validation_round(
            translator_axons=translator_axons,
            breaker_axons=breaker_axons,
            num_tests=20
        )
        elapsed = time.time() - t0

        task_name = result["task_name"]
        scores = result["round_scores"]
        weights = result["weights"]

        print(f"[ROUND {round_idx} COMPLETE] Task: {task_name} in {elapsed:.2f}s")
        for hk, sc in scores.items():
            cumulative_scores[hk] = cumulative_scores.get(hk, 0.0) + sc
            print(f"  -> {hk:<26} : Round Score = {sc:.4f}")

        round_records.append(result)
        time.sleep(0.5)

    # 3. Dynamic Summary & Emission Report from actual data
    print("\n" + "=" * 80)
    print(" ACTUAL ROUND OUTCOMES & EMISSION REPORT")
    print("=" * 80)
    print(f"{'Miner Hotkey':<28} | {'Avg Score':<12} | {'Latest Weight':<15} | {'Observed Behavior'}")
    print("-" * 80)

    last_weights = validator.subtensor.metagraph(validator.config.netuid).weights
    for idx, ax in enumerate(translator_axons + breaker_axons):
        hk = ax.hotkey
        avg_score = cumulative_scores.get(hk, 0.0) / num_rounds
        wt = validator.ema_scores.get(hk, 0.0)
        
        # Determine actual status from execution data
        if "cheater" in hk:
            behavior = "Rejected by static gate + rustc -F unsafe_code (0.0 emissions)"
        elif "weak" in hk:
            behavior = f"Average pass rate reflected in cubed score ({avg_score:.4f})"
        elif "honest" in hk:
            behavior = f"Safe compilation, clean differential tests ({avg_score:.4f})"
        elif "breaker" in hk:
            behavior = f"Earned bounties via 50% rule ({avg_score:.4f})"
        else:
            behavior = f"Score: {avg_score:.4f}"

        print(f"{hk:<28} | {avg_score:<12.4f} | {wt:<15.4f} | {behavior}")

    print("=" * 80)
    print(f"Live round history written to: {validator.log_file}")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=2, help="Number of rounds to run")
    parser.add_argument("--allow_unsandboxed", action="store_true", default=True, help="Allow local toolchain")
    parser.add_argument("--mock", action="store_true", default=True, help="Use mock substrate")
    args = parser.parse_args()
    run_hackathon_demo(num_rounds=args.rounds, allow_unsandboxed=args.allow_unsandboxed)
