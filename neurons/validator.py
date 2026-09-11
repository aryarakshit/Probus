"""
Validator Neuron for C-to-Safe-Rust Subnet (neurons/validator.py)
Orchestrates static analysis gating, sandboxed compilation, differential fuzzing,
adversarial breaker challenges, and the squared pass-rate scoring mechanism.
"""

import sys
import os
import re
import time
import argparse
import logging
from typing import Tuple, Dict, Any, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from sandbox.sandbox_runner import SandboxRunner
from dataset.hidden_tests import generate_hidden_tests

logger = logging.getLogger("validator")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [VALIDATOR] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)


BANNED_STATIC_PATTERNS = [
    (r"\bunsafe\b", "Hard Gate: Unsafe block or keyword detected"),
    (r"\bbuild\.rs\b", "Hard Gate: Build script reference detected"),
    (r"std::process::(Command|exit)", "Hard Gate: Process spawning or exit manipulation detected"),
    (r"\blibc::", "Hard Gate: Raw libc FFI detected"),
    (r'extern\s+"C"', "Hard Gate: External C linkage detected"),
    (r"std::fs::", "Hard Gate: Direct filesystem interaction detected"),
]


def static_analysis_gate(rust_code: str) -> Tuple[bool, Optional[str]]:
    """
    Step 1: Static Analysis Hard Gate.
    Immediately rejects untrusted code with unsafe, process manipulation, or libc backdoors.
    Execution takes < 1 second.
    """
    if not rust_code or not rust_code.strip():
        return False, "Empty or missing Rust code"

    for pattern, reason in BANNED_STATIC_PATTERNS:
        if re.search(pattern, rust_code, re.IGNORECASE):
            return False, reason

    return True, None


def calculate_score(
    pass_rate: float,
    has_unsafe: bool,
    actual_time: float,
    max_time: float = 10.0
) -> Tuple[float, Dict[str, float]]:
    """
    Step 4: Scoring Formula according to 01_ARCHITECTURE.md:
    Base Score = (Differential_Fuzz_Pass_Rate)^2
    Safety Penalty = 1.0 if 0 unsafe blocks, else 0.0 (Hard Reject)
    Speed Bonus = min(1.2, 1.0 + (Max_Allowed_Time - Actual_Time) / Max_Allowed_Time)
    Final Score = Base Score * Safety Penalty * Speed Bonus
    """
    if has_unsafe:
        return 0.0, {
            "base_score": 0.0,
            "safety_penalty": 0.0,
            "speed_bonus": 0.0,
            "final_score": 0.0
        }

    base_score = float(pass_rate) ** 2
    safety_penalty = 1.0

    if actual_time < max_time and max_time > 0:
        time_ratio = (max_time - actual_time) / max_time
        speed_bonus = min(1.2, 1.0 + max(0.0, time_ratio * 0.2))
    else:
        speed_bonus = 1.0

    final_score = base_score * safety_penalty * speed_bonus
    return round(final_score, 4), {
        "base_score": round(base_score, 4),
        "safety_penalty": safety_penalty,
        "speed_bonus": round(speed_bonus, 4),
        "final_score": round(final_score, 4)
    }


class Validator:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.dendrite = bt.dendrite(wallet=self.wallet)
        self.sandbox = SandboxRunner(force_local=config.no_docker)

        # Load benchmark C code
        c_code_path = os.path.join(os.path.dirname(__file__), "..", "dataset", "sample_c_code.c")
        if os.path.exists(c_code_path):
            with open(c_code_path, "r", encoding="utf-8") as f:
                self.sample_c_code = f.read()
        else:
            self.sample_c_code = "int main() { return 0; }"

        logger.info(f"Validator initialized on netuid={config.netuid} (Docker={self.sandbox.docker_available})")

    def run_validation_round(
        self,
        translator_axons: List[Any],
        breaker_axons: Optional[List[Any]] = None,
        num_tests: int = 50
    ) -> Dict[str, Any]:
        """
        Executes one full validation round across all miners:
        1. Queries Translator miners with C code.
        2. Applies Static Analysis Hard Gate.
        3. Queries Breaker miners for adversarial edge cases.
        4. Sandboxes, compiles, and differentially fuzzes (C vs Rust).
        5. Computes squared pass-rate scores and breaker bounties.
        """
        logger.info(f"--- Starting Validation Round (Target tests: {num_tests}) ---")
        
        # 1. Synthesize hidden test suite
        hidden_inputs = generate_hidden_tests(count=num_tests)
        
        # 2. Query Translator miners
        synapse_req = TranslationSynapse(
            c_code=self.sample_c_code,
            function_name="reverse_string",
            timeout_seconds=10.0
        )
        
        logger.info(f"Querying {len(translator_axons)} Translator miners via dendrite...")
        responses = self.dendrite.query(axons=translator_axons, synapse=synapse_req, timeout=12.0)
        
        round_results = []
        uids = []
        scores = []
        
        breaker_reports = []

        for idx, resp in enumerate(responses):
            miner_axon = translator_axons[idx]
            hotkey = getattr(miner_axon, "hotkey", f"uid_{idx}")
            rust_code = resp.rust_code or ""
            proc_time = resp.dendrite.process_time or 1.0
            
            logger.info(f"[MINER #{idx} ({hotkey})] Received {len(rust_code)} bytes of Rust code.")

            # STEP 1: Static Analysis Hard Gate
            gate_pass, reject_reason = static_analysis_gate(rust_code)
            if not gate_pass:
                logger.warning(f"[STATIC GATE REJECT] Miner {hotkey} failed hard gate: {reject_reason}")
                final_score, breakdown = calculate_score(0.0, has_unsafe=True, actual_time=proc_time)
                round_results.append({
                    "hotkey": hotkey,
                    "role": "translator",
                    "status": "REJECTED_STATIC_GATE",
                    "reason": reject_reason,
                    "pass_rate": 0.0,
                    "score": final_score,
                    "breakdown": breakdown
                })
                uids.append(idx)
                scores.append(final_score)
                continue

            # STEP 2 & 3: Breaker Miner Challenge & Differential Fuzzing
            combined_test_inputs = list(hidden_inputs)
            breaker_divergence_found = False

            if breaker_axons:
                breaker_syn = BreakerSynapse(
                    c_code=self.sample_c_code,
                    rust_code=rust_code,
                    function_name="reverse_string",
                    num_inputs_requested=10
                )
                breaker_resps = self.dendrite.query(axons=breaker_axons, synapse=breaker_syn, timeout=8.0)
                for b_resp in breaker_resps:
                    if b_resp.test_inputs:
                        logger.info(f"[BREAKER] Injected {len(b_resp.test_inputs)} adversarial edge-cases")
                        combined_test_inputs.extend(b_resp.test_inputs)

            # Sandboxed differential execution
            test_results = self.sandbox.compile_and_test(
                c_code=self.sample_c_code,
                rust_code=rust_code,
                test_inputs=combined_test_inputs,
                timeout=5.0
            )

            pass_rate = test_results.get("pass_rate", 0.0)
            divergences = test_results.get("divergences", [])
            
            if divergences:
                logger.warning(f"[DIFF FUZZ] Miner {hotkey} encountered {len(divergences)} divergences!")
                breaker_divergence_found = True

            # STEP 4: Scoring Formula
            final_score, breakdown = calculate_score(
                pass_rate=pass_rate,
                has_unsafe=False,
                actual_time=proc_time,
                max_time=10.0
            )

            logger.info(
                f"[SCORED] Miner {hotkey}: PassRate={pass_rate*100:.1f}%, "
                f"Formula=({breakdown['base_score']} * {breakdown['safety_penalty']} * {breakdown['speed_bonus']}) "
                f"-> FinalScore={final_score}"
            )

            round_results.append({
                "hotkey": hotkey,
                "role": "translator",
                "status": "PASSED" if pass_rate > 0.8 else "WEAK",
                "pass_rate": pass_rate,
                "passed_tests": test_results.get("passed_tests", 0),
                "total_tests": test_results.get("total_tests", len(combined_test_inputs)),
                "divergences_count": len(divergences),
                "score": final_score,
                "breakdown": breakdown
            })
            uids.append(idx)
            scores.append(final_score)

        # Reward Breaker if divergence was successfully proven
        breaker_score = 0.0
        if breaker_axons:
            breaker_hotkey = getattr(breaker_axons[0], "hotkey", "breaker_hotkey")
            # If breaker found any divergence against a weak translator
            weak_found = any(r.get("divergences_count", 0) > 0 for r in round_results)
            breaker_score = 0.50 if weak_found else 0.05
            round_results.append({
                "hotkey": breaker_hotkey,
                "role": "breaker",
                "status": "BOUNTY_AWARDED" if weak_found else "ACTIVE",
                "score": breaker_score,
                "divergence_caught": weak_found
            })
            uids.append(len(uids))
            scores.append(breaker_score)

        # Set weights on chain
        self.subtensor.set_weights(
            netuid=self.config.netuid,
            wallet=self.wallet,
            uids=uids,
            weights=scores
        )

        return {
            "round_results": round_results,
            "weights_set": dict(zip(uids, scores))
        }


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Bittensor C-to-Safe-Rust Subnet Validator")
    parser.add_argument("--netuid", type=int, default=1, help="Subnet netuid")
    parser.add_argument("--wallet_name", type=str, default="default", help="Validator wallet name")
    parser.add_argument("--wallet_hotkey", type=str, default="validator_hotkey", help="Hotkey name")
    parser.add_argument("--axon_port", type=int, default=8090, help="Port to host validator axon")
    parser.add_argument("--subtensor_network", type=str, default="local", help="Network (local/finney/test)")
    parser.add_argument("--no_docker", action="store_true", default=False, help="Force local/emulated sandbox")
    parser.add_argument("--rounds", type=int, default=1, help="Number of validation rounds to run")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    val = Validator(args)
    logger.info("Validator ready.")
