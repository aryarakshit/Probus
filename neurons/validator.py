"""
Validator Neuron for Aegis Subnet (neurons/validator.py)
Orchestrates:
1. Dynamic parameterized task sampling (UB-free C reference)
2. Secret, sanitizer-checked hidden test suite generation
3. Translator challenge and strict sandboxed differential compilation
4. Post-translation breaker challenge with sanitizer validation
5. Cubed pass-rate and 50% anti-collusion breaker scoring
6. Per-UID EMA weight updating and on-chain emission submission
7. Continuous JSONL round logging for the live command center dashboard
"""

import sys
import os
import re
import json
import time
import argparse
import logging
from typing import Tuple, Dict, Any, List, Optional, Set

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from sandbox.sandbox_runner import SandboxRunner
from dataset.tasks import sample_task, TaskInstance
from dataset.hidden_tests import generate_sanitizer_verified_hidden_tests
from neurons.scoring import calculate_translator_pre_score, score_round, update_ema_weights

logger = logging.getLogger("validator")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [VALIDATOR] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

BANNED_STATIC_PATTERNS = [
    (r"\bunsafe\b", "Static Gate: 'unsafe' keyword detected"),
    (r"\bbuild\.rs\b", "Static Gate: 'build.rs' reference detected"),
    (r"std::process::(Command|exit)", "Static Gate: Process execution detected"),
    (r"\blibc::", "Static Gate: Raw libc FFI detected"),
    (r'extern\s+"C"', "Static Gate: External C linkage detected"),
    (r"std::fs::", "Static Gate: Direct filesystem interaction detected"),
]


def static_analysis_gate(rust_code: str) -> Tuple[bool, Optional[str]]:
    """
    Step 1: Static Analysis Pre-filter Gate.
    Fast check for obvious banned patterns before passing to compiler.
    Real enforcement is guaranteed by rustc -F unsafe_code.
    """
    if not rust_code or not rust_code.strip():
        return False, "Empty or missing Rust code"

    for pattern, reason in BANNED_STATIC_PATTERNS:
        if re.search(pattern, rust_code, re.IGNORECASE):
            return False, reason

    return True, None


class Validator:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.dendrite = bt.dendrite(wallet=self.wallet)
        self.sandbox = SandboxRunner(force_unsandboxed=getattr(config, "no_docker", False))
        
        self.log_file = getattr(config, "log_file", "rounds.jsonl")
        self.ema_scores: Dict[str, float] = {}
        self.total_rounds = 0
        self.last_weight_set_block = 0
        self.tempo = getattr(config, "tempo", 100)

        logger.info(
            f"Validator initialized on netuid={config.netuid} "
            f"(Docker={self.sandbox.docker_available}, LogFile='{self.log_file}')"
        )

    def run_validation_round(
        self,
        translator_axons: List[Any],
        breaker_axons: Optional[List[Any]] = None,
        num_tests: int = 30,
        task_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes one full adversarial validation cycle:
        1. Samples a fresh parameterized C task (with per-round constants).
        2. Generates secret, sanitizer-checked hidden tests.
        3. Queries translators and executes differential tests in the sandbox.
        4. Queries breakers ONLY after receiving translator candidate codes.
        5. Evaluates breaker inputs on ref_san and applies the 50% anti-collusion rule.
        6. Updates UID EMA weights and logs the round to JSONL.
        """
        self.total_rounds += 1
        round_id = self.total_rounds
        logger.info(f"========== Starting Validation Round #{round_id} ==========")

        # 1. Sample fresh task instance with unique per-round constants
        task_inst = sample_task(task_name=task_name)
        logger.info(f"[TASK] Sampled: '{task_inst.task_name}' with constants: {task_inst.constants}")

        # 2. Synthesize sanitizer-verified hidden test inputs
        hidden_inputs = generate_sanitizer_verified_hidden_tests(
            c_code=task_inst.c_code,
            sandbox_runner=self.sandbox,
            count=num_tests
        )
        logger.info(f"[HIDDEN TESTS] Generated {len(hidden_inputs)} sanitizer-verified secret inputs")

        # 3. Query Translator Miners
        synapse_req = TranslationSynapse(
            c_code=task_inst.c_code,
            task_name=task_inst.task_name,
            timeout_seconds=15.0
        )

        logger.info(f"[TRANSLATORS] Querying {len(translator_axons)} translator axons...")
        translator_responses = self.dendrite.query(axons=translator_axons, synapse=synapse_req, timeout=18.0)

        translator_evals: Dict[str, Dict[str, Any]] = {}
        for idx, resp in enumerate(translator_responses):
            miner_axon = translator_axons[idx]
            hotkey = getattr(miner_axon, "hotkey", f"translator_uid_{idx}")
            rust_code = resp.rust_code or ""
            proc_time = getattr(getattr(resp, "dendrite", None), "process_time", 1.0) or 1.0

            logger.info(f"[TRANSLATOR {hotkey}] Received {len(rust_code)} bytes Rust code")

            # Static analysis pre-filter
            gate_ok, gate_reason = static_analysis_gate(rust_code)
            if not gate_ok:
                logger.warning(f"[GATE REJECT] Translator {hotkey} rejected: {gate_reason}")
                translator_evals[hotkey] = {
                    "rust_code": rust_code,
                    "pre_t": 0.0,
                    "passed_hidden": 0,
                    "total_hidden": len(hidden_inputs),
                    "compile_success": False,
                    "gate_success": False,
                    "reject_reason": gate_reason,
                    "proc_time": proc_time
                }
                continue

            # Sandboxed differential execution against hidden tests
            test_res = self.sandbox.compile_and_test(
                c_code=task_inst.c_code,
                rust_code=rust_code,
                test_inputs=hidden_inputs,
                timeout=2.0
            )

            comp_ok = test_res.get("compilation_success", False)
            passed_tests = test_res.get("passed_tests", 0)
            total_tests = test_res.get("total_tests", len(hidden_inputs))
            pass_rate = test_res.get("pass_rate", 0.0)

            pre_t = calculate_translator_pre_score(
                passed_hidden=passed_tests,
                total_hidden=total_tests,
                compile_success=comp_ok,
                gate_success=True,
                code_size_bytes=len(rust_code.encode("utf-8"))
            )

            logger.info(
                f"[TRANSLATOR {hotkey}] PassRate={pass_rate*100:.1f}% ({passed_tests}/{total_tests}), "
                f"Cubed pre_t={pre_t:.4f}"
            )

            translator_evals[hotkey] = {
                "rust_code": rust_code,
                "pre_t": pre_t,
                "passed_hidden": passed_tests,
                "total_hidden": total_tests,
                "pass_rate": pass_rate,
                "compile_success": comp_ok,
                "gate_success": True,
                "error": test_res.get("error"),
                "proc_time": proc_time
            }

        # 4. Query Breakers (Only AFTER translator deadline, passing candidates)
        breaker_submissions: Dict[str, List[bytes]] = {}
        if breaker_axons:
            # Pick strongest candidate to challenge breakers with
            best_cand_code = ""
            for t_hk, t_info in translator_evals.items():
                if t_info["pre_t"] > 0:
                    best_cand_code = t_info["rust_code"]
                    break

            for b_idx, b_axon in enumerate(breaker_axons):
                b_hk = getattr(b_axon, "hotkey", f"breaker_uid_{b_idx}")
                breaker_syn = BreakerSynapse(
                    c_code=task_inst.c_code,
                    rust_code=best_cand_code,
                    task_name=task_inst.task_name,
                    num_inputs_requested=12
                )
                b_resps = self.dendrite.query(axons=[b_axon], synapse=breaker_syn, timeout=10.0)
                raw_inputs = b_resps[0].get_raw_inputs() if b_resps else []
                breaker_submissions[b_hk] = raw_inputs
                logger.info(f"[BREAKER {b_hk}] Submitted {len(raw_inputs)} adversarial candidate inputs")

        # 5. Score Round with Sanitizer Check & 50% Anti-Collusion Rule
        score_details = score_round(
            translators=translator_evals,
            breaker_submissions=breaker_submissions,
            sandbox_runner=self.sandbox,
            c_code=task_inst.c_code,
            timeout=2.0
        )

        round_scores = score_details["round_scores"]
        logger.info(f"[SCORED ROUND #{round_id}] Final Scores: {round_scores}")

        # 6. Map to Metagraph UIDs and Update EMA Weights
        uids_by_hotkey: Dict[str, int] = {}
        for idx, ax in enumerate(translator_axons):
            hk = getattr(ax, "hotkey", f"translator_uid_{idx}")
            uids_by_hotkey[hk] = idx
        if breaker_axons:
            for idx, ax in enumerate(breaker_axons):
                hk = getattr(ax, "hotkey", f"breaker_uid_{idx}")
                uids_by_hotkey[hk] = len(translator_axons) + idx

        self.ema_scores, normalized_weights = update_ema_weights(
            current_ema=self.ema_scores,
            round_scores=round_scores,
            uids_by_hotkey=uids_by_hotkey,
            alpha=0.1
        )

        # Set weights on chain / subtensor
        uids_list = list(normalized_weights.keys())
        weights_list = [normalized_weights[u] for u in uids_list]
        self.subtensor.set_weights(
            netuid=self.config.netuid,
            wallet=self.wallet,
            uids=uids_list,
            weights=weights_list,
            version_key=1
        )

        # 7. Log Round to JSONL
        round_log_entry = {
            "round_id": round_id,
            "timestamp": time.time(),
            "task_name": task_inst.task_name,
            "constants": task_inst.constants,
            "round_scores": round_scores,
            "normalized_weights": {str(k): v for k, v in normalized_weights.items()},
            "translator_evals": {
                k: {
                    "pre_t": v.get("pre_t"),
                    "pass_rate": v.get("pass_rate", 0.0),
                    "passed_hidden": v.get("passed_hidden", 0),
                    "total_hidden": v.get("total_hidden", 0),
                    "compile_success": v.get("compile_success", False),
                    "gate_success": v.get("gate_success", False),
                    "final_score": score_details["translator_scores"].get(k, 0.0)
                } for k, v in translator_evals.items()
            },
            "breaker_evals": {
                k: {
                    "final_score": score_details["breaker_scores"].get(k, 0.0),
                    "inputs_submitted": len(breaker_submissions.get(k, [])),
                    "invalid_inputs": score_details["invalid_counts"].get(k, 0)
                } for k in breaker_submissions
            },
            "breaker_hits": score_details["breaker_hits"]
        }

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(round_log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed writing round log to {self.log_file}: {e}")

        return {
            "round_id": round_id,
            "task_name": task_inst.task_name,
            "round_scores": round_scores,
            "weights": normalized_weights,
            "details": score_details,
            "translator_evals": translator_evals
        }

    def run(self):
        """Continuous validation loop on live chain or local network."""
        logger.info("Starting continuous validation loop...")
        while True:
            try:
                self.metagraph.sync(subtensor=self.subtensor)
                # Find serving axons
                serving_axons = [ax for ax in self.metagraph.axons if getattr(ax, "is_serving", True)]
                if serving_axons:
                    self.run_validation_round(
                        translator_axons=serving_axons,
                        breaker_axons=None,
                        num_tests=30
                    )
                else:
                    logger.info("No active serving axons found in metagraph. Sleeping...")
                time.sleep(12.0)
            except KeyboardInterrupt:
                logger.info("Validator stopped by user.")
                break
            except Exception as e:
                logger.error(f"Error in validator loop: {e}", exc_info=True)
                time.sleep(5.0)


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Bittensor C-to-Safe-Rust Subnet Validator")
    parser.add_argument("--netuid", type=int, default=1, help="Subnet netuid")
    parser.add_argument("--wallet_name", type=str, default="default", help="Validator wallet name")
    parser.add_argument("--wallet_hotkey", type=str, default="validator_hotkey", help="Hotkey name")
    parser.add_argument("--axon_port", type=int, default=8090, help="Port to host validator axon")
    parser.add_argument("--subtensor_network", type=str, default="local", help="Network (local/finney/test)")
    parser.add_argument("--no_docker", action="store_true", default=False, help="Allow local unsandboxed toolchain")
    parser.add_argument("--rounds", type=int, default=1, help="Number of validation rounds to run")
    parser.add_argument("--log_file", type=str, default="rounds.jsonl", help="JSONL log file path")
    parser.add_argument("--mock", action="store_true", default=False, help="Enable mock substrate")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    val = Validator(args)
    val.run()
