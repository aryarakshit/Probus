"""
Validator Neuron for Probus Subnet (neurons/validator.py)

One validation round:
  1. sample a parameterized C task (fresh constants every round)
  2. generate a secret hidden test-suite, keeping only inputs the ASan/UBSan
     reference build accepts (no UB farming, but non-zero exits are allowed)
  3. challenge every translator; static gate -> rustc -F unsafe_code ->
     differential execution in the sandbox
  4. hand EVERY compiling candidate to EVERY breaker
  5. score: cubed pass-rate for translators, 50% anti-collusion bounty for
     breakers, invalid-input penalties
  6. EMA weights -> set_weights on chain
  7. commit the round to the merkle-chained ledger and the JSONL log

`on_event` (optional callback) receives structured progress events so a UI can
stream the round as it happens.
"""

import sys
import os
import re
import json
import time
import base64
import argparse
import logging
from typing import Tuple, Dict, Any, List, Optional, Callable

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
from neurons.ledger import Ledger, sha256_text, sha256_bytes

logger = logging.getLogger("validator")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [VALIDATOR] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

# Case-sensitive on purpose: `std::process::ExitCode` is the sanctioned way to
# return a non-zero status and must not trip the `exit` rule.
BANNED_STATIC_PATTERNS = [
    (r"\bunsafe\b", "Static Gate: 'unsafe' keyword detected"),
    (r"\bbuild\.rs\b", "Static Gate: 'build.rs' reference detected"),
    (r"std::process::(Command|exit)\b", "Static Gate: process execution / exit detected"),
    (r"\blibc::", "Static Gate: raw libc FFI detected"),
    (r'extern\s+"C"', "Static Gate: external C linkage detected"),
    (r"std::fs::", "Static Gate: direct filesystem access detected"),
    (r"\basm!\s*\(", "Static Gate: inline assembly detected"),
    (r"#!\[allow\(unsafe_code\)\]", "Static Gate: unsafe_code lint re-enabled"),
]


def static_analysis_gate(rust_code: str) -> Tuple[bool, Optional[str]]:
    """Step 1: sub-millisecond pre-filter. Real enforcement is rustc -F unsafe_code."""
    if not rust_code or not rust_code.strip():
        return False, "No submission: miner returned no Rust code"
    for pattern, reason in BANNED_STATIC_PATTERNS:
        if re.search(pattern, rust_code):
            return False, reason
    return True, None


class Validator:
    def __init__(self, config: argparse.Namespace, on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.dendrite = bt.dendrite(wallet=self.wallet)
        self.sandbox = SandboxRunner(force_unsandboxed=getattr(config, "no_docker", False))
        self.ledger = Ledger(getattr(config, "ledger_dir", None))
        self.on_event = on_event

        self.log_file = getattr(config, "log_file", "rounds.jsonl")
        self.translator_timeout = float(getattr(config, "translator_timeout", 180.0))
        self.breaker_timeout = float(getattr(config, "breaker_timeout", 60.0))
        self.ema_scores: Dict[str, float] = {}
        self.total_rounds = 0

        logger.info(f"Validator initialized on netuid={config.netuid} "
                    f"(Docker={self.sandbox.docker_available}, ledger='{self.ledger.root}', log='{self.log_file}')")

    # ------------------------------------------------------------------ util
    def emit(self, kind: str, **payload):
        evt = {"t": time.time(), "kind": kind, **payload}
        if self.on_event:
            try:
                self.on_event(evt)
            except Exception:
                pass

    @staticmethod
    def _hotkey(ax, fallback: str) -> str:
        return getattr(ax, "hotkey", None) or fallback

    # ----------------------------------------------------------------- round
    def run_validation_round(
        self,
        translator_axons: List[Any],
        breaker_axons: Optional[List[Any]] = None,
        num_tests: int = 30,
        task_name: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.total_rounds += 1
        round_id = self.total_rounds
        t_round = time.time()
        logger.info(f"========== Validation Round #{round_id} ==========")
        self.emit("round_start", round_id=round_id)

        # 1. Task with fresh constants
        task_inst = sample_task(task_name=task_name, seed=seed)
        c_sha = sha256_text(task_inst.c_code)
        logger.info(f"[TASK] {task_inst.task_name} constants={task_inst.constants} c_sha256={c_sha[:12]}")
        self.emit("task", round_id=round_id, task=task_inst.task_name, constants=task_inst.constants,
                  c_sha256=c_sha, c_code=task_inst.c_code)

        # 2. Hidden tests
        hidden_inputs = generate_sanitizer_verified_hidden_tests(
            c_code=task_inst.c_code, sandbox_runner=self.sandbox, count=num_tests)
        hidden_digest = sha256_bytes(b"".join(sha256_bytes(h).encode() for h in hidden_inputs))
        logger.info(f"[HIDDEN TESTS] {len(hidden_inputs)} sanitizer-verified secret inputs (digest {hidden_digest[:12]})")
        self.emit("hidden_tests", round_id=round_id, count=len(hidden_inputs), digest=hidden_digest)

        # 3. Translators
        synapse_req = TranslationSynapse(c_code=task_inst.c_code, task_name=task_inst.task_name,
                                         timeout_seconds=self.translator_timeout)
        logger.info(f"[TRANSLATORS] querying {len(translator_axons)} axons (timeout {self.translator_timeout:.0f}s)")
        self.emit("translators_query", round_id=round_id, count=len(translator_axons))
        translator_responses = self.dendrite.query(axons=translator_axons, synapse=synapse_req,
                                                   timeout=self.translator_timeout + 5)

        translator_evals: Dict[str, Dict[str, Any]] = {}
        for idx, resp in enumerate(translator_responses):
            hotkey = self._hotkey(translator_axons[idx], f"translator_uid_{idx}")
            rust_code = resp.rust_code or ""
            proc_time = getattr(getattr(resp, "dendrite", None), "process_time", 0.0) or 0.0
            notes = getattr(resp, "compiler_notes", None)
            attempts = getattr(resp, "repair_attempts", 0)
            status = getattr(getattr(resp, "dendrite", None), "status_code", 200)
            logger.info(f"[TRANSLATOR {hotkey}] {len(rust_code)} bytes, {attempts} attempt(s), {proc_time:.1f}s, status {status}: {notes}")

            t_gate = time.perf_counter()
            gate_ok, gate_reason = static_analysis_gate(rust_code)
            gate_ms = (time.perf_counter() - t_gate) * 1000
            base = {
                "rust_code": rust_code,
                "rust_sha256": sha256_text(rust_code) if rust_code else None,
                "proc_time": round(proc_time, 3),
                "attempts": attempts,
                "miner_notes": notes,
                "gate_ms": round(gate_ms, 3),
                "total_hidden": len(hidden_inputs),
            }
            if not gate_ok:
                logger.warning(f"[GATE REJECT] {hotkey}: {gate_reason} ({gate_ms:.3f} ms)")
                translator_evals[hotkey] = {**base, "pre_t": 0.0, "passed_hidden": 0, "pass_rate": 0.0,
                                            "compile_success": False, "gate_success": False, "reject_reason": gate_reason}
                self.emit("translator_eval", round_id=round_id, hotkey=hotkey, gate=False, reason=gate_reason,
                          gate_ms=round(gate_ms, 3), rust_sha256=base["rust_sha256"], attempts=attempts, notes=notes)
                continue

            test_res = self.sandbox.compile_and_test(c_code=task_inst.c_code, rust_code=rust_code,
                                                     test_inputs=hidden_inputs, timeout=2.0)
            comp_ok = test_res.get("compilation_success", False)
            passed = test_res.get("passed_tests", 0)
            total = test_res.get("total_tests", len(hidden_inputs))
            pass_rate = test_res.get("pass_rate", 0.0)
            pre_t = calculate_translator_pre_score(passed_hidden=passed, total_hidden=total, compile_success=comp_ok,
                                                   gate_success=True, code_size_bytes=len(rust_code.encode("utf-8")))
            err = test_res.get("error")
            if not comp_ok:
                logger.warning(f"[COMPILE FAIL] {hotkey} at {test_res.get('stage')}: {str(err)[:300]}")
            else:
                logger.info(f"[TRANSLATOR {hotkey}] pass {passed}/{total} = {pass_rate*100:.1f}%  -> pre_t={pre_t:.4f}")
            translator_evals[hotkey] = {**base, "pre_t": pre_t, "passed_hidden": passed, "pass_rate": pass_rate,
                                        "compile_success": comp_ok, "gate_success": True, "error": err,
                                        "hidden_divergences": test_res.get("divergences", [])[:5]}
            self.emit("translator_eval", round_id=round_id, hotkey=hotkey, gate=True, compile=comp_ok,
                      passed=passed, total=total, pre_t=pre_t, error=(str(err)[:300] if err else None),
                      rust_sha256=base["rust_sha256"], attempts=attempts, notes=notes, gate_ms=round(gate_ms, 3))

        # 4. Breakers attack every compiling candidate
        breaker_submissions: Dict[str, List[bytes]] = {}
        breaker_rationale: Dict[str, List[str]] = {}
        if breaker_axons:
            candidates = [(hk, ev["rust_code"]) for hk, ev in translator_evals.items() if ev["pre_t"] > 0]
            logger.info(f"[BREAKERS] {len(breaker_axons)} breaker(s) x {len(candidates)} candidate(s)")
            for b_idx, b_axon in enumerate(breaker_axons):
                b_hk = self._hotkey(b_axon, f"breaker_uid_{b_idx}")
                collected: List[bytes] = []
                breaker_rationale[b_hk] = []
                for t_hk, cand_code in candidates:
                    self.emit("breaker_query", round_id=round_id, breaker=b_hk, target=t_hk)
                    syn = BreakerSynapse(c_code=task_inst.c_code, rust_code=cand_code,
                                         task_name=task_inst.task_name, num_inputs_requested=12)
                    resps = self.dendrite.query(axons=[b_axon], synapse=syn, timeout=self.breaker_timeout)
                    raw = resps[0].get_raw_inputs() if resps else []
                    rationale = getattr(resps[0], "divergence_rationale", None) if resps else None
                    breaker_rationale[b_hk].append(f"vs {t_hk}: {rationale}")
                    logger.info(f"[BREAKER {b_hk}] vs {t_hk}: {len(raw)} inputs. {rationale}")
                    self.emit("breaker_result", round_id=round_id, breaker=b_hk, target=t_hk, inputs=len(raw), rationale=rationale)
                    collected.extend(raw)
                # de-duplicate while preserving order
                seen = set(); uniq = []
                for r in collected:
                    if r not in seen:
                        seen.add(r); uniq.append(r)
                breaker_submissions[b_hk] = uniq

        # 5. Score
        score_details = score_round(translators=translator_evals, breaker_submissions=breaker_submissions,
                                    sandbox_runner=self.sandbox, c_code=task_inst.c_code, timeout=2.0)
        round_scores = score_details["round_scores"]
        logger.info(f"[SCORED #{round_id}] {round_scores}")
        for t_hk, hits in score_details["breaker_hits"].items():
            if hits:
                rep = score_details["divergences"][t_hk][0]
                logger.info(f"[BROKEN] {t_hk} by {hits}: smallest reproducer {rep['input_len']} bytes {rep['input_repr']} ({rep['reason']})")

        # 6. Weights
        uids_by_hotkey: Dict[str, int] = {}
        for idx, ax in enumerate(translator_axons):
            uids_by_hotkey[self._hotkey(ax, f"translator_uid_{idx}")] = idx
        for idx, ax in enumerate(breaker_axons or []):
            uids_by_hotkey[self._hotkey(ax, f"breaker_uid_{idx}")] = len(translator_axons) + idx
        self.ema_scores, normalized_weights = update_ema_weights(current_ema=self.ema_scores, round_scores=round_scores,
                                                                 uids_by_hotkey=uids_by_hotkey, alpha=0.1)
        uids_list = list(normalized_weights.keys())
        self.subtensor.set_weights(netuid=self.config.netuid, wallet=self.wallet, uids=uids_list,
                                   weights=[normalized_weights[u] for u in uids_list], version_key=1)
        self.emit("weights", round_id=round_id, weights={str(k): v for k, v in normalized_weights.items()},
                  hotkeys={hk: uid for hk, uid in uids_by_hotkey.items()})

        # 7. Ledger + JSONL
        chain_entry = self._commit_ledger(round_id, task_inst, c_sha, hidden_digest, len(hidden_inputs),
                                          translator_evals, breaker_submissions, score_details, round_scores, normalized_weights)
        elapsed = round(time.time() - t_round, 3)

        round_log_entry = {
            "round_id": round_id,
            "timestamp": time.time(),
            "elapsed_seconds": elapsed,
            "task_name": task_inst.task_name,
            "constants": task_inst.constants,
            "c_sha256": c_sha,
            "hidden_tests": len(hidden_inputs),
            "round_scores": round_scores,
            "normalized_weights": {str(k): v for k, v in normalized_weights.items()},
            "uids": {hk: uid for hk, uid in uids_by_hotkey.items()},
            "translator_evals": {
                k: {
                    "pre_t": v.get("pre_t"),
                    "pass_rate": v.get("pass_rate", 0.0),
                    "passed_hidden": v.get("passed_hidden", 0),
                    "total_hidden": v.get("total_hidden", 0),
                    "compile_success": v.get("compile_success", False),
                    "gate_success": v.get("gate_success", False),
                    "reject_reason": v.get("reject_reason"),
                    "compile_error": (str(v.get("error"))[:600] if v.get("error") else None),
                    "gate_ms": v.get("gate_ms"),
                    "attempts": v.get("attempts"),
                    "miner_notes": v.get("miner_notes"),
                    "proc_time": v.get("proc_time"),
                    "rust_sha256": v.get("rust_sha256"),
                    "rust_bytes": len(v.get("rust_code") or ""),
                    "final_score": score_details["translator_scores"].get(k, 0.0),
                    "broken_by": score_details["breaker_hits"].get(k, []),
                    "reproducers": score_details["divergences"].get(k, [])[:3],
                } for k, v in translator_evals.items()
            },
            "breaker_evals": {
                k: {
                    "final_score": score_details["breaker_scores"].get(k, 0.0),
                    "inputs_submitted": len(breaker_submissions.get(k, [])),
                    "valid_inputs": score_details["valid_counts"].get(k, 0),
                    "invalid_inputs": score_details["invalid_counts"].get(k, 0),
                    "rationale": breaker_rationale.get(k, []),
                } for k in breaker_submissions
            },
            "breaker_hits": score_details["breaker_hits"],
            "ledger": chain_entry,
        }
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(round_log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed writing round log to {self.log_file}: {e}")

        self.emit("round_end", round_id=round_id, elapsed=elapsed, scores=round_scores, ledger=chain_entry)
        return {
            "round_id": round_id,
            "task_name": task_inst.task_name,
            "round_scores": round_scores,
            "weights": normalized_weights,
            "details": score_details,
            "translator_evals": translator_evals,
            "log_entry": round_log_entry,
        }

    def _commit_ledger(self, round_id, task_inst: TaskInstance, c_sha, hidden_digest, n_hidden,
                       translator_evals, breaker_submissions, score_details, round_scores, weights) -> Dict[str, Any]:
        self.ledger.put(task_inst.c_code.encode("utf-8"))
        submissions = []
        for hk, ev in translator_evals.items():
            code = ev.get("rust_code") or ""
            if code:
                self.ledger.put(code.encode("utf-8"))
            submissions.append({
                "hotkey": hk,
                "rust_sha256": ev.get("rust_sha256"),
                "gate": ev.get("gate_success", False),
                "compiled": ev.get("compile_success", False),
                "passed_hidden": ev.get("passed_hidden", 0),
                "total_hidden": ev.get("total_hidden", 0),
                "pre_t": ev.get("pre_t", 0.0),
                "final": score_details["translator_scores"].get(hk, 0.0),
                "broken_by": score_details["breaker_hits"].get(hk, []),
            })
        reproducers = []
        for t_hk, divs in score_details["divergences"].items():
            for d in divs[:5]:
                raw = base64.b64decode(d["input_b64"])
                digest = self.ledger.put(raw)
                reproducers.append({
                    "translator": t_hk, "breaker": d.get("breaker"), "input_sha256": digest,
                    "input_len": len(raw), "reason": d["reason"], "c_exit": d["c_exit"], "rust_exit": d["rust_exit"],
                })
        record = {
            "round_id": round_id,
            "timestamp": time.time(),
            "task": task_inst.task_name,
            "constants": task_inst.constants,
            "c_sha256": c_sha,
            "hidden_tests": {"count": n_hidden, "digest": hidden_digest},
            "submissions": submissions,
            "reproducers": reproducers,
            "breakers": {hk: {"submitted": len(v), "score": score_details["breaker_scores"].get(hk, 0.0)} for hk, v in breaker_submissions.items()},
            "scores": round_scores,
            "weights": {str(k): v for k, v in weights.items()},
            "validator": getattr(self.wallet, "ss58_address", str(self.wallet)),
        }
        try:
            entry = self.ledger.commit(record)
            logger.info(f"[LEDGER] height {entry['height']} root {entry['root'][:16]}… prev {entry['prev_root'][:8]}…")
            return entry
        except Exception as e:
            logger.error(f"Ledger commit failed: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------ loop
    def run(self):
        logger.info("Starting continuous validation loop...")
        while True:
            try:
                self.metagraph.sync(subtensor=self.subtensor)
                serving = [ax for ax in self.metagraph.axons if getattr(ax, "is_serving", True)]
                if serving:
                    # On a live network the roles are discovered by probing: a translator answers a
                    # TranslationSynapse, a breaker answers a BreakerSynapse. Here we attack with all.
                    self.run_validation_round(translator_axons=serving, breaker_axons=serving, num_tests=30)
                else:
                    logger.info("No serving axons in metagraph. Sleeping...")
                time.sleep(12.0)
            except KeyboardInterrupt:
                logger.info("Validator stopped by user.")
                break
            except Exception as e:
                logger.error(f"Error in validator loop: {e}", exc_info=True)
                time.sleep(5.0)


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Probus C-to-Safe-Rust Subnet Validator")
    parser.add_argument("--netuid", type=int, default=1)
    parser.add_argument("--wallet_name", type=str, default="default")
    parser.add_argument("--wallet_hotkey", type=str, default="validator_hotkey")
    parser.add_argument("--axon_port", type=int, default=8090)
    parser.add_argument("--subtensor_network", type=str, default="local", help="local | test | finney")
    parser.add_argument("--no_docker", action="store_true", default=False, help="Use the host toolchain (dev only)")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--log_file", type=str, default="rounds.jsonl")
    parser.add_argument("--ledger_dir", type=str, default=None)
    parser.add_argument("--translator_timeout", type=float, default=180.0, help="Seconds a translator may take (LLM + repair loop)")
    parser.add_argument("--breaker_timeout", type=float, default=60.0)
    parser.add_argument("--mock", action="store_true", default=False)
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    Validator(args).run()
