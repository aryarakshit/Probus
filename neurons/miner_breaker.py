"""
Breaker Miner (neurons/miner_breaker.py)

The red team. Given (C reference, Rust candidate) it tries to earn the bounty
by producing inputs on which the two programs disagree. Three stages, each
feeding the next:

  1. Static analysis   - constants, buffer sizes and literals in *both* sources
                         become boundary-sized seeds (n-1, n, n+1, 2n ...).
  2. LLM hypotheses    - optional: the model reads the diff between C and Rust
                         and proposes concrete byte strings likely to diverge.
  3. Differential fuzz - the candidate is compiled locally and mutated inputs are
                         run against the C oracle until the time budget is spent.
                         Every hit is checked against the ASan/UBSan build (so it
                         cannot be UB farming) and shrunk with delta debugging.

Only sanitizer-clean, minimized reproducers are submitted, ranked smallest
first. If the fuzzer finds nothing, the breaker still submits its best boundary
seeds - the validator scores them the same way, they just rarely hit.
"""

import sys
import os
import re
import time
import json
import random
import base64
import argparse
import logging
from typing import List, Tuple, Dict, Any, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import substrate as bt
from protocol import BreakerSynapse
from neurons.llm import LLMClient
from neurons.difffuzz import LocalDiff, default_seeds, boundary_seeds, BASE_SEEDS, Divergence, MAX_INPUT

logger = logging.getLogger("miner_breaker")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [BREAKER] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

HYPOTHESIS_SYSTEM = """You are a security researcher auditing a C-to-Rust port. You will be shown the original C program and the Rust translation. Both read all of stdin as bytes and write bytes to stdout.

Find inputs where the Rust program's stdout bytes or exit code could differ from the C program. Think about: UTF-8 decoding of raw bytes, off-by-one at buffer/constant boundaries, integer width and wrap-around, signed/unsigned casts, trailing newline handling, CR/LF, NUL bytes, empty input, inputs larger than internal buffers, overflow detection paths, and error exit codes.

Reply with ONLY a JSON array of up to 12 candidate inputs, each a string using Python bytes escapes (e.g. "\\xff\\x00abc", "A"*70 must be written out explicitly). No commentary."""


def _parse_hypotheses(text: str) -> List[bytes]:
    m = re.search(r"\[[\s\S]*\]", text)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except Exception:
        return []
    out: List[bytes] = []
    for it in items:
        if not isinstance(it, str):
            continue
        try:
            out.append(it.encode("latin-1", errors="replace").decode("unicode_escape").encode("latin-1", errors="replace")[:MAX_INPUT])
        except Exception:
            out.append(it.encode("utf-8", errors="replace")[:MAX_INPUT])
    return out


class BreakerMiner:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.axon = bt.axon(wallet=self.wallet, port=config.axon_port, ip=config.axon_ip)
        self.fuzz_seconds = float(getattr(config, "fuzz_seconds", 8.0))
        self.use_llm = bool(getattr(config, "use_llm", False))
        self.llm: Optional[LLMClient] = LLMClient() if self.use_llm else None
        self.last_report: Dict[str, Any] = {}
        logger.info(f"Initialized BreakerMiner wallet={self.wallet} fuzz_budget={self.fuzz_seconds}s "
                    f"llm={'on:' + self.llm.describe() if self.llm and self.llm.available else 'off'}")

    # ------------------------------------------------------------- stages
    def _llm_hypotheses(self, c_code: str, rust_code: str) -> List[bytes]:
        if not self.llm or not self.llm.available:
            return []
        user = f"C program:\n```c\n{c_code}\n```\n\nRust translation:\n```rust\n{rust_code}\n```"
        res = self.llm.complete(HYPOTHESIS_SYSTEM, user, max_tokens=4000)
        if res is None:
            return []
        hyps = _parse_hypotheses(res.text)
        logger.info(f"LLM proposed {len(hyps)} hypothesis inputs ({res.provider}:{res.model}{' replay' if res.replayed else ''})")
        return hyps

    def attack(self, c_code: str, rust_code: str, count: int = 12, budget_s: Optional[float] = None) -> Tuple[List[bytes], Dict[str, Any]]:
        """Return (inputs_to_submit, report)."""
        t0 = time.time()
        budget = self.fuzz_seconds if budget_s is None else budget_s
        report: Dict[str, Any] = {"stages": [], "divergences": [], "elapsed_s": 0.0}

        static_seeds = boundary_seeds(c_code, rust_code)
        report["stages"].append({"stage": "static", "seeds": len(static_seeds)})
        hyps = self._llm_hypotheses(c_code, rust_code) if rust_code else []
        if hyps:
            report["stages"].append({"stage": "llm", "seeds": len(hyps)})

        seeds = list(dict.fromkeys(BASE_SEEDS + static_seeds + hyps))
        found: List[Divergence] = []
        # Probes used to fill unused slots when the fuzzer finds nothing; screened below so an
        # input that crashes the C reference is never submitted (it would cost a penalty).
        fill = sorted(dict.fromkeys(static_seeds + BASE_SEEDS), key=len)

        with LocalDiff(c_code, timeout=2.0) as diff:
            if diff.c_bin is None:
                report["stages"].append({"stage": "fuzz", "error": "C oracle failed to build locally"})
            elif not rust_code.strip():
                report["stages"].append({"stage": "fuzz", "skipped": "no candidate code supplied"})
            elif not diff.build_rust(rust_code):
                # A candidate that does not compile will be zeroed by the validator anyway.
                report["stages"].append({"stage": "fuzz", "error": "candidate does not compile", "rustc": diff.rust_error[:400]})
            else:
                log = []
                found = diff.fuzz(seeds, budget_s=budget, rng=random.Random(), want=count,
                                  on_progress=lambda m: (log.append(m), logger.info(m)))
                report["stages"].append({"stage": "fuzz", "budget_s": budget, "hits": len(found), "log": log[:20]})
            if diff.c_bin is not None and len(found) < count:
                probe = fill[: 3 * count]
                fill = [s for s, ok in zip(probe, diff.is_clean(probe)) if ok]

        found.sort(key=lambda d: (len(d.input), d.input))
        report["divergences"] = [d.to_dict() for d in found[:count]]
        submit: List[bytes] = [d.input for d in found[:count]]

        if len(submit) < count:
            submit.extend([s for s in fill if s not in submit][: count - len(submit)])
        report["elapsed_s"] = round(time.time() - t0, 3)
        report["submitted"] = len(submit)
        self.last_report = report
        return submit, report

    # ------------------------------------------------------------- legacy API
    def generate_adversarial_inputs(self, c_code: str, rust_code: str, count: int = 10) -> List[bytes]:
        inputs, _ = self.attack(c_code, rust_code, count=count)
        return inputs

    # ------------------------------------------------------------------ axon
    def forward(self, synapse: BreakerSynapse) -> BreakerSynapse:
        task_name = getattr(synapse, "task_name", "task")
        logger.info(f"Received breaker challenge for task '{task_name}' ({len(synapse.rust_code or '')} bytes of Rust)")
        inputs, report = self.attack(synapse.c_code, synapse.rust_code or "", count=synapse.num_inputs_requested)
        synapse.test_inputs = [base64.b64encode(i).decode("ascii") for i in inputs]
        synapse.input_encoding = "base64"
        hits = report["divergences"]
        if hits:
            first = hits[0]
            synapse.divergence_rationale = (
                f"{len(hits)} sanitizer-clean divergence(s) found by local differential fuzzing in "
                f"{report['elapsed_s']}s; smallest reproducer {first['input_len']} bytes "
                f"(shrunk from {first['minimized_from'] or first['input_len']}): {first['reason']}"
            )
        else:
            synapse.divergence_rationale = (
                f"No divergence found within {self.fuzz_seconds}s; submitting {len(inputs)} boundary probes "
                f"derived from {report['stages'][0]['seeds']} static seeds."
            )
        logger.info(synapse.divergence_rationale)
        return synapse

    def blacklist(self, synapse: BreakerSynapse) -> Tuple[bool, str]:
        caller = synapse.dendrite.hotkey
        if self.config.subtensor_network != "local" and not getattr(self.config, "mock", False):
            if caller not in self.metagraph.hotkeys:
                return True, f"Hotkey {caller} not registered in metagraph"
        return False, "Allowed"

    def run(self):
        self.axon.attach(forward_fn=self.forward, blacklist_fn=self.blacklist)
        self.axon.start()
        logger.info(f"Breaker miner serving on {self.axon.ip}:{self.axon.port}")
        return self

    def serve_forever(self):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.axon.stop()


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Aegis Breaker Miner (adversarial differential fuzzer)")
    parser.add_argument("--netuid", type=int, default=1)
    parser.add_argument("--wallet_name", type=str, default="default")
    parser.add_argument("--wallet_hotkey", type=str, default="breaker_fuzzer")
    parser.add_argument("--axon_port", type=int, default=8092)
    parser.add_argument("--axon_ip", type=str, default="127.0.0.1")
    parser.add_argument("--subtensor_network", type=str, default="local")
    parser.add_argument("--fuzz_seconds", type=float, default=8.0, help="Differential fuzzing budget per challenge")
    parser.add_argument("--use_llm", action="store_true", default=False, help="Ask an LLM for hypothesis inputs first")
    parser.add_argument("--mock", action="store_true", default=False)
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    miner = BreakerMiner(args)
    miner.run()
    miner.serve_forever()
