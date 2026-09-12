"""
Translator Miner (neurons/miner_translator.py)

Translates a whole C program (stdin bytes -> stdout bytes + exit code) into a
100% Safe Rust program with `fn main()`.

Modes
  llm      - the real miner. Provider-agnostic LLM translation (neurons/llm.py)
             followed by a local repair loop:
               1. static gate  (unsafe / libc / FFI / process spawning)
               2. rustc -F unsafe_code
               3. self-red-team: differential fuzz against the C oracle
             Each failure is fed back to the model with the exact evidence
             (compiler stderr or a minimized divergent input) for up to
             --max_repairs rounds. The miner never sees a reference solution.
  weak     - benchmark fixture: a deliberately flawed translation for the task
             (dataset/fixtures.py). Exists so the validator/breaker pipeline can be
             demonstrated and unit-tested without spending model calls.
  cheater  - benchmark fixture: an `unsafe`-using submission, to show the gate.

The fixture modes are test doubles, not competitors; they are labelled as such
in every log line and in the dashboard.
"""

import sys
import os
import re
import time
import random
import hashlib
import argparse
import logging
from typing import Optional, Tuple, Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import substrate as bt
from protocol import TranslationSynapse
from neurons.llm import LLMClient
from neurons.difffuzz import LocalDiff, default_seeds

logger = logging.getLogger("miner_translator")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [TRANSLATOR] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

BANNED_PATTERNS = [
    (r"\bunsafe\b", "Forbidden 'unsafe' block or keyword detected"),
    (r"\bbuild\.rs\b", "Forbidden 'build.rs' reference detected"),
    (r"std::process::(Command|exit)", "Forbidden process spawning detected"),
    (r"\blibc::", "Forbidden raw libc access detected"),
    (r'extern\s+"C"', "Forbidden external C FFI detected"),
    (r"std::fs::", "Forbidden filesystem access detected"),
]

SYSTEM_PROMPT = """You are a systems programmer migrating legacy C to memory-safe Rust for a security-critical pipeline.

You will receive one complete C program. It reads raw bytes from stdin, writes raw bytes to stdout, and returns an exit code. Produce a Rust program with IDENTICAL observable behaviour: for every possible stdin, the stdout bytes and the process exit code must match the C program byte-for-byte.

Hard rules (violations are rejected by an automated gate and score zero):
1. Begin the file with `#![forbid(unsafe_code)]`. No `unsafe`, no FFI, no `libc`, no `build.rs`, no `std::process`, no `std::fs`.
2. Standard library only. Edition 2021. Must compile with `rustc -F unsafe_code -C overflow-checks=on`.
3. Treat stdin as raw bytes (`Vec<u8>` via `read_to_end`). Never decode it as UTF-8 or `String` unless the C program's behaviour genuinely depends on UTF-8.
4. Write stdout as raw bytes with `write_all`. Match every byte the C program prints, including trailing newlines, spacing, and hex case.
5. Match C's exit codes exactly. `std::process::exit` is forbidden: have `main` return `std::process::ExitCode` (`ExitCode::from(n)`), or return `()` when the C program only ever exits 0.
6. Reproduce C integer semantics deliberately: unsigned wrap-around uses `wrapping_add` / `wrapping_mul` / `wrapping_shl` etc.; narrowing casts use `as`; signed overflow in C is undefined so the harness never sends inputs that trigger it.
7. The program must never panic. Bounds, empty input, a single byte, inputs with NUL and 0xFF bytes, inputs larger than any internal buffer, and CRLF line endings must all be handled exactly as the C code handles them.
8. No comments explaining the C; just the working program.

Reply with ONLY the Rust source inside one ```rust fenced block."""

REPAIR_PROMPT = """The Rust program you produced was rejected. Evidence:

{evidence}

Fix the program so it compiles under the rules and matches the C program's stdout bytes and exit code for the failing inputs AND all other inputs. Reply with ONLY the complete corrected Rust source inside one ```rust fenced block."""


def local_static_check(rust_code: str) -> Tuple[bool, Optional[str]]:
    """Mirror of the validator's static gate, run before submitting."""
    if not rust_code or not rust_code.strip():
        return False, "Empty Rust code"
    for pattern, reason in BANNED_PATTERNS:
        if re.search(pattern, rust_code):
            return False, reason
    return True, None


def extract_rust(text: str) -> str:
    m = re.search(r"```(?:rust|rs)?\s*\n([\s\S]*?)```", text)
    code = m.group(1) if m else text
    code = code.strip() + "\n"
    if "#![forbid(unsafe_code)]" not in code:
        code = "#![forbid(unsafe_code)]\n" + code
    return code


def _describe_bytes(b: bytes, limit: int = 96) -> str:
    return f"{len(b)} bytes: {b[:limit]!r}" + (" ..." if len(b) > limit else "")


class TranslatorMiner:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.axon = bt.axon(wallet=self.wallet, port=config.axon_port, ip=config.axon_ip)
        self.mode = config.mode
        self.max_repairs = getattr(config, "max_repairs", 2)
        self.self_fuzz_seconds = getattr(config, "self_fuzz_seconds", 4.0)
        self.llm: Optional[LLMClient] = None
        if self.mode == "llm":
            self.llm = LLMClient()
            logger.info(f"LLM backend: {self.llm.describe()}")
        self.last_trace: List[Dict[str, Any]] = []
        role = "FIXTURE" if self.mode in ("weak", "cheater") else "LLM"
        logger.info(f"Initialized TranslatorMiner wallet={self.wallet} mode='{self.mode}' ({role})")

    # ---------------------------------------------------------------- fixtures
    def _fixture(self, c_code: str) -> str:
        from dataset.fixtures import fixture_rust
        return fixture_rust(self.mode, c_code)

    # --------------------------------------------------------------- real path
    def _translate_llm(self, c_code: str, task_name: str) -> Tuple[str, int, str]:
        """Translate + repair. Returns (rust_code, attempts, notes)."""
        trace: List[Dict[str, Any]] = []
        self.last_trace = trace
        if self.llm is None or not self.llm.available:
            return "", 0, "no LLM provider available"

        user = f"Task: {task_name}\n\n```c\n{c_code}\n```"
        c_digest = hashlib.sha256(c_code.encode("utf-8")).hexdigest()[:16]
        res = self.llm.complete(SYSTEM_PROMPT, user, replay_key=f"{task_name}:{c_digest}:attempt1")
        if res is None:
            if self.llm.provider is None:
                return "", 1, ("no LLM credentials and no recording for this task/seed - set ANTHROPIC_API_KEY "
                               "(or OPENAI_API_KEY / GEMINI_API_KEY / OLLAMA_HOST) or run scripts/record_translations.py")
            return "", 1, "LLM call failed"
        code = extract_rust(res.text)
        trace.append({"attempt": 1, "provider": res.provider, "model": res.model,
                      "replayed": res.replayed, "latency_s": res.latency_s, "bytes": len(code)})

        best_code, best_div = code, None
        attempts = 1
        with LocalDiff(c_code, timeout=2.0) as diff:
            if diff.c_bin is None:
                logger.warning("Could not build the C oracle locally; submitting without self-test")
                return code, attempts, "no local C toolchain"
            rng = random.Random(0xA3615)

            while True:
                evidence = None
                ok, reason = local_static_check(code)
                if not ok:
                    evidence = f"Static gate: {reason}"
                elif not diff.build_rust(code):
                    err = diff.rust_error[:3000]
                    evidence = f"rustc failed:\n{err}"
                else:
                    # re-derive boundary seeds per draft: a repair can introduce a new constant
                    seeds = default_seeds(c_code, code)
                    hits = diff.fuzz(seeds, budget_s=self.self_fuzz_seconds, rng=rng, want=3)
                    n_div = len(hits)
                    if best_div is None or n_div < best_div:
                        best_code, best_div = code, n_div
                    if hits:
                        lines = []
                        for h in hits[:3]:
                            lines.append(
                                f"- input {_describe_bytes(h.input)}\n"
                                f"  C  : exit={h.c_exit} stdout={_describe_bytes(h.c_stdout)}\n"
                                f"  Rust: exit={h.r_exit} stdout={_describe_bytes(h.r_stdout)} ({h.reason})"
                            )
                        evidence = "Differential test found divergences from the C program:\n" + "\n".join(lines)
                trace[-1]["verdict"] = evidence or "clean"
                if evidence is None:
                    return code, attempts, f"self-test clean after {attempts} attempt(s)"
                logger.info(f"[attempt {attempts}] {evidence.splitlines()[0][:120]}")
                if attempts > self.max_repairs:
                    break
                res = self.llm.complete(SYSTEM_PROMPT, user + "\n\n" + REPAIR_PROMPT.format(evidence=evidence),
                                        replay_key=f"{task_name}:{c_digest}:attempt{attempts + 1}")
                if res is None:
                    break          # no model answer for the repair: keep the best draft so far
                attempts += 1
                code = extract_rust(res.text)
                trace.append({"attempt": attempts, "provider": res.provider, "model": res.model,
                              "replayed": res.replayed, "latency_s": res.latency_s, "bytes": len(code)})

        # Out of repairs: submit the best compiling candidate we saw.
        if best_div is None:
            return code, attempts, "never compiled cleanly; submitting last attempt"
        return best_code, attempts, f"submitting best of {attempts} (self-test divergences={best_div})"

    # ------------------------------------------------------------------ axon
    def synthesize_rust(self, c_code: str, task_name: str) -> Tuple[str, int]:
        code, attempts, _ = self.synthesize_rust_with_notes(c_code, task_name)
        return code, attempts

    def synthesize_rust_with_notes(self, c_code: str, task_name: str) -> Tuple[str, int, str]:
        if self.mode in ("weak", "cheater"):
            return self._fixture(c_code), 1, f"benchmark fixture '{self.mode}'"
        if self.mode == "llm":
            return self._translate_llm(c_code, task_name)
        raise ValueError(f"unknown translator mode '{self.mode}' (use llm|weak|cheater)")

    def forward(self, synapse: TranslationSynapse) -> TranslationSynapse:
        task_name = getattr(synapse, "task_name", "task")
        logger.info(f"Received translation request for task '{task_name}' (mode={self.mode})")
        t0 = time.time()
        rust_code, attempts, notes = self.synthesize_rust_with_notes(synapse.c_code, task_name)
        synapse.rust_code = rust_code
        synapse.repair_attempts = attempts
        synapse.compiler_notes = notes
        logger.info(f"Returning {len(rust_code)} bytes of Rust after {attempts} attempt(s) in {time.time() - t0:.1f}s: {notes}")
        return synapse

    def blacklist(self, synapse: TranslationSynapse) -> Tuple[bool, str]:
        caller = synapse.dendrite.hotkey
        if self.config.subtensor_network != "local" and not getattr(self.config, "mock", False):
            if caller not in self.metagraph.hotkeys:
                return True, f"Hotkey {caller} not registered in metagraph"
        return False, "Allowed"

    def run(self):
        self.axon.attach(forward_fn=self.forward, blacklist_fn=self.blacklist)
        self.axon.start()
        logger.info(f"Translator miner ({self.mode}) serving on {self.axon.ip}:{self.axon.port}")
        return self

    def serve_forever(self):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.axon.stop()


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Aegis C-to-Safe-Rust Translator Miner")
    parser.add_argument("--netuid", type=int, default=1)
    parser.add_argument("--wallet_name", type=str, default="default")
    parser.add_argument("--wallet_hotkey", type=str, default="translator_miner")
    parser.add_argument("--axon_port", type=int, default=8091)
    parser.add_argument("--axon_ip", type=str, default="127.0.0.1")
    parser.add_argument("--subtensor_network", type=str, default="local", help="local | test | finney")
    parser.add_argument("--mode", type=str, default="llm", choices=["llm", "weak", "cheater"],
                        help="llm = real miner; weak/cheater = benchmark fixtures")
    parser.add_argument("--max_repairs", type=int, default=2, help="LLM repair rounds after the first attempt")
    parser.add_argument("--self_fuzz_seconds", type=float, default=4.0, help="Budget for local differential self-test per attempt")
    parser.add_argument("--mock", action="store_true", default=False, help="Use mock substrate")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    miner = TranslatorMiner(args)
    miner.run()
    miner.serve_forever()
