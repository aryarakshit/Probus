"""
Record real model output for offline replay (scripts/record_translations.py)

Runs the LLM translator against every task in the pool for a fixed set of seeds
with PROBUS_LLM_RECORD=1, so the raw responses (including the repair rounds and
any failures) land in dataset/llm_replay/ with provider, model, prompt hash and
timestamp. A machine without credentials can then run the demo and dashboard
against genuine model output instead of a hand-written answer key.

    ANTHROPIC_API_KEY=... python scripts/record_translations.py
    python scripts/record_translations.py --tasks utf8_validate,base64_encode --seeds 101,202
"""

import os
import sys
import time
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")
os.environ.setdefault("PROBUS_MOCK", "1")
os.environ["PROBUS_LLM_RECORD"] = "1"

from neurons.llm import LLMClient
from neurons.miner_translator import TranslatorMiner, parse_args
from protocol import TranslationSynapse
from dataset.tasks import sample_task, list_tasks
from neurons.difffuzz import LocalDiff, default_seeds

DEFAULT_SEEDS = [101, 202, 303]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default=",".join(list_tasks()))
    ap.add_argument("--seeds", default=",".join(map(str, DEFAULT_SEEDS)))
    ap.add_argument("--max_repairs", type=int, default=2)
    args = ap.parse_args()

    client = LLMClient()
    if not client.provider:
        print("No LLM credentials in the environment; nothing to record.")
        print("Set ANTHROPIC_API_KEY (or OPENAI_API_KEY / GEMINI_API_KEY / OLLAMA_HOST) and rerun.")
        sys.exit(1)
    print(f"Recording with {client.describe()}")

    miner = TranslatorMiner(parse_args(["--mock", "--mode", "llm", "--max_repairs", str(args.max_repairs),
                                        "--wallet_hotkey", "recorder"]))
    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    rows = []
    for name in tasks:
        for seed in seeds:
            t = sample_task(name, seed=seed)
            t0 = time.time()
            resp = miner.forward(TranslationSynapse(c_code=t.c_code, task_name=name))
            # independent check with a fresh fuzz pass so the table below is honest
            with LocalDiff(t.c_code) as d:
                compiled = d.build_rust(resp.rust_code or "")
                hits = d.fuzz(default_seeds(t.c_code, resp.rust_code or ""), budget_s=5, want=1) if compiled else []
            status = "compile-fail" if not compiled else ("diverges" if hits else "clean")
            rows.append((name, seed, resp.repair_attempts, status, round(time.time() - t0, 1)))
            print(f"  {name:<16} seed={seed:<4} attempts={resp.repair_attempts} {status:<13} {rows[-1][-1]}s  {resp.compiler_notes}")

    print("\nsummary:")
    for name in tasks:
        sub = [r for r in rows if r[0] == name]
        clean = sum(1 for r in sub if r[3] == "clean")
        print(f"  {name:<16} {clean}/{len(sub)} clean after repair loop")
    print("\nrecorded responses are in dataset/llm_replay/ - commit them so the offline demo replays real model output.")


if __name__ == "__main__":
    main()
