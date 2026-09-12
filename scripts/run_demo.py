"""
Live subnet demo (scripts/run_demo.py)

Spins up one validator and four neurons on the mock substrate and runs real
validation rounds - real compilers, real sanitizers, real differential fuzzing:

  translator_llm      the actual miner: provider-agnostic LLM translation with a
                      self-fuzzing repair loop. Uses whatever credentials are in
                      the environment; with none, it replays recorded model output
                      from dataset/llm_replay/ (see scripts/record_translations.py).
  translator_weak     benchmark fixture with a realistic porting bug
  translator_cheater  benchmark fixture that uses `unsafe`
  breaker             differential fuzzer hunting for bounty

Nothing printed here is scripted: every number comes out of the round.

    python scripts/run_demo.py --rounds 3
    python scripts/run_demo.py --task utf8_validate --seed 7
"""

import sys
import os
import time
import base64
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")
os.environ.setdefault("PROBUS_MOCK", "1")

from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, parse_args as parse_val_args
from neurons.llm import LLMClient
from dataset.tasks import list_tasks, TASK_DESCRIPTIONS

REPLAY_SEEDS = [101, 202, 303]   # the seeds scripts/record_translations.py records


def banner(text: str):
    print("\n" + "=" * 88)
    print(f" {text}")
    print("=" * 88)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--task", type=str, default=None, help="one of: " + ", ".join(list_tasks()))
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--tests", type=int, default=20)
    ap.add_argument("--fuzz_seconds", type=float, default=8.0)
    ap.add_argument("--self_fuzz_seconds", type=float, default=4.0)
    ap.add_argument("--docker", action="store_true", help="use the Docker sandbox instead of the host toolchain")
    args = ap.parse_args()

    banner("PROBUS SUBNET - LIVE ADVERSARIAL C-TO-SAFE-RUST VALIDATION")
    probe = LLMClient()
    if probe.provider:
        print(f"[LLM] live provider: {probe.describe()}")
    else:
        print("[LLM] no credentials found -> translator_llm replays recorded model output from dataset/llm_replay/")
        print("      (set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY / OLLAMA_HOST for a live run)")

    v_args = parse_val_args(["--mock"] + ([] if args.docker else ["--no_docker"]))
    v_args.wallet_hotkey = "validator"
    validator = Validator(v_args)

    def mk_tr(hotkey, mode, extra=()):
        a = parse_tr_args(["--mock", "--mode", mode, "--wallet_hotkey", hotkey, *extra])
        return TranslatorMiner(a).run()

    m_llm = mk_tr("translator_llm", "llm", ["--self_fuzz_seconds", str(args.self_fuzz_seconds)])
    m_weak = mk_tr("translator_weak", "weak")
    m_cheat = mk_tr("translator_cheater", "cheater")
    b_args = parse_br_args(["--mock", "--wallet_hotkey", "breaker", "--fuzz_seconds", str(args.fuzz_seconds)])
    m_break = BreakerMiner(b_args).run()

    translators = [m_llm.axon, m_weak.axon, m_cheat.axon]
    breakers = [m_break.axon]
    print(f"\n[SETUP] 3 translators + 1 breaker online. Task pool: {len(list_tasks())} programs.")

    totals = {}
    for r in range(1, args.rounds + 1):
        seed = args.seed if args.seed is not None else (None if probe.provider else REPLAY_SEEDS[(r - 1) % len(REPLAY_SEEDS)])
        banner(f"ROUND {r}/{args.rounds}")
        t0 = time.time()
        res = validator.run_validation_round(translators, breakers, num_tests=args.tests, task_name=args.task, seed=seed)
        entry = res["log_entry"]
        print(f"\n[ROUND {r}] task={entry['task_name']} {entry['constants']}  "
              f"hidden_tests={entry['hidden_tests']}  {time.time() - t0:.1f}s")
        print(f"  {TASK_DESCRIPTIONS.get(entry['task_name'], '')}")
        print(f"\n  {'neuron':<20} {'gate':<6} {'rustc':<6} {'hidden':<9} {'pre_t':<8} {'final':<8} verdict")
        for hk, ev in entry["translator_evals"].items():
            gate = "PASS" if ev["gate_success"] else "REJECT"
            comp = "ok" if ev["compile_success"] else ("-" if not ev["gate_success"] else "FAIL")
            hidden = f"{ev['passed_hidden']}/{ev['total_hidden']}" if ev["compile_success"] else "-"
            verdict = ev.get("reject_reason") or ""
            if ev["broken_by"]:
                rep = ev["reproducers"][0]
                verdict = f"BROKEN by {ev['broken_by']} - reproducer {rep['input_len']}B {rep['input_repr']} ({rep['reason']})"
            elif ev["compile_success"] and ev["final_score"] > 0:
                verdict = f"survived ({ev['attempts']} attempt(s); {ev['miner_notes']})"
            elif not ev["compile_success"] and ev["gate_success"]:
                verdict = "rustc: " + (ev.get("compile_error") or "")[:60]
            print(f"  {hk:<20} {gate:<6} {comp:<6} {hidden:<9} {ev['pre_t']:<8.4f} {ev['final_score']:<8.4f} {verdict}")
        for hk, ev in entry["breaker_evals"].items():
            print(f"  {hk:<20} {'-':<6} {'-':<6} {ev['valid_inputs']:>3} valid  {'':<8} {ev['final_score']:<8.4f} bounty")
        print(f"\n  weights -> {entry['normalized_weights']}")
        led = entry.get("ledger", {})
        if "root" in led:
            print(f"  ledger  -> height {led['height']}  root {led['root'][:20]}…  prev {led['prev_root'][:12]}…")
        for hk, sc in entry["round_scores"].items():
            totals[hk] = totals.get(hk, 0.0) + sc

    banner("SUMMARY")
    print(f"  {'neuron':<20} {'avg score':<12} {'EMA weight':<12}")
    for hk, tot in sorted(totals.items(), key=lambda x: -x[1]):
        print(f"  {hk:<20} {tot / args.rounds:<12.4f} {validator.ema_scores.get(hk, 0.0):<12.4f}")
    v = validator.ledger.verify()
    print(f"\n  ledger verify: {'OK' if v['ok'] else 'FAILED'}  rounds={v['rounds']} objects={v['objects_checked']} head={v['head'][:16]}…")
    print("  round log   : rounds.jsonl   dashboard: python server.py\n")


if __name__ == "__main__":
    main()
