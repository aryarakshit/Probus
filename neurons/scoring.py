"""
Scoring and Incentive Engine for Aegis Subnet (neurons/scoring.py)
Implements:
1. Cubed pass-rate formula for translators: pre_t = (passed_hidden / total_hidden) ** 3
2. Sanitizer-verified validity for Breaker inputs (prevention of UB farming)
3. The 50% Anti-Collusion Breaker Bounty rule
4. Invalid input penalties and deduplication
5. Per-UID round scoring and Exponential Moving Average (EMA) weight assignment
"""

import logging
from typing import Dict, List, Any, Tuple, Optional, Set

logger = logging.getLogger("scoring")
MAX_INPUT_SIZE = 16 * 1024  # 16 KB input limit


def calculate_translator_pre_score(
    passed_hidden: int,
    total_hidden: int,
    compile_success: bool = True,
    gate_success: bool = True,
    code_size_bytes: int = 0,
    max_size_bytes: int = 65536
) -> float:
    """
    Computes translator pre-score:
    compile fail / gate fail / oversize -> 0.0
    pre_t = (passed_hidden / total_hidden) ** 3
    """
    if not compile_success or not gate_success:
        return 0.0
    if code_size_bytes > max_size_bytes or total_hidden <= 0:
        return 0.0

    ratio = min(1.0, max(0.0, passed_hidden / total_hidden))
    pre_score = ratio ** 3
    return round(pre_score, 6)


def score_round(
    translators: Dict[str, Dict[str, Any]],
    breaker_submissions: Dict[str, List[bytes]],
    sandbox_runner,
    c_code: str,
    timeout: float = 2.0,
    invalid_penalty: float = 0.05
) -> Dict[str, Any]:
    """
    Scores one complete round across translators and breakers.

    translators: {
        hotkey: {
            "rust_code": str,
            "pre_t": float,
            "passed_hidden": int,
            "total_hidden": int,
            "compile_success": bool,
            "gate_success": bool
        }
    }
    breaker_submissions: {
        hotkey: [input_bytes_1, input_bytes_2, ...]
    }
    """
    # 1. Pre-screen Breaker inputs on ref_san (AddressSanitizer + UndefinedBehaviorSanitizer)
    valid_inputs_by_breaker: Dict[str, List[bytes]] = {}
    invalid_count_by_breaker: Dict[str, int] = {}

    all_breaker_inputs = []
    input_mapping = []  # (b_hk, input_bytes)

    for b_hk, inputs in breaker_submissions.items():
        valid_inputs_by_breaker[b_hk] = []
        invalid_count_by_breaker[b_hk] = 0
        for inp in inputs:
            raw = inp if isinstance(inp, bytes) else str(inp).encode("utf-8")
            if len(raw) > MAX_INPUT_SIZE:
                invalid_count_by_breaker[b_hk] += 1
                continue
            all_breaker_inputs.append(raw)
            input_mapping.append((b_hk, raw))

    if all_breaker_inputs:
        san_results = sandbox_runner.run_sanitizer_precheck(c_code, all_breaker_inputs, timeout=timeout)
        for (b_hk, raw_inp), san_res in zip(input_mapping, san_results):
            if san_res.get("is_clean", False):
                valid_inputs_by_breaker[b_hk].append(raw_inp)
            elif san_res.get("infra_error", False):
                continue  # our harness failed, not the breaker: neither credit nor penalty
            else:
                invalid_count_by_breaker[b_hk] += 1

    # 2. Challenge candidate translators with valid breaker inputs
    breaker_hits: Dict[str, Set[str]] = {t_hk: set() for t_hk in translators}
    breaking_inputs_record: Dict[str, List[Dict[str, Any]]] = {t_hk: [] for t_hk in translators}

    for t_hk, t_info in translators.items():
        pre_t = t_info.get("pre_t", 0.0)
        rust_code = t_info.get("rust_code", "")
        if pre_t <= 0.0 or not rust_code:
            continue

        for b_hk, valid_inputs in valid_inputs_by_breaker.items():
            if not valid_inputs:
                continue

            test_res = sandbox_runner.compile_and_test(
                c_code=c_code,
                rust_code=rust_code,
                test_inputs=valid_inputs,
                timeout=timeout
            )

            divergences = test_res.get("divergences", [])
            if divergences:
                breaker_hits[t_hk].add(b_hk)
                for d in divergences:
                    d = dict(d)
                    d["breaker"] = b_hk
                    breaking_inputs_record[t_hk].append(d)

    # 3. Apply the 50% Anti-Collusion Bounty Rule
    # If translator t is broken by set B_t:
    #   translator t round score = 0.0
    #   each breaker b in B_t earns: 0.5 * pre_t / |B_t|
    final_translator_scores: Dict[str, float] = {}
    breaker_bounties: Dict[str, float] = {b_hk: 0.0 for b_hk in breaker_submissions}

    for t_hk, t_info in translators.items():
        pre_t = t_info.get("pre_t", 0.0)
        b_set = breaker_hits[t_hk]

        if b_set and pre_t > 0.0:
            final_translator_scores[t_hk] = 0.0
            split_bounty = (0.5 * pre_t) / len(b_set)
            for b_hk in b_set:
                breaker_bounties[b_hk] += split_bounty
            logger.info(
                f"[SCORING] Translator {t_hk} BROKEN by {len(b_set)} breakers: "
                f"pre_t={pre_t:.4f} -> 0.0, each breaker receives {split_bounty:.4f}"
            )
        else:
            final_translator_scores[t_hk] = pre_t

    # 4. Apply Breaker Penalties for invalid (UB) inputs floored at 0.0
    final_breaker_scores: Dict[str, float] = {}
    for b_hk in breaker_submissions:
        earned = breaker_bounties.get(b_hk, 0.0)
        invalids = invalid_count_by_breaker.get(b_hk, 0)
        penalty = invalids * invalid_penalty
        score = max(0.0, earned - penalty)
        final_breaker_scores[b_hk] = round(score, 6)

    # 5. Compile aggregate round results per hotkey
    round_scores: Dict[str, float] = {}
    all_hotkeys = set(translators.keys()) | set(breaker_submissions.keys())

    for hk in all_hotkeys:
        t_score = final_translator_scores.get(hk, 0.0)
        b_score = final_breaker_scores.get(hk, 0.0)
        round_scores[hk] = round(t_score + b_score, 6)

    for t_hk in breaking_inputs_record:
        breaking_inputs_record[t_hk].sort(key=lambda d: (d.get("input_len", 0), d.get("input_repr", "")))

    return {
        "round_scores": round_scores,
        "translator_scores": final_translator_scores,
        "breaker_scores": final_breaker_scores,
        "breaker_hits": {k: sorted(v) for k, v in breaker_hits.items()},
        "invalid_counts": invalid_count_by_breaker,
        "valid_counts": {k: len(v) for k, v in valid_inputs_by_breaker.items()},
        "divergences": breaking_inputs_record
    }


def update_ema_weights(
    current_ema: Dict[str, float],
    round_scores: Dict[str, float],
    uids_by_hotkey: Dict[str, int],
    alpha: float = 0.1
) -> Tuple[Dict[str, float], Dict[int, float]]:
    """
    Updates Exponential Moving Average (EMA) per UID:
    EMA_t = (1 - alpha) * EMA_{t-1} + alpha * Score_t
    Normalizes weights so sum(weights) == 1.0 (or 0.0 if all zero).
    """
    new_ema = dict(current_ema)
    for hk, score in round_scores.items():
        prev = new_ema.get(hk, 0.0)
        new_ema[hk] = round((1.0 - alpha) * prev + alpha * score, 6)

    # Normalize across all registered hotkeys/uids
    total_val = sum(new_ema.get(hk, 0.0) for hk in uids_by_hotkey)
    normalized_weights: Dict[int, float] = {}

    for hk, uid in uids_by_hotkey.items():
        val = new_ema.get(hk, 0.0)
        if total_val > 0.0:
            normalized_weights[uid] = round(val / total_val, 6)
        else:
            normalized_weights[uid] = 0.0

    return new_ema, normalized_weights
