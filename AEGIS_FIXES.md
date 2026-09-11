# Aegis Subnet — Fix Plan

**Deadlines:**
- **Sep 20, 2026:** Checkpoint #1, subnet proposal.
- **Oct 19, 2026:** final submission. Requires a **working Bittensor testnet deployment**, real miner–validator evaluation, and a demo video on testnet.
- For reference, the showcased example (Proven) ran 3 validators + 10 miners on testnet.

**Rule for whoever implements this:** no emulators, no hardcoded outcomes. If Docker or the chain isn't available, fail loudly. Never fake results.

> **Recheck (Sep 11):** 2 new commits were pushed since review. Both only restyle the dashboard (`server.py`: colours and fonts); nothing was fixed.
> - The dashboard still starts the hardcoded honest/weak/cheater miners and scores them through the fake emulator. A nicer UI is displaying fabricated results.
> - The hackathon page says polish is not the priority. **Freeze all UI work until the sandbox and scoring are real.**
>
> This recheck also fixed the purge command and added the items marked **(new)**.

---

## P0 — Do today

1. **Purge the `.md/` AI-agent prompts** (and the empty `mem.json`) from git history:
   ```bash
   git filter-repo --path .md --path mem.json --invert-paths && git push --force --all
   ```
2. **Remove false claims** from the README and pitch until they're true:
   - "production-ready"
   - "slashing": Aegis has no stake or collateral, so a zero score only means zero emissions. Real slashing would need a collateral contract.
   - "cryptographically randomized": the tests use `random.Random(42)`.
   - "Hypothesis-driven": the strategy is defined but never used.
   - "--read-only sandbox": the flag isn't passed.
   - "<1 ms gate"
3. **Delete the scripted conclusions** in `scripts/run_demo.py`. The labels like "VERIFIED_SAFE / HIGH REWARD" and the "PROOF OF ADVERSARIAL INTEGRITY" lines are hardcoded prints.

---

## P1 — Sandbox (currently fake; fix first)

### 1. Delete the emulator

**Problem:** `_run_emulated_or_local` doesn't compile anything; it greps for strings like `"WEAK MINER"`. Arbitrary text scores a 100% pass rate and 1.1998 (≈ max).

**Fix:**
- Remove the emulator entirely.
- No Docker → raise an error.
- A dev-only escape hatch (`AEGIS_ALLOW_UNSANDBOXED=1`) may run the *same* real compile/run pipeline natively, never a simulation.

### 2. I/O contract (fixes argv null-byte crash + text decoding)

- **Tasks** are whole C programs: read all of **stdin as bytes**, write **stdout bytes**, return an exit code.
- **Submissions** are whole Rust programs with `fn main()` doing the same. Your "honest" miner currently has no `main`, so it can't compile.
- **Tests** are passed via stdin, never argv. Argv can't carry `\x00`, and `subprocess` raises `ValueError` on it today.
- **Never** use `text=True`. Compare raw bytes; C output is often invalid UTF-8.

### 3. Compile rules

```text
C reference (trusted):  gcc -std=c11 -O2 ref.c -o ref
C sanitizer build:      gcc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all ref.c -o ref_san
Rust candidate:         rustc --edition 2021 -O -C overflow-checks=on -F unsafe_code main.rs -o cand
```

- `-F unsafe_code` is the real enforcement. A forbidden lint can't be re-allowed inside the file. The regex gate is only a cheap pre-filter, and today `use std::process as p;` bypasses it.
- No Cargo means no crates. Compile inside a container that holds only `main.rs`, so `include_bytes!` can't read anything interesting.
- Source size limit: e.g. 64 KB.

### 4. Run rules (Docker)

```text
docker run --rm --name <unique> --network none --read-only \
  --tmpfs /tmp:rw,noexec,size=16m --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m --memory-swap 256m --cpus 1 --user 65534:65534 ...
```

- **Batch** all tests for one submission in **one** container using a small trusted runner. Per test it enforces a timeout and output-size cap, captures stdout and the exit code, and returns JSON. Today the code starts 2 containers per test.
- **Host-side timeouts must also `docker rm -f <name>`.** Killing the docker CLI does not stop the container.
- Run the C reference and the Rust candidate in **separate** containers.
- **Pass** = identical stdout bytes **and** identical exit code.

**Done when:**
- A known-correct Rust translation scores 100%.
- Char-reversal vs byte-reversal fails on non-ASCII input.
- A program without `main` fails compilation.
- `unsafe` is rejected by rustc even when the regex is bypassed.
- A `\x00` input works via stdin.
- An infinite loop times out and leaves no container running.

---

## P1 — Tasks & hidden tests (currently one fixed task + public seed)

### Task pool

- **Problem:** every round is `reverse_string` with `seed=42` tests from the public repo, so miners just cache answers.
- **Pool:** C programs that are **UB-free for every input**:
  - use unsigned arithmetic for wraparound (signed overflow is UB);
  - bounds-check everything.
- **Per-round constants:** parameterize each task with constants injected into the C source every round, so cached translations break.
- **Starter set** (then grow from CRUST-Bench-style programs):

| Task | Per-round constant | Edge cases it forces |
|---|---|---|
| `reverse_bytes` | chunk size | byte vs char, `\x00` |
| `rle_encode` | max run length | runs > 255, empty input |
| `fnv1a_lines` | offset basis / prime | `u32` wraparound, CRLF, no trailing newline |
| `crc32` | polynomial | bit ops, large input |
| `parse_sum_i64` | separator set | signs, overflow, junk tokens (wrapping sum) |
| `base64_encode` | alphabet permutation | padding, lengths mod 3 |

### Hidden tests

- **Seed:** `secrets.randbits(64)` per validator per round; never sent to miners.
- **Generator per task:** empty, 1 byte, `0x00`, `0xFF` runs, invalid UTF-8, boundary lengths, CRLF / no final newline, overflow-sized numbers, plus random bytes. Enforce a max input size.
- **Pre-check:** every hidden input runs on `ref_san` first. Drop any input that triggers a sanitizer report.
- **Publish:** release inputs only **after** the round (dataset value); the next round's constants differ.

---

## P1 — Scoring & incentives (currently gameable)

### Translator score

```text
compile fail / gate fail / oversize        -> 0
pre_t = (passed_hidden / total_hidden) ** 3
```

- **Remove the speed bonus.** It rewards caching and pre-computation. If you want a tie-breaker, cap it at a few percent, only for 100%-correct submissions, measured relative to the C runtime.

### Breakers: validity, attribution, anti-collusion

- **Problem:** today the breaker gets `0.50` if **any** translator diverges (even from hidden tests) and `0.05` for sending nothing. Only `breaker_axons[0]` is paid.
- **Valid input:** size ≤ limit, **and** `ref_san` runs clean within the timeout. An input is invalid if it crashes, times out, or its stderr contains `runtime error:` or `AddressSanitizer`.
  - This is critical: differential testing on inputs that trigger UB in C is meaningless, and breakers would farm them.
- **Break:** a valid input where the candidate's stdout or exit code differs from `ref`.
- **The 50% rule:** if translator `t` is broken by breaker set `B_t`:
  ```text
  translator t round score = 0
  each b in B_t earns        0.5 * pre_t / |B_t|
  ```
  - A colluding pair (plant a bug, claim the bounty) loses `pre_t` and gains `0.5 * pre_t`, so it's always unprofitable.
  - Breaking strong translators pays more than breaking weak ones, which is the right incentive.
- **Dedupe:** identical inputs from several breakers split the bounty.
- **Penalties:** empty response → 0. Each invalid input → small penalty, floored at 0.
- **Ordering:** breakers receive translator code only **after** the translation deadline.

### Weights

**Problem:** weights are currently set by response list index, and the breaker gets `uid = len(uids)`.

**Fix:**
- Iterate `metagraph` **UIDs**; query every serving axon. A miner may act as translator, breaker, or both.
- Per-UID round score = translator score + breaker earnings.
- Keep an EMA per UID (α ≈ 0.1). Normalize to weights.
- Set weights once per tempo while respecting the weights rate limit; include a `version_key`.

---

## P1 — Neurons (currently exit immediately)

### Validator

`while True`:
1. Sync the metagraph.
2. Sample a task and fresh constants; generate hidden tests.
3. Query translators → sandbox → query breakers → validate inputs → score.
4. Update the EMA; set weights on schedule.

Log every round to a JSONL file. The dashboard must read this file, not mock data.

### Miners (both roles)

- Serve an axon and keep the process alive.
- Blacklist unregistered hotkeys and callers without a validator permit; prioritize by stake.

### Translator miner

Replace the hardcoded templates:
1. Call a real LLM (provider-agnostic; key from env). The prompt contains the C source, the I/O contract, and the rules (no `unsafe`, exact byte semantics, wrapping arithmetic where C uses unsigned).
2. Locally compile with the **same flags**.
3. Run local differential tests against the locally compiled C.
4. Feed failures back to the LLM, up to N repair attempts.

### Breaker miner

Replace the static list with real search:
1. Compile `ref_san` and the candidate locally, sandboxed.
2. Mutation-fuzz from edge-case seeds: bit flips, boundary bytes, length extremes, splicing.
3. Keep inputs that diverge **and** are sanitizer-clean; return the top-k with a rationale.

---

## P1 — Testnet (required for final judging)

1. Get a testnet netuid: create one (needs testnet TAO; ask the Bittensor community or the organizers) or use a hackathon-provided one. Check `btcli --help` for your version's commands.
2. Remove the silent mock fallback in `substrate/__init__.py` for testnet runs. Mock only via an explicit `--mock` flag.
3. **Run at least 2 validators + 5 miners:**
   - 1–2 LLM translators;
   - 1 deliberately weak translator;
   - 1 breaker;
   - 1 **colluding translator + breaker pair**, to show on-chain that the 50% rule makes collusion lose.
4. **Evidence:** weights on chain, per-round JSONL logs, the dashboard reading real results, and a demo video of all of it.

---

## P2 — Dataset (backs the "verified dataset" pitch)

- **Per round, store:** task instance hash, C source, Rust source, pass stats, and breaking inputs.
- **Signing:** records signed with the validator hotkey. Only then is "cryptographically verified" true.
- **Publishing:** release after the round.

---

## Tests (acceptance criteria)

**Sandbox**
- Correct translation = 100%.
- Byte-vs-char bug caught.
- No `main` → compile fail.
- `unsafe` rejected by rustc.
- `\x00` via stdin OK.
- Timeout kills the container.
- Output-size cap enforced.
- No Docker → hard error.

**Tasks**
- Every hidden input is sanitizer-clean.
- Same seed → same task and tests; different seed → different constants.

**Scoring**
- The 50% rule makes collusion net-negative.
- Bounty splits across breakers.
- Invalid (UB) input earns nothing and is penalized.
- Empty breaker response → 0.
- Weights sum to 1 and map to the correct UIDs.

**End-to-end (local chain or testnet)**
- The weak translator ranks below the LLM translator.
- The breaker earns only when it actually breaks something.
- The colluding pair earns less than honest play.

---

## Proposal (Sep 20) must contain

1. The problem, and why C→Rust verification is a digital commodity.
2. Miner roles and the I/O contract.
3. The sandbox spec: flags, limits, fail-closed.
4. The task pool, per-round constants, and secret hidden tests.
5. Scoring formulas: `pre_t`, breaker validity via sanitizers, the 50% rule, EMA → weights.
6. The attack list with a mitigation for each: caching, copying, UB farming, collusion, sandbox escape, gate bypass.
7. The testnet plan and roadmap.

## Order of work

| Dates | Work |
|---|---|
| Sep 11–20 | P0, sandbox rewrite + tests, 3 tasks, scoring module + tests, write the proposal |
| Sep 21–30 | Validator/miner loops, real LLM translator, fuzzing breaker, local end-to-end |
| Oct 1–10 | Testnet deployment, adversarial miners, JSONL logs, dashboard on real data |
| Oct 11–19 | Remaining tasks, dataset signing, README honesty pass, demo video, final pitch |
