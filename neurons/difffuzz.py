"""
Local differential fuzzing engine (neurons/difffuzz.py).

Shared by both miner roles:
  * the Translator runs it against its own candidate before submitting
    (self-red-team: any divergence found here is fed back into the repair loop);
  * the Breaker runs it against a rival's candidate to find bounty-earning inputs.

It compiles the C reference twice (plain -O2 oracle and an ASan/UBSan build that
decides whether an input is *valid*), compiles the Rust candidate, then mutates
seed inputs and keeps every input where the two programs disagree on stdout bytes
or exit code. Each hit is shrunk with delta debugging so the reproducer submitted
to the validator is as small as possible.

Nothing here talks to the validator's Docker sandbox: miners own their toolchain.
"""

import os
import re
import sys
import time
import random
import base64
import shutil
import struct
import tempfile
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Callable

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox.batch_runner import run_batch
from sandbox.sandbox_runner import _get_rustc_extra_args

MAX_INPUT = 16 * 1024
EXE = ".exe" if sys.platform == "win32" else ""

INTERESTING_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFF, 0x0A, 0x0D, 0x20, 0x09, 0x22, 0x5C, 0x3D, 0x5B, 0x5D, 0x2C]
INTERESTING_INTS = [0, 1, 127, 128, 255, 256, 16383, 16384, 32767, 32768, 65535, 65536,
                    2**21 - 1, 2**21, 2**28 - 1, 2**28, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**35, 2**63 - 1]


def input_is_valid(run_result: Dict[str, Any]) -> bool:
    """Shared validity rule for one sanitizer-build execution record (see LocalDiff.is_clean)."""
    if run_result.get("timed_out"):
        return False
    if run_result.get("sanitizer_triggered"):
        return False
    code = run_result.get("exit_code", -1)
    return 0 <= code <= 127

BASE_SEEDS: List[bytes] = [
    b"", b"\x00", b"\xff", b"a", b"\n", b"\r\n", b" \t\r\n ",
    b"\x00" * 16, b"\xff" * 16, b"\x00" * 300, b"\xff" * 300,
    b"Hello\x00World\x00", b"!@#$%^&*()_+-=[]{}|;':\",./<>?",
    b"\xff\xfe\xfd\x80\x81\x82", "🦀 Rust vs C 🚀".encode("utf-8"),
    "áéíóúñÁÉÍÓÚÑ".encode("utf-8"), b"Line 1\r\nLine 2\nLine 3 (no nl)",
    b"A" * 255, b"B" * 256, b"C" * 1024, b"\xaa\x55" * 64, b"0123456789" * 20,
    b"key=value\n", b"[section]\nk = v\n", b"a,b,c\n\"q,\"\"x\"\"\",1\n",
    b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
    b"\xc0\x80", b"\xe0\x80\x80", b"\xf0\x9f\xa6\x80",
]


@dataclass
class Divergence:
    input: bytes
    c_stdout: bytes
    r_stdout: bytes
    c_exit: int
    r_exit: int
    r_timed_out: bool
    reason: str
    minimized_from: int = 0
    origin: str = "fuzz"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_b64": base64.b64encode(self.input).decode("ascii"),
            "input_repr": repr(self.input[:64]),
            "input_len": len(self.input),
            "minimized_from": self.minimized_from,
            "c_stdout_b64": base64.b64encode(self.c_stdout[:256]).decode("ascii"),
            "rust_stdout_b64": base64.b64encode(self.r_stdout[:256]).decode("ascii"),
            "c_exit": self.c_exit,
            "rust_exit": self.r_exit,
            "rust_timed_out": self.r_timed_out,
            "reason": self.reason,
            "origin": self.origin,
        }


# ----------------------------------------------------------------------------
# Static seed extraction
# ----------------------------------------------------------------------------
def extract_constants(c_code: str) -> Dict[str, int]:
    """Pull `#define NAME <int>` and obvious array sizes out of the C source."""
    consts: Dict[str, int] = {}
    for m in re.finditer(r"#define\s+([A-Za-z_]\w*)\s+\(?\s*(\d+)\s*\)?", c_code):
        consts[m.group(1)] = int(m.group(2))
    for m in re.finditer(r"\[\s*(\d{1,6})\s*\]", c_code):
        n = int(m.group(1))
        if 1 < n <= 65536:
            consts.setdefault(f"array_{n}", n)
    return consts


def boundary_seeds(c_code: str, rust_code: str = "") -> List[bytes]:
    """Inputs sized around every constant the translator might have mishandled."""
    seeds: List[bytes] = []
    values = set(extract_constants(c_code).values())
    for m in re.finditer(r"\b(\d{1,6})\b", rust_code):
        n = int(m.group(1))
        if 1 < n <= 4096:
            values.add(n)
    for n in sorted(values):
        if n > MAX_INPUT // 2:
            continue
        for k in (n - 1, n, n + 1, 2 * n, 2 * n + 1):
            if 0 <= k <= MAX_INPUT:
                seeds.append(b"X" * k)
                seeds.append(bytes((i % 256) for i in range(k)))
                seeds.append(b"\x00" * k)
        seeds.append((b"a" * n + b"\n") * 3)
        seeds.append(b"\xff" * n + b"\n")
    return seeds


# ----------------------------------------------------------------------------
# Mutation engine
# ----------------------------------------------------------------------------
def mutate(data: bytes, rng: random.Random, pool: List[bytes]) -> bytes:
    op = rng.randint(0, 12)
    b = bytearray(data)
    if op == 0 and b:                       # bit flip
        i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif op == 1 and b:                     # interesting byte
        i = rng.randrange(len(b)); b[i] = rng.choice(INTERESTING_BYTES)
    elif op == 2:                           # insert byte
        i = rng.randint(0, len(b)); b.insert(i, rng.choice(INTERESTING_BYTES + [rng.randrange(256)]))
    elif op == 3 and b:                     # delete byte
        del b[rng.randrange(len(b))]
    elif op == 4 and b:                     # duplicate a chunk
        i = rng.randrange(len(b)); j = min(len(b), i + rng.randint(1, 64)); b[j:j] = b[i:j]
    elif op == 5 and b:                     # truncate
        b = b[: rng.randrange(len(b))]
    elif op == 6:                           # append run
        b += bytes([rng.choice(INTERESTING_BYTES)]) * rng.choice([1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 257])
    elif op == 7 and pool:                  # splice with another seed
        other = rng.choice(pool)
        if other:
            cut = rng.randint(0, len(b)); ocut = rng.randint(0, len(other)); b = b[:cut] + other[ocut:]
    elif op == 8:                           # inject interesting int (LE / BE / decimal / LEB128)
        n = rng.choice(INTERESTING_INTS)
        form = rng.randint(0, 3)
        if form == 0: enc = struct.pack("<I", n & 0xFFFFFFFF)
        elif form == 1: enc = struct.pack(">I", n & 0xFFFFFFFF)
        elif form == 2: enc = str(n).encode()
        else:
            enc = b""; v = n
            while True:
                byte = v & 0x7F; v >>= 7
                enc += bytes([byte | (0x80 if v else 0)])
                if not v: break
        i = rng.randint(0, len(b)); b[i:i] = enc
    elif op == 9 and b:                     # newline games
        i = rng.randrange(len(b)); b[i:i + 1] = rng.choice([b"\n", b"\r\n", b"\r", b"\n\n", b""])
    elif op == 10:                          # high-bit / invalid UTF-8 injection
        i = rng.randint(0, len(b)); b[i:i] = rng.choice([b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\x80", b"\xff\xfe", b"\xe2\x82"])
    elif op == 11 and b:                    # repeat whole input
        b = bytes(b) * rng.choice([2, 3, 4])
    else:                                   # random bytes
        b = bytes(rng.randrange(256) for _ in range(rng.randint(1, 96)))
    out = bytes(b)
    return out[:MAX_INPUT]


# ----------------------------------------------------------------------------
# Toolchain + execution
# ----------------------------------------------------------------------------
class LocalDiff:
    """Compile once, run many. Call close() (or use as a context manager) to clean up."""

    def __init__(self, c_code: str, rust_code: Optional[str] = None, timeout: float = 2.0):
        self.c_code = c_code
        self.timeout = timeout
        self.work = tempfile.mkdtemp(prefix="aegis_fuzz_")
        self.rustc_extra = _get_rustc_extra_args()
        self.c_bin: Optional[str] = None
        self.c_san: Optional[str] = None
        self.r_bin: Optional[str] = None
        self.c_error = ""
        self.rust_error = ""
        self._cache: Dict[Tuple[str, bytes], Dict[str, Any]] = {}
        self.build_c()
        if rust_code is not None:
            self.build_rust(rust_code)

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _run_cmd(self, cmd: List[str], timeout: float = 60.0) -> Tuple[bool, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return res.returncode == 0, res.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return False, "compiler timed out"
        except Exception as e:
            return False, str(e)

    def build_c(self) -> bool:
        src = os.path.join(self.work, "ref.c")
        with open(src, "w", encoding="utf-8") as f:
            f.write(self.c_code)
        plain = os.path.join(self.work, "ref" + EXE)
        san = os.path.join(self.work, "ref_san" + EXE)
        ok, err = self._run_cmd(["gcc", "-std=c11", "-O2", src, "-o", plain])
        if not ok:
            self.c_error = err
            return False
        ok2, err2 = self._run_cmd(["gcc", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined",
                                   "-fno-sanitize-recover=all", src, "-o", san])
        self.c_bin = plain
        self.c_san = san if ok2 else plain   # fall back to plain oracle if sanitizers unavailable
        return True

    def build_rust(self, rust_code: str) -> bool:
        src = os.path.join(self.work, "cand.rs")
        with open(src, "w", encoding="utf-8") as f:
            f.write(rust_code)
        out = os.path.join(self.work, "cand" + EXE)
        ok, err = self._run_cmd(["rustc"] + self.rustc_extra + ["--edition", "2021", "-O",
                                 "-C", "overflow-checks=on", "-F", "unsafe_code", src, "-o", out])
        self.rust_error = "" if ok else err
        self.r_bin = out if ok else None
        self._cache = {k: v for k, v in self._cache.items() if k[0] != "r"}
        return ok

    def _exec(self, which: str, inputs: List[bytes]) -> List[Dict[str, Any]]:
        binary = {"c": self.c_bin, "s": self.c_san, "r": self.r_bin}[which]
        if binary is None:
            return [{"exit_code": -1, "stdout_b64": "", "stderr_b64": "", "timed_out": False, "sanitizer_triggered": False} for _ in inputs]
        todo = [i for i in inputs if (which, i) not in self._cache]
        if todo:
            for inp, res in zip(todo, run_batch(binary, todo, per_test_timeout=self.timeout)):
                self._cache[(which, inp)] = res
        return [self._cache[(which, i)] for i in inputs]

    def is_clean(self, inputs: List[bytes]) -> List[bool]:
        """Valid input == the ASan/UBSan build finishes with no diagnostic, no crash signal, no timeout.

        A non-zero *programmatic* exit code (0..127) is still valid: many real programs
        report bad input that way, and those paths are exactly what a translation must match."""
        return [input_is_valid(r) for r in self._exec("s", inputs)]

    def compare(self, inputs: List[bytes], origin: str = "fuzz") -> List[Divergence]:
        if not inputs or self.r_bin is None:
            return []
        c_res = self._exec("c", inputs)
        r_res = self._exec("r", inputs)
        hits: List[Divergence] = []
        for inp, c, r in zip(inputs, c_res, r_res):
            if c["exit_code"] == -1 or (r["exit_code"] == -1 and not r["timed_out"]):
                # launch failure on our side: forget the cached record so it is retried later
                self._cache.pop(("c", inp), None); self._cache.pop(("r", inp), None)
                continue
            c_out = base64.b64decode(c["stdout_b64"]); r_out = base64.b64decode(r["stdout_b64"])
            if c_out == r_out and c["exit_code"] == r["exit_code"] and not r["timed_out"]:
                continue
            reason = ("rust timeout" if r["timed_out"] else
                      "exit code mismatch" if c["exit_code"] != r["exit_code"] else "stdout mismatch")
            if r["exit_code"] == 101:
                reason = "rust panic"
            hits.append(Divergence(inp, c_out, r_out, c["exit_code"], r["exit_code"], r["timed_out"], reason, origin=origin))
        return hits

    # ------------------------------------------------------------- minimize
    def minimize(self, inp: bytes, max_iters: int = 400, budget_s: float = 3.0) -> bytes:
        """ddmin over bytes: shrink while the input still diverges AND is still sanitizer-clean."""
        deadline = time.time() + budget_s
        def still_bad(candidate: bytes) -> bool:
            if not self.is_clean([candidate])[0]:
                return False
            return bool(self.compare([candidate], origin="min"))

        cur = inp
        if len(cur) <= 1 or not still_bad(cur):
            return cur
        n = 2
        iters = 0
        while len(cur) >= 2 and iters < max_iters and time.time() < deadline:
            chunk = max(1, len(cur) // n)
            reduced = False
            for i in range(0, len(cur), chunk):
                iters += 1
                trial = cur[:i] + cur[i + chunk:]
                if trial != cur and still_bad(trial):
                    cur = trial
                    n = max(n - 1, 2)
                    reduced = True
                    break
            if not reduced:
                if n >= len(cur):
                    break
                n = min(len(cur), n * 2)
        return cur

    # ----------------------------------------------------------------- fuzz
    def fuzz(
        self,
        seeds: List[bytes],
        budget_s: float = 8.0,
        batch: int = 24,
        rng: Optional[random.Random] = None,
        want: int = 8,
        minimize: bool = True,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> List[Divergence]:
        """Mutate seeds until the time budget runs out; return unique, minimized, valid divergences."""
        if self.r_bin is None:
            return []
        rng = rng or random.Random()
        pool = [s[:MAX_INPUT] for s in seeds if s is not None]
        found: Dict[bytes, Divergence] = {}
        seen: set = set()
        deadline = time.time() + budget_s

        def absorb(cands: List[bytes], origin: str):
            fresh = [c for c in cands if c not in seen]
            for c in fresh: seen.add(c)
            if not fresh: return
            hits = self.compare(fresh, origin=origin)
            if not hits: return
            clean = self.is_clean([h.input for h in hits])
            for h, ok in zip(hits, clean):
                if not ok: continue
                key = h.input
                remaining = deadline - time.time()
                # Minimize only while there is budget left; a 4 KB reproducer that arrives late
                # is still a hit, just not a small one.
                if minimize and len(h.input) > 1 and remaining > 0.5:
                    small = self.minimize(h.input, budget_s=min(3.0, remaining))
                    if small != h.input:
                        for m in self.compare([small], origin=origin):
                            m.minimized_from = len(h.input); h = m
                    key = h.input
                if key not in found:
                    found[key] = h
                    if on_progress: on_progress(f"divergence #{len(found)} ({h.reason}) len={len(h.input)} from {origin}")

        # Seeds are probed in batches so the deadline is honoured even with many seeds.
        for i in range(0, len(pool), batch):
            if time.time() >= deadline or len(found) >= want:
                break
            absorb(pool[i:i + batch], "seed")
        gen = 0
        while time.time() < deadline and len(found) < want:
            gen += 1
            parents = pool + [d.input for d in found.values()]
            mutants = [mutate(rng.choice(parents), rng, pool) for _ in range(batch)]
            absorb(mutants, f"gen{gen}")
        return list(found.values())


def default_seeds(c_code: str, rust_code: str = "") -> List[bytes]:
    return BASE_SEEDS + boundary_seeds(c_code, rust_code)
