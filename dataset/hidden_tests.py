"""
Secret Hidden Test Generator for Differential Verification (dataset/hidden_tests.py)
Produces cryptographically seeded, boundary-dense raw byte test suites.
Pre-checks every input against the AddressSanitizer and UndefinedBehaviorSanitizer
reference binary (ref_san) to ensure 100% UB-free differential testing.
"""

import os
import random
import secrets
from typing import List, Optional, Union


MAX_INPUT_SIZE = 16 * 1024  # 16 KB input size limit


def generate_raw_hidden_tests(count: int = 40, seed: Optional[int] = None) -> List[bytes]:
    """
    Generates deterministic or cryptographically random raw byte edge-cases.
    Seed is generated per validator round using secrets.randbits(64).
    """
    if seed is None:
        seed = secrets.randbits(64)

    rng = random.Random(seed)
    tests: List[bytes] = []

    # 1. Mandatory boundary edge cases
    tests.append(b"")                                      # Empty input
    tests.append(b"\x00")                                  # Single null byte
    tests.append(b"\xff")                                  # Single max byte
    tests.append(b"a")                                     # Single ASCII char
    tests.append(b"\n")                                    # Single newline
    tests.append(b"\r\n")                                  # Windows CRLF
    tests.append(b"\t\r\n ")                               # Whitespaces
    tests.append(b"\x00" * 16)                             # Run of nulls
    tests.append(b"\xff" * 16)                             # Run of 0xFF
    tests.append(b"\x00" * 300)                            # Run > 255 bytes (tests RLE overflow)
    tests.append(b"\xff" * 300)                            # Large run of 0xFF
    tests.append(b"Hello\x00World\x00")                    # Embedded null bytes
    tests.append(b"!@#$%^&*()_+-=[]{}|;':\",./<>?")        # Complex ASCII symbols
    tests.append(b"\xff\xfe\xfd\x80\x81\x82")              # Invalid UTF-8 sequence
    tests.append("🦀 Rust vs C 🚀".encode("utf-8"))        # Valid multi-byte UTF-8 emoji
    tests.append("áéíóúñÁÉÍÓÚÑ".encode("utf-8"))          # Accented UTF-8
    tests.append(b"Line 1\r\nLine 2\nLine 3 (no nl)")      # Mixed line endings
    tests.append(b"A" * 255)                               # 255 boundary
    tests.append(b"B" * 256)                               # 256 boundary
    tests.append(b"C" * 1024)                              # 1 KB buffer boundary
    tests.append(b"\xaa\x55" * 64)                         # Alternating bit patterns
    tests.append(b"0123456789" * 20)                       # Numeric sequence

    # 2. Seeded random bytes and fuzz inputs
    patterns = [
        b"\x00\x01\x02\x03",
        b"abc\n123\n",
        b"\xfe\xff\x00\x01",
        b"\r\n\r\n",
        b" \t \t \n"
    ]

    while len(tests) < count:
        mode = rng.randint(0, 4)
        if mode == 0:
            # Random raw bytes
            length = rng.randint(1, 256)
            data = bytes(rng.randint(0, 255) for _ in range(length))
            tests.append(data)
        elif mode == 1:
            # Pattern repetition
            pat = rng.choice(patterns)
            reps = rng.randint(2, 30)
            tests.append(pat * reps)
        elif mode == 2:
            # High bytes / non-ASCII
            length = rng.randint(4, 64)
            data = bytes(rng.randint(128, 255) for _ in range(length))
            tests.append(data)
        elif mode == 3:
            # Lines of text
            lines = [f"line_{rng.randint(0, 1000)}" for _ in range(rng.randint(1, 10))]
            tests.append("\n".join(lines).encode("utf-8"))
        else:
            # Alternating nulls and ASCII
            chars = [rng.choice([b"\x00", b"x", b" ", b"\n"]) for _ in range(rng.randint(5, 50))]
            tests.append(b"".join(chars))

    # Enforce max input size
    return [t[:MAX_INPUT_SIZE] for t in tests[:count]]


def generate_sanitizer_verified_hidden_tests(
    c_code: str,
    sandbox_runner,
    count: int = 30,
    seed: Optional[int] = None
) -> List[bytes]:
    """
    Generates the hidden test suite and verifies each candidate on ref_san (ASan+UBSan).
    Inputs that trigger sanitizer diagnostics, crash, or time out are dropped; inputs that
    make the reference exit non-zero are kept - error paths are part of the contract.
    """
    if seed is None:
        seed = secrets.randbits(64)

    # Structural boundary probes derived from the constants in this round's C source
    # (n-1, n, n+1, 2n ... for every #define and array size), then seeded random fuzz.
    from neurons.difffuzz import boundary_seeds
    structural = boundary_seeds(c_code)
    rng = random.Random(seed)
    rng.shuffle(structural)
    keep = max(4, count // 3)
    candidates = structural[:keep] + generate_raw_hidden_tests(count=count + 15, seed=seed)

    # Run sanitizer check
    san_results = sandbox_runner.run_sanitizer_precheck(c_code, candidates, timeout=2.0)

    clean_tests: List[bytes] = []
    for cand, res in zip(candidates, san_results):
        if res.get("is_clean", False):
            clean_tests.append(cand)
            if len(clean_tests) >= count:
                break

    return clean_tests


if __name__ == "__main__":
    cases = generate_raw_hidden_tests(count=10, seed=42)
    print(f"Generated {len(cases)} raw byte test cases:")
    for idx, c in enumerate(cases):
        print(f"[{idx+1:02d}] len={len(c)}: {repr(c[:40])}")
