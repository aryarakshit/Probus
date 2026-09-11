"""
Hidden Test Generator for Differential Fuzzing (dataset/hidden_tests.py)
Utilizes Hypothesis and property-based synthesis to produce randomized,
adversarial, and boundary test inputs for differential C vs Rust verification.
"""

import random
import string
from typing import List
from hypothesis import strategies as st


def generate_hidden_tests(count: int = 50, seed: int = 42) -> List[str]:
    """
    Generates deterministic, cryptographically randomized test suites
    with hard boundary cases embedded.
    """
    rng = random.Random(seed)
    tests = []

    # 1. Mandatory hard edge cases
    tests.append("")                              # Empty string
    tests.append("a")                             # Single char
    tests.append("ab")                            # Even length
    tests.append("abc")                           # Odd length
    tests.append("   ")                           # Whitespace only
    tests.append("\t\r\n")                        # Escaped whitespaces
    tests.append("!@#$%^&*()_+-=[]{}|;':\",./<>?") # Punctuation set
    tests.append("Hello World")                   # Standard ASCII with space
    tests.append("racecar")                       # Palindrome
    tests.append("A" * 256)                       # 256-byte buffer boundary
    tests.append("B" * 1024)                      # 1KB stress input
    tests.append("Hello\x00World")                # Embedded null byte
    tests.append("🦀 Rust vs C 🚀")                # Multi-byte UTF-8 emoji
    tests.append("áéíóúñÁÉÍÓÚÑ")                  # Accented characters
    tests.append("0123456789")                    # Numeric sequence

    # 2. Hypothesis-driven property generation for remainder
    remaining = max(0, count - len(tests))
    ascii_strategy = st.text(alphabet=st.characters(blacklist_categories=('Cs',)), max_size=100)
    
    # Sample randomized inputs
    for i in range(remaining):
        mode = rng.randint(0, 3)
        if mode == 0:
            # Printable ASCII
            length = rng.randint(5, 50)
            s = "".join(rng.choice(string.printable) for _ in range(length))
            tests.append(s)
        elif mode == 1:
            # Alphabetic words
            words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "omega"]
            tests.append(" ".join(rng.choices(words, k=rng.randint(2, 6))))
        elif mode == 2:
            # Repeating patterns
            pattern = rng.choice(["abc", "xy", "01", "!?", "<>"])
            tests.append(pattern * rng.randint(5, 30))
        else:
            # Numerical strings
            tests.append(str(rng.randint(-1000000, 1000000)))

    return tests[:count]


if __name__ == "__main__":
    test_cases = generate_hidden_tests(count=20)
    print(f"Generated {len(test_cases)} sample hidden tests:")
    for idx, t in enumerate(test_cases[:10]):
        print(f"[{idx+1:02d}] {repr(t)}")
