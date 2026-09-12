"""
Benchmark fixtures (dataset/fixtures.py).

Deliberately flawed or malicious Rust submissions, one per task, used to
demonstrate and unit-test the validator pipeline without spending model calls:

    weak     - compiles, passes the static gate, but carries a real translation
               bug (UTF-8 decoding, off-by-one at a boundary, wrong wrap-around).
               The Breaker is expected to find it.
    cheater  - contains `unsafe`. The static gate must reject it in < 1 ms.

These are test doubles. The real translator (`--mode llm`) never imports this
module and never sees `reference_rust`.
"""

from dataset.tasks import infer_task, build_task


def fixture_rust(mode: str, c_code: str) -> str:
    """Return the fixture submission for the exact task instance encoded in `c_code`."""
    task_name, constants = infer_task(c_code)
    inst = build_task(task_name, constants)
    if mode == "weak":
        return inst.weak_rust
    if mode == "cheater":
        return inst.cheater_rust
    raise ValueError(f"no fixture for mode '{mode}'")
