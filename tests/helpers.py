"""
Shared test helpers (tests/helpers.py).

`install_stub_llm` registers an in-process model double so the *plumbing* of the
LLM miner (prompting, code extraction, static gate, rustc, self-fuzz, repair loop)
can be exercised without credentials. The double deliberately answers with a
buggy program first so the repair loop has to do real work. It is only ever
wired in by tests; the demo and the miners never import this module.
"""

import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")
os.environ.setdefault("PROBUS_MOCK", "1")

from neurons import llm
from dataset.tasks import infer_task, build_task


def _task_from_prompt(user: str):
    m = re.search(r"```c\n([\s\S]*?)```", user)
    name, consts = infer_task(m.group(1))
    return build_task(name, consts)


class StubModel:
    def __init__(self, buggy_first: bool = True):
        self.buggy_first = buggy_first
        self.calls = 0

    def __call__(self, system: str, user: str) -> str:
        self.calls += 1
        t = _task_from_prompt(user)
        code = t.weak_rust if (self.buggy_first and self.calls == 1) else t.reference_rust
        return f"Sure.\n```rust\n{code}```\n"


def install_stub_llm(buggy_first: bool = True) -> StubModel:
    stub = StubModel(buggy_first=buggy_first)
    llm.set_stub(stub)
    os.environ["PROBUS_LLM_PROVIDER"] = "stub"
    os.environ.pop("PROBUS_LLM_REPLAY", None)
    return stub
