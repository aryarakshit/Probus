"""
Bittensor Synapse Protocols for C-to-Safe-Rust Subnet.
Defines TranslationSynapse and BreakerSynapse.
"""

import base64
from typing import List, Dict, Any, Optional, Union
from substrate import Synapse
from pydantic import Field


class TranslationSynapse(Synapse):
    """
    Synapse request sent from Validator to Translator Miners.
    Carries complete C source code to be translated into 100% Safe Rust with fn main().
    """
    # Inputs (Validator -> Miner)
    c_code: str = Field(..., description="Legacy C source code to translate")
    task_name: str = Field(default="reverse_bytes", description="Target task name")
    function_name: Optional[str] = Field(default="main", description="Target entrypoint")
    timeout_seconds: float = Field(default=15.0, description="Allowed computation time")
    
    # Outputs (Miner -> Validator)
    rust_code: Optional[str] = Field(default=None, description="Translated 100% Safe Rust code with fn main()")
    repair_attempts: int = Field(default=0, description="Number of translate/repair rounds the miner ran")
    compiler_notes: Optional[str] = Field(default=None, description="Miner's own verdict (self-test result, provider used)")

    def deserialize(self) -> Optional[str]:
        return self.rust_code


class BreakerSynapse(Synapse):
    """
    Synapse request sent from Validator to Breaker Miners.
    Carries (C code, Rust code) pair. Breaker searches for edge cases
    that provoke divergence, panic, or invariant violations.
    """
    # Inputs (Validator -> Breaker Miner)
    c_code: str = Field(..., description="Reference C source code")
    rust_code: str = Field(..., description="Candidate Rust source code under audit")
    task_name: str = Field(default="reverse_bytes", description="Task name under test")
    function_name: Optional[str] = Field(default="main", description="Function entrypoint under test")
    num_inputs_requested: int = Field(default=10, description="Target number of adversarial test inputs")

    # Outputs (Breaker Miner -> Validator)
    # Synapses travel as JSON on a real network, so arbitrary bytes must be base64-encoded.
    test_inputs: List[Union[str, bytes]] = Field(default_factory=list, description="Adversarial inputs (base64 strings when input_encoding == 'base64')")
    input_encoding: str = Field(default="utf8", description="'base64' or 'utf8' for entries of test_inputs")
    divergence_rationale: Optional[str] = Field(default=None, description="Breaker's explanation of the flaw it targets")

    def deserialize(self) -> List[bytes]:
        return self.get_raw_inputs()

    def get_raw_inputs(self) -> List[bytes]:
        raw_list: List[bytes] = []
        for item in self.test_inputs:
            if isinstance(item, bytes):
                raw_list.append(item)
            elif isinstance(item, str):
                if self.input_encoding == "base64":
                    try:
                        raw_list.append(base64.b64decode(item, validate=True))
                    except Exception:
                        continue
                else:
                    raw_list.append(item.encode("utf-8"))
        return raw_list
