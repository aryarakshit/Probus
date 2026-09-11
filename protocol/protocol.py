"""
Bittensor Synapse Protocols for C-to-Safe-Rust Subnet.
Defines TranslationSynapse and BreakerSynapse.
"""

from typing import List, Dict, Any, Optional
from substrate import Synapse
from pydantic import Field


class TranslationSynapse(Synapse):
    """
    Synapse request sent from Validator to Translator Miners.
    Carries C source code to be translated into 100% Safe Rust.
    """
    # Inputs (Validator -> Miner)
    c_code: str = Field(..., description="Legacy C source code to translate")
    function_name: str = Field(..., description="Target entrypoint function name")
    timeout_seconds: float = Field(default=10.0, description="Allowed computation time")
    
    # Outputs (Miner -> Validator)
    rust_code: Optional[str] = Field(default=None, description="Translated 100% Safe Rust code")
    repair_attempts: int = Field(default=0, description="Number of local repair cycles attempted")
    compiler_notes: Optional[str] = Field(default=None, description="Miner local validation notes")

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
    function_name: str = Field(..., description="Function entrypoint under test")
    num_inputs_requested: int = Field(default=10, description="Target number of adversarial test inputs")

    # Outputs (Breaker Miner -> Validator)
    test_inputs: List[Any] = Field(default_factory=list, description="List of edge-case test inputs")
    divergence_rationale: Optional[str] = Field(default=None, description="Hypothesized flaw explanation")

    def deserialize(self) -> List[Any]:
        return self.test_inputs
