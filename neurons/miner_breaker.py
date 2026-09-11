"""
Breaker Miner (neurons/miner_breaker.py)
Adversarial miner that analyzes C and candidate Rust code pairs,
synthesizing edge-case fuzzing inputs to prove divergences, panics,
or logic regressions.
"""

import sys
import os
import json
import time
import argparse
import logging
from typing import List, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import substrate as bt
from protocol import BreakerSynapse

logger = logging.getLogger("miner_breaker")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [BREAKER] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)


class BreakerMiner:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        self.wallet = bt.wallet(name=config.wallet_name, hotkey=config.wallet_hotkey)
        self.subtensor = bt.subtensor(network=config.subtensor_network, netuid=config.netuid)
        self.metagraph = self.subtensor.metagraph(config.netuid)
        self.axon = bt.axon(wallet=self.wallet, port=config.axon_port, ip=config.axon_ip)
        self.strategy = config.strategy

        logger.info(f"Initialized BreakerMiner with wallet={self.wallet} strategy='{self.strategy}'")

    def generate_adversarial_inputs(self, c_code: str, rust_code: str, count: int = 10) -> List[Any]:
        """
        Synthesize adversarial inputs tailored to expose divergences between C and Rust.
        Includes integer boundary targets, null bytes, unicode multi-byte characters,
        buffer boundary tests, and empty strings.
        """
        inputs = []
        
        # 1. Boundary string inputs
        inputs.append("") # Empty input
        inputs.append("\x00") # Embedded null byte (C string terminator vs Rust String)
        inputs.append("A" * 1024) # Length boundary
        inputs.append("🚀🦀🔥") # Multi-byte UTF-8 grapheme clusters
        inputs.append("Hello\x00World") # Mid-string null byte
        inputs.append("!@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./") # Complex ASCII special chars
        inputs.append(" \t\r\n ") # Whitespace edge cases
        inputs.append("12345\n67890") # Multiline string
        inputs.append("çüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ") # Extended Latin-1
        inputs.append("\u200B\u200C\u200D\uFEFF") # Zero-width formatting characters

        # 2. If function appears to take numbers (inspect signature)
        if "int " in c_code or "long " in c_code or "i32" in rust_code:
            inputs.extend([
                0,
                -1,
                1,
                2147483647,  # INT32_MAX
                -2147483648, # INT32_MIN
                9223372036854775807, # INT64_MAX
            ])

        return inputs[:count]

    def forward(self, synapse: BreakerSynapse) -> BreakerSynapse:
        """Bittensor Axon forward handler for BreakerSynapse."""
        logger.info(f"Received breaker challenge for function: '{synapse.function_name}'")
        t_start = time.time()
        
        adversarial_cases = self.generate_adversarial_inputs(
            c_code=synapse.c_code,
            rust_code=synapse.rust_code,
            count=synapse.num_inputs_requested
        )
        
        synapse.test_inputs = adversarial_cases
        synapse.divergence_rationale = (
            f"Synthesized {len(adversarial_cases)} adversarial boundary tests "
            f"targeting null-terminators, multi-byte UTF-8, and buffer boundaries."
        )
        logger.info(f"Generated {len(adversarial_cases)} breaker test cases in {time.time() - t_start:.3f}s")
        return synapse

    def run(self):
        """Attach forward handler and serve requests."""
        self.axon.attach(forward_fn=self.forward)
        self.axon.start()
        logger.info(f"Breaker miner running on {self.axon.ip}:{self.axon.port}")
        return self


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Bittensor C-to-Safe-Rust Breaker Miner")
    parser.add_argument("--netuid", type=int, default=1, help="Subnet netuid")
    parser.add_argument("--wallet_name", type=str, default="default", help="Bittensor wallet name")
    parser.add_argument("--wallet_hotkey", type=str, default="breaker_fuzzer", help="Hotkey name")
    parser.add_argument("--axon_port", type=int, default=8092, help="Port to host axon on")
    parser.add_argument("--axon_ip", type=str, default="127.0.0.1", help="IP address for axon")
    parser.add_argument("--subtensor_network", type=str, default="local", help="Network (local/finney/test)")
    parser.add_argument("--strategy", type=str, default="adversarial_fuzz", help="Fuzzing strategy")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    miner = BreakerMiner(args)
    miner.run()
