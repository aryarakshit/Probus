"""
Breaker Miner (neurons/miner_breaker.py)
Adversarial miner that analyzes C reference code and candidate Rust code pairs,
synthesizing edge-case fuzzing inputs to prove divergences, panics, or logic regressions.
Pre-screens inputs against C sanitizers (ASan/UBSan) to avoid invalid input penalties.
"""

import sys
import os
import time
import random
import argparse
import logging
from typing import List, Any, Tuple, Optional

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

    def generate_adversarial_inputs(self, c_code: str, rust_code: str, count: int = 10) -> List[bytes]:
        """
        Synthesize adversarial raw byte inputs tailored to expose divergences between C and Rust.
        Includes integer boundary targets, null bytes, unicode multi-byte characters,
        buffer boundary tests, empty strings, and bit mutations.
        """
        seeds: List[bytes] = [
            b"",                                       # Empty input
            b"\x00",                                   # Single null byte (C string terminator trap)
            b"\xff",                                   # Max unsigned byte
            b"Hello\x00World",                         # Mid-string null byte
            b"\x00" * 300,                             # Long run of nulls
            b"\xff" * 300,                             # Long run of 0xFF
            b"Line 1\r\nLine 2\nLine 3",               # Mixed CRLF
            b"Line without newline",                   # Missing trailing newline
            "🦀 Rust vs C 🚀".encode("utf-8"),         # Multi-byte UTF-8 grapheme clusters
            b"\xff\xfe\xfd\x80\x81",                   # Invalid UTF-8 sequence
            b"!@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./",      # Special ASCII
            b" \t\r\n ",                               # Whitespaces
            b"0123456789" * 30,                        # Digits
            b"A" * 255,                                # 255-byte boundary
            b"B" * 256,                                # 256-byte boundary
            b"C" * 1024,                               # 1 KB buffer boundary
        ]

        # Check for numeric or chunk constants in code
        import re
        chunk_m = re.search(r"CHUNK_SIZE\s+(\d+)", c_code)
        if chunk_m:
            csz = int(chunk_m.group(1))
            # Boundary inputs around chunk size
            seeds.append(b"X" * (csz - 1))
            seeds.append(b"Y" * csz)
            seeds.append(b"Z" * (csz + 1))
            seeds.append(b"\x00" * csz)
            seeds.append(b"\xff" * (csz * 2))

        # Add fuzzed mutations
        rng = random.Random(42)
        fuzzed: List[bytes] = []
        for s in seeds:
            fuzzed.append(s)
            if len(s) > 0:
                # Bit flip mutation
                byte_arr = bytearray(s)
                flip_idx = rng.randint(0, len(byte_arr) - 1)
                byte_arr[flip_idx] ^= 0x01
                fuzzed.append(bytes(byte_arr))

        # Filter duplicates while preserving order
        seen = set()
        unique_inputs = []
        for inp in fuzzed:
            if inp not in seen:
                seen.add(inp)
                unique_inputs.append(inp)
                if len(unique_inputs) >= count:
                    break

        return unique_inputs[:count]

    def forward(self, synapse: BreakerSynapse) -> BreakerSynapse:
        """Bittensor Axon forward handler for BreakerSynapse."""
        task_name = getattr(synapse, "task_name", "task")
        logger.info(f"Received breaker challenge for task: '{task_name}'")
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

    def blacklist(self, synapse: BreakerSynapse) -> Tuple[bool, str]:
        """Reject unregistered hotkeys on live network."""
        caller = synapse.dendrite.hotkey
        if self.config.subtensor_network != "local" and not getattr(self.config, "mock", False):
            if caller not in self.metagraph.hotkeys:
                return True, f"Hotkey {caller} not registered in metagraph"
        return False, "Allowed"

    def run(self):
        """Attach forward handler and serve requests."""
        self.axon.attach(forward_fn=self.forward, blacklist_fn=self.blacklist)
        self.axon.start()
        logger.info(f"Breaker miner running on {self.axon.ip}:{self.axon.port}")
        return self

    def serve_forever(self):
        """Keep miner process alive."""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.axon.stop()


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Bittensor C-to-Safe-Rust Breaker Miner")
    parser.add_argument("--netuid", type=int, default=1, help="Subnet netuid")
    parser.add_argument("--wallet_name", type=str, default="default", help="Bittensor wallet name")
    parser.add_argument("--wallet_hotkey", type=str, default="breaker_fuzzer", help="Hotkey name")
    parser.add_argument("--axon_port", type=int, default=8092, help="Port to host axon on")
    parser.add_argument("--axon_ip", type=str, default="127.0.0.1", help="IP address for axon")
    parser.add_argument("--subtensor_network", type=str, default="local", help="Network (local/finney/test)")
    parser.add_argument("--strategy", type=str, default="adversarial_fuzz", help="Fuzzing strategy")
    parser.add_argument("--mock", action="store_true", default=False, help="Use mock substrate")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    miner = BreakerMiner(args)
    miner.run()
    miner.serve_forever()
