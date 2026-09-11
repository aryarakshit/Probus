"""
Batch Runner for Sandbox Execution (sandbox/batch_runner.py)
Executes a binary against a sequence of binary inputs via stdin,
enforcing per-test timeouts, output size limits, and raw byte capture.
Used both inside Docker containers and natively in unsandboxed development mode.
"""

import sys
import os
import time
import struct
import base64
import json
import subprocess
from typing import List, Dict, Any


def read_input_bundle(bundle_path: str) -> List[bytes]:
    """Reads a binary bundle of inputs formatted as: [count: uint32] then [len: uint32, data]..."""
    inputs = []
    with open(bundle_path, "rb") as f:
        header = f.read(4)
        if len(header) < 4:
            return inputs
        count = struct.unpack(">I", header)[0]
        for _ in range(count):
            len_bytes = f.read(4)
            if len(len_bytes) < 4:
                break
            length = struct.unpack(">I", len_bytes)[0]
            data = f.read(length)
            inputs.append(data)
    return inputs


def write_input_bundle(bundle_path: str, inputs: List[bytes]):
    """Writes a binary bundle of inputs."""
    with open(bundle_path, "wb") as f:
        f.write(struct.pack(">I", len(inputs)))
        for item in inputs:
            if isinstance(item, str):
                item = item.encode("utf-8")
            f.write(struct.pack(">I", len(item)))
            f.write(item)


def run_batch(
    binary_path: str,
    inputs: List[bytes],
    per_test_timeout: float = 2.0,
    max_output_bytes: int = 65536
) -> List[Dict[str, Any]]:
    """
    Executes binary sequentially for each test input.
    Stdin is passed as raw bytes.
    Stdout and stderr are captured up to max_output_bytes.
    """
    results = []
    sanitizer_patterns = [
        b"runtime error:",
        b"AddressSanitizer",
        b"UndefinedBehaviorSanitizer",
        b"ASan",
        b"UBSan",
        b"Sanitizer"
    ]

    for idx, test_input in enumerate(inputs):
        t0 = time.perf_counter()
        timed_out = False
        stdout_buf = b""
        stderr_buf = b""
        exit_code = -1

        try:
            proc = subprocess.Popen(
                [binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            try:
                stdout_buf, stderr_buf = proc.communicate(input=test_input, timeout=per_test_timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    stdout_buf, stderr_buf = proc.communicate(timeout=0.5)
                except Exception:
                    pass
                exit_code = -9
        except Exception as e:
            stderr_buf = f"Execution error: {str(e)}".encode("utf-8", errors="replace")
            exit_code = -1

        elapsed = time.perf_counter() - t0

        # Cap output sizes
        if len(stdout_buf) > max_output_bytes:
            stdout_buf = stdout_buf[:max_output_bytes]
        if len(stderr_buf) > max_output_bytes:
            stderr_buf = stderr_buf[:max_output_bytes]

        # Check for sanitizer violations
        san_triggered = any(p in stderr_buf for p in sanitizer_patterns)

        results.append({
            "index": idx,
            "stdout_b64": base64.b64encode(stdout_buf).decode("ascii"),
            "stderr_b64": base64.b64encode(stderr_buf).decode("ascii"),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "elapsed_seconds": round(elapsed, 4),
            "sanitizer_triggered": san_triggered
        })

    return results


def main():
    if len(sys.argv) < 3:
        print("Usage: python batch_runner.py <binary_path> <input_bundle_path> [output_json_path] [timeout_s] [max_output_bytes]")
        sys.exit(1)

    binary_path = sys.argv[1]
    input_bundle_path = sys.argv[2]
    output_json_path = sys.argv[3] if len(sys.argv) > 3 else "results.json"
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
    max_output = int(sys.argv[5]) if len(sys.argv) > 5 else 65536

    inputs = read_input_bundle(input_bundle_path)
    results = run_batch(binary_path, inputs, per_test_timeout=timeout, max_output_bytes=max_output)

    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f)


if __name__ == "__main__":
    main()
