"""
Sandbox Runner for C-to-Safe-Rust Subnet (sandbox/sandbox_runner.py).
Strictly isolated compilation and differential execution.
Supports Docker (--network none, --read-only, --cap-drop ALL, memory/pid limits)
and a dev-only native compiler pipeline via AEGIS_ALLOW_UNSANDBOXED=1.
NEVER uses emulators or simulated string-matching results.
"""

import sys
import os
import time
import uuid
import shutil
import base64
import tempfile
import subprocess
import logging
from typing import Tuple, Dict, Any, List, Optional, Union

from sandbox.batch_runner import run_batch, write_input_bundle, read_input_bundle

logger = logging.getLogger("sandbox")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [SANDBOX] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

MAX_SOURCE_SIZE = 64 * 1024  # 64 KB source size limit


def _check_docker() -> bool:
    """Verify if Docker CLI and daemon are responsive."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )
        return res.returncode == 0
    except Exception:
        return False


def _get_rustc_extra_args() -> List[str]:
    """Detect if host rustc needs target flags (e.g. gnullvm on Windows with llvm-mingw)."""
    if sys.platform == "win32":
        # Test compiling a dummy rust snippet
        try:
            with tempfile.TemporaryDirectory() as td:
                rs = os.path.join(td, "check.rs")
                with open(rs, "w") as f:
                    f.write("fn main(){}")
                test_res = subprocess.run(
                    ["rustc", "--edition", "2021", rs, "-o", os.path.join(td, "check.exe")],
                    capture_output=True,
                    timeout=5
                )
                if test_res.returncode != 0:
                    # Try gnullvm
                    gnullvm_res = subprocess.run(
                        ["rustc", "--target", "x86_64-pc-windows-gnullvm", "--edition", "2021", rs, "-o", os.path.join(td, "check.exe")],
                        capture_output=True,
                        timeout=5
                    )
                    if gnullvm_res.returncode == 0:
                        return ["--target", "x86_64-pc-windows-gnullvm"]
        except Exception:
            pass
    return []


class SandboxRunner:
    def __init__(self, docker_image: str = "c2rust-sandbox", force_unsandboxed: bool = False):
        self.docker_image = docker_image
        self.docker_available = _check_docker()
        
        allow_unsandboxed = force_unsandboxed or (os.environ.get("AEGIS_ALLOW_UNSANDBOXED") == "1")

        if not self.docker_available and not allow_unsandboxed:
            raise RuntimeError(
                "Docker is not available and AEGIS_ALLOW_UNSANDBOXED=1 is not set. "
                "Refusing to run untrusted code without container sandbox. "
                "Set AEGIS_ALLOW_UNSANDBOXED=1 only for local development."
            )

        self.use_docker = self.docker_available and not force_unsandboxed
        self.rustc_extra_args = _get_rustc_extra_args() if not self.use_docker else []
        logger.info(f"Sandbox initialized. Docker: {self.docker_available}, Active Mode: {'Docker' if self.use_docker else 'Unsandboxed Local Toolchain'}")

    def compile_c(
        self,
        c_code: str,
        work_dir: str,
        output_name: str = "c_binary",
        sanitizer: bool = False
    ) -> Tuple[bool, str, str]:
        """
        Compiles trusted C reference code.
        Standard: gcc -std=c11 -O2 ref.c -o ref
        Sanitizer: gcc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all ref.c -o ref_san
        """
        src_name = "ref.c"
        src_path = os.path.join(work_dir, src_name)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(c_code)

        bin_suffix = ".exe" if (sys.platform == "win32" and not self.use_docker) else ""
        out_bin_name = output_name + bin_suffix
        out_path = os.path.join(work_dir, out_bin_name)

        if sanitizer:
            c_flags = ["-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
        else:
            c_flags = ["-std=c11", "-O2"]

        if self.use_docker:
            container_name = f"aegis_compile_c_{uuid.uuid4().hex[:8]}"
            cmd = [
                "docker", "run", "--rm", "--name", container_name,
                "--network", "none",
                "-v", f"{work_dir}:/work", "-w", "/work",
                self.docker_image,
                "gcc"
            ] + c_flags + [src_name, "-o", output_name]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=30)
                stderr_text = res.stderr.decode("utf-8", errors="replace")
                if res.returncode != 0:
                    return False, "", f"Docker C compilation failed (exit {res.returncode}): {stderr_text}"
                return True, os.path.join(work_dir, output_name), ""
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
                return False, "", "C compilation timed out in container"
        else:
            cmd = ["gcc"] + c_flags + [src_path, "-o", out_path]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=30)
                stderr_text = res.stderr.decode("utf-8", errors="replace")
                if res.returncode != 0:
                    return False, "", f"Local GCC compilation failed (exit {res.returncode}): {stderr_text}"
                return True, out_path, ""
            except subprocess.TimeoutExpired:
                return False, "", "C compilation timed out locally"
            except Exception as e:
                return False, "", f"GCC invocation error: {str(e)}"

    def compile_rust(
        self,
        rust_code: str,
        work_dir: str,
        output_name: str = "rust_binary"
    ) -> Tuple[bool, str, str]:
        """
        Compiles candidate Rust code:
        rustc --edition 2021 -O -C overflow-checks=on -F unsafe_code main.rs -o cand
        Enforces 64 KB source size limit.
        """
        # 1. Check size limit
        encoded_bytes = rust_code.encode("utf-8")
        if len(encoded_bytes) > MAX_SOURCE_SIZE:
            return False, "", f"Source code exceeds limit: {len(encoded_bytes)} bytes > {MAX_SOURCE_SIZE} bytes max"

        src_name = "main.rs"
        src_path = os.path.join(work_dir, src_name)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(rust_code)

        bin_suffix = ".exe" if (sys.platform == "win32" and not self.use_docker) else ""
        out_bin_name = output_name + bin_suffix
        out_path = os.path.join(work_dir, out_bin_name)

        rust_flags = [
            "--edition", "2021",
            "-O",
            "-C", "overflow-checks=on",
            "-F", "unsafe_code"
        ]

        if self.use_docker:
            container_name = f"aegis_compile_rs_{uuid.uuid4().hex[:8]}"
            cmd = [
                "docker", "run", "--rm", "--name", container_name,
                "--network", "none",
                "-v", f"{work_dir}:/work", "-w", "/work",
                self.docker_image,
                "rustc"
            ] + rust_flags + [src_name, "-o", output_name]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=30)
                stderr_text = res.stderr.decode("utf-8", errors="replace")
                if res.returncode != 0:
                    return False, "", f"Rust compilation failed (exit {res.returncode}): {stderr_text}"
                return True, os.path.join(work_dir, output_name), ""
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
                return False, "", "Rust compilation timed out in container"
        else:
            cmd = ["rustc"] + self.rustc_extra_args + rust_flags + [src_path, "-o", out_path]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=30)
                stderr_text = res.stderr.decode("utf-8", errors="replace")
                if res.returncode != 0:
                    return False, "", f"Local rustc compilation failed (exit {res.returncode}): {stderr_text}"
                return True, out_path, ""
            except subprocess.TimeoutExpired:
                return False, "", "Rust compilation timed out locally"
            except Exception as e:
                return False, "", f"rustc invocation error: {str(e)}"

    def execute_batch(
        self,
        binary_path: str,
        work_dir: str,
        binary_basename: str,
        test_inputs: List[Union[bytes, str]],
        per_test_timeout: float = 2.0,
        max_output_bytes: int = 65536
    ) -> List[Dict[str, Any]]:
        """
        Executes binary against all test inputs in a single batch.
        Uses Docker with strict security flags if enabled, or native execution under unsandboxed mode.
        """
        raw_inputs = [i.encode("utf-8") if isinstance(i, str) else bytes(i) for i in test_inputs]
        
        if self.use_docker:
            container_name = f"aegis_run_{uuid.uuid4().hex[:8]}"
            bundle_path = os.path.join(work_dir, "inputs.bin")
            write_input_bundle(bundle_path, raw_inputs)

            # Copy batch_runner.py into work_dir so container can run it
            runner_src = os.path.join(os.path.dirname(__file__), "batch_runner.py")
            shutil.copyfile(runner_src, os.path.join(work_dir, "batch_runner.py"))

            cmd = [
                "docker", "run", "--rm", "--name", container_name,
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,size=16m",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "64",
                "--memory", "256m",
                "--memory-swap", "256m",
                "--cpus", "1",
                "--user", "65534:65534",
                "-v", f"{work_dir}:/work:ro",
                "-v", f"{work_dir}:/results:rw",
                "-w", "/work",
                self.docker_image,
                "python3", "/work/batch_runner.py",
                f"/work/{binary_basename}",
                "/work/inputs.bin",
                "/results/results.json",
                str(per_test_timeout),
                str(max_output_bytes)
            ]

            total_timeout = max(10.0, per_test_timeout * len(raw_inputs) + 15.0)
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=total_timeout)
                results_path = os.path.join(work_dir, "results.json")
                if os.path.exists(results_path):
                    import json
                    with open(results_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                else:
                    err_msg = res.stderr.decode("utf-8", errors="replace")
                    logger.error(f"Docker batch runner produced no output: {err_msg}")
                    return [{"exit_code": -1, "stdout_b64": "", "stderr_b64": "", "timed_out": True} for _ in raw_inputs]
            except subprocess.TimeoutExpired:
                logger.warning(f"Host timeout killing container {container_name}")
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
                return [{"exit_code": -9, "stdout_b64": "", "stderr_b64": "", "timed_out": True} for _ in raw_inputs]
        else:
            return run_batch(
                binary_path=binary_path,
                inputs=raw_inputs,
                per_test_timeout=per_test_timeout,
                max_output_bytes=max_output_bytes
            )

    def run_sanitizer_precheck(
        self,
        c_code: str,
        test_inputs: List[Union[bytes, str]],
        timeout: float = 2.0
    ) -> List[Dict[str, Any]]:
        """
        Executes test inputs on ref_san (AddressSanitizer + UndefinedBehaviorSanitizer build).
        Inputs that crash, timeout, or trigger sanitizers are flagged as invalid (UB).
        """
        temp_dir = tempfile.mkdtemp(prefix="aegis_san_")
        try:
            ok, bin_path, err = self.compile_c(c_code, temp_dir, output_name="ref_san", sanitizer=True)
            if not ok:
                logger.error(f"Failed to build sanitizer reference: {err}")
                return [{"is_clean": False, "reason": f"Sanitizer build failed: {err}"} for _ in test_inputs]

            results = self.execute_batch(
                binary_path=bin_path,
                work_dir=temp_dir,
                binary_basename="ref_san",
                test_inputs=test_inputs,
                per_test_timeout=timeout
            )

            evaluated = []
            for res in results:
                stderr_bytes = base64.b64decode(res.get("stderr_b64", ""))
                timed_out = res.get("timed_out", False)
                exit_code = res.get("exit_code", 0)
                san_trig = res.get("sanitizer_triggered", False)

                # Valid == no sanitizer diagnostic, no crash signal, no timeout. A programmatic
                # non-zero exit (0..127) is a legitimate behaviour the translation must reproduce.
                crashed = not (0 <= exit_code <= 127)
                infra = (exit_code == -1) and not timed_out
                is_clean = (not timed_out) and (not san_trig) and (not crashed)
                reason = "clean"
                if infra:
                    reason = "harness could not launch the reference binary"
                elif timed_out:
                    reason = "timeout"
                elif san_trig:
                    reason = f"sanitizer (exit={exit_code}): {stderr_bytes[:150].decode(errors='replace')}"
                elif crashed:
                    reason = f"crash signal (exit={exit_code})"

                evaluated.append({
                    "is_clean": is_clean,
                    "infra_error": infra,
                    "reason": reason,
                    "exit_code": exit_code,
                    "timed_out": timed_out
                })
            return evaluated
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def compile_and_test(
        self,
        c_code: str,
        rust_code: str,
        test_inputs: List[Union[bytes, str]],
        timeout: float = 2.0
    ) -> Dict[str, Any]:
        """
        Full differential fuzzing cycle:
        1. Compiles C reference binary in isolated work dir.
        2. Compiles Rust candidate binary in separate isolated work dir.
        3. Executes batch test suite against both binaries.
        4. Compares stdout bytes and exit codes.
        """
        total = len(test_inputs)
        if total == 0:
            return {
                "compilation_success": True,
                "pass_rate": 0.0,
                "passed_tests": 0,
                "total_tests": 0,
                "divergences": []
            }

        # 1. Compile C reference in C temp dir
        c_temp_dir = tempfile.mkdtemp(prefix="aegis_c_")
        rs_temp_dir = tempfile.mkdtemp(prefix="aegis_rs_")

        try:
            c_ok, c_bin, c_err = self.compile_c(c_code, c_temp_dir, output_name="c_ref", sanitizer=False)
            if not c_ok:
                return {
                    "compilation_success": False,
                    "stage": "c_compilation",
                    "error": c_err,
                    "pass_rate": 0.0,
                    "passed_tests": 0,
                    "total_tests": total,
                    "divergences": []
                }

            # 2. Compile Rust candidate in isolated Rust temp dir
            rs_ok, rs_bin, rs_err = self.compile_rust(rust_code, rs_temp_dir, output_name="rust_cand")
            if not rs_ok:
                return {
                    "compilation_success": False,
                    "stage": "rust_compilation",
                    "error": rs_err,
                    "pass_rate": 0.0,
                    "passed_tests": 0,
                    "total_tests": total,
                    "divergences": []
                }

            # 3. Execute batch on C reference
            c_results = self.execute_batch(
                binary_path=c_bin,
                work_dir=c_temp_dir,
                binary_basename="c_ref",
                test_inputs=test_inputs,
                per_test_timeout=timeout
            )

            # 4. Execute batch on Rust candidate
            rs_results = self.execute_batch(
                binary_path=rs_bin,
                work_dir=rs_temp_dir,
                binary_basename="rust_cand",
                test_inputs=test_inputs,
                per_test_timeout=timeout
            )

            # 5. Compare byte outputs and exit codes
            passed = 0
            divergences = []
            infra_errors = 0

            for idx, (c_res, rs_res) in enumerate(zip(c_results, rs_results)):
                c_out = base64.b64decode(c_res.get("stdout_b64", ""))
                rs_out = base64.b64decode(rs_res.get("stdout_b64", ""))
                c_exit = c_res.get("exit_code", -1)
                rs_exit = rs_res.get("exit_code", -1)
                rs_timed_out = rs_res.get("timed_out", False)

                # exit -1 means the harness could not launch the binary at all. That is our
                # problem, not the miner's: never count it as a pass or as a divergence.
                if c_exit == -1 or (rs_exit == -1 and not rs_timed_out):
                    infra_errors += 1
                    continue

                # Pass iff identical stdout bytes AND identical exit code
                if (c_out == rs_out) and (c_exit == rs_exit) and (not rs_timed_out):
                    passed += 1
                else:
                    inp_raw = test_inputs[idx]
                    inp_bytes = inp_raw.encode("utf-8") if isinstance(inp_raw, str) else bytes(inp_raw)
                    reason = ("rust timeout" if rs_timed_out else
                              "rust panic" if rs_exit == 101 and c_exit != 101 else
                              "exit code mismatch" if c_exit != rs_exit else "stdout mismatch")
                    divergences.append({
                        "index": idx,
                        "input_b64": base64.b64encode(inp_bytes).decode("ascii"),
                        "input_repr": repr(inp_bytes[:64]),
                        "input_len": len(inp_bytes),
                        "c_stdout_b64": base64.b64encode(c_out[:256]).decode("ascii"),
                        "rust_stdout_b64": base64.b64encode(rs_out[:256]).decode("ascii"),
                        "c_stdout_len": len(c_out),
                        "rust_stdout_len": len(rs_out),
                        "c_exit": c_exit,
                        "rust_exit": rs_exit,
                        "rust_timed_out": rs_timed_out,
                        "reason": reason
                    })

            scored = total - infra_errors
            pass_rate = passed / scored if scored > 0 else 0.0
            if infra_errors:
                logger.warning(f"{infra_errors}/{total} executions failed to launch; excluded from scoring")

            return {
                "compilation_success": True,
                "pass_rate": pass_rate,
                "passed_tests": passed,
                "total_tests": scored,
                "infra_errors": infra_errors,
                "divergences": divergences
            }

        finally:
            shutil.rmtree(c_temp_dir, ignore_errors=True)
            shutil.rmtree(rs_temp_dir, ignore_errors=True)
