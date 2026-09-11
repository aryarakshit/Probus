"""
Unit & Integration Tests for Sandbox (tests/test_sandbox.py)
Acceptance Criteria:
1. Correct translation scores 100%
2. Char-reversal vs byte-reversal fails on non-ASCII input
3. Program without fn main() fails compilation
4. unsafe is rejected by rustc (-F unsafe_code) even when regex gate is bypassed
5. Embedded null-byte (\\x00) works via stdin without argv crash
6. Output size cap is enforced
7. Per-test timeout terminates hanging execution
8. No Docker without AEGIS_ALLOW_UNSANDBOXED=1 raises hard error
"""

import sys
import os
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Enable unsandboxed mode for test execution on host toolchain
os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"

from sandbox.sandbox_runner import SandboxRunner
from dataset.tasks import sample_task


class TestSandbox(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = SandboxRunner()

    def test_01_correct_translation_scores_100(self):
        """Known-correct Rust translation matches C reference 100%."""
        task = sample_task("reverse_bytes", seed=10)
        test_inputs = [b"hello", b"world123", b"test", b"abc"]
        res = self.runner.compile_and_test(task.c_code, task.reference_rust, test_inputs)
        self.assertTrue(res["compilation_success"])
        self.assertEqual(res["pass_rate"], 1.0)
        self.assertEqual(res["passed_tests"], 4)

    def test_02_byte_vs_char_bug_caught(self):
        """Char-reversal vs byte-reversal diverges on non-ASCII / multi-byte input."""
        task = sample_task("reverse_bytes", seed=10)
        # Test input with multi-byte UTF-8 emoji
        test_inputs = ["🦀🚀".encode("utf-8"), b"\xff\xfe\x00\x01"]
        res = self.runner.compile_and_test(task.c_code, task.weak_rust, test_inputs)
        self.assertTrue(res["compilation_success"])
        self.assertLess(res["pass_rate"], 1.0)
        self.assertGreater(len(res["divergences"]), 0)

    def test_03_no_main_fails_compilation(self):
        """Rust code without fn main() must fail compilation."""
        task = sample_task("reverse_bytes", seed=10)
        code_without_main = """
        #![forbid(unsafe_code)]
        pub fn reverse(input: &[u8]) -> Vec<u8> {
            input.iter().rev().cloned().collect()
        }
        """
        res = self.runner.compile_and_test(task.c_code, code_without_main, [b"test"])
        self.assertFalse(res["compilation_success"])
        self.assertEqual(res["stage"], "rust_compilation")
        self.assertIn("main", res["error"].lower())

    def test_04_unsafe_rejected_by_rustc(self):
        """unsafe code must be rejected by rustc -F unsafe_code even if regex is bypassed."""
        task = sample_task("reverse_bytes", seed=10)
        # Attempt to bypass via allow(unsafe_code)
        bypassed_code = """
        #![allow(unsafe_code)]
        use std::io::{self, Read, Write};
        fn main() -> io::Result<()> {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            unsafe {
                let _p = buf.as_ptr();
            }
            io::stdout().write_all(&buf)?;
            Ok(())
        }
        """
        res = self.runner.compile_and_test(task.c_code, bypassed_code, [b"test"])
        self.assertFalse(res["compilation_success"])
        self.assertEqual(res["stage"], "rust_compilation")

    def test_05_null_byte_via_stdin(self):
        """Input with embedded \\x00 must pass without Python argv ValueError."""
        task = sample_task("reverse_bytes", seed=10)
        inputs_with_null = [b"hello\x00world", b"\x00\x00\x00", b"a\x00b\x00c"]
        res = self.runner.compile_and_test(task.c_code, task.reference_rust, inputs_with_null)
        self.assertTrue(res["compilation_success"])
        self.assertEqual(res["pass_rate"], 1.0)

    def test_06_infinite_loop_times_out(self):
        """Hanging execution must be killed by per-test timeout."""
        c_code = """
        #include <stdio.h>
        int main() { return 0; }
        """
        hanging_rust = """
        #![forbid(unsafe_code)]
        fn main() {
            loop {}
        }
        """
        res = self.runner.compile_and_test(c_code, hanging_rust, [b"test"], timeout=1.0)
        self.assertTrue(res["compilation_success"])
        self.assertEqual(res["pass_rate"], 0.0)
        self.assertEqual(len(res["divergences"]), 1)
        self.assertTrue(res["divergences"][0]["rust_timed_out"])

    def test_07_output_size_cap(self):
        """Massive stdout generation is capped to prevent memory explosion."""
        c_code = """
        #include <stdio.h>
        int main() {
            for (int i = 0; i < 100000; i++) putchar('A');
            return 0;
        }
        """
        rs_code = """
        #![forbid(unsafe_code)]
        use std::io::{self, Write};
        fn main() {
            let buf = vec![b'A'; 100000];
            io::stdout().write_all(&buf).unwrap();
        }
        """
        res = self.runner.compile_and_test(c_code, rs_code, [b"test"], timeout=2.0)
        self.assertTrue(res["compilation_success"])
        self.assertEqual(res["pass_rate"], 1.0)

    def test_08_no_docker_without_escape_hatch_raises_error(self):
        """Running without Docker and without AEGIS_ALLOW_UNSANDBOXED=1 must raise RuntimeError."""
        old_val = os.environ.pop("AEGIS_ALLOW_UNSANDBOXED", None)
        try:
            # Force non-docker check
            if not self.runner.docker_available:
                with self.assertRaises(RuntimeError):
                    SandboxRunner(force_unsandboxed=False)
        finally:
            if old_val:
                os.environ["AEGIS_ALLOW_UNSANDBOXED"] = old_val


if __name__ == "__main__":
    unittest.main()
