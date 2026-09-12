"""
LLM client tests (tests/test_llm.py): provider selection, stub, replay recording.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from neurons import llm


class TestLLMClient(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        for k in ("AEGIS_LLM_PROVIDER", "AEGIS_LLM_REPLAY", "AEGIS_LLM_RECORD", "AEGIS_LLM_MODEL",
                  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY",
                  "GOOGLE_API_KEY", "OLLAMA_HOST"):
            os.environ.pop(k, None)
        llm.set_stub(None)
        self.tmp = tempfile.mkdtemp()
        self._orig_dir = llm.REPLAY_DIR
        llm.REPLAY_DIR = self.tmp

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        llm.set_stub(None)
        llm.REPLAY_DIR = self._orig_dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_no_credentials_means_replay_only(self):
        c = llm.LLMClient()
        self.assertIsNone(c.provider)
        self.assertTrue(c.replay)
        self.assertIsNone(c.complete("sys", "user"))

    def test_02_provider_detection(self):
        os.environ["ANTHROPIC_API_KEY"] = "x"
        c = llm.LLMClient()
        self.assertEqual(c.provider, "anthropic")
        self.assertEqual(c.model, "claude-opus-5")
        os.environ["AEGIS_LLM_PROVIDER"] = "ollama"
        os.environ["AEGIS_LLM_MODEL"] = "qwen2.5-coder:32b"
        c = llm.LLMClient()
        self.assertEqual((c.provider, c.model), ("ollama", "qwen2.5-coder:32b"))

    def test_03_stub_then_record_then_replay(self):
        llm.set_stub(lambda s, u: "```rust\nfn main() {}\n```")
        os.environ["AEGIS_LLM_RECORD"] = "1"
        c = llm.LLMClient()
        self.assertEqual(c.provider, "stub")
        res = c.complete("S", "U")
        self.assertIn("fn main", res.text)
        # stub responses are never recorded (they are not model output)
        self.assertEqual(os.listdir(self.tmp), [])

        # simulate a recorded live response, then a box with no credentials replays it
        digest = llm._prompt_hash("anthropic", "claude-opus-5", "S", "U")
        c._save_replay(llm.LLMResult(text="```rust\nfn main() { }\n```", provider="anthropic",
                                     model="claude-opus-5", latency_s=1.2, prompt_sha256=digest), "S", "U")
        llm.set_stub(None)
        os.environ.pop("AEGIS_LLM_RECORD")
        c2 = llm.LLMClient()
        self.assertIsNone(c2.provider)
        rep = c2.complete("S", "U")
        self.assertIsNotNone(rep)
        self.assertTrue(rep.replayed)
        self.assertEqual(rep.model, "claude-opus-5")
        files = os.listdir(self.tmp)
        self.assertEqual(len(files), 2)
        with open(os.path.join(self.tmp, files[0]), encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue({"provider", "model", "prompt_sha256", "recorded_at", "response_text"} <= set(data))

    def test_04_replay_key_survives_prompt_drift(self):
        """A repair prompt embeds fuzzer evidence that differs per machine; the stable key still replays."""
        c = llm.LLMClient()
        digest = llm._prompt_hash("anthropic", "claude-opus-5", "S", "evidence run A")
        c._save_replay(llm.LLMResult(text="```rust\nfn main() {}\n```", provider="anthropic", model="claude-opus-5",
                                     latency_s=2.0, prompt_sha256=digest), "S", "evidence run A", replay_key="crc32:abc:attempt2")
        self.assertIsNone(c.complete("S", "evidence run B"))
        rep = c.complete("S", "evidence run B", replay_key="crc32:abc:attempt2")
        self.assertIsNotNone(rep)
        self.assertTrue(rep.replayed)


if __name__ == "__main__":
    unittest.main()
