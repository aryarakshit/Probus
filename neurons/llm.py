"""
Provider-agnostic LLM client for Aegis miners (neurons/llm.py).

Miners on a decentralized subnet pick their own model, so this module speaks to
several backends behind one interface:

    anthropic  - official `anthropic` SDK (default when ANTHROPIC_API_KEY is set)
    openai     - Chat Completions over HTTPS
    gemini     - Generative Language API over HTTPS
    ollama     - local HTTP server (http://localhost:11434)
    stub       - in-process callable, used by the test-suite to exercise plumbing

Two switches matter for demos:

    AEGIS_LLM_RECORD=1  - write every live response to dataset/llm_replay/
    AEGIS_LLM_REPLAY=1  - serve responses from dataset/llm_replay/ instead of a
                          provider (used when no credentials are present so the
                          demo replays *real* recorded model output, never a
                          hand-written answer key). Replay files carry provider,
                          model, prompt hash and timestamp for provenance.
"""

import os
import sys
import json
import time
import hashlib
import logging
import urllib.request
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any

logger = logging.getLogger("llm")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s] [LLM] [%(levelname)s] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

REPLAY_DIR = os.path.join(os.path.dirname(__file__), "..", "dataset", "llm_replay")

DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-4o",
    "gemini": "gemini-2.0-flash",
    "ollama": "qwen2.5-coder:7b",
    "stub": "stub",
}

_STUB_FN: Optional[Callable[[str, str], str]] = None


def set_stub(fn: Optional[Callable[[str, str], str]]) -> None:
    """Register an in-process function (system, user) -> text for the 'stub' provider."""
    global _STUB_FN
    _STUB_FN = fn


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    latency_s: float
    replayed: bool = False
    usage: Dict[str, Any] = field(default_factory=dict)
    prompt_sha256: str = ""


def sha_key(key: str) -> str:
    return hashlib.sha256(("replay-key:" + key).encode("utf-8")).hexdigest()


def _prompt_hash(provider: str, model: str, system: str, user: str) -> str:
    h = hashlib.sha256()
    for part in (provider, model, system, user):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def detect_provider() -> Optional[str]:
    """Pick a provider from AEGIS_LLM_PROVIDER or from whichever credential is present."""
    forced = os.environ.get("AEGIS_LLM_PROVIDER", "").strip().lower()
    if forced:
        return forced
    if _STUB_FN is not None:
        return "stub"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    return None


class LLMClient:
    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None, timeout: float = 120.0):
        self.provider = provider or detect_provider()
        self.model = model or os.environ.get("AEGIS_LLM_MODEL") or DEFAULT_MODELS.get(self.provider or "", "")
        self.timeout = timeout
        self.record = os.environ.get("AEGIS_LLM_RECORD") == "1"
        self.replay = os.environ.get("AEGIS_LLM_REPLAY") == "1" or self.provider is None
        self._anthropic = None

    @property
    def available(self) -> bool:
        return self.provider is not None or self.replay

    def describe(self) -> str:
        if self.provider:
            return f"{self.provider}:{self.model}" + (" (+record)" if self.record else "")
        return "replay-only (no provider credentials)"

    # ------------------------------------------------------------------ public
    def complete(self, system: str, user: str, max_tokens: int = 16000,
                 replay_key: Optional[str] = None) -> Optional[LLMResult]:
        """Return the model's text for (system, user), or None if nothing can answer.

        `replay_key` is a caller-chosen stable id (e.g. task + C hash + attempt number) that lets
        a recording be replayed even when the exact prompt text differs slightly between runs
        (repair prompts embed fuzzer evidence that is not byte-identical across machines)."""
        key_provider = self.provider or "replay"
        key_model = self.model or "replay"
        digest = _prompt_hash(key_provider, key_model, system, user)

        if self.replay:
            hit = self._load_replay(digest, system, user, replay_key)
            if hit:
                return hit
            if self.provider is None:
                logger.warning("No LLM provider configured and no replay entry for prompt %s", digest[:12])
                return None

        t0 = time.time()
        try:
            if self.provider == "anthropic":
                text, usage = self._call_anthropic(system, user, max_tokens)
            elif self.provider == "openai":
                text, usage = self._call_openai(system, user, max_tokens)
            elif self.provider == "gemini":
                text, usage = self._call_gemini(system, user, max_tokens)
            elif self.provider == "ollama":
                text, usage = self._call_ollama(system, user, max_tokens)
            elif self.provider == "stub":
                if _STUB_FN is None:
                    raise RuntimeError("stub provider selected but no stub function registered")
                text, usage = _STUB_FN(system, user), {}
            else:
                raise RuntimeError(f"Unknown LLM provider '{self.provider}'")
        except Exception as e:
            logger.error("LLM call failed (%s): %s", self.describe(), e)
            return None

        result = LLMResult(
            text=text,
            provider=self.provider,
            model=self.model,
            latency_s=round(time.time() - t0, 3),
            usage=usage,
            prompt_sha256=digest,
        )
        if self.record and self.provider != "stub":
            self._save_replay(result, system, user, replay_key)
        return result

    # ----------------------------------------------------------------- replay
    def _replay_path(self, digest: str) -> str:
        return os.path.join(REPLAY_DIR, f"{digest[:24]}.json")

    def _load_replay(self, digest: str, system: str, user: str, replay_key: Optional[str]) -> Optional[LLMResult]:
        # 1. exact provider/model/prompt  2. same prompt, any provider  3. caller's stable key
        candidates = [self._replay_path(digest), self._replay_path(_prompt_hash("*", "*", system, user))]
        if replay_key:
            candidates.append(self._replay_path(sha_key(replay_key)))
        path = next((p for p in candidates if os.path.exists(p)), None)
        if path is None:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info("[REPLAY] %s recorded %s by %s:%s", os.path.basename(path),
                        data.get("recorded_at"), data.get("provider"), data.get("model"))
            return LLMResult(
                text=data["response_text"],
                provider=data.get("provider", "replay"),
                model=data.get("model", "replay"),
                latency_s=0.0,
                replayed=True,
                usage=data.get("usage", {}),
                prompt_sha256=data.get("prompt_sha256", digest),
            )
        except Exception as e:
            logger.warning("Replay file %s unreadable: %s", path, e)
            return None

    def _save_replay(self, result: LLMResult, system: str, user: str, replay_key: Optional[str] = None) -> None:
        os.makedirs(REPLAY_DIR, exist_ok=True)
        payload = {
            "provider": result.provider,
            "model": result.model,
            "prompt_sha256": result.prompt_sha256,
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "latency_s": result.latency_s,
            "usage": result.usage,
            "response_text": result.text,
        }
        if replay_key:
            payload["replay_key"] = replay_key
        paths = [self._replay_path(result.prompt_sha256), self._replay_path(_prompt_hash("*", "*", system, user))]
        if replay_key:
            paths.append(self._replay_path(sha_key(replay_key)))
        for path in paths:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        logger.info("[RECORD] saved %s", os.path.basename(self._replay_path(result.prompt_sha256)))

    # -------------------------------------------------------------- providers
    def _call_anthropic(self, system: str, user: str, max_tokens: int):
        import anthropic  # official SDK; resolves ANTHROPIC_API_KEY / auth profile itself
        if self._anthropic is None:
            self._anthropic = anthropic.Anthropic(timeout=self.timeout)
        kwargs: Dict[str, Any] = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
        # Haiku 4.5 still uses the budget form; every current Opus/Sonnet takes adaptive.
        if not self.model.startswith("claude-haiku"):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["output_config"] = {"effort": os.environ.get("AEGIS_LLM_EFFORT", "high")}
        with self._anthropic.messages.stream(**kwargs) as stream:
            msg = stream.get_final_message()
        if msg.stop_reason == "refusal":
            raise RuntimeError("model refused the request")
        text = "".join(b.text for b in msg.content if b.type == "text")
        usage = {
            "input_tokens": msg.usage.input_tokens,
            "output_tokens": msg.usage.output_tokens,
            "cache_read_input_tokens": getattr(msg.usage, "cache_read_input_tokens", 0),
        }
        return text, usage

    def _http_json(self, url: str, body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json", **headers})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _call_openai(self, system: str, user: str, max_tokens: int):
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        data = self._http_json(
            f"{base}/chat/completions",
            {"model": self.model, "temperature": 0.1, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
        )
        return data["choices"][0]["message"]["content"], data.get("usage", {})

    def _call_gemini(self, system: str, user: str, max_tokens: int):
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={key}"
        data = self._http_json(
            url,
            {"system_instruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": user}]}],
             "generationConfig": {"temperature": 0.1, "maxOutputTokens": max_tokens}},
            {},
        )
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts), data.get("usageMetadata", {})

    def _call_ollama(self, system: str, user: str, max_tokens: int):
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        data = self._http_json(
            f"{host}/api/chat",
            {"model": self.model, "stream": False,
             "options": {"temperature": 0.1, "num_predict": max_tokens},
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            {},
        )
        return data["message"]["content"], {
            "input_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count")}
