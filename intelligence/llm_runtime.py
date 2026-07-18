"""
llm_runtime.py - Local LLM Runtime (Phase 3)
=============================================

The investigator's model backend, kept behind a tiny interface so the
rest of NetWatch never depends on a specific engine — and so the whole
investigation pipeline is testable with a scripted runtime and no model
installed at all.

Backends
--------
* :class:`OllamaRuntime` — talks to a **local** Ollama server
  (127.0.0.1:11434) over stdlib HTTP.  Fully offline; zero cloud, zero
  new dependencies.  This is the real runtime when Harsha has Ollama +
  a quantized 4–8B model pulled.
* :class:`ScriptedRuntime` — returns a fixed list of responses in order.
  Drives the tool-calling loop deterministically in tests.

Both expose one method: ``generate(messages) -> str`` where *messages*
is an OpenAI-style ``[{"role", "content"}]`` list and the return is the
model's raw text (the investigator parses JSON out of it).
"""

import json
import logging
import urllib.error
import urllib.request
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

_OLLAMA_HOST = "127.0.0.1"
_OLLAMA_PORT = 11434


class LLMUnavailable(RuntimeError):
    """Raised when no local model backend can be reached."""


class OllamaRuntime:
    """Local Ollama chat backend (offline, localhost only)."""

    def __init__(self, model: str = "llama3", host: str = _OLLAMA_HOST,
                 port: int = _OLLAMA_PORT, timeout: float = 60.0,
                 keep_alive: Optional[str] = None,
                 num_predict: Optional[int] = None):
        self.model = model
        self._base = f"http://{host}:{port}"
        self._timeout = timeout
        self._keep_alive = keep_alive
        self._num_predict = num_predict

    def is_available(self) -> bool:
        """True if a local Ollama server answers on the loopback port."""
        try:
            req = urllib.request.Request(f"{self._base}/api/tags")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def generate(self, messages: List[Dict[str, str]]) -> str:
        # Low temperature: investigation must be faithful, not creative.
        options: Dict[str, object] = {"temperature": 0.1}
        if self._num_predict is not None:
            options["num_predict"] = self._num_predict
        body: Dict[str, object] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        # keep_alive holds the model resident between calls so only the first
        # generation pays the load-from-disk cost (biggest latency win).
        if self._keep_alive is not None:
            body["keep_alive"] = self._keep_alive
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            raise LLMUnavailable(f"Ollama request failed: {exc}") from exc
        return (body.get("message") or {}).get("content", "")


class ScriptedRuntime:
    """Deterministic backend that replays a fixed list of responses.

    Each ``generate`` call returns the next scripted response.  Used by
    tests to drive the tool-calling loop without a model.
    """

    def __init__(self, responses: List[str]):
        self._responses = list(responses)
        self._i = 0
        self.calls: List[List[Dict[str, str]]] = []

    def is_available(self) -> bool:
        return True

    def generate(self, messages: List[Dict[str, str]]) -> str:
        self.calls.append(messages)
        if self._i >= len(self._responses):
            # Out of script — return a terminal answer so loops always end.
            return json.dumps({"action": "answer",
                               "answer": "No further information.",
                               "citations": []})
        resp = self._responses[self._i]
        self._i += 1
        return resp


def get_runtime(model: Optional[str] = None) -> Optional[OllamaRuntime]:
    """Return a ready local runtime, or None when none is available.

    Mirrors the graceful-degradation pattern used across NetWatch: the
    caller treats None as "LLM investigations are off" rather than an
    error.
    """
    try:
        from config import (LLM_TIMEOUT_SECONDS as _timeout,
                            LLM_MODEL as _model,
                            LLM_KEEP_ALIVE as _keep_alive,
                            LLM_NUM_PREDICT as _num_predict)
    except ImportError:          # config not importable (standalone use)
        _timeout, _model = 180.0, "llama3.2:3b"
        _keep_alive, _num_predict = "30m", 512
    runtime = OllamaRuntime(model=model or _model, timeout=_timeout,
                            keep_alive=_keep_alive, num_predict=_num_predict)
    if runtime.is_available():
        return runtime
    logger.info("No local Ollama runtime reachable — LLM investigations "
                "unavailable (install Ollama + pull '%s' to enable).",
                model or _model)
    return None
