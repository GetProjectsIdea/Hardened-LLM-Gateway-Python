"""Upstream LLM backends: a real OpenAI-compatible HTTP backend (Ollama,
LiteLLM, vLLM, llama.cpp server) and an offline mock for demos and tests."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class UpstreamError(Exception):
    pass


class HTTPUpstream:
    """Forwards to ``<base>/chat/completions`` and ``<base>/models``.

    Only the gateway knows ``api_key``; the client's own Authorization header is
    never forwarded.
    """

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 120.0):
        self.base = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout

    def _req(self, method: str, path: str, body: dict | None = None):
        headers = {"Content-Type": "application/json", "User-Agent": "hardened-llm-gateway/1.0"}
        if self._api_key:
            headers["Authorization"] = "Bearer " + self._api_key
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=self.timeout) as f:
                return f.status, json.loads(f.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read() or b"{}")
            except Exception:
                payload = {"error": {"message": f"upstream HTTP {e.code}"}}
            return e.code, payload
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise UpstreamError(f"upstream unreachable: {getattr(e, 'reason', e)}") from None

    def chat(self, payload: dict):
        return self._req("POST", "/chat/completions", payload)

    def embeddings(self, payload: dict):
        return self._req("POST", "/embeddings", payload)

    def models(self):
        return self._req("GET", "/models")


class MockUpstream:
    """Deterministic, offline OpenAI-compatible backend."""

    def __init__(self, models=("qwen2.5-coder:3b", "llama3.2:3b", "gpt-4o")):
        self._models = list(models)
        self.calls: list[dict] = []

    def chat(self, payload: dict):
        self.calls.append(payload)
        msgs = payload.get("messages") or []
        last = str(msgs[-1].get("content", "")) if msgs else ""
        if payload.get("model") not in self._models:
            return 404, {"error": {"message": f"model {payload.get('model')!r} not found"}}
        text = "Hello from the mock model. You said: " + last[:60]
        mt = payload.get("max_tokens")
        if mt is not None and int(mt) <= 1:
            text = "Hi"
        pt = max(1, len(" ".join(str(m.get("content", "")) for m in msgs).split()))
        ct = 1 if text == "Hi" else len(text.split())
        return 200, {"id": "chatcmpl-mock", "object": "chat.completion", "model": payload.get("model"),
                     "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                  "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct}}

    def embeddings(self, payload: dict):
        self.calls.append(payload)
        return 200, {"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
                     "model": payload.get("model"), "usage": {"prompt_tokens": 3, "total_tokens": 3}}

    def models(self):
        return 200, {"object": "list", "data": [{"id": m, "object": "model"} for m in self._models]}
