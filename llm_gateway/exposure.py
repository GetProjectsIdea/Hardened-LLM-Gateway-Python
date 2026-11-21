"""Check YOUR OWN endpoint for unauthenticated access (read-only GETs).

Sends a handful of harmless GET requests without credentials and reports
whether model lists or configuration are readable by anyone. It never sends
credentials, never calls write/management endpoints and never tries
passwords. Only use it on hosts you own or are authorised to test.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable

PROBES = [
    ("Ollama model list", "/api/tags", "ollama"),
    ("Ollama version", "/api/version", "ollama"),
    ("OpenAI-compatible model list", "/v1/models", "openai"),
    ("LiteLLM model info", "/model/info", "litellm"),
    ("Open WebUI public config", "/api/config", "openwebui"),
]

Fetcher = Callable[[str], tuple[int, str]]


def default_fetch(url: str, timeout: float = 5.0) -> tuple[int, str]:
    r = urllib.request.Request(url, headers={"User-Agent": "hardened-llm-gateway-selfcheck/1.0"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as f:
            return f.status, f.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # unreachable, TLS error, timeout
        return 0, str(getattr(e, "reason", e))


def check_exposure(base_url: str, fetch: Fetcher = default_fetch) -> list[dict]:
    base = base_url.rstrip("/")
    results = []
    for title, path, product in PROBES:
        status, body = fetch(base + path)
        res = {"check": title, "path": path, "status": status, "verdict": "closed", "detail": ""}
        data = None
        try:
            data = json.loads(body) if body else None
        except json.JSONDecodeError:
            pass
        if status == 0:
            res["verdict"], res["detail"] = "unreachable", body[:120]
        elif status in (401, 403):
            res["verdict"], res["detail"] = "protected", "authentication required"
        elif status == 200 and isinstance(data, dict):
            if product == "ollama" and "models" in data:
                names = [m.get("name") for m in data.get("models", [])][:5]
                res["verdict"] = "EXPOSED"
                res["detail"] = f"anyone can list and run models: {', '.join(map(str, names)) or '(none)'}"
            elif product == "ollama" and "version" in data:
                res["verdict"], res["detail"] = "EXPOSED", f"Ollama {data['version']} answers without auth"
            elif product in ("openai", "litellm") and "data" in data:
                res["verdict"], res["detail"] = "EXPOSED", f"{len(data['data'])} models listed without a key"
            elif product == "openwebui":
                feats = data.get("features") or {}
                if feats.get("auth") is False:
                    res["verdict"], res["detail"] = "EXPOSED", "Open WebUI reports auth disabled"
                elif feats.get("enable_signup"):
                    res["verdict"], res["detail"] = "WARN", "Open WebUI allows public sign-up"
                else:
                    res["verdict"], res["detail"] = "ok", "auth on, sign-up off"
        results.append(res)
    return results
