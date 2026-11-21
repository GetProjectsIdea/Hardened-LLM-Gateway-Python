"""Detect default, example and weak secrets.

Used by the gateway's start-up checks (it refuses to start with a weak secret)
and by the config auditor (which flags weak secrets in LiteLLM / Open WebUI /
Ollama / docker-compose files).
"""
from __future__ import annotations

import math
import re
import secrets
from collections import Counter

# Values that appear in official docs, quick-start guides, tutorials and
# docker-compose examples. Attackers' playbooks try exactly these.
KNOWN_DEFAULTS = {
    "sk-1234", "sk-12345", "sk-123456", "sk-1234567890", "sk-litellm", "sk-master",
    "sk-admin", "sk-test", "sk-xxxx", "sk-xxx", "sk-your-key", "sk-your-master-key",
    "t0p-s3cr3t", "top-secret", "changeme", "change-me", "change_me", "changeit",
    "password", "passw0rd", "p@ssw0rd", "admin", "administrator", "root", "secret",
    "default", "test", "testing", "example", "demo", "letmein", "qwerty", "123456",
    "12345678", "1234567890", "ollama", "litellm", "openwebui", "open-webui",
    "postgres", "mysecretkey", "mysecret", "supersecret", "your-secret-key",
    "your_secret_key", "secret-key", "secretkey", "none", "null", "token", "apikey",
    "api-key", "api_key",
}
PLACEHOLDER_HINTS = ("changeme", "change-me", "change_me", "replace", "your-", "your_",
                     "example", "placeholder", "dummy", "xxxx", "todo", "<", ">")
MIN_LENGTH = 32


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character (0 for empty strings)."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def secret_problems(value: str | None, min_length: int = MIN_LENGTH) -> list[str]:
    """Return a list of human-readable reasons why *value* is unsafe.

    An empty list means the secret looks strong enough.
    """
    if value is None or value.strip() == "":
        return ["is empty or not set"]
    v = value.strip()
    low = v.lower()
    problems: list[str] = []
    if low in KNOWN_DEFAULTS:
        problems.append("is a well-known default value")
    elif any(h in low for h in PLACEHOLDER_HINTS):
        problems.append("looks like a placeholder from an example file")
    if re.fullmatch(r"(sk-)?\d+", low):
        problems.append("contains only digits")
    if len(v) < min_length:
        problems.append(f"is too short ({len(v)} chars, need at least {min_length})")
    if len(set(v)) < 10:
        problems.append("uses too few distinct characters")
    elif shannon_entropy(v) < 3.5:
        problems.append("has low entropy (looks guessable)")
    if re.search(r"(.{1,4})\1{4,}", v):
        problems.append("contains a repeating pattern")
    return problems


def is_weak(value: str | None, min_length: int = MIN_LENGTH) -> bool:
    return bool(secret_problems(value, min_length))


def generate_secret(nbytes: int = 32, prefix: str = "") -> str:
    """Cryptographically strong URL-safe secret (43+ chars for 32 bytes)."""
    return prefix + secrets.token_urlsafe(nbytes)


def redact(value: str, keep: int = 4) -> str:
    """Show only the first *keep* characters of a secret."""
    if not value:
        return ""
    if len(value) <= keep + 2:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * 6


# Provider key formats worth flagging when found hard-coded in config files.
PROVIDER_KEY_PATTERNS = [
    ("OpenAI project key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style key", re.compile(r"\bsk-(?!proj-|ant-)[A-Za-z0-9]{32,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Groq key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("OpenRouter key", re.compile(r"\bsk-or-v1-[a-f0-9]{40,}\b")),
]


def find_provider_keys(text: str) -> list[tuple[str, str]]:
    """Return (kind, redacted_value) for provider keys found in *text*."""
    found = []
    for kind, pat in PROVIDER_KEY_PATTERNS:
        for m in pat.finditer(text):
            found.append((kind, redact(m.group(0), 8)))
    return found
