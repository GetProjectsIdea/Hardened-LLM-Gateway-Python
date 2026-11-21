"""Gateway settings (from environment variables) and the start-up preflight.

The gateway REFUSES TO START when any preflight check is an ERROR, for example
a default/weak pepper or admin token, a default upstream key such as
``sk-1234``, a world-readable key file, or a public bind address without an
explicit opt-in.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .keys import file_is_private
from .secrets_check import secret_problems


def _bool(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    key_pepper: str = ""
    admin_token: str = ""
    upstream_url: str = "http://127.0.0.1:11434/v1"
    upstream_api_key: str = ""
    models: list[str] = field(default_factory=lambda: ["qwen2.5-coder:3b"])
    keys_file: str = "data/keys.json"
    audit_log: str = "data/audit.jsonl"
    host: str = "127.0.0.1"
    port: int = 8088
    allow_public_bind: bool = False
    trust_proxy: bool = False
    max_body_kb: int = 256
    max_tokens: int = 2048
    upstream_timeout: float = 120.0
    log_prompt_hash: bool = True
    auth_fail_limit: int = 10

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Settings":
        e = os.environ if env is None else env
        s = cls()
        s.key_pepper = e.get("GATEWAY_KEY_PEPPER", "")
        s.admin_token = e.get("GATEWAY_ADMIN_TOKEN", "")
        s.upstream_url = e.get("GATEWAY_UPSTREAM_URL", s.upstream_url).rstrip("/")
        s.upstream_api_key = e.get("GATEWAY_UPSTREAM_API_KEY", "")
        if e.get("GATEWAY_MODELS"):
            s.models = [m.strip() for m in e["GATEWAY_MODELS"].split(",") if m.strip()]
        s.keys_file = e.get("GATEWAY_KEYS_FILE", s.keys_file)
        s.audit_log = e.get("GATEWAY_AUDIT_LOG", s.audit_log)
        s.host = e.get("GATEWAY_HOST", s.host)
        s.port = int(e.get("GATEWAY_PORT", s.port))
        s.allow_public_bind = _bool(e.get("GATEWAY_ALLOW_PUBLIC_BIND"))
        s.trust_proxy = _bool(e.get("GATEWAY_TRUST_PROXY"))
        s.max_body_kb = int(e.get("GATEWAY_MAX_BODY_KB", s.max_body_kb))
        s.max_tokens = int(e.get("GATEWAY_MAX_TOKENS", s.max_tokens))
        s.upstream_timeout = float(e.get("GATEWAY_UPSTREAM_TIMEOUT", s.upstream_timeout))
        s.log_prompt_hash = not _bool(e.get("GATEWAY_NO_PROMPT_HASH"))
        s.auth_fail_limit = int(e.get("GATEWAY_AUTH_FAIL_LIMIT", s.auth_fail_limit))
        return s


def load_env_file(path: str | os.PathLike, into: dict | None = None) -> dict:
    """Minimal ``KEY=value`` parser for .env files (no shell expansion)."""
    target = os.environ if into is None else into
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        target.setdefault(k, v)
    return target


@dataclass
class Check:
    level: str  # ERROR | WARN | OK
    name: str
    message: str


def is_loopback_host(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def preflight(s: Settings) -> list[Check]:
    out: list[Check] = []
    p = secret_problems(s.key_pepper)
    out.append(Check("ERROR", "GATEWAY_KEY_PEPPER", "pepper " + "; ".join(p)) if p
               else Check("OK", "GATEWAY_KEY_PEPPER", "strong pepper set (keys are HMAC-SHA256 hashed at rest)"))
    if s.admin_token:
        p = secret_problems(s.admin_token)
        if p:
            out.append(Check("ERROR", "GATEWAY_ADMIN_TOKEN", "admin token " + "; ".join(p)))
        elif s.admin_token == s.key_pepper:
            out.append(Check("ERROR", "GATEWAY_ADMIN_TOKEN", "admin token must differ from the pepper"))
        else:
            out.append(Check("OK", "GATEWAY_ADMIN_TOKEN", "strong admin token set (admin UI enabled)"))
    else:
        out.append(Check("OK", "GATEWAY_ADMIN_TOKEN", "not set: admin UI disabled (CLI only)"))
    if s.upstream_api_key:
        p = secret_problems(s.upstream_api_key, min_length=20)
        out.append(Check("ERROR", "GATEWAY_UPSTREAM_API_KEY", "upstream key " + "; ".join(p)) if p
                   else Check("OK", "GATEWAY_UPSTREAM_API_KEY", "upstream key set (never sent to clients or logs)"))
    u = urlparse(s.upstream_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        out.append(Check("ERROR", "GATEWAY_UPSTREAM_URL", f"invalid upstream URL: {s.upstream_url!r}"))
    elif u.scheme == "http" and not is_loopback_host(u.hostname) and "." in u.hostname:
        out.append(Check("WARN", "GATEWAY_UPSTREAM_URL", "plain HTTP to a non-local upstream; use TLS or a private network"))
    else:
        out.append(Check("OK", "GATEWAY_UPSTREAM_URL", f"upstream {s.upstream_url}"))
    if not is_loopback_host(s.host):
        if s.allow_public_bind:
            out.append(Check("WARN", "GATEWAY_HOST", f"binding {s.host}: put a TLS reverse proxy or firewall in front"))
        else:
            out.append(Check("ERROR", "GATEWAY_HOST",
                             f"refusing to bind {s.host} without GATEWAY_ALLOW_PUBLIC_BIND=1 (default is 127.0.0.1)"))
    else:
        out.append(Check("OK", "GATEWAY_HOST", f"bound to loopback {s.host}"))
    if not s.models:
        out.append(Check("ERROR", "GATEWAY_MODELS", "no models allowed; set GATEWAY_MODELS"))
    else:
        out.append(Check("OK", "GATEWAY_MODELS", "allowed models: " + ", ".join(s.models)))
    if os.path.exists(s.keys_file) and not file_is_private(s.keys_file):
        out.append(Check("ERROR", "GATEWAY_KEYS_FILE", f"{s.keys_file} is readable by other users; chmod 600 it"))
    if s.max_tokens > 32768 or s.max_tokens < 1:
        out.append(Check("WARN", "GATEWAY_MAX_TOKENS", f"max_tokens cap {s.max_tokens} looks wrong"))
    return out


def has_errors(checks: list[Check]) -> bool:
    return any(c.level == "ERROR" for c in checks)
