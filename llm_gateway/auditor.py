"""Config auditor for self-hosted LLM stacks (LiteLLM, Open WebUI, Ollama).

Read-only: it parses docker-compose files, LiteLLM ``config.yaml``, ``.env``
files and systemd units, and reports default keys, weak secrets, exposed
ports, disabled authentication, hard-coded provider keys and outdated LiteLLM
images. It never connects anywhere and never changes a file.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

from .secrets_check import find_provider_keys, redact, secret_problems

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
LITELLM_MIN_SAFE = (1, 84, 0)  # CVE-2026-40217 fixed in 1.83.10; /key/regenerate rebind fixed in 1.84.0
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}


@dataclass
class Finding:
    severity: str
    rule: str
    title: str
    file: str
    line: int
    detail: str
    fix: str

    def as_dict(self) -> dict:
        return asdict(self)


def _line_of(text: str, needle: str) -> int:
    if not needle:
        return 0
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 0


def _is_reference(v: str) -> bool:
    v = v.strip()
    return v.startswith("os.environ/") or bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*(:?[-?][^}]*)?\}?", v))


def _truthy(v) -> bool:
    return str(v).strip().strip("'\"").lower() in {"1", "true", "yes", "on"}


def _falsy(v) -> bool:
    return str(v).strip().strip("'\"").lower() in {"0", "false", "no", "off"}


def _env_dict(env) -> dict:
    if isinstance(env, dict):
        return {str(k): ("" if v is None else str(v)) for k, v in env.items()}
    out = {}
    for item in env or []:
        s = str(item)
        if "=" in s:
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip()
        else:
            out[s.strip()] = ""
    return out


def parse_env_text(text: str) -> dict:
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^Environment=(.*)$", line)
        if m:  # systemd unit: Environment="A=1" "B=2"
            for part in re.findall(r'"([^"]*)"|(\S+)', m.group(1)):
                kv = part[0] or part[1]
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    out[k] = v
            continue
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.split(" #")[0].strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


# ------------------------------------------------------------------ env rules
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|MASTER_KEY|SALT_KEY|PEPPER)$", re.I)


def check_env(env: dict, fname: str, text: str, *, in_container: bool = False, kind: str = "") -> list[Finding]:
    f: list[Finding] = []

    def add(sev, rule, title, key, detail, fix):
        f.append(Finding(sev, rule, title, fname, _line_of(text, key), detail, fix))

    flagged = set()
    for key, val in env.items():
        if not val or _is_reference(val):
            continue
        up = key.upper()
        probs = secret_problems(val)
        if up == "LITELLM_MASTER_KEY" and probs:
            add("HIGH", "LGW-L01", "Default or weak LiteLLM master key", key,
                f"LITELLM_MASTER_KEY={redact(val)} {probs[0]}. Attack playbooks try the LiteLLM default master key first.",
                "Generate a long random key (python -m llm_gateway init), keep it in a secret store, and give users virtual keys instead of the master key.")
            flagged.add(key)
        elif up == "WEBUI_SECRET_KEY" and probs:
            add("HIGH", "LGW-W02", "Default or weak Open WebUI secret key", key,
                f"WEBUI_SECRET_KEY={redact(val)} {probs[0]}. It signs login tokens, so a known value lets anyone forge a session.",
                "Set WEBUI_SECRET_KEY to a long random value and restart Open WebUI (users must log in again).")
            flagged.add(key)
        elif up in ("GATEWAY_KEY_PEPPER", "GATEWAY_ADMIN_TOKEN") and probs:
            add("HIGH", "LGW-G01", f"Weak {up}", key, f"{up} {probs[0]}; the gateway will refuse to start.",
                "Run `python -m llm_gateway init` to generate strong values.")
            flagged.add(key)
        elif up == "UI_PASSWORD" and probs:
            add("HIGH", "LGW-L10", "Weak LiteLLM admin UI password", key, f"UI_PASSWORD {probs[0]}.",
                "Use SSO or a long random UI_PASSWORD and keep the LiteLLM UI off the internet.")
            flagged.add(key)
        elif up == "LITELLM_SALT_KEY" and probs:
            add("MEDIUM", "LGW-L11", "Weak LiteLLM salt key", key,
                f"LITELLM_SALT_KEY {probs[0]}. It encrypts provider keys stored in the database.",
                "Set a long random salt key before adding provider keys (it cannot be changed later without re-adding them).")
            flagged.add(key)
        elif up in ("POSTGRES_PASSWORD", "REDIS_PASSWORD") and probs:
            add("MEDIUM", "LGW-D01", f"Weak {up}", key, f"{up} {probs[0]}. The database holds hashed keys, spend data and encrypted provider keys.",
                "Use a long random password and keep the database on an internal network.")
            flagged.add(key)

    for key, val in env.items():
        if key in flagged or not val or _is_reference(val) or not SECRET_NAME.search(key):
            continue
        probs = secret_problems(val, min_length=16)
        if any("default" in p or "placeholder" in p for p in probs):
            add("MEDIUM", "LGW-S02", f"Default or placeholder value in {key}", key,
                f"{key}={redact(val)} {probs[0]}.", "Replace it with a real secret from a secret manager or an untracked .env file.")

    g = {k.upper(): v for k, v in env.items()}
    if "WEBUI_AUTH" in g and _falsy(g["WEBUI_AUTH"]):
        add("HIGH", "LGW-W01", "Open WebUI authentication disabled", "WEBUI_AUTH",
            "WEBUI_AUTH=False turns off login: anyone who can reach the UI can use every connected model and see stored provider connections.",
            "Remove WEBUI_AUTH=False (the default is True). Use it only for a single-user, localhost-only install.")
    if _truthy(g.get("ENABLE_SIGNUP", "")):
        add("MEDIUM", "LGW-W03", "Open WebUI public sign-up enabled", "ENABLE_SIGNUP",
            "ENABLE_SIGNUP=True lets strangers create accounts.",
            "Set ENABLE_SIGNUP=False after creating the admin account, and invite users instead.")
    if g.get("DEFAULT_USER_ROLE", "").strip().lower() == "admin":
        add("HIGH", "LGW-W04", "New Open WebUI users become admins", "DEFAULT_USER_ROLE",
            "DEFAULT_USER_ROLE=admin gives every new account admin rights (connections, API keys, users).",
            "Use DEFAULT_USER_ROLE=pending (default) or user.")
    if kind == "openwebui" and "WEBUI_SECRET_KEY" not in g and not _falsy(g.get("WEBUI_AUTH", "true")):
        add("LOW", "LGW-W06", "Open WebUI secret key not set explicitly", "open-webui",
            "Without WEBUI_SECRET_KEY the container generates one on first start; make sure the data volume is persistent and private.",
            "Set WEBUI_SECRET_KEY from a secret so sessions survive restarts and the value is managed.")
    host = g.get("OLLAMA_HOST", "")
    if host and not in_container and re.match(r"^(https?://)?(0\.0\.0\.0|\[?::\]?)(:|$)", host):
        add("MEDIUM", "LGW-O01", "Ollama listens on all network interfaces", "OLLAMA_HOST",
            f"OLLAMA_HOST={host} exposes the unauthenticated Ollama API (chat, /api/pull, /api/create, /api/delete) to the network.",
            "Use OLLAMA_HOST=127.0.0.1:11434 and put the hardened gateway in front, or firewall port 11434.")
    if g.get("OLLAMA_ORIGINS", "").strip() == "*":
        add("MEDIUM", "LGW-O02", "Ollama allows requests from any web origin", "OLLAMA_ORIGINS",
            "OLLAMA_ORIGINS=* lets any website you visit call your local Ollama from the browser.",
            "Remove it or list only the exact origins you need.")
    return f


# -------------------------------------------------------------- compose rules
def _service_kind(name: str, svc: dict) -> str:
    img = str(svc.get("image", "")).lower()
    n = name.lower()
    for kind, hints in (("litellm", ("litellm",)), ("openwebui", ("open-webui", "openwebui")),
                        ("ollama", ("ollama",)), ("postgres", ("postgres",)), ("redis", ("redis", "valkey")),
                        ("gateway", ("hardened-llm-gateway", "llm-gateway", "llm_gateway"))):
        if any(h in img for h in hints):
            return kind
    for kind, hints in (("litellm", ("litellm",)), ("openwebui", ("webui",)), ("ollama", ("ollama",)),
                        ("gateway", ("gateway",))):
        if any(h in n for h in hints):
            return kind
    return "other"


def _ports(svc: dict) -> list[tuple[str, str, str]]:
    """Return (host_ip, published, target) for each published port."""
    out = []
    for p in svc.get("ports") or []:
        if isinstance(p, dict):
            out.append((str(p.get("host_ip", "")), str(p.get("published", "")), str(p.get("target", ""))))
            continue
        s = str(p).split("/")[0]
        m = re.match(r"^(?:\[?([0-9a-fA-F:.]+?)\]?:)?(\d+(?:-\d+)?):(\d+(?:-\d+)?)$", s)
        if m:
            out.append((m.group(1) or "", m.group(2), m.group(3)))
        elif re.fullmatch(r"\d+", s):
            out.append(("", "random", s))
    return out


def _is_public(ip: str) -> bool:
    return ip in ("", "0.0.0.0", "::", "[::]")


def _version(tag: str):
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(x) for x in m.groups()) if m else None


def check_compose(doc: dict, fname: str, text: str) -> list[Finding]:
    f: list[Finding] = []
    services = doc.get("services") or {}
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        kind = _service_kind(name, svc)
        env = _env_dict(svc.get("environment"))
        f += check_env(env, fname, text, in_container=True, kind=kind)
        for ip, pub, target in _ports(svc):
            public = _is_public(ip)
            where = f"{ip or '0.0.0.0'}:{pub}->{target}"
            if not public:
                continue
            if kind == "ollama" or target == "11434":
                f.append(Finding("HIGH", "LGW-O03", "Ollama API published on all interfaces", fname,
                                 _line_of(text, f"{pub}:{target}") or _line_of(text, name), f"service '{name}' publishes {where}. Ollama has no authentication, so anyone who can reach it can run, pull, create or delete models.",
                                 "Remove the ports entry (other containers reach it over the internal network) or bind 127.0.0.1:11434:11434."))
            elif kind == "litellm" or target == "4000":
                f.append(Finding("HIGH", "LGW-L02", "LiteLLM proxy published on all interfaces", fname,
                                 _line_of(text, f"{pub}:{target}") or _line_of(text, name), f"service '{name}' publishes {where}, including the admin UI and the /key, /user and /guardrails management APIs.",
                                 "Bind 127.0.0.1 and expose only the chat routes through the hardened gateway or a reverse proxy with an allow-list."))
            elif kind in ("postgres", "redis") or target in ("5432", "6379"):
                f.append(Finding("HIGH", "LGW-D02", f"{kind.title()} published on all interfaces", fname,
                                 _line_of(text, f"{pub}:{target}") or _line_of(text, name), f"service '{name}' publishes {where}.",
                                 "Delete the ports entry; only the app containers need the database."))
            elif kind == "openwebui":
                f.append(Finding("MEDIUM", "LGW-W05", "Open WebUI published on all interfaces", fname,
                                 _line_of(text, f"{pub}:{target}") or _line_of(text, name), f"service '{name}' publishes {where} over plain HTTP.",
                                 "Bind 127.0.0.1 and publish it through a TLS reverse proxy; keep authentication on and sign-up off."))
            elif kind == "gateway":
                f.append(Finding("LOW", "LGW-G02", "Gateway published on all interfaces", fname,
                                 _line_of(text, f"{pub}:{target}") or _line_of(text, name), f"service '{name}' publishes {where} without TLS.",
                                 "Terminate TLS in a reverse proxy and bind the gateway to 127.0.0.1 or an internal network."))
        if svc.get("network_mode") == "host" and kind in ("ollama", "litellm", "openwebui"):
            f.append(Finding("MEDIUM", "LGW-C02", "Host networking on an LLM service", fname, _line_of(text, "network_mode"),
                             f"service '{name}' uses network_mode: host, so every port it opens is on the host's interfaces.",
                             "Use a private bridge network and publish nothing you do not need."))
        if svc.get("privileged") is True:
            f.append(Finding("MEDIUM", "LGW-C01", "Privileged container", fname, _line_of(text, "privileged"),
                             f"service '{name}' runs privileged; a compromise becomes a host compromise.",
                             "Remove privileged: true; use device reservations for GPUs instead."))
        if kind == "litellm":
            img = str(svc.get("image", ""))
            tag = img.split(":", 1)[1] if ":" in img.split("/")[-1] else "latest"
            ver = _version(tag)
            if ver is None:
                f.append(Finding("MEDIUM", "LGW-L03", "LiteLLM image not pinned to a version", fname, _line_of(text, img),
                                 f"image '{img}' uses tag '{tag}'. You cannot tell whether known-exploited LiteLLM fixes are included.",
                                 "Pin a patched stable tag (1.84.0 or later) and update deliberately."))
            elif ver < LITELLM_MIN_SAFE:
                f.append(Finding("HIGH", "LGW-L04", "Outdated LiteLLM image", fname, _line_of(text, img),
                                 f"image '{img}' is older than 1.84.0. CVE-2026-40217 (guardrail sandbox escape, in CISA KEV since 18 Nov 2026) is fixed in 1.83.10 and the /key/regenerate privilege escalation in 1.84.0.",
                                 "Upgrade LiteLLM to 1.84.0 or later, then rotate the master key and any virtual keys."))
    return f


# -------------------------------------------------------------- LiteLLM rules
def check_litellm(doc: dict, fname: str, text: str) -> list[Finding]:
    f: list[Finding] = []
    gs = doc.get("general_settings") or {}
    mk = gs.get("master_key")
    if mk in (None, ""):
        f.append(Finding("HIGH", "LGW-L05", "LiteLLM proxy has no master key", fname, _line_of(text, "general_settings"),
                         "Without general_settings.master_key (or LITELLM_MASTER_KEY) the proxy does not require keys at all.",
                         "Set master_key: os.environ/LITELLM_MASTER_KEY with a strong random value and issue virtual keys."))
    elif not _is_reference(str(mk)):
        probs = secret_problems(str(mk))
        if probs:
            f.append(Finding("HIGH", "LGW-L01", "Default or weak LiteLLM master key", fname, _line_of(text, "master_key"),
                             f"master_key {redact(str(mk))} {probs[0]}. 'sk-1234' appears in many examples and attack playbooks.",
                             "Use master_key: os.environ/LITELLM_MASTER_KEY with a long random value; never commit it."))
        else:
            f.append(Finding("MEDIUM", "LGW-L06", "LiteLLM master key hard-coded in config", fname, _line_of(text, "master_key"),
                             "The master key is written in the config file, so it ends up in Git, images and backups.",
                             "Use master_key: os.environ/LITELLM_MASTER_KEY."))
    db = gs.get("database_url")
    if isinstance(db, str) and not _is_reference(db) and re.search(r"://[^:/]+:[^@]+@", db):
        f.append(Finding("MEDIUM", "LGW-L09", "Database password in LiteLLM config", fname, _line_of(text, "database_url"),
                         "database_url contains a password in plain text.", "Use database_url: os.environ/DATABASE_URL."))
    for m in doc.get("model_list") or []:
        if not isinstance(m, dict):
            continue
        lp = m.get("litellm_params") or {}
        key = lp.get("api_key")
        if key in (None, "") or _is_reference(str(key)):
            continue
        name = m.get("model_name", "?")
        if find_provider_keys(str(key)) or (len(str(key)) >= 24 and not secret_problems(str(key), 24)):
            f.append(Finding("HIGH", "LGW-L07", "Provider API key hard-coded in LiteLLM config", fname, _line_of(text, str(key)[:12]),
                             f"model '{name}' has api_key {redact(str(key), 8)} written in the file. Gateways that pool provider keys are the main target of key-theft campaigns.",
                             "Use api_key: os.environ/PROVIDER_API_KEY, rotate this key now, and set a spend limit at the provider."))
        else:
            f.append(Finding("LOW", "LGW-L12", "Placeholder api_key in LiteLLM config", fname, _line_of(text, str(key)[:12]),
                             f"model '{name}' has a literal api_key value ({redact(str(key))}).",
                             "Fine for keyless local backends like Ollama; otherwise reference an environment variable."))
    for g in doc.get("guardrails") or []:
        gp = (g or {}).get("litellm_params") or {}
        if "custom_code" in str(gp.get("guardrail", "")) or "custom_code" in str(gp.get("mode", "")):
            f.append(Finding("MEDIUM", "LGW-L08", "Custom-code guardrail configured", fname, _line_of(text, "custom_code"),
                             "Custom-code guardrails run Python inside the proxy. CVE-2026-40217 (sandbox escape via /guardrails/test_custom_code) is in CISA KEV.",
                             "Run LiteLLM 1.84.0+, block /guardrails/* from the internet, and run the container as non-root."))
    return f


# ------------------------------------------------------------------ dispatch
def _kind_of(name: str, text: str):
    low = name.lower()
    base = os.path.basename(low)
    if base.endswith((".service", ".conf")) and "[service]" in text.lower():
        return "env", None
    if base.startswith(".env") or base.endswith(".env") or base in ("env", "environment"):
        return "env", None
    if base.endswith((".yml", ".yaml")):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return "invalid-yaml", None
        if isinstance(doc, dict) and isinstance(doc.get("services"), dict):
            return "compose", doc
        if isinstance(doc, dict) and any(k in doc for k in ("model_list", "general_settings", "litellm_settings", "router_settings")):
            return "litellm", doc
        return "yaml", doc
    if re.search(r"^[A-Z_][A-Z0-9_]*=", text, re.M):
        return "env", None
    return "unknown", None


def audit_text(text: str, name: str = "config") -> list[Finding]:
    kind, doc = _kind_of(name, text)
    f: list[Finding] = []
    if kind == "compose":
        f += check_compose(doc, name, text)
    elif kind == "litellm":
        f += check_litellm(doc, name, text)
    elif kind == "env":
        f += check_env(parse_env_text(text), name, text)
    elif kind == "invalid-yaml":
        f.append(Finding("INFO", "LGW-X01", "Could not parse YAML", name, 0, "The file is not valid YAML.", "Fix the syntax and re-run."))
    seen = set()
    for kindname, red in find_provider_keys(text):
        if red in seen or any(red in x.detail for x in f):
            continue
        seen.add(red)
        f.append(Finding("HIGH", "LGW-S01", f"{kindname} found in file", name, _line_of(text, red[:8]),
                         f"A {kindname} ({red}) is stored in plain text.",
                         "Revoke and rotate it at the provider, remove it from Git history, and load keys from a secret store."))
    return sort_findings(f)


def sort_findings(f: list[Finding]) -> list[Finding]:
    return sorted(f, key=lambda x: (SEV_ORDER.get(x.severity, 9), x.file, x.line, x.rule))


CANDIDATE = re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$|\.ya?ml$|(^|/)\.env[^/]*$|\.env$|\.service$|(^|/)ollama\.conf$")


def audit_path(path: str | os.PathLike) -> list[Finding]:
    p = Path(path)
    files = [p] if p.is_file() else [x for x in sorted(p.rglob("*"))
                                     if x.is_file() and not (SKIP_DIRS & set(x.parts)) and CANDIDATE.search(x.as_posix())]
    out: list[Finding] = []
    for fp in files:
        try:
            text = fp.read_text(errors="replace")
        except OSError:
            continue
        if len(text) > 2_000_000:
            continue
        rel = fp.as_posix() if p.is_file() else fp.relative_to(p).as_posix()
        for fd in audit_text(text, rel):
            out.append(fd)
        if fp.name.startswith(".env") and os.name == "posix" and fp.stat().st_mode & 0o004:
            out.append(Finding("LOW", "LGW-S03", ".env file is world-readable", rel, 0,
                               "Other local users can read this file.", f"chmod 600 {rel}"))
    return sort_findings(out)


def score(findings: list[Finding]) -> int:
    """0-100 hardening score (100 = no findings)."""
    penalty = {"HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
    return max(0, 100 - sum(penalty.get(x.severity, 0) for x in findings))
