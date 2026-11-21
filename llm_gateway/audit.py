"""Append-only, hash-chained JSONL audit log and a detection report.

Every request (allowed or denied) becomes one JSON line. API keys and prompt
text are never written; only the key id, the user, the model, token counts and
an optional SHA-256 of the prompt. Each line stores the SHA-256 of the previous
line, so ``verify`` detects edited, deleted or re-ordered lines.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

GENESIS = "0" * 64
FORBIDDEN_FIELDS = {"api_key", "authorization", "key", "prompt", "messages", "password", "secret"}


def _digest(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = ""
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = line.rstrip("\n")
        return _digest(last) if last else GENESIS

    def write(self, event: str, **fields) -> dict:
        bad = FORBIDDEN_FIELDS & set(fields)
        if bad:
            raise ValueError(f"refusing to log sensitive fields: {sorted(bad)}")
        with self._lock:
            rec = {"ts": round(time.time(), 3),
                   "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "event": event, **fields, "prev": self._last}
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            new = not self.path.exists()
            with self.path.open("a") as fh:
                fh.write(line + "\n")
            if new and os.name == "posix":
                os.chmod(self.path, 0o600)
            self._last = _digest(line)
            return rec

    def tail(self, n: int = 50) -> list[dict]:
        return read_events(self.path)[-n:]


def read_events(path: str | os.PathLike) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"event": "corrupt_line"})
    return out


def verify(path: str | os.PathLike) -> tuple[bool, int, str]:
    """Return (ok, lines_checked, message)."""
    p = Path(path)
    if not p.exists():
        return False, 0, f"{p} does not exist"
    prev = GENESIS
    n = 0
    for n, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, n, f"line {n}: not valid JSON"
        if rec.get("prev") != prev:
            return False, n, f"line {n}: hash chain broken (line edited, deleted or re-ordered)"
        prev = _digest(line)
    return True, n, f"OK: {n} lines, hash chain intact"


# ---------------------------------------------------------------- detections
MGMT_PATH_HINTS = ("/api/pull", "/api/create", "/api/delete", "/api/push", "/api/copy", "/key/",
                   "/user/", "/team/", "/guardrails/", "/config", "/model/new", "/admin",
                   "/.env", "/debug", "/metrics", "/spend/")


def detect(events: list[dict], *, auth_fail_threshold: int = 5, probe_threshold: int = 3,
           ip_spread_threshold: int = 3, budget_warn_ratio: float = 0.8,
           budgets: dict[str, int] | None = None) -> list[dict]:
    """Turn raw audit events into findings a human should look at.

    Defensive heuristics only; each finding says what to check next.
    """
    findings: list[dict] = []
    auth_fail = Counter()
    probes = Counter()
    blocked_paths = defaultdict(set)
    ips_per_key = defaultdict(set)
    tokens_per_key = Counter()
    denied_models = Counter()
    rate_limited = Counter()
    users = {}
    dead_key_use = defaultdict(set)
    for e in events:
        ev, ip, kid = e.get("event"), e.get("ip", "?"), e.get("key_id")
        if kid and e.get("user"):
            users[kid] = e["user"]
        if ev == "auth_failed":
            auth_fail[ip] += 1
            if e.get("reason") in ("revoked_key", "expired_key") and kid:
                dead_key_use[kid].add(ip)
        elif ev == "blocked_path":
            blocked_paths[ip].add(e.get("path", "?"))
        elif ev == "model_denied" and kid:
            denied_models[kid] += 1
        elif ev == "rate_limited" and kid:
            rate_limited[kid] += 1
        if ev in ("request", "upstream_error") and kid:
            ips_per_key[kid].add(ip)
            tokens_per_key[kid] += int(e.get("total_tokens") or 0)
            mt = e.get("max_tokens")
            if mt is not None and int(mt) <= 1:
                probes[(kid, ip)] += 1

    for ip, n in auth_fail.items():
        if n >= auth_fail_threshold:
            findings.append({"severity": "HIGH", "rule": "D1-auth-spray", "subject": ip,
                             "detail": f"{n} failed authentications from {ip}",
                             "advice": "Possible key guessing or a leaked-but-revoked key in use. Block the IP at the firewall and check where the attempts come from."})
    for ip, paths in blocked_paths.items():
        findings.append({"severity": "HIGH" if len(paths) >= 2 else "MEDIUM", "rule": "D2-mgmt-probe", "subject": ip,
                         "detail": f"requests to management/admin paths: {', '.join(sorted(paths))}",
                         "advice": "Someone is looking for model-management or key endpoints (pull/create/key/guardrails). Make sure LiteLLM/Ollama admin APIs are never exposed."})
    for (kid, ip), n in probes.items():
        if n >= probe_threshold:
            findings.append({"severity": "HIGH", "rule": "D3-key-validation", "subject": kid,
                             "detail": f"{n} requests with max_tokens<=1 for key {kid} ({users.get(kid, '?')}) from {ip}",
                             "advice": "Tiny single-token requests are a known pattern for checking whether a stolen key works. Rotate this key and ask the owner."})
    for kid, ips in ips_per_key.items():
        if len(ips) >= ip_spread_threshold:
            findings.append({"severity": "MEDIUM", "rule": "D4-key-ip-spread", "subject": kid,
                             "detail": f"key {kid} ({users.get(kid, '?')}) used from {len(ips)} IPs: {', '.join(sorted(ips)[:6])}",
                             "advice": "A personal key used from many addresses may have leaked (Git, Docker image, notebook, paste site)."})
    for kid, n in rate_limited.items():
        findings.append({"severity": "LOW" if n < 20 else "MEDIUM", "rule": "D5-rate-limited", "subject": kid,
                         "detail": f"key {kid} ({users.get(kid, '?')}) was rate limited {n} time(s)",
                         "advice": "Bursty automation or abuse. Confirm with the key owner."})
    for kid, n in denied_models.items():
        findings.append({"severity": "LOW", "rule": "D6-model-denied", "subject": kid,
                         "detail": f"key {kid} ({users.get(kid, '?')}) asked for models it may not use {n} time(s)",
                         "advice": "Expected occasionally; repeated attempts at premium models can indicate misuse."})
    for kid, ips in dead_key_use.items():
        findings.append({"severity": "MEDIUM", "rule": "D8-revoked-key-use", "subject": kid,
                         "detail": f"revoked/expired key {kid} ({users.get(kid, '?')}) still used from {', '.join(sorted(ips))}",
                         "advice": "Something still holds the old key: a script, a CI secret or someone who copied it. Find and update or block it."})
    for kid, used in tokens_per_key.items():
        b = (budgets or {}).get(kid)
        if b and used >= budget_warn_ratio * b:
            findings.append({"severity": "MEDIUM", "rule": "D7-spend", "subject": kid,
                             "detail": f"key {kid} ({users.get(kid, '?')}) used {used} of {b} daily tokens",
                             "advice": "Unexpected spend is often the first sign of a stolen key."})
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(findings, key=lambda f: (order[f["severity"]], f["rule"]))


def summary(events: list[dict]) -> dict:
    c = Counter(e.get("event") for e in events)
    toks = sum(int(e.get("total_tokens") or 0) for e in events if e.get("event") == "request")
    per_user = Counter()
    for e in events:
        if e.get("event") == "request":
            per_user[e.get("user", "?")] += int(e.get("total_tokens") or 0)
    return {"events": len(events), "by_event": dict(c), "total_tokens": toks, "tokens_by_user": dict(per_user)}
