"""Offline end-to-end demo with a mock model (no GPU, no network)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from .audit import AuditLog, detect, read_events, verify
from .cli import c, print_checks, tag
from .keys import KeyStore
from .secrets_check import generate_secret, redact
from .settings import Settings, has_errors, preflight
from .upstream import MockUpstream


def step(n: int, title: str) -> None:
    print("\n" + c(f"[{n}] {title}", "1;36"))


def show(resp, label: str) -> None:
    code = resp.status_code
    color = "32" if code < 300 else "31"
    msg = ""
    data = resp.get_json(silent=True) or {}
    if "error" in data:
        msg = data["error"]["message"]
    elif "choices" in data:
        msg = data["choices"][0]["message"]["content"][:70]
    elif "data" in data:
        msg = "models: " + ", ".join(m["id"] for m in data["data"])
    print(f"  {label:<44} -> {c('HTTP ' + str(code), color)}  {msg}")


def run_demo() -> int:
    from .gateway import create_app
    tmp = Path(tempfile.mkdtemp(prefix="lgw-demo-"))
    print(c("Hardened LLM gateway: offline demo (mock model, temp dir " + tmp.name + ")", "1"))

    step(1, "Try to start with the LiteLLM-style default secret 'sk-1234'")
    bad = Settings(key_pepper="sk-1234", admin_token="changeme", upstream_api_key="sk-1234",
                   keys_file=str(tmp / "keys.json"), audit_log=str(tmp / "audit.jsonl"), host="0.0.0.0")
    checks = preflight(bad)
    print_checks([x for x in checks if x.level == "ERROR"])
    print("  " + c("REFUSING TO START" if has_errors(checks) else "started?!", "1;31"))

    step(2, "Generate strong secrets and start on 127.0.0.1")
    s = Settings(key_pepper=generate_secret(), admin_token=generate_secret(), models=["qwen2.5-coder:3b", "llama3.2:3b"],
                 keys_file=str(tmp / "keys.json"), audit_log=str(tmp / "audit.jsonl"), max_tokens=512)
    print_checks([x for x in preflight(s) if x.name in ("GATEWAY_KEY_PEPPER", "GATEWAY_ADMIN_TOKEN", "GATEWAY_HOST")])
    ks = KeyStore(s.keys_file, s.key_pepper)
    log = AuditLog(s.audit_log)
    app = create_app(s, upstream=MockUpstream(), keystore=ks, audit=log)
    cl = app.test_client()
    print(f"  keys in store: {len(ks)}  (no default key exists)")

    step(3, "Create per-user keys (shown once, stored as HMAC-SHA256)")
    alice, ra = ks.create("alice", rpm=5, daily_tokens=5000)
    bob, rb = ks.create("bob", models=["llama3.2:3b"], rpm=30)
    print(f"  alice -> {redact(alice, 17)}   bob -> {redact(bob, 17)}")
    print(f"  on disk: {ra.key_hash[:24]}…  (the key itself is never stored)")

    def chat(key, model="qwen2.5-coder:3b", ip="10.0.0.5", **kw):
        body = {"model": model, "messages": [{"role": "user", "content": "Write hello world in Python"}], **kw}
        h = {"Authorization": f"Bearer {key}"} if key else {}
        return cl.post("/v1/chat/completions", json=body, headers=h, environ_base={"REMOTE_ADDR": ip})

    step(4, "Requests through the gateway")
    show(chat(None), "no key")
    show(chat("sk-1234"), "LiteLLM default master key 'sk-1234'")
    show(chat(alice), "alice, qwen2.5-coder:3b")
    show(chat(bob), "bob asks for a model he may not use")
    show(cl.get("/v1/models", headers={"Authorization": f"Bearer {bob}"}), "bob lists his models")
    show(cl.post("/api/pull", json={"model": "evil"}, environ_base={"REMOTE_ADDR": "203.0.113.9"}), "Ollama /api/pull (model management)")
    show(cl.post("/key/generate", json={}, environ_base={"REMOTE_ADDR": "203.0.113.9"}), "LiteLLM /key/generate (admin API)")
    show(cl.post("/guardrails/test_custom_code", json={}, environ_base={"REMOTE_ADDR": "203.0.113.9"}), "LiteLLM /guardrails/test_custom_code")
    show(cl.get("/v1/models?api_key=" + alice), "key sent in the URL")

    step(5, "Rate limit (alice: 5 requests/minute) and key-validation probes")
    for i in range(4):
        r = chat(alice, ip="198.51.100.7", max_tokens=1)
    show(r, "alice x4 with max_tokens=1 from a new IP")
    show(chat(alice), "alice 6th request this minute")

    step(6, "Revoke and key spraying")
    ks.revoke(rb.key_id)
    show(chat(bob, model="llama3.2:3b"), "bob after revoke")
    for i in range(5):
        r = chat("lgw_000000000000_" + "x" * 40, ip="203.0.113.9")
    show(r, "5 guessed keys from 203.0.113.9")

    step(7, "Audit log: hash chain + detections")
    ok, n, msg = verify(s.audit_log)
    print("  " + c(msg, "32" if ok else "31"))
    ev = read_events(s.audit_log)
    print("  sample line: " + c(str({k: ev[2][k] for k in ("event", "user", "model", "status", "total_tokens") if k in ev[2]}), "2"))
    for f in detect(ev, budgets={ra.key_id: ra.daily_tokens}):
        print(f"  {tag(f['severity'])} {f['rule']:<18} {f['detail']}")
    print("\n" + c("Done. No API key or prompt text was written to the log.", "32"))
    return 0
