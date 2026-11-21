import json

import pytest

from llm_gateway.audit import read_events, verify
from llm_gateway.upstream import UpstreamError

from conftest import ADMIN, chat


def events(e):
    return read_events(e.settings.audit_log)


def test_health(env):
    r = env.client.get("/healthz")
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}


def test_no_key_401(env):
    r = chat(env.client, None)
    assert r.status_code == 401 and events(env)[-1]["reason"] == "missing_key"


def test_default_litellm_key_401(env):
    assert chat(env.client, "sk-1234").status_code == 401


def test_valid_key_200_and_audited(env):
    r = chat(env.client, env.alice)
    assert r.status_code == 200
    assert r.get_json()["choices"][0]["message"]["content"].startswith("Hello from the mock")
    ev = events(env)[-1]
    assert ev["event"] == "request" and ev["user"] == "alice" and ev["status"] == 200 and ev["total_tokens"] > 0


def test_x_api_key_header(env):
    r = env.client.post("/v1/chat/completions", json={"model": "qwen2.5-coder:3b", "messages": [{"role": "user", "content": "x"}]},
                        headers={"x-api-key": env.alice})
    assert r.status_code == 200


def test_key_in_url_rejected(env):
    r = env.client.get("/v1/models?api_key=" + env.alice)
    assert r.status_code == 400 and events(env)[-1]["event"] == "key_in_url"


def test_audit_never_contains_key_or_prompt(env):
    chat(env.client, env.alice)
    chat(env.client, "lgw_0123456789ab_" + "z" * 40)
    raw = open(env.settings.audit_log).read()
    assert env.alice not in raw and env.alice.split("_", 2)[2] not in raw
    assert "hello there" not in raw and "z" * 40 not in raw
    assert "prompt_sha256" in raw


def test_client_auth_header_not_forwarded(env):
    chat(env.client, env.alice)
    sent = env.up.calls[-1]
    assert "Authorization" not in json.dumps(sent) and sent["user"] == "alice"


def test_model_allowlist_global(env):
    r = chat(env.client, env.alice, model="gpt-4o")
    assert r.status_code == 403 and events(env)[-1]["event"] == "model_denied"


def test_model_allowlist_per_key(env):
    bob, _ = env.ks.create("bob", models=["llama3.2:3b"])
    assert chat(env.client, bob).status_code == 403
    assert chat(env.client, bob, model="llama3.2:3b").status_code == 200


def test_models_endpoint_filtered(env):
    bob, _ = env.ks.create("bob", models=["llama3.2:3b"])
    r = env.client.get("/v1/models", headers={"Authorization": f"Bearer {bob}"})
    assert [m["id"] for m in r.get_json()["data"]] == ["llama3.2:3b"]


@pytest.mark.parametrize("path,method", [("/api/pull", "post"), ("/api/create", "post"), ("/api/delete", "delete"),
                                         ("/api/tags", "get"), ("/key/generate", "post"), ("/key/regenerate", "post"),
                                         ("/guardrails/test_custom_code", "post"), ("/config/update", "post"),
                                         ("/.env", "get"), ("/v1/chat/completions", "get")])
def test_management_paths_blocked(env, path, method):
    r = getattr(env.client, method)(path, headers={"Authorization": f"Bearer {env.alice}"})
    assert r.status_code == 404
    assert events(env)[-1]["event"] == "blocked_path"
    assert env.up.calls == []


def test_rate_limit(env):
    for _ in range(5):
        assert chat(env.client, env.alice).status_code == 200
    r = chat(env.client, env.alice)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    env.clock.tick(13)
    assert chat(env.client, env.alice).status_code == 200


def test_daily_token_budget(env):
    big = "word " * 200
    r = env.client.post("/v1/chat/completions", json={"model": "qwen2.5-coder:3b", "messages": [{"role": "user", "content": big}]},
                        headers={"Authorization": f"Bearer {env.alice}"})
    assert r.status_code == 200 and r.headers["X-Gateway-Tokens-Remaining"] == "0"
    r = chat(env.client, env.alice)
    assert r.status_code == 429 and r.get_json()["error"]["type"] == "budget_exceeded"


def test_max_tokens_clamped(env):
    chat(env.client, env.alice, max_tokens=99999)
    assert env.up.calls[-1]["max_tokens"] == 512
    chat(env.client, env.alice)
    assert env.up.calls[-1]["max_tokens"] == 512


@pytest.mark.parametrize("mt", [0, -5, "10", True])
def test_bad_max_tokens(env, mt):
    assert chat(env.client, env.alice, max_tokens=mt).status_code == 400


@pytest.mark.parametrize("body", [[1, 2], "text", {"model": "qwen2.5-coder:3b"}, {"model": "qwen2.5-coder:3b", "messages": []},
                                  {"model": "qwen2.5-coder:3b", "messages": ["hi"]}])
def test_bad_bodies(env, body):
    r = env.client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {env.alice}"})
    assert r.status_code in (400, 403)


def test_body_size_limit(env):
    r = env.client.post("/v1/chat/completions", data="x" * (513 * 1024), content_type="application/json",
                        headers={"Authorization": f"Bearer {env.alice}"})
    assert r.status_code == 413


def test_revoked_key(env):
    env.ks.revoke(env.alice_rec.key_id)
    r = chat(env.client, env.alice)
    assert r.status_code == 401 and events(env)[-1]["reason"] == "revoked_key"


def test_ip_lockout_after_failures(env):
    for _ in range(5):
        chat(env.client, "lgw_0123456789ab_" + "q" * 40, ip="203.0.113.9")
    r = chat(env.client, env.alice, ip="203.0.113.9")
    assert r.status_code == 429 and r.get_json()["error"]["type"] == "ip_blocked"
    assert chat(env.client, env.alice, ip="10.0.0.8").status_code == 200


def test_upstream_down_502(env):
    def boom(_payload):
        raise UpstreamError("down")
    env.up.chat = boom
    r = chat(env.client, env.alice)
    assert r.status_code == 502 and events(env)[-1]["event"] == "upstream_error"


def test_upstream_error_status(env):
    env.up.chat = lambda p: (500, {"error": {"message": "boom"}})
    assert chat(env.client, env.alice).status_code == 502


def test_stream_returns_sse(env):
    r = chat(env.client, env.alice, stream=True)
    assert r.status_code == 200 and r.mimetype == "text/event-stream"
    assert b"data: [DONE]" in r.data
    assert env.up.calls[-1]["stream"] is False


def test_embeddings(env):
    r = env.client.post("/v1/embeddings", json={"model": "qwen2.5-coder:3b", "input": "hi"},
                        headers={"Authorization": f"Bearer {env.alice}"})
    assert r.status_code == 200 and r.get_json()["data"][0]["embedding"]


def test_security_headers(env):
    r = env.client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_trust_proxy_off_ignores_xff(env):
    chat(env.client, None, ip="10.1.1.1")
    env.client.post("/v1/chat/completions", json={}, headers={"X-Forwarded-For": "1.2.3.4"})
    assert events(env)[-1]["ip"] != "1.2.3.4"


def test_log_chain_valid_after_traffic(env):
    for k in (env.alice, None, "sk-1234"):
        chat(env.client, k)
    env.client.post("/api/pull")
    assert verify(env.settings.audit_log)[0]


def test_favicon_not_logged_as_probe(env):
    assert env.client.get("/favicon.ico").status_code == 204
    assert not any(e.get("path") == "/favicon.ico" for e in events(env))
