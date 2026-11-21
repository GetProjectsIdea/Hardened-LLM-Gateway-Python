import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from llm_gateway.audit import AuditLog  # noqa: E402
from llm_gateway.gateway import create_app  # noqa: E402
from llm_gateway.keys import KeyStore  # noqa: E402
from llm_gateway.ratelimit import IpFailureTracker, RateLimiter  # noqa: E402
from llm_gateway.settings import Settings  # noqa: E402
from llm_gateway.upstream import MockUpstream  # noqa: E402

PEPPER = "pX7-vQ2_kL9mZr4TbW8nYc3HdF6jS1aE0uGi"
ADMIN = "Ad9_Lm3-Qw7Zt2Xv5Bn8Kc1Rf4Hy6Js0PgUe"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def settings(tmp_path):
    return Settings(key_pepper=PEPPER, admin_token=ADMIN, models=["qwen2.5-coder:3b", "llama3.2:3b"],
                    keys_file=str(tmp_path / "keys.json"), audit_log=str(tmp_path / "audit.jsonl"), max_tokens=512)


@pytest.fixture
def env(settings, clock):
    ks = KeyStore(settings.keys_file, settings.key_pepper)
    log = AuditLog(settings.audit_log)
    up = MockUpstream()
    app = create_app(settings, upstream=up, keystore=ks, audit=log, limiter=RateLimiter(clock=clock),
                     ip_tracker=IpFailureTracker(max_failures=5, clock=clock))
    app.config["TESTING"] = True

    class E:
        pass
    e = E()
    e.app, e.client, e.ks, e.log, e.up, e.settings, e.clock = app, app.test_client(), ks, log, up, settings, clock
    e.alice, e.alice_rec = ks.create("alice", rpm=5, daily_tokens=100)
    return e


def chat(client, key, model="qwen2.5-coder:3b", ip="10.0.0.5", **kw):
    body = {"model": model, "messages": [{"role": "user", "content": "hello there"}], **kw}
    h = {"Authorization": f"Bearer {key}"} if key else {}
    return client.post("/v1/chat/completions", json=body, headers=h, environ_base={"REMOTE_ADDR": ip})
