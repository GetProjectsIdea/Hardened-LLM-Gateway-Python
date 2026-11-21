import json

import pytest

from llm_gateway.audit import AuditLog, detect, read_events, summary, verify


def test_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.write("request", key_id="k1", user="alice", total_tokens=i)
    ok, n, msg = verify(tmp_path / "a.jsonl")
    assert ok and n == 5


def test_chain_continues_after_reopen(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("request", user="a")
    AuditLog(p).write("request", user="b")
    assert verify(p)[0]


@pytest.mark.parametrize("mode", ["edit", "delete", "reorder"])
def test_tampering_detected(tmp_path, mode):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.write("request", user=f"u{i}", total_tokens=10)
    lines = p.read_text().splitlines()
    if mode == "edit":
        lines[1] = lines[1].replace('"total_tokens":10', '"total_tokens":1')
    elif mode == "delete":
        del lines[1]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert not verify(p)[0]


def test_missing_file(tmp_path):
    assert verify(tmp_path / "none.jsonl")[0] is False
    assert read_events(tmp_path / "none.jsonl") == []


@pytest.mark.parametrize("field", ["api_key", "authorization", "prompt", "messages", "password"])
def test_refuses_sensitive_fields(tmp_path, field):
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "a.jsonl").write("request", **{field: "x"})


def test_lines_are_json_with_time(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("auth_failed", ip="1.1.1.1")
    rec = json.loads(p.read_text())
    assert rec["event"] == "auth_failed" and rec["time"].endswith("Z") and len(rec["prev"]) == 64


def _ev(event, **kw):
    return {"event": event, **kw}


def test_detect_auth_spray():
    f = detect([_ev("auth_failed", ip="9.9.9.9")] * 5)
    assert f[0]["rule"] == "D1-auth-spray" and f[0]["severity"] == "HIGH"


def test_detect_below_threshold_is_quiet():
    assert detect([_ev("auth_failed", ip="9.9.9.9")] * 2) == []


def test_detect_mgmt_probe():
    f = detect([_ev("blocked_path", ip="5.5.5.5", path="/api/pull"), _ev("blocked_path", ip="5.5.5.5", path="/key/generate")])
    assert f[0]["rule"] == "D2-mgmt-probe" and f[0]["severity"] == "HIGH"


def test_detect_max_tokens_one_probes():
    evs = [_ev("request", key_id="k", user="a", ip="7.7.7.7", max_tokens=1, total_tokens=2)] * 3
    assert any(x["rule"] == "D3-key-validation" for x in detect(evs))


def test_detect_ip_spread():
    evs = [_ev("request", key_id="k", user="a", ip=f"10.0.0.{i}", max_tokens=100) for i in range(3)]
    assert any(x["rule"] == "D4-key-ip-spread" for x in detect(evs))


def test_detect_revoked_key_use():
    evs = [_ev("auth_failed", ip="1.1.1.1", key_id="k", reason="revoked_key")]
    assert any(x["rule"] == "D8-revoked-key-use" for x in detect(evs))


def test_detect_spend():
    evs = [_ev("request", key_id="k", user="a", ip="1.1.1.1", total_tokens=90, max_tokens=100)]
    assert any(x["rule"] == "D7-spend" for x in detect(evs, budgets={"k": 100}))
    assert not any(x["rule"] == "D7-spend" for x in detect(evs, budgets={"k": 1000}))


def test_summary():
    s = summary([_ev("request", user="a", total_tokens=5), _ev("request", user="b", total_tokens=7), _ev("auth_failed")])
    assert s["total_tokens"] == 12 and s["by_event"]["auth_failed"] == 1 and s["tokens_by_user"] == {"a": 5, "b": 7}
