import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from llm_gateway.cli import main

from conftest import ADMIN, PEPPER

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def genv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for k in list(os.environ):
        if k.startswith("GATEWAY_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("GATEWAY_KEY_PEPPER", PEPPER)
    monkeypatch.setenv("GATEWAY_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("GATEWAY_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("GATEWAY_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


def test_init_writes_private_env(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--env-file", "x.env", "init"]) == 0
    text = (tmp_path / "x.env").read_text()
    assert "GATEWAY_KEY_PEPPER=" in text
    if os.name == "posix":
        assert (os.stat(tmp_path / "x.env").st_mode & 0o077) == 0
    out = capsys.readouterr().out
    pepper = [l.split("=", 1)[1] for l in text.splitlines() if l.startswith("GATEWAY_KEY_PEPPER=")][0]
    assert pepper not in out
    assert main(["--env-file", "x.env", "init"]) == 1


def test_preflight_refuses_default(genv, monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_KEY_PEPPER", "sk-1234")
    assert main(["preflight"]) == 2
    assert "REFUSING TO START" in capsys.readouterr().out


def test_serve_refuses_default(genv, monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_ADMIN_TOKEN", "changeme")
    assert main(["serve"]) == 2


def test_preflight_ok(genv):
    assert main(["preflight"]) == 0


def test_keys_lifecycle(genv, capsys):
    assert main(["keys", "list"]) == 0
    assert "There is no default key" in capsys.readouterr().out
    assert main(["keys", "create", "alice", "--rpm", "5"]) == 0
    out = capsys.readouterr().out
    key = [l.strip() for l in out.splitlines() if l.strip().startswith("lgw_")][0]
    kid = key.split("_")[1]
    assert key not in (genv / "keys.json").read_text()
    assert main(["keys", "rotate", kid]) == 0
    assert main(["keys", "revoke", "nope"]) == 1
    capsys.readouterr()
    main(["keys", "list"])
    out = capsys.readouterr().out
    assert "revoked" in out and "active" in out


def test_keys_need_strong_pepper(genv, monkeypatch):
    monkeypatch.setenv("GATEWAY_KEY_PEPPER", "admin")
    assert main(["keys", "create", "alice"]) == 2


def test_audit_config_exit_codes(capsys):
    assert main(["audit-config", str(ROOT / "examples" / "insecure")]) == 1
    assert main(["audit-config", str(ROOT / "examples" / "secure")]) == 0
    assert main(["audit-config", "--fail-on", "never", str(ROOT / "examples" / "insecure")]) == 0
    assert main(["audit-config", "/nope/missing"]) == 1


def test_audit_config_json(capsys):
    main(["audit-config", "--json", str(ROOT / "examples" / "insecure")])
    data = json.loads(capsys.readouterr().out)
    assert data["score"] == 0 and len(data["findings"]) > 10


def test_logs_verify_and_report(genv, capsys):
    from llm_gateway.audit import AuditLog
    log = AuditLog(genv / "audit.jsonl")
    for _ in range(6):
        log.write("auth_failed", ip="203.0.113.9", reason="unknown_key")
    assert main(["logs", "verify"]) == 0
    assert main(["logs", "report"]) == 1
    assert "D1-auth-spray" in capsys.readouterr().out
    assert main(["logs", "report", "--json"]) == 0


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "REFUSING TO START" in out and "HTTP 429" in out and "hash chain intact" in out


def test_module_entrypoint():
    r = subprocess.run([sys.executable, "-m", "llm_gateway", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "1.0.0"
