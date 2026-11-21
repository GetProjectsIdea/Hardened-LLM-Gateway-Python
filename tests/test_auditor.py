from pathlib import Path

import pytest

from llm_gateway.auditor import audit_path, audit_text, parse_env_text, score

ROOT = Path(__file__).resolve().parent.parent


def rules(findings):
    return {f.rule for f in findings}


def test_insecure_examples_flag_everything():
    r = rules(audit_path(ROOT / "examples" / "insecure"))
    assert {"LGW-O03", "LGW-L02", "LGW-L01", "LGW-L04", "LGW-W01", "LGW-W02", "LGW-W03", "LGW-W04", "LGW-D02",
            "LGW-D01", "LGW-L07", "LGW-L08", "LGW-O01", "LGW-O02", "LGW-L10"} <= r


def test_secure_examples_clean():
    f = audit_path(ROOT / "examples" / "secure")
    assert f == [] and score(f) == 100


def test_compose_loopback_port_ok():
    t = "services:\n  ollama:\n    image: ollama/ollama:0.40.16\n    ports: ['127.0.0.1:11434:11434']\n"
    assert audit_text(t, "docker-compose.yml") == []


@pytest.mark.parametrize("port", ["11434:11434", "0.0.0.0:11434:11434", "8000:11434"])
def test_compose_public_ollama(port):
    t = f"services:\n  llm:\n    image: ollama/ollama\n    ports: ['{port}']\n"
    assert "LGW-O03" in rules(audit_text(t, "compose.yaml"))


def test_compose_long_port_syntax():
    t = "services:\n  litellm:\n    image: ghcr.io/berriai/litellm:main-v1.85.0-stable\n    ports:\n      - target: 4000\n        published: 4000\n"
    assert rules(audit_text(t, "docker-compose.yml")) == {"LGW-L02"}


@pytest.mark.parametrize("tag,rule", [("main-v1.83.4-stable", "LGW-L04"), ("latest", "LGW-L03"), ("main-latest", "LGW-L03")])
def test_litellm_image_versions(tag, rule):
    t = f"services:\n  litellm:\n    image: ghcr.io/berriai/litellm:{tag}\n"
    assert rule in rules(audit_text(t, "docker-compose.yml"))


def test_litellm_patched_image_ok():
    t = "services:\n  litellm:\n    image: ghcr.io/berriai/litellm:v1.84.0-stable\n"
    assert audit_text(t, "docker-compose.yml") == []


def test_litellm_no_master_key():
    assert "LGW-L05" in rules(audit_text("model_list: []\ngeneral_settings: {}\n", "config.yaml"))


def test_litellm_env_reference_ok():
    t = "general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n"
    assert audit_text(t, "config.yaml") == []


def test_litellm_strong_literal_master_key_medium():
    t = "general_settings:\n  master_key: sk-Qm4_Xw9-Lr2Zt7Vb5Nc8Kd1Pf3Hg6Js0Ty\n"
    f = audit_text(t, "config.yaml")
    assert rules(f) == {"LGW-L06"} and f[0].severity == "MEDIUM"


def test_litellm_db_password():
    t = "general_settings:\n  master_key: os.environ/K\n  database_url: postgresql://u:pw@db/x\n"
    assert "LGW-L09" in rules(audit_text(t, "config.yaml"))


def test_ollama_placeholder_api_key_low():
    t = "general_settings:\n  master_key: os.environ/K\nmodel_list:\n  - model_name: q\n    litellm_params:\n      model: ollama/q\n      api_key: none\n"
    f = audit_text(t, "config.yaml")
    assert rules(f) == {"LGW-L12"} and f[0].severity == "LOW"


def test_env_file_rules():
    t = "WEBUI_AUTH=false\nENABLE_SIGNUP=true\nDEFAULT_USER_ROLE=admin\nOLLAMA_HOST=0.0.0.0\nOLLAMA_ORIGINS=*\n"
    assert {"LGW-W01", "LGW-W03", "LGW-W04", "LGW-O01", "LGW-O02"} <= rules(audit_text(t, ".env"))


def test_ollama_localhost_ok():
    assert audit_text("OLLAMA_HOST=127.0.0.1:11434\n", ".env") == []


def test_env_references_skipped():
    t = "LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}\nWEBUI_SECRET_KEY=${WEBUI_SECRET_KEY:?set it}\n"
    assert audit_text(t, ".env") == []


def test_weak_gateway_secrets():
    assert "LGW-G01" in rules(audit_text("GATEWAY_KEY_PEPPER=changeme\n", ".env"))


def test_systemd_unit():
    t = '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434" "OLLAMA_ORIGINS=*"\n'
    assert {"LGW-O01", "LGW-O02"} <= rules(audit_text(t, "ollama.service"))


def test_provider_key_anywhere():
    t = "OPENAI_API_KEY=sk-proj-" + "Ab1" * 12 + "\n"
    f = audit_text(t, ".env")
    assert "LGW-S01" in rules(f)
    assert "Ab1Ab1Ab1Ab1" not in " ".join(x.detail for x in f)


def test_placeholder_secret_generic():
    assert "LGW-S02" in rules(audit_text("SOME_SERVICE_API_KEY=changeme\n", ".env"))


def test_privileged_and_host_network():
    t = "services:\n  ollama:\n    image: ollama/ollama:0.40.16\n    privileged: true\n    network_mode: host\n"
    assert {"LGW-C01", "LGW-C02"} <= rules(audit_text(t, "docker-compose.yml"))


def test_invalid_yaml():
    assert rules(audit_text("services: [\n", "docker-compose.yml")) == {"LGW-X01"}


def test_line_numbers():
    t = "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: postgres\n"
    f = [x for x in audit_text(t, "docker-compose.yml") if x.rule == "LGW-D01"][0]
    assert f.line == 5


def test_parse_env_text():
    assert parse_env_text("A=1 # comment\nexport B='x'\n#C=3\n") == {"A": "1", "B": "x"}


def test_score_bounds():
    assert score([]) == 100
    assert score(audit_path(ROOT / "examples" / "insecure")) == 0


def test_audit_path_skips_venv(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / ".env").write_text("WEBUI_AUTH=False\n")
    assert audit_path(tmp_path) == []
