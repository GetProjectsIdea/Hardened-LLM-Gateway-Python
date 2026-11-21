import os

import pytest

from llm_gateway.settings import Settings, has_errors, is_loopback_host, load_env_file, preflight

from conftest import ADMIN, PEPPER


def levels(s):
    return {c.name: c.level for c in preflight(s)}


def test_good_settings_pass(settings):
    assert not has_errors(preflight(settings))


@pytest.mark.parametrize("pepper", ["", "sk-1234", "changeme", "short"])
def test_weak_pepper_refused(settings, pepper):
    settings.key_pepper = pepper
    assert levels(settings)["GATEWAY_KEY_PEPPER"] == "ERROR"


def test_weak_admin_token_refused(settings):
    settings.admin_token = "admin"
    assert levels(settings)["GATEWAY_ADMIN_TOKEN"] == "ERROR"


def test_admin_token_equal_pepper_refused(settings):
    settings.admin_token = settings.key_pepper
    assert levels(settings)["GATEWAY_ADMIN_TOKEN"] == "ERROR"


def test_no_admin_token_is_ok(settings):
    settings.admin_token = ""
    assert levels(settings)["GATEWAY_ADMIN_TOKEN"] == "OK"


def test_default_upstream_key_refused(settings):
    settings.upstream_api_key = "sk-1234"
    assert levels(settings)["GATEWAY_UPSTREAM_API_KEY"] == "ERROR"


def test_public_bind_needs_opt_in(settings):
    settings.host = "0.0.0.0"
    assert levels(settings)["GATEWAY_HOST"] == "ERROR"
    settings.allow_public_bind = True
    assert levels(settings)["GATEWAY_HOST"] == "WARN"


def test_world_readable_keys_file_refused(settings, tmp_path):
    if os.name != "posix":
        pytest.skip("posix only")
    p = tmp_path / "keys.json"
    p.write_text("{}")
    os.chmod(p, 0o644)
    settings.keys_file = str(p)
    assert levels(settings)["GATEWAY_KEYS_FILE"] == "ERROR"


def test_invalid_upstream_url(settings):
    settings.upstream_url = "ftp://x"
    assert levels(settings)["GATEWAY_UPSTREAM_URL"] == "ERROR"


def test_plain_http_remote_upstream_warns(settings):
    settings.upstream_url = "http://llm.example.com/v1"
    assert levels(settings)["GATEWAY_UPSTREAM_URL"] == "WARN"


def test_no_models_refused(settings):
    settings.models = []
    assert levels(settings)["GATEWAY_MODELS"] == "ERROR"


def test_from_env():
    s = Settings.from_env({"GATEWAY_KEY_PEPPER": PEPPER, "GATEWAY_ADMIN_TOKEN": ADMIN, "GATEWAY_MODELS": "a, b",
                           "GATEWAY_PORT": "9000", "GATEWAY_ALLOW_PUBLIC_BIND": "true", "GATEWAY_UPSTREAM_URL": "http://x:1/v1/"})
    assert s.models == ["a", "b"] and s.port == 9000 and s.allow_public_bind and s.upstream_url == "http://x:1/v1"


def test_env_file_parser(tmp_path):
    p = tmp_path / ".env"
    p.write_text("# c\nexport A=1\nB='two words'\nC=\"x=y\"\nbad line\n")
    d = load_env_file(p, {})
    assert d == {"A": "1", "B": "two words", "C": "x=y"}


def test_loopback():
    assert is_loopback_host("127.0.0.1") and is_loopback_host("::1") and is_loopback_host("localhost")
    assert not is_loopback_host("0.0.0.0") and not is_loopback_host("example.com")
