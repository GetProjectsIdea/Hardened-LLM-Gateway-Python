import re

import pytest

from llm_gateway.gateway import create_app
from llm_gateway.upstream import MockUpstream

from conftest import ADMIN


def login(env, token=ADMIN):
    return env.client.post("/admin/login", data={"token": token}, environ_base={"REMOTE_ADDR": "127.0.0.1"})


def csrf(env):
    html = env.client.get("/admin").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_admin_requires_login(env):
    r = env.client.get("/admin")
    assert r.status_code == 302 and "/admin/login" in r.headers["Location"]


def test_wrong_token(env):
    r = login(env, "admin")
    assert r.status_code == 200 and b"Wrong admin token" in r.data


def test_login_and_dashboard(env):
    assert login(env).status_code == 302
    html = env.client.get("/admin").get_data(as_text=True)
    assert "Start-up checks" in html and "alice" in html and "there is no default key" in html


def test_dashboard_never_shows_hash(env):
    login(env)
    html = env.client.get("/admin").get_data(as_text=True)
    assert env.alice_rec.key_hash not in html and env.alice not in html


def test_create_key_requires_csrf(env):
    login(env)
    r = env.client.post("/admin/keys", data={"action": "create", "user": "carol"})
    assert r.status_code == 400


def test_create_key_shown_once(env):
    login(env)
    tok = csrf(env)
    env.client.post("/admin/keys", data={"action": "create", "user": "carol", "csrf": tok, "rpm": "10"})
    first = env.client.get("/admin").get_data(as_text=True)
    m = re.search(r"(lgw_[a-f0-9]{12}_[A-Za-z0-9_\-]{32,})", first)
    assert m and env.ks.verify(m.group(1))[1] == "ok"
    second = env.client.get("/admin").get_data(as_text=True)
    assert m.group(1) not in second


def test_revoke_via_ui(env):
    login(env)
    env.client.post("/admin/keys", data={"action": "revoke", "key_id": env.alice_rec.key_id, "csrf": csrf(env)})
    assert env.ks.get(env.alice_rec.key_id).revoked


def test_admin_disabled_without_token(settings, tmp_path):
    settings.admin_token = ""
    app = create_app(settings, upstream=MockUpstream())
    c = app.test_client()
    assert c.get("/admin").status_code == 404 and c.get("/admin/login").status_code == 404


def test_admin_login_lockout(env):
    for _ in range(5):
        login(env, "nope")
    assert login(env).status_code == 429


def test_config_auditor_page(env):
    login(env)
    r = env.client.post("/admin/audit-config", data={"csrf": csrf(env), "name": "config.yaml",
                                                     "text": "general_settings:\n  master_key: sk-1234\n"})
    assert b"LGW-L01" in r.data


def test_session_cookie_flags(env):
    r = login(env)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
