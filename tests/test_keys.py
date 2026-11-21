import json
import os
import stat

import pytest

from llm_gateway.keys import KeyError_, KeyStore, file_is_private, hash_key

from conftest import PEPPER


def test_new_store_has_no_default_key(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    assert len(ks) == 0
    assert ks.verify("sk-1234")[0] is None


def test_create_and_verify(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    full, rec = ks.create("alice")
    assert full.startswith("lgw_" + rec.key_id + "_")
    got, reason = ks.verify(full)
    assert reason == "ok" and got.user == "alice"


def test_key_is_hashed_at_rest(tmp_path):
    p = tmp_path / "k.json"
    ks = KeyStore(p, PEPPER)
    full, rec = ks.create("alice")
    raw = p.read_text()
    assert full not in raw and full.split("_", 2)[2] not in raw
    assert json.loads(raw)["keys"][0]["key_hash"] == hash_key(PEPPER, full)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_key_file_is_chmod_600(tmp_path):
    p = tmp_path / "k.json"
    KeyStore(p, PEPPER).create("alice")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert file_is_private(p)


def test_wrong_pepper_cannot_verify(tmp_path):
    p = tmp_path / "k.json"
    full, _ = KeyStore(p, PEPPER).create("alice")
    assert KeyStore(p, "another-pepper-value-that-is-long-123")._keys
    assert KeyStore(p, "another-pepper-value-that-is-long-123").verify(full)[1] == "unknown_key"


def test_persistence_roundtrip(tmp_path):
    p = tmp_path / "k.json"
    full, _ = KeyStore(p, PEPPER).create("bob", models=["llama3.2:3b"], rpm=7)
    rec, reason = KeyStore(p, PEPPER).verify(full)
    assert reason == "ok" and rec.models == ["llama3.2:3b"] and rec.rpm == 7


@pytest.mark.parametrize("bad", ["", None, "sk-1234", "lgw_xyz_abc", "lgw_0123456789ab_short", "Bearer lgw_"])
def test_malformed_or_missing(tmp_path, bad):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    assert ks.verify(bad)[0] is None


def test_tampered_secret_rejected(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    full, _ = ks.create("alice")
    assert ks.verify(full[:-1] + ("A" if full[-1] != "A" else "B"))[1] == "unknown_key"


def test_revoke(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    full, rec = ks.create("alice")
    ks.revoke(rec.key_id)
    assert ks.verify(full)[1] == "revoked_key"
    with pytest.raises(KeyError_):
        ks.revoke("nope")


def test_expiry(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    full, rec = ks.create("alice", ttl_days=1)
    assert ks.verify(full, now=rec.created + 3600)[1] == "ok"
    assert ks.verify(full, now=rec.created + 2 * 86400)[1] == "expired_key"


def test_rotate_keeps_settings(tmp_path):
    ks = KeyStore(tmp_path / "k.json", PEPPER)
    old, rec = ks.create("alice", models=["a"], rpm=9, daily_tokens=50)
    new, nrec = ks.rotate(rec.key_id)
    assert ks.verify(old)[1] == "revoked_key"
    assert ks.verify(new)[1] == "ok"
    assert (nrec.models, nrec.rpm, nrec.daily_tokens, nrec.user) == (["a"], 9, 50, "alice")


@pytest.mark.parametrize("user", ["", "a b", "x" * 65, "../etc", "<script>"])
def test_invalid_user(tmp_path, user):
    with pytest.raises(KeyError_):
        KeyStore(tmp_path / "k.json", PEPPER).create(user)


def test_pepper_required(tmp_path):
    with pytest.raises(KeyError_):
        KeyStore(tmp_path / "k.json", "")


def test_public_view_hides_hash(tmp_path):
    _, rec = KeyStore(tmp_path / "k.json", PEPPER).create("alice")
    assert "key_hash" not in rec.public() and rec.public()["status"] == "active"


def test_running_store_sees_cli_changes(tmp_path):
    p = tmp_path / "k.json"
    server = KeyStore(p, PEPPER)
    cli = KeyStore(p, PEPPER)
    full, rec = cli.create("carol")
    assert server.verify(full)[1] == "ok"
    cli.revoke(rec.key_id)
    assert server.verify(full)[1] == "revoked_key"


def test_last_used_survives_reload(tmp_path):
    p = tmp_path / "k.json"
    server = KeyStore(p, PEPPER)
    full, rec = server.create("dave")
    server.verify(full)
    KeyStore(p, PEPPER).create("erin")
    assert [k for k in server.list() if k.user == "dave"][0].last_used is not None
