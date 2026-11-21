import json

from llm_gateway.exposure import check_exposure


def fake(responses):
    def f(url):
        for suffix, resp in responses.items():
            if url.endswith(suffix):
                return resp
        return 404, ""
    return f


def verdicts(res):
    return {r["path"]: r["verdict"] for r in res}


def test_open_ollama_detected():
    res = check_exposure("http://h:11434", fake({"/api/tags": (200, json.dumps({"models": [{"name": "llama3"}]})),
                                                 "/api/version": (200, '{"version":"0.40.16"}')}))
    v = verdicts(res)
    assert v["/api/tags"] == "EXPOSED" and v["/api/version"] == "EXPOSED"


def test_protected_gateway():
    res = check_exposure("http://h:8088", fake({"/v1/models": (401, "")}))
    assert verdicts(res)["/v1/models"] == "protected"


def test_open_openai_models():
    res = check_exposure("http://h:4000", fake({"/v1/models": (200, '{"data":[{"id":"gpt-4o"}]}')}))
    assert verdicts(res)["/v1/models"] == "EXPOSED"


def test_openwebui_auth_states():
    off = check_exposure("http://h", fake({"/api/config": (200, '{"features":{"auth":false}}')}))
    signup = check_exposure("http://h", fake({"/api/config": (200, '{"features":{"auth":true,"enable_signup":true}}')}))
    ok = check_exposure("http://h", fake({"/api/config": (200, '{"features":{"auth":true,"enable_signup":false}}')}))
    assert verdicts(off)["/api/config"] == "EXPOSED"
    assert verdicts(signup)["/api/config"] == "WARN"
    assert verdicts(ok)["/api/config"] == "ok"


def test_unreachable():
    res = check_exposure("http://h", lambda u: (0, "connection refused"))
    assert set(verdicts(res).values()) == {"unreachable"}


def test_only_get_paths_no_credentials():
    seen = []
    check_exposure("http://h/", lambda u: (seen.append(u), (404, ""))[1])
    assert all(u.startswith("http://h/") and "//api" not in u[8:] for u in seen)
    assert not any(p in u for u in seen for p in ("pull", "create", "delete", "key/"))
