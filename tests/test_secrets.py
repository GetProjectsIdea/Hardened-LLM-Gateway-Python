import pytest

from llm_gateway.secrets_check import (find_provider_keys, generate_secret, is_weak, redact, secret_problems,
                                       shannon_entropy)


@pytest.mark.parametrize("value", ["sk-1234", "t0p-s3cr3t", "changeme", "admin", "password", "", None, "   ",
                                   "sk-1234567890", "your-secret-key-goes-here-please-change-it", "a" * 40,
                                   "abcabcabcabcabcabcabcabcabcabcabcabc", "0123456789012345678901234567890123"])
def test_weak_values_rejected(value):
    assert is_weak(value)


def test_generated_secret_is_strong():
    s = generate_secret()
    assert len(s) >= 43 and secret_problems(s) == []


def test_known_default_reason():
    assert "well-known default" in secret_problems("sk-1234")[0]


def test_placeholder_detected():
    assert any("placeholder" in p for p in secret_problems("REPLACE_ME_with_a_real_value_1234567890"))


def test_short_reason_mentions_length():
    assert any("too short" in p for p in secret_problems("Xy7#kq2L"))


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy(generate_secret()) > 4


def test_redact_hides_secret():
    r = redact("lgw_abcdef123456_supersecretvalue")
    assert r.startswith("lgw_") and "supersecret" not in r
    assert redact("") == "" and redact("abc") == "***"


def test_find_provider_keys():
    text = "a=sk-proj-" + "A" * 30 + "\nb=AKIA" + "B" * 16 + "\nc=hf_" + "c" * 34
    kinds = {k for k, _ in find_provider_keys(text)}
    assert {"OpenAI project key", "AWS access key ID", "Hugging Face token"} <= kinds
    assert all("A" * 30 not in v for _, v in find_provider_keys(text))


def test_no_false_positive_on_reference():
    assert find_provider_keys("api_key: os.environ/OPENAI_API_KEY") == []
