from __future__ import annotations

import json

import httpx
import pytest

from api_testing_agent.auth import provider as auth_mod
from api_testing_agent.auth.provider import (
    ApiKeyProvider, AuthConfig, BearerProvider, LoginProvider, build_provider,
)
from api_testing_agent.errors import AuthenticationError, InvalidInputError, UnsafeTargetError
from api_testing_agent.security.redaction import REDACTED, redact_obj, redact_text, truncate
from api_testing_agent.security.safety_policy import SafetyPolicy, TargetClass, parse_target

# ------------------------------------------------------------------ redaction


def test_redaction_removes_known_secrets_and_patterns():
    secret = "s3cr3t-token-value"
    text = f"Authorization: Bearer {secret}\nBearer abcdefgh12345678 and password=hunter22 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345"
    out = redact_text(text, [secret])
    for leak in (secret, "abcdefgh12345678", "hunter22", "eyJhbGciOiJIUzI1NiJ9"):
        assert leak not in out
    assert REDACTED in out


def test_redact_obj_handles_nested_and_sensitive_keys():
    obj = {"headers": {"Authorization": "Bearer x", "Accept": "json"}, "body": [{"password": "p", "name": "ok token=abc12345"}]}
    out = redact_obj(obj, ["abc12345"])
    assert out["headers"]["Authorization"] == REDACTED and out["headers"]["Accept"] == "json"
    assert out["body"][0]["password"] == REDACTED and "abc12345" not in json.dumps(out)


def test_truncate():
    assert truncate("x" * 10, 5).startswith("xxxxx...") and truncate("ab", 5) == "ab"


# ------------------------------------------------------------------ target safety policy


@pytest.mark.parametrize("url,klass", [
    ("http://127.0.0.1:8000", TargetClass.LOOPBACK), ("http://localhost:3000/api", TargetClass.LOOPBACK),
    ("http://10.1.2.3", TargetClass.PRIVATE), ("http://192.168.0.5:8080", TargetClass.PRIVATE),
    ("http://169.254.10.10", TargetClass.LINK_LOCAL), ("https://8.8.8.8", TargetClass.PUBLIC),
])
def test_target_classification(url, klass):
    assert parse_target(url).klass == klass


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/x", "http://[fd00:ec2::254]/", "http://100.100.100.200"])
def test_cloud_metadata_is_always_refused(url):
    with pytest.raises(UnsafeTargetError):
        parse_target(url)


@pytest.mark.parametrize("url", ["ftp://host", "http://", "not a url", "http://user:pw@127.0.0.1", "http://127.0.0.1?x=1", "http://127.0.0.1:99999"])
def test_invalid_urls_rejected(url):
    with pytest.raises(InvalidInputError):
        parse_target(url)


def test_base_path_and_default_ports():
    t = parse_target("https://10.0.0.1/api/v1/")
    assert (t.port, t.base_path, t.base_url) == (443, "/api/v1", "https://10.0.0.1/api/v1")


def test_policy_requires_approval_and_explicit_class_opt_in():
    loop, priv, pub = parse_target("http://127.0.0.1"), parse_target("http://10.0.0.1"), parse_target("http://8.8.8.8")
    with pytest.raises(UnsafeTargetError, match="not approved"):
        SafetyPolicy().check_target(loop)
    SafetyPolicy(approve_target=True).check_target(loop)
    with pytest.raises(UnsafeTargetError, match="allow-private"):
        SafetyPolicy(approve_target=True).check_target(priv)
    SafetyPolicy(approve_target=True, allow_private=True).check_target(priv)
    with pytest.raises(UnsafeTargetError, match="allow-public"):
        SafetyPolicy(approve_target=True).check_target(pub)


def test_destructive_never_allowed_on_public_hosts():
    with pytest.raises(UnsafeTargetError, match="never run against public"):
        SafetyPolicy(approve_target=True, allow_public=True, allow_destructive=True).check_target(parse_target("http://8.8.8.8"))
    SafetyPolicy(approve_target=True, allow_destructive=True).check_target(parse_target("http://127.0.0.1"))


def test_method_decisions_are_read_only_first():
    p = SafetyPolicy()
    assert p.method_decision("GET")[0] and p.method_decision("get")[0]
    assert not p.method_decision("POST")[0] and not p.method_decision("DELETE")[0]
    q = SafetyPolicy(allow_mutating=True)
    assert q.method_decision("PUT")[0] and not q.method_decision("DELETE")[0]


# ------------------------------------------------------------------ auth providers


def test_bearer_and_api_key_from_env(monkeypatch):
    monkeypatch.delenv("API_AGENT_TOKEN", raising=False)
    res = BearerProvider(AuthConfig(method="bearer")).resolve("http://x")
    assert not res.available and "API_AGENT_TOKEN" in res.reason
    monkeypatch.setenv("API_AGENT_TOKEN", "tok-1234567890")
    res = BearerProvider(AuthConfig(method="bearer")).resolve("http://x")
    assert res.available and res.header_value_template == "Bearer {{auth_token}}", "collection must reference a variable, never the value"
    assert res.secrets == ["tok-1234567890"] and "tok-1234567890" not in res.header_value_template
    monkeypatch.setenv("API_AGENT_API_KEY", "key-abcdef")
    res = ApiKeyProvider(AuthConfig(method="api-key", api_key_header="X-Custom")).resolve("http://x")
    assert res.header_name == "X-Custom" and res.header_value_template == "{{api_key}}"
    q = ApiKeyProvider(AuthConfig(method="api-key", api_key_in="query", api_key_header="k")).resolve("http://x")
    assert q.query_name == "k" and q.header_name is None


def _mock_login(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(auth_mod.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "transport"}))


def _login_cfg():
    return AuthConfig(method="login", login_path="/auth/login", login_token_path="data.token")


def test_login_success_extracts_token_and_hides_it(monkeypatch):
    monkeypatch.setenv("API_AGENT_USERNAME", "qa")
    monkeypatch.setenv("API_AGENT_PASSWORD", "pa55word!")
    seen = {}

    def handler(request):
        seen["url"], seen["body"] = str(request.url), json.loads(request.content)
        return httpx.Response(200, json={"data": {"token": "abcdef123456"}, "expires_in": 60})

    _mock_login(monkeypatch, handler)
    res = LoginProvider(_login_cfg()).resolve("http://api.test/v1")
    assert seen["url"] == "http://api.test/v1/auth/login" and seen["body"] == {"username": "qa", "password": "pa55word!"}
    assert res.available and res.env_vars["auth_token"] == "abcdef123456"
    assert set(res.secrets) == {"pa55word!", "abcdef123456"} and res.notes


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"error": "bad pa55word!"}),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json={"data": {}}),
    httpx.Response(302, headers={"location": "http://evil"}),
])
def test_login_validates_response_and_never_leaks_credentials(monkeypatch, response):
    monkeypatch.setenv("API_AGENT_USERNAME", "qa")
    monkeypatch.setenv("API_AGENT_PASSWORD", "pa55word!")
    _mock_login(monkeypatch, lambda request: response)
    with pytest.raises(AuthenticationError) as exc:
        LoginProvider(_login_cfg()).resolve("http://api.test")
    assert "pa55word!" not in str(exc.value)


def test_login_connection_error_is_redacted(monkeypatch):
    monkeypatch.setenv("API_AGENT_USERNAME", "qa")
    monkeypatch.setenv("API_AGENT_PASSWORD", "pa55word!")

    def boom(request):
        raise httpx.ConnectError("connect failed for pa55word!")

    _mock_login(monkeypatch, boom)
    with pytest.raises(AuthenticationError) as exc:
        LoginProvider(_login_cfg()).resolve("http://api.test")
    assert "pa55word!" not in str(exc.value)


def test_login_without_credentials_is_unavailable_and_unknown_endpoint_is_an_auth_error(monkeypatch):
    monkeypatch.delenv("API_AGENT_USERNAME", raising=False)
    monkeypatch.delenv("API_AGENT_PASSWORD", raising=False)
    assert not LoginProvider(_login_cfg()).resolve("http://x").available
    monkeypatch.setenv("API_AGENT_USERNAME", "qa")
    monkeypatch.setenv("API_AGENT_PASSWORD", "pa55word!")
    with pytest.raises(AuthenticationError, match="--login-path"):  # nothing to detect from and no --login-path
        LoginProvider(AuthConfig(method="login"), use_llm=False).resolve("http://x")
    assert build_provider(AuthConfig(method="none")).resolve("http://x").available is False


def test_auth_config_holds_env_var_names_only():
    dumped = AuthConfig(method="bearer").model_dump_json()
    assert "API_AGENT_TOKEN" in dumped, "env var *names* are fine"
    assert set(AuthConfig.model_fields) .isdisjoint({"token", "password", "api_key", "secret"})
