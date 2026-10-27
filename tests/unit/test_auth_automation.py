"""Login auto-detection, LLM assist, cookie/basic providers and login-aware collection generation (no network, no Newman)."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from api_testing_agent.auth import llm as llm_mod
from api_testing_agent.auth import provider as auth_mod
from api_testing_agent.auth.detector import rank_login_candidates, score_endpoint
from api_testing_agent.auth.provider import (
    AuthConfig, BasicProvider, LoginProvider, SessionProvider, assumed_resolution, build_provider,
)
from api_testing_agent.errors import AuthenticationError
from api_testing_agent.models.endpoint import Endpoint, EndpointInventory, RequestBody, ResponseSpec
from api_testing_agent.test_generation.collection_generator import GenerationOptions, generate, subset_collection
from api_testing_agent.security.safety_policy import SafetyPolicy

PWD = "pa55word!"


def ep(method, route, body_fields=None, ctype="application/json", resp_fields=None, requires_auth=None):
    return Endpoint(
        method=method, route=route, original_path=route, requires_auth=requires_auth,
        request_body=RequestBody(content_type=ctype, schema_def={"properties": {f: {"type": "string"} for f in body_fields}}) if body_fields else None,
        responses=[ResponseSpec(status="200", content_type="application/json", schema_def={"properties": {f: {"type": "string"} for f in resp_fields}})] if resp_fields else [],
    )


def inventory(*eps):
    return EndpointInventory(endpoints=list(eps))


REAL_CLIENT = httpx.Client  # captured once so repeated mock_http calls in one test never wrap a previous mock


def mock_http(monkeypatch, handler):
    monkeypatch.setattr(auth_mod.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "transport"}))


@pytest.fixture(autouse=True)
def creds(monkeypatch):
    monkeypatch.setenv("API_AGENT_USERNAME", "admin")
    monkeypatch.setenv("API_AGENT_PASSWORD", PWD)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


# ------------------------------------------------------------------ detection


def test_detects_login_with_field_names_and_documented_token():
    inv = inventory(
        ep("GET", "/items"),
        ep("POST", "/auth/login", ["email", "password"], resp_fields=["data"]),
        ep("POST", "/users", ["email", "password"]),  # registration-shaped, no login-ish route
        ep("POST", "/auth/logout"), ep("POST", "/auth/refresh", ["refresh_token"]), ep("POST", "/register", ["email", "password"]),
    )
    cands = rank_login_candidates(inv, AuthConfig(method="login"))
    assert [c.path for c in cands] == ["/auth/login"]
    assert (cands[0].username_field, cands[0].password_field, cands[0].content_type, cands[0].source) == ("email", "password", "json", "heuristic")


def test_oauth_token_form_endpoint_and_token_path_from_schema():
    inv = inventory(ep("POST", "/oauth/token", ["username", "password", "grant_type"], ctype="application/x-www-form-urlencoded", resp_fields=["access_token", "token_type"]))
    c = rank_login_candidates(inv, AuthConfig(method="login"))[0]
    assert c.content_type == "form" and c.token_path == "access_token"


def test_cli_overrides_beat_detection_and_non_candidates_score_zero():
    inv = inventory(ep("POST", "/signin", ["login", "pwd"]))
    c = rank_login_candidates(inv, AuthConfig(method="login", login_content_type="form", login_token_path="data.jwt"))[0]
    assert (c.content_type, c.token_path, c.username_field, c.password_field) == ("form", "data.jwt", "login", "pwd")
    assert score_endpoint(ep("GET", "/login")) == 0 and score_endpoint(ep("POST", "/orders", ["qty"])) == 0


# ------------------------------------------------------------------ login provider (auto)


def test_auto_login_finds_endpoint_and_token_and_never_leaks(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"], seen["body"] = str(request.url), json.loads(request.content)
        return httpx.Response(200, json={"token": "tok-abcdef-123456"})

    mock_http(monkeypatch, handler)
    inv = inventory(ep("POST", "/auth/login", ["username", "password"]))
    res = LoginProvider(AuthConfig(method="login"), inv, use_llm=False).resolve("http://api.test/v1")
    assert seen["url"] == "http://api.test/v1/auth/login" and seen["body"] == {"username": "admin", "password": PWD}
    assert res.available and res.env_vars["auth_token"] == "tok-abcdef-123456" and res.relogin_supported
    assert res.login.source == "heuristic" and res.login.endpoint_id == inv.endpoints[0].id
    assert {PWD, "tok-abcdef-123456"} <= set(res.secrets)


def test_form_login_sends_urlencoded(monkeypatch):
    seen = {}

    def handler(request):
        seen["ct"], seen["body"] = request.headers["content-type"], request.content.decode()
        return httpx.Response(200, json={"access_token": "form-token-123456"})

    mock_http(monkeypatch, handler)
    inv = inventory(ep("POST", "/oauth/token", ["username", "password"], ctype="application/x-www-form-urlencoded"))
    res = LoginProvider(AuthConfig(method="login"), inv, use_llm=False).resolve("http://api.test")
    assert "x-www-form-urlencoded" in seen["ct"] and "username=admin" in seen["body"] and res.available


def test_token_found_in_common_locations_and_header(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"data": {"accessToken": "nested-token-12345"}}))
    cfg = AuthConfig(method="login", login_path="/x/login")
    assert LoginProvider(cfg).resolve("http://api.test").env_vars["auth_token"] == "nested-token-12345"
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={}, headers={"X-Auth-Token": "header-token-12345"}))
    cfg = AuthConfig(method="login", login_path="/x/login", login_token_path="header:X-Auth-Token")
    assert LoginProvider(cfg).resolve("http://api.test").env_vars["auth_token"] == "header-token-12345"


def test_rejected_credentials_stop_at_first_candidate(monkeypatch):
    calls = []
    mock_http(monkeypatch, lambda r: (calls.append(str(r.url)), httpx.Response(401, json={"error": PWD}))[1])
    inv = inventory(ep("POST", "/auth/login", ["username", "password"]), ep("POST", "/signin", ["username", "password"]))
    with pytest.raises(AuthenticationError) as exc:
        LoginProvider(AuthConfig(method="login"), inv, use_llm=False).resolve("http://api.test")
    assert len(calls) == 1, "wrong credentials must not be replayed against other endpoints"
    assert PWD not in str(exc.value)


def test_falls_back_to_next_candidate_when_first_has_no_token(monkeypatch):
    def handler(request):
        if request.url.path == "/auth/login":
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"token": "second-token-12345"})

    mock_http(monkeypatch, handler)
    inv = inventory(ep("POST", "/auth/login", ["username", "password"], resp_fields=["token"]), ep("POST", "/signin", ["username", "password"]))
    res = LoginProvider(AuthConfig(method="login"), inv, use_llm=False).resolve("http://api.test")
    assert res.login.path == "/signin"


def test_relogin_reuses_the_endpoint_that_worked(monkeypatch):
    n = {"i": 0}

    def handler(request):
        n["i"] += 1
        return httpx.Response(200, json={"token": f"token-number-{n['i']}-xx"})

    mock_http(monkeypatch, handler)
    p = LoginProvider(AuthConfig(method="login"), inventory(ep("POST", "/auth/login", ["username", "password"])), use_llm=False)
    first, second = p.resolve("http://api.test"), p.resolve("http://api.test")
    assert first.env_vars["auth_token"] != second.env_vars["auth_token"] and p.spec.path == "/auth/login"


def test_no_candidates_and_no_flag_gives_actionable_error():
    with pytest.raises(AuthenticationError, match="--login-path"):
        LoginProvider(AuthConfig(method="login"), inventory(ep("GET", "/items")), use_llm=False).resolve("http://api.test")


def test_expiry_note_from_expires_in_and_jwt(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"token": "abcdefgh12345", "expires_in": 90}))
    assert any("90s" in n for n in LoginProvider(AuthConfig(method="login", login_path="/l")).resolve("http://api.test").notes)
    payload = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 600}).encode()).decode().rstrip("=")
    jwt = f"eyJhbGciOiJIUzI1NiJ9.{payload}.signaturesig"
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"access_token": jwt}))
    assert any("expires" in n for n in LoginProvider(AuthConfig(method="login", login_path="/l")).resolve("http://api.test").notes)


# ------------------------------------------------------------------ session + basic


def test_session_login_captures_cookie(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"ok": True}, headers={"set-cookie": "sid=cookie-value-9876; Path=/"}))
    inv = inventory(ep("POST", "/session/login", ["username", "password"]))
    res = SessionProvider(AuthConfig(method="session"), inv, use_llm=False).resolve("http://api.test")
    assert res.header_name == "Cookie" and res.header_value_template == "{{auth_cookie}}"
    assert res.env_vars["auth_cookie"] == "sid=cookie-value-9876" and "cookie-value-9876" in res.secrets


def test_session_login_without_cookie_fails(monkeypatch):
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"token": "abcdefgh12345"}))
    with pytest.raises(AuthenticationError, match="cookie"):
        SessionProvider(AuthConfig(method="session", login_path="/l")).resolve("http://api.test")


def test_basic_auth_header_is_built_and_redacted():
    res = BasicProvider(AuthConfig(method="basic")).resolve("http://x")
    enc = base64.b64encode(f"admin:{PWD}".encode()).decode()
    assert res.header_value_template == "Basic {{auth_basic}}" and res.env_vars == {"auth_basic": enc}
    assert enc in res.secrets and PWD in res.secrets
    assert isinstance(build_provider(AuthConfig(method="basic")), BasicProvider)


def test_assumed_resolution_shapes():
    assert assumed_resolution(AuthConfig(method="session")).header_name == "Cookie"
    assert assumed_resolution(AuthConfig(method="basic")).header_value_template == "Basic {{auth_basic}}"
    assert not assumed_resolution(AuthConfig(method="none")).available


# ------------------------------------------------------------------ LLM assist


def _llm_reply(monkeypatch, content, captured=None, status=200):
    def fake_post(url, headers=None, json=None, **kw):  # noqa: A002
        if captured is not None:
            captured.update(url=url, headers=headers, payload=json)
        return httpx.Response(status, json={"choices": [{"message": {"content": content}}]}, request=httpx.Request("POST", url))

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)


def test_llm_skipped_without_key():
    r = llm_mod.suggest_login(inventory(ep("POST", "/members/enter", ["u", "p"])), AuthConfig(method="login"))
    assert r.specs == [] and "OPENROUTER_API_KEY" in r.note


def test_llm_suggestion_validated_and_prompt_has_no_credentials(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123456")
    cap = {}
    _llm_reply(monkeypatch, 'Sure:\n{"found": true, "login_path": "/members/enter", "content_type": "form", "username_field": "u", "password_field": "p", "token_path": "data.jwt"}', cap)
    r = llm_mod.suggest_login(inventory(ep("POST", "/members/enter", ["u", "p"])), AuthConfig(method="login"))
    s = r.specs[0]
    assert (s.path, s.content_type, s.username_field, s.password_field, s.token_path, s.source) == ("/members/enter", "form", "u", "p", "data.jwt", "llm")
    sent = json.dumps(cap["payload"])
    assert PWD not in sent and "admin" not in sent and cap["headers"]["Authorization"] == "Bearer or-key-123456"


@pytest.mark.parametrize("reply", [
    "not json at all", '{"found": false}', '{"found": true, "login_path": "http://evil.example/login"}',
    '{"found": true, "login_path": "/../etc/passwd"}', '{"found": true, "login_path": "/billing/invoices"}',
])
def test_llm_bad_or_unsafe_suggestions_are_rejected(monkeypatch, reply):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123456")
    _llm_reply(monkeypatch, reply)
    assert llm_mod.suggest_login(inventory(ep("GET", "/x")), AuthConfig(method="login")).specs == []


def test_llm_http_error_never_raises(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123456")
    _llm_reply(monkeypatch, "{}", status=500)
    assert llm_mod.suggest_login(inventory(ep("GET", "/x")), AuthConfig(method="login")).specs == []


def test_provider_uses_llm_when_heuristics_find_nothing(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-123456")
    _llm_reply(monkeypatch, '{"found": true, "login_path": "/members/enter", "content_type": "json", "username_field": "u", "password_field": "p", "token_path": "token"}')
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"token": "llm-found-token-12"})

    mock_http(monkeypatch, handler)
    inv = inventory(ep("POST", "/members/enter", ["u", "p"]))
    res = LoginProvider(AuthConfig(method="login"), inv).resolve("http://api.test")
    assert seen["body"] == {"u": "admin", "p": PWD} and res.llm_used and res.login.source == "llm"
    # --no-llm: same inventory, same key, but the assist must not run
    with pytest.raises(AuthenticationError, match="--login-path"):
        LoginProvider(AuthConfig(method="login"), inv, use_llm=False).resolve("http://api.test")


# ------------------------------------------------------------------ collection generation


def test_login_endpoint_uses_runtime_variables_and_no_token():
    inv = inventory(ep("POST", "/auth/login", ["username", "password"]), ep("GET", "/users/me", requires_auth=True))
    spec = rank_login_candidates(inv, AuthConfig(method="login"))[0]
    res = assumed_resolution(AuthConfig(method="login"))
    res.login = spec
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=res))
    items = {i["name"].split(" [")[0]: i for f in gen.collection["item"] for i in f["item"] if i["name"].endswith("[positive]")}
    login = items["POST /auth/login"]["request"]
    assert json.loads(login["body"]["raw"]) == {"username": "{{auth_username}}", "password": "{{auth_password}}"}
    assert not any(h["key"] == "Authorization" for h in login["header"])
    assert any(h["key"] == "Authorization" and h["value"] == "Bearer {{auth_token}}" for h in items["GET /users/me"]["request"]["header"])
    assert {v["key"] for v in gen.environment["values"]} >= {"auth_token", "auth_username", "auth_password"}
    dumped = json.dumps(gen.collection)
    assert PWD not in dumped and "admin" not in dumped


def test_login_endpoint_respects_mutating_policy():
    inv = inventory(ep("POST", "/auth/login", ["username", "password"]))
    res = assumed_resolution(AuthConfig(method="login"))
    res.login = rank_login_candidates(inv, AuthConfig(method="login"))[0]
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(), auth=res))  # read-only policy
    assert not gen.plan.requests and gen.plan.blocked[0].reason_code == "POLICY_NOT_AUTHORIZED"


def test_subset_collection_keeps_only_requested_items():
    inv = inventory(ep("GET", "/a"), ep("GET", "/b"), ep("GET", "/c/d"))
    gen = generate(inv, GenerationOptions())
    keep = {gen.plan.requests[0].item_id}
    sub = subset_collection(gen.collection, keep)
    ids = [i["id"] for f in sub["item"] for i in f["item"]]
    assert ids == list(keep)
