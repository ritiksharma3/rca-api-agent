"""Request headers, run ordering, id chaining, account protection and token detection."""

from __future__ import annotations

import json

import httpx
import pytest

from api_testing_agent.auth import provider as auth_mod
from api_testing_agent.auth.headers import (
    DYNAMIC_UUID, HeaderPlan, detect_header_hints, parse_header_flags, resolve_headers,
)
from api_testing_agent.auth.provider import AuthConfig, AuthResolution, LoginProvider, LoginSpec, _find_token, assumed_resolution
from api_testing_agent.discovery.registry import STRATEGIES  # noqa: F401  (import side effects keep the registry loaded)
from api_testing_agent.errors import AuthenticationError
from api_testing_agent.models.endpoint import Endpoint, EndpointInventory, ParamLocation, Parameter, RequestBody
from api_testing_agent.security.safety_policy import SafetyPolicy
from api_testing_agent.test_generation.collection_generator import (
    EndpointFixture, Fixtures, GenerationOptions, generate, is_session_end, lifecycle_rank, resource_of,
)

REAL_CLIENT = httpx.Client


def ep(method, route, body=None, requires_auth=True):
    names = [p[1:-1] for p in route.split("/") if p.startswith("{")]
    return Endpoint(
        method=method, route=route, original_path=route, requires_auth=requires_auth, path_param_names=names,
        parameters=[Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names],
        request_body=RequestBody(content_type="application/json", schema_def={"type": "object", "properties": {f: {"type": "string"} for f in body}}) if body else None,
    )


def logged_in(**extra):
    res = assumed_resolution(AuthConfig(method="login"))
    res.login = LoginSpec(path="/api/v1/auth/login", username_field="email", password_field="password")
    for k, v in extra.items():
        setattr(res, k, v)
    return res


def items_of(gen):
    return [i for f in gen.collection["item"] for i in f["item"]]


# ------------------------------------------------------------------ headers
def write_backend(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "middleware.js").write_text(
        "const key = req.get('X-API-Key');\n"
        "const v = req.get('X-Client-Version');\n"
        "const t = req.get('X-Tenant-ID');\n"
        "const idem = req.get('Idempotency-Key');\n"
        "const sig = req.get('X-Signature');\n"
        "const auth = req.get('Authorization');\n"
        "const rid = req.get('X-Request-ID');\n"
        "const fromHeaders = req.headers['x-env-name'];\n", encoding="utf-8")
    return tmp_path


def test_header_names_are_found_in_source_and_standard_ones_skipped(tmp_path):
    names = {h.name.lower() for h in detect_header_hints(None, write_backend(tmp_path))}
    assert names == {"x-api-key", "x-client-version", "x-tenant-id", "idempotency-key", "x-signature", "x-env-name"}


def test_header_values_come_from_flags_env_and_generators_never_the_source(tmp_path):
    hints = detect_header_hints(None, write_backend(tmp_path))
    plan = resolve_headers(hints, {"x-tenant-id": "tenant-acme"}, use_llm=False, environ={"API_AGENT_API_KEY": "key-from-env-123"})
    by = {h.name.lower(): h for h in plan.headers}
    assert by["x-api-key"].value == "key-from-env-123" and by["x-api-key"].source == "env" and by["x-api-key"].secret
    assert by["x-tenant-id"].source == "flag"
    assert by["idempotency-key"].dynamic == DYNAMIC_UUID and by["idempotency-key"].value is None
    assert by["x-client-version"].value == "1.0.0" and by["x-client-version"].source == "default"
    assert [h.name for h in plan.unresolved] == ["X-Env-Name"] and plan.unsupported == ["X-Signature"]
    assert "key-from-env-123" in plan.secrets() and "key-from-env-123" not in json.dumps(plan.summary())
    assert plan.env_vars()["hdr_x_api_key"] == "key-from-env-123"
    assert "API_AGENT_HEADER_X_ENV_NAME" in plan.hint_for_missing()


def test_placeholder_env_values_are_not_used_and_secret_headers_never_go_to_the_llm(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("api_testing_agent.auth.llm.suggest_header_values", lambda pending: (called.extend(h.name for h in pending) or {}, "n"))
    plan = resolve_headers(detect_header_hints(None, write_backend(tmp_path)), None, use_llm=True,
                           environ={"API_AGENT_API_KEY": "replace-me", "API_AGENT_HEADER_X_TENANT_ID": ""})
    assert "X-API-Key" in [h.name for h in plan.unresolved]
    assert "X-API-Key" not in called and "X-Tenant-ID" in called  # tenant ids are not secret, keys are


def test_header_flags(monkeypatch):
    monkeypatch.setenv("MY_KEY", "abc12345")
    assert parse_header_flags(["X-API-Key=env:MY_KEY", "X-A=b=c"]) == {"x-api-key": "abc12345", "x-a": "b=c"}
    with pytest.raises(Exception, match="NAME=VALUE"):
        parse_header_flags(["no-equals"])
    with pytest.raises(Exception, match="not set"):
        parse_header_flags(["X-K=env:DOES_NOT_EXIST_XYZ"])


def test_headers_are_added_to_every_request_including_the_no_credentials_check():
    plan = resolve_headers([], {"x-api-key": "k-123456", "x-tenant-id": "tenant-acme"}, use_llm=False, environ={})
    inv = EndpointInventory(endpoints=[ep("GET", "/things")])
    gen = generate(inv, GenerationOptions(auth=logged_in(), headers=plan))
    for item in items_of(gen):
        hdrs = {h["key"]: h["value"] for h in item["request"]["header"]}
        assert hdrs["X-Api-Key"] == "{{hdr_x_api_key}}" or hdrs.get("X-API-Key") == "{{hdr_x_api_key}}"
    assert {i["name"].split("[")[1] for i in items_of(gen)} == {"positive]", "auth_required]"}
    assert "k-123456" not in json.dumps(gen.collection) and "tenant-acme" not in json.dumps(gen.collection)  # values stay in the runtime env
    assert {"hdr_x_api_key", "hdr_x_tenant_id"} <= {v["key"] for v in gen.environment["values"]}


# ------------------------------------------------------------------ login with headers / errors / tokens
def mock_http(monkeypatch, handler):
    monkeypatch.setattr(auth_mod.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "transport"}))


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("API_AGENT_USERNAME", "admin@example.com")
    monkeypatch.setenv("API_AGENT_PASSWORD", "S3cret-pw!")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


def login_inventory():
    return EndpointInventory(endpoints=[ep("POST", "/api/v1/auth/login", ["email", "password"], requires_auth=None)])


def test_login_sends_required_headers_and_reads_a_camelcase_token(monkeypatch, creds):
    seen = {}

    def handler(request):
        seen.update(request.headers)
        if request.headers.get("x-api-key") != "k-123456":
            return httpx.Response(401, json={"error": {"code": "INVALID_API_KEY", "message": "Missing or invalid X-API-Key header"}})
        return httpx.Response(200, json={"accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.sig", "refreshToken": "r" * 40, "tokenType": "Bearer", "expiresIn": 900})

    mock_http(monkeypatch, handler)
    plan = resolve_headers([], {"x-api-key": "k-123456", "idempotency-key": "x"}, use_llm=False, environ={})
    provider = LoginProvider(AuthConfig(method="login"), login_inventory(), use_llm=False)
    provider.header_plan = plan
    res = provider.resolve("http://api.test")
    assert res.available and res.env_vars["auth_token"].startswith("eyJ") and res.header_value_template == "Bearer {{auth_token}}"
    assert res.refresh_available and res.env_vars["auth_refresh_token"] == "r" * 40 and "r" * 40 in res.secrets
    assert seen["x-api-key"] == "k-123456"
    # the same login without the header: the 401 is reported for what it is, not as "wrong credentials"
    bare = LoginProvider(AuthConfig(method="login"), login_inventory(), use_llm=False)
    with pytest.raises(AuthenticationError) as ei:
        bare.resolve("http://api.test")
    assert "INVALID_API_KEY" in str(ei.value) and "required request header" in str(ei.value)
    assert not getattr(ei.value, "credentials_rejected", False)


def test_genuinely_wrong_credentials_are_still_reported_as_such(monkeypatch, creds):
    mock_http(monkeypatch, lambda r: httpx.Response(401, json={"error": {"code": "BAD_CREDENTIALS", "message": "Invalid email or password"}}))
    with pytest.raises(AuthenticationError) as ei:
        LoginProvider(AuthConfig(method="login"), login_inventory(), use_llm=False).resolve("http://api.test")
    assert getattr(ei.value, "credentials_rejected", False) and "BAD_CREDENTIALS" in str(ei.value)


@pytest.mark.parametrize("body,expected", [
    ({"accessToken": "a" * 20, "refreshToken": "r" * 20}, "accessToken"),
    ({"data": {"session": {"jwt_value": "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"}}}, "data.session.jwt_value"),
    ({"result": {"authToken": "t" * 16, "refresh_token": "r" * 16}}, "result.authToken"),
    ({"user": {"id": 1}, "credentials": {"bearer_token": "b" * 16}}, "credentials.bearer_token"),
])
def test_token_is_found_wherever_the_server_puts_it(body, expected):
    found = _find_token(httpx.Response(200, json=body), body, None)
    assert found is not None and found[1] == expected


def test_a_stale_configured_token_path_is_only_a_preference():
    body = {"accessToken": "a" * 20}
    assert _find_token(httpx.Response(200, json=body), body, "access_token")[1] == "accessToken"
    assert _find_token(httpx.Response(200, json={"refreshToken": "r" * 20, "tokenType": "Bearer"}), {"refreshToken": "r" * 20, "tokenType": "Bearer"}, None) is None


def test_llm_token_fallback_receives_only_the_masked_shape(monkeypatch, creds):
    from api_testing_agent.auth import llm

    body = {"payload": {"credential_blob": "SECRETVALUE-123456789"}, "email": "someone@example.com"}
    sent = {}

    def fake_complete(system, user, max_tokens, timeout_s=30.0):
        sent["user"] = user
        return '{"token_path": "payload.credential_blob"}', "LLM (test)"

    monkeypatch.setattr(llm, "_complete", fake_complete)
    mock_http(monkeypatch, lambda r: httpx.Response(200, json=body))
    res = LoginProvider(AuthConfig(method="login"), login_inventory(), use_llm=True).resolve("http://api.test")
    assert res.available and res.llm_used and res.env_vars["auth_token"] == "SECRETVALUE-123456789"
    assert "SECRETVALUE" not in sent["user"] and "someone@example.com" not in sent["user"] and "credential_blob" in sent["user"]


# ------------------------------------------------------------------ ordering
def test_lifecycle_helpers():
    assert resource_of("/api/v1/products/{id}") == "products" and resource_of("/health") == "health" and resource_of("/") == "root"
    assert [lifecycle_rank(m, r) for m, r in [("POST", "/x"), ("GET", "/x"), ("GET", "/x/{id}"), ("PATCH", "/x/{id}"), ("DELETE", "/x/{id}")]] == [0, 1, 2, 3, 4]
    assert is_session_end("POST", "/api/v1/auth/logout") and is_session_end("POST", "/signout") and not is_session_end("POST", "/api/v1/orders")


def test_order_is_create_list_read_update_delete_with_logout_and_login_last():
    inv = EndpointInventory(endpoints=[
        ep("DELETE", "/api/v1/items/{id}"), ep("GET", "/api/v1/items/{id}"), ep("PATCH", "/api/v1/items/{id}", ["name"]),
        ep("GET", "/api/v1/items"), ep("POST", "/api/v1/items", ["name"]), ep("POST", "/api/v1/auth/logout"),
        ep("POST", "/api/v1/auth/login", ["email", "password"], requires_auth=None),
    ])
    res = logged_in()
    res.login.endpoint_id = inv.endpoints[-1].id
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_destructive=True), auth=res))
    names = [i["name"] for i in items_of(gen)]
    positives = [n.replace(" [positive]", "") for n in names if n.endswith("[positive]")]
    assert positives == ["POST /api/v1/items", "GET /api/v1/items", "GET /api/v1/items/{id}", "PATCH /api/v1/items/{id}",
                         "DELETE /api/v1/items/{id}", "POST /api/v1/auth/logout", "POST /api/v1/auth/login"]
    # every "without credentials" check of a resource comes after its positive flow, so it cannot disturb it
    items_idx = [n for n in names if "/items" in n]
    assert max(i for i, n in enumerate(items_idx) if n.endswith("[positive]")) < min(i for i, n in enumerate(items_idx) if n.endswith("[auth_required]"))
    assert gen.collection["item"][-1]["name"].startswith("session-ending")
    assert [i["name"] for i in gen.collection["item"][-1]["item"]][:1] == ["POST /api/v1/auth/logout [positive]"]


# ------------------------------------------------------------------ id chaining
def test_created_id_is_captured_and_used_for_read_update_delete():
    inv = EndpointInventory(endpoints=[ep("DELETE", "/things/{id}"), ep("GET", "/things/{id}"), ep("PATCH", "/things/{id}", ["name"]), ep("POST", "/things", ["name"])])
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_destructive=True), auth=logged_in()))
    by = {i["name"]: i for i in items_of(gen)}
    post = "\n".join(by["POST /things [positive]"]["event"][0]["script"]["exec"])
    assert "pm.collectionVariables.set('id_things'" in post and "pm.collectionVariables.set('cur_things'" in post
    assert by["GET /things/{id} [positive]"]["request"]["url"]["raw"] == "{{base_url}}/things/{{cur_things}}"
    assert by["PATCH /things/{id} [positive]"]["request"]["url"]["raw"] == "{{base_url}}/things/{{id_things}}"
    assert by["DELETE /things/{id} [positive]"]["request"]["url"]["raw"] == "{{base_url}}/things/{{id_things}}"
    assert not gen.plan.blocked


def test_listed_ids_are_only_ever_read_never_modified_or_deleted():
    inv = EndpointInventory(endpoints=[ep("GET", "/things"), ep("GET", "/things/{id}"), ep("DELETE", "/things/{id}"), ep("PATCH", "/things/{id}", ["name"])])
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_destructive=True), auth=logged_in()))
    by = {i["name"]: i for i in items_of(gen)}
    assert "cur_things" in "\n".join(by["GET /things [positive]"]["event"][0]["script"]["exec"])
    assert "id_things" not in "\n".join(by["GET /things [positive]"]["event"][0]["script"]["exec"]).replace("cur_things", "")
    assert by["GET /things/{id} [positive]"]["request"]["url"]["raw"].endswith("/things/{{cur_things}}")
    blocked = {(b.method, b.scenario.value): b.reason for b in gen.plan.blocked}
    assert "never modified or deleted" in blocked[("DELETE", "positive")] and ("PATCH", "positive") in blocked


def test_without_mutation_rights_the_message_says_how_to_get_an_id():
    inv = EndpointInventory(endpoints=[ep("POST", "/things", ["name"]), ep("GET", "/things/{id}")])
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(), auth=logged_in()))  # POST not allowed
    reason = next(b.reason for b in gen.plan.blocked if b.method == "GET")
    assert "--allow-mutating" in reason and "fixtures" in reason


def test_fixture_ids_still_win_over_chaining():
    inv = EndpointInventory(endpoints=[ep("POST", "/things", ["name"]), ep("GET", "/things/{id}")])
    fx = Fixtures(path_params={"id": 42})
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=logged_in(), fixtures=fx))
    assert next(i for i in items_of(gen) if i["name"] == "GET /things/{id} [positive]")["request"]["url"]["raw"].endswith("/things/42")


# ------------------------------------------------------------------ protecting the login account / refresh / uniqueness
def test_updates_cannot_change_the_credentials_the_run_logs_in_with():
    inv = EndpointInventory(endpoints=[ep("PATCH", "/users/me", ["name", "password", "email"])])
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=logged_in()))
    body = json.loads(next(i for i in items_of(gen) if i["name"].endswith("[positive]"))["request"]["body"]["raw"])
    assert body["password"] == "{{auth_password}}" and body["email"] == "{{auth_username}}" and body["name"] != "{{auth_username}}"


def test_register_style_posts_are_not_rewritten_and_get_unique_emails():
    inv = EndpointInventory(endpoints=[ep("POST", "/auth/register", ["email", "password", "name"], requires_auth=None)])
    fx = Fixtures(endpoints={"POST /auth/register": EndpointFixture(body={"email": "new.user@example.com", "password": "Passw0rd!", "name": "N"}, generated=True)})
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=logged_in(), fixtures=fx))
    body = json.loads(next(i for i in items_of(gen) if i["name"].endswith("[positive]"))["request"]["body"]["raw"])
    assert body["email"] == "new.user+{{$timestamp}}{{$randomInt}}@example.com" and body["password"] == "Passw0rd!"
    # a user-supplied fixture body is never touched
    fx2 = Fixtures(endpoints={"POST /auth/register": EndpointFixture(body={"email": "fixed@example.com", "password": "x", "name": "N"})})
    gen2 = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=logged_in(), fixtures=fx2))
    assert json.loads(next(i for i in items_of(gen2) if i["name"].endswith("[positive]"))["request"]["body"]["raw"])["email"] == "fixed@example.com"


def test_refresh_token_field_gets_the_real_refresh_token():
    inv = EndpointInventory(endpoints=[ep("POST", "/auth/refresh", ["refreshToken"], requires_auth=None)])
    gen = generate(inv, GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=logged_in(refresh_available=True)))
    body = json.loads(next(i for i in items_of(gen) if i["name"].endswith("[positive]"))["request"]["body"]["raw"])
    assert body == {"refreshToken": "{{auth_refresh_token}}"}


def test_llm_bodies_are_validated():
    from api_testing_agent.auth.llm import _body_ok

    assert _body_ok({"items": [{"productId": 1, "quantity": 2}], "note": "hi"})
    assert not _body_ok({"x": "{{auth_password}}"}) and not _body_ok({"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}})
    assert not _body_ok({"s": "x" * 500})


def test_hdrplan_summary_has_no_values():
    plan = HeaderPlan()
    assert plan.summary() == [] and plan.hint_for_missing() == ""
    assert isinstance(AuthResolution("none", False).refresh_available, bool)
