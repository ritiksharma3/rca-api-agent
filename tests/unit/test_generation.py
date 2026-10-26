from __future__ import annotations

import json

import jsonschema
import pytest

from api_testing_agent.auth.provider import AuthResolution
from api_testing_agent.errors import CollectionGenerationError
from api_testing_agent.models.endpoint import (
    Endpoint, EndpointInventory, ParamLocation, Parameter, RequestBody, ResponseSpec,
)
from api_testing_agent.models.execution import Scenario
from api_testing_agent.security.safety_policy import SafetyPolicy
from api_testing_agent.test_generation.collection_generator import (
    COLLECTION_SCHEMA, Fixtures, GenerationOptions, generate, validate_collection,
)
from api_testing_agent.test_generation.schema_analyzer import to_json_schema
from api_testing_agent.test_generation.test_data import CannotGenerate, DataGenerator

USER_SCHEMA = {
    "type": "object",
    "required": ["email", "age", "role"],
    "properties": {
        "email": {"type": "string", "format": "email"},
        "age": {"type": "integer", "minimum": 18, "maximum": 65},
        "role": {"type": "string", "enum": ["admin", "user"]},
        "nick": {"type": "string", "minLength": 3, "maxLength": 8},
        "score": {"type": "number", "minimum": 0.5, "maximum": 9.5},
        "tags": {"type": "array", "items": {"type": "string"}, "minItems": 2},
        "active": {"type": "boolean"},
    },
}


# ------------------------------------------------------------------ data generation
def test_valid_data_satisfies_schema_and_is_reproducible():
    a = DataGenerator(7).valid(USER_SCHEMA)
    b = DataGenerator(7).valid(USER_SCHEMA)
    c = DataGenerator(8).valid(USER_SCHEMA)
    jsonschema.validate(a, USER_SCHEMA)
    assert a == b and a != c
    assert len(a["tags"]) >= 2 and a["role"] == "admin"


def test_examples_and_defaults_take_precedence():
    g = DataGenerator(1)
    assert g.valid({"type": "string", "example": "hello", "default": "x", "enum": ["y"]}) == "hello"
    assert g.valid({"type": "integer", "default": 5, "minimum": 1}) == 5
    assert g.valid({"type": "string", "enum": ["only"]}) == "only"


def test_never_invents_foreign_keys():
    with pytest.raises(CannotGenerate, match="existing resource"):
        DataGenerator(1).valid({"type": "object", "required": ["customer_id"], "properties": {"customer_id": {"type": "integer"}}})
    # optional id-like fields are simply omitted
    out = DataGenerator(1).valid({"type": "object", "properties": {"parent_id": {"type": "integer"}, "n": {"type": "string"}}})
    assert "parent_id" not in out and "n" in out
    # an explicit example is accepted
    assert DataGenerator(1).valid({"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "integer", "example": 42}}}) == {"user_id": 42}


def test_unsatisfiable_pattern_raises_instead_of_guessing():
    with pytest.raises(CannotGenerate, match="pattern"):
        DataGenerator(1).valid({"type": "string", "pattern": "^ZZ-[0-9]{3}-QQ$"})


def test_invalid_payloads_really_violate_the_schema():
    g = DataGenerator(3)
    valid = g.valid(USER_SCHEMA)
    variants = g.invalid_variants(USER_SCHEMA, valid, limit=10)
    assert variants
    for desc, payload, evidence in variants:
        assert evidence, "negative tests need stated evidence"
        validator = jsonschema.Draft7Validator(USER_SCHEMA, format_checker=jsonschema.FormatChecker())
        assert list(validator.iter_errors(payload)), f"variant did not violate the schema: {desc}"


# ------------------------------------------------------------------ collection generation
def ep(method, route, **kw):
    names = [p for p in __import__("re").findall(r"\{(\w+)\}", route)]
    params = [Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "integer"}) for n in names]
    return Endpoint(method=method, route=route, original_path=route, path_param_names=names, parameters=params + kw.pop("extra", []), strategy="openapi", **kw)


def inventory():
    return EndpointInventory(project_root="/p", endpoints=[
        ep("GET", "/health", responses=[ResponseSpec(status="200")]),
        ep("GET", "/items/{item_id}", responses=[ResponseSpec(status="200", content_type="application/json", schema_def={"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}})]),
        ep("POST", "/items", request_body=RequestBody(schema_def=USER_SCHEMA, required=True), responses=[ResponseSpec(status="201")]),
        ep("DELETE", "/items/{item_id}"),
        ep("GET", "/me", requires_auth=True, security_schemes=["bearer"]),
    ])


def names(gen):
    return {i["name"] for f in gen.collection["item"] for i in f["item"]}


def blocked(gen):
    return {(b.method, b.route, b.scenario.value): b.reason_code for b in gen.plan.blocked}


def test_collection_is_valid_postman_v21_and_secretless():
    auth = AuthResolution("bearer", True, header_name="Authorization", header_value_template="Bearer {{auth_token}}", env_vars={"auth_token": "SUPERSECRETTOKEN"}, secrets=["SUPERSECRETTOKEN"])
    gen = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True), auth=auth, fixtures=Fixtures(path_params={"item_id": 7})))
    assert gen.collection["info"]["schema"] == COLLECTION_SCHEMA
    validate_collection(gen.collection)
    blob = json.dumps(gen.collection) + json.dumps(gen.environment)
    assert "SUPERSECRETTOKEN" not in blob and "{{auth_token}}" in blob
    assert all(v["value"] == "" for v in gen.environment["values"]), "environment template must hold names only"
    assert "GET /items/{item_id} [positive]" in names(gen)
    req = next(i for f in gen.collection["item"] for i in f["item"] if i["name"] == "GET /items/{item_id} [positive]")
    assert req["request"]["url"]["raw"] == "{{base_url}}/items/7"
    script = "\n".join(req["event"][0]["script"]["exec"])
    assert "jsonSchema" in script and "status code is one of [200]" in script
    assert len({i["id"] for f in gen.collection["item"] for i in f["item"]}) == len(gen.plan.requests)


def test_policy_blocks_mutating_and_destructive_by_default():
    gen = generate(inventory(), GenerationOptions(fixtures=Fixtures(path_params={"item_id": 1})))
    b = blocked(gen)
    assert b[("POST", "/items", "positive")] == "POLICY_NOT_AUTHORIZED"
    assert b[("DELETE", "/items/{item_id}", "positive")] == "POLICY_NOT_AUTHORIZED"
    assert not any("POST" in n or "DELETE" in n for n in names(gen)), "no mutating request may be in the collection"
    assert "GET /health [positive]" in names(gen)


def test_delete_requires_its_own_opt_in():
    gen = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True), fixtures=Fixtures(path_params={"item_id": 1})))
    assert blocked(gen)[("DELETE", "/items/{item_id}", "positive")] == "POLICY_NOT_AUTHORIZED"
    gen = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_destructive=True), fixtures=Fixtures(path_params={"item_id": 1})))
    assert "DELETE /items/{item_id} [positive]" in names(gen)


def test_missing_fixture_and_missing_auth_are_blocked_not_invented():
    gen = generate(inventory(), GenerationOptions())
    b = blocked(gen)
    assert b[("GET", "/items/{item_id}", "positive")] == "MISSING_FIXTURE"
    assert b[("GET", "/me", "positive")] == "MISSING_AUTH"
    # the unauthenticated check needs no credentials and is still generated
    assert "GET /me [auth_required]" in names(gen)


def test_negative_tests_only_when_requested_with_evidence():
    opts = dict(auth=None, fixtures=Fixtures(path_params={"item_id": 1}))
    off = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True), **opts))
    assert not any("[negative]" in n for n in names(off))
    on = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_negative=True), **opts))
    neg = [r for r in on.plan.requests if r.scenario == Scenario.NEGATIVE]
    assert neg and all(r.expected_basis and "inferred" in r.expected_basis for r in neg)
    assert all(r.description for r in neg)


def test_request_budget_is_enforced_and_positives_come_first():
    gen = generate(inventory(), GenerationOptions(policy=SafetyPolicy(allow_mutating=True, allow_negative=True, max_requests=2), fixtures=Fixtures(path_params={"item_id": 1})))
    assert len(gen.plan.requests) == 2 and all(r.scenario == Scenario.POSITIVE for r in gen.plan.requests)
    assert gen.plan.skipped_over_budget and any(b.reason_code == "REQUEST_BUDGET" for b in gen.plan.blocked)


def test_validate_collection_rejects_bad_documents():
    with pytest.raises(CollectionGenerationError):
        validate_collection({"info": {"name": "x"}, "item": []})
    good = generate(inventory(), GenerationOptions()).collection
    good["item"][0]["item"][0]["request"]["method"] = "FETCH"
    with pytest.raises(CollectionGenerationError, match="invalid method"):
        validate_collection(good)


def test_to_json_schema_is_conservative():
    s = to_json_schema({"type": "string", "nullable": True, "format": "date", "example": "x", "minimum": 1})
    assert s["type"] == ["string", "null"] and "format" not in s and "example" not in s
    assert to_json_schema({"type": "integer", "minimum": 0, "exclusiveMinimum": True}) == {"type": "integer", "exclusiveMinimum": 0}
