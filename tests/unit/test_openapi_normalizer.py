from __future__ import annotations

import json

import pytest
import yaml

from api_testing_agent.discovery.base import DiscoveryContext
from api_testing_agent.discovery.normalizer import dedupe, finalize, join_paths, normalize_path, validate_inventory
from api_testing_agent.discovery.openapi_adapter import OpenApiAdapter
from api_testing_agent.errors import DiscoveryError, InvalidInventoryError
from api_testing_agent.models.endpoint import Endpoint, EndpointInventory, ParamLocation
from api_testing_agent.scanner.repository_scanner import scan_repository

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "t", "version": "1"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "security": [{"bearer": []}],
    "paths": {
        "/pets/{petId}": {
            "parameters": [{"name": "petId", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "get": {
                "operationId": "getPet",
                "parameters": [{"name": "verbose", "in": "query", "schema": {"type": "boolean"}}],
                "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}},
            },
        },
        "/pets": {
            "post": {
                "security": [],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewPet"}}}},
                "responses": {"201": {"description": "created"}},
            }
        },
        "/ext": {"get": {"responses": {"200": {"description": "x", "content": {"application/json": {"schema": {"$ref": "other.yaml#/Thing"}}}}}}},
    },
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Pet": {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}, "parent": {"$ref": "#/components/schemas/Pet"}}},
            "NewPet": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "minLength": 1}}},
        },
    },
}


def _ctx(tmp_path, spec_name, content):
    (tmp_path / spec_name).write_text(content, encoding="utf-8")
    scan = scan_repository(tmp_path)
    return DiscoveryContext(root=tmp_path, scan=scan)


@pytest.mark.parametrize("name,dump", [("openapi.json", json.dumps), ("openapi.yaml", yaml.safe_dump)])
def test_openapi_json_and_yaml(tmp_path, name, dump):
    out = OpenApiAdapter().discover(_ctx(tmp_path, name, dump(SPEC)))
    by = {(e.method, e.route): e for e in out.endpoints}
    assert set(by) == {("GET", "/pets/{petId}"), ("POST", "/pets"), ("GET", "/ext")}
    get = by[("GET", "/pets/{petId}")]
    assert get.operation_id == "getPet"
    assert get.requires_auth is True and get.security_schemes == ["bearer"]
    names = {(p.name, p.location) for p in get.parameters}
    assert ("petId", ParamLocation.PATH) in names and ("verbose", ParamLocation.QUERY) in names
    assert get.responses[0].schema_def["properties"]["id"]["type"] == "integer"
    post = by[("POST", "/pets")]
    assert post.requires_auth is False, "operation-level `security: []` overrides the global requirement"
    assert post.request_body.required and post.request_body.schema_def["required"] == ["name"]
    assert out.server_base_path == "/v1"
    assert out.complete is False


def test_local_refs_resolved_recursion_truncated_external_flagged(tmp_path):
    out = OpenApiAdapter().discover(_ctx(tmp_path, "openapi.json", json.dumps(SPEC)))
    pet = next(e for e in out.endpoints if e.route == "/pets/{petId}").responses[0].schema_def
    assert pet["properties"]["id"]["type"] == "integer"
    assert "recursive reference" in pet["properties"]["parent"]["description"]
    assert any("unresolved" in w.message.lower() for w in out.warnings)
    assert any("recursive" in l for l in out.limitations)


def test_swagger2_is_supported(tmp_path):
    sw = {"swagger": "2.0", "info": {"title": "t", "version": "1"}, "basePath": "/api",
          "paths": {"/u": {"post": {"parameters": [{"in": "body", "name": "b", "required": True, "schema": {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}}],
                                    "responses": {"200": {"description": "ok"}}}}}}
    out = OpenApiAdapter().discover(_ctx(tmp_path, "swagger.json", json.dumps(sw)))
    assert out.endpoints[0].request_body.schema_def["required"] == ["a"]
    assert out.server_base_path == "/api"


def test_empty_or_invalid_spec_raises_for_fallback(tmp_path):
    ctx = _ctx(tmp_path, "openapi.yaml", "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\n")
    with pytest.raises(DiscoveryError):
        OpenApiAdapter().discover(ctx)


def test_no_spec_means_not_applicable(tmp_path):
    (tmp_path / "x.py").write_text("print(1)")
    ctx = DiscoveryContext(root=tmp_path, scan=scan_repository(tmp_path))
    assert not OpenApiAdapter().applicable(ctx).ok


@pytest.mark.parametrize("raw,route,names", [
    ("/users/:id", "/users/{id}", ["id"]),
    ("/users/<int:user_id>/posts/<slug>", "/users/{user_id}/posts/{slug}", ["user_id", "slug"]),
    ("users/{id?}", "/users/{id}", ["id"]),
    ("/items/{id:int}/", "/items/{id}", ["id"]),
    ("^articles/(?P<year>[0-9]{4})/$", "/^articles/{year}/$".replace("^", "").replace("$", ""), ["year"]),
    ("/files/*path", "/files/{path}", ["path"]),
    ("//a//b", "/a/b", []),
    ("/", "/", []),
])
def test_normalize_path_preserves_parameter_names(raw, route, names):
    got_route, got_names = normalize_path(raw)
    assert got_names == names
    assert got_route == route or got_route.replace("^", "").replace("$", "") == route


def test_join_paths():
    assert join_paths("/api/", "v1", "/users") == "/api/v1/users"
    assert join_paths("", "") == "/"


def _ep(method, route, **kw):
    r, n = normalize_path(route)
    return Endpoint(method=method, route=r, original_path=route, path_param_names=n, **kw)


def test_dedupe_merges_equivalents_but_keeps_distinct_methods_and_versions():
    a = _ep("GET", "/v1/users/:id", strategy="static")
    b = _ep("GET", "/v1/users/{id}", strategy="openapi", operation_id="getUser")
    c = _ep("POST", "/v1/users/{id}")
    d = _ep("GET", "/v2/users/{id}")
    out = dedupe([a, b, c, d])
    assert len(out) == 3
    merged = next(e for e in out if e.method == "GET" and e.route == "/v1/users/{id}")
    assert merged.operation_id == "getUser"
    assert len({e.id for e in out}) == 3


def test_finalize_declares_missing_path_params_and_flags_partial():
    e = _ep("GET", "/x/{id}", strategy="static")
    finalize([e])
    assert any(p.name == "id" and p.location == ParamLocation.PATH and p.required for p in e.parameters)
    assert e.discovery_status.value == "PARTIAL"
    assert e.validation_status.value == "VALID"


def test_validate_inventory_rejects_inconsistent_entries():
    bad = _ep("GET", "/x/{id}")
    bad.path_param_names = []
    with pytest.raises(InvalidInventoryError):
        validate_inventory(EndpointInventory(endpoints=[bad]))
    dup1, dup2 = _ep("GET", "/a"), _ep("GET", "/a")
    with pytest.raises(InvalidInventoryError, match="duplicate"):
        validate_inventory(EndpointInventory(endpoints=[dup1, dup2]))
