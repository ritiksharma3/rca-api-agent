"""Postman test-script (JavaScript) builders for schema-derived assertions."""

from __future__ import annotations

import json
from typing import Any


def _js(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def status_assertion(expected: list[int], basis: str, accept_range: tuple[int, int] | None = None) -> list[str]:
    if expected:
        label = f"status code is one of {expected} ({basis})"
        return [f"pm.test({_js(label)}, function () {{ pm.expect({_js(expected)}).to.include(pm.response.code); }});"]
    lo, hi = accept_range or (200, 299)
    label = f"status code is {lo}-{hi} ({basis})"
    return [f"pm.test({_js(label)}, function () {{ pm.expect(pm.response.code).to.be.within({lo}, {hi}); }});"]


def response_time_assertion(max_ms: int) -> list[str]:
    return [f"pm.test({_js(f'response time below {max_ms} ms')}, function () {{ pm.expect(pm.response.responseTime).to.be.below({max_ms}); }});"]


def json_schema_assertion(schema: dict[str, Any]) -> list[str]:
    """Only generated when a documented response schema exists; verifies content-type then the schema."""
    return [
        'pm.test("response is JSON (documented content type)", function () { pm.expect(pm.response.headers.get("Content-Type") || "").to.include("json"); });',
        f'pm.test("response matches documented schema", function () {{ var schema = {_js(schema)}; pm.response.to.have.jsonSchema(schema); }});',
    ]


def render(lines: list[str]) -> list[str]:
    return lines
