"""Schema helpers: OpenAPI schema -> plain JSON Schema for response assertions."""

from __future__ import annotations

import copy
from typing import Any

# Keywords that Postman's Ajv build either does not know or that add no assertion value.
_DROP = {"example", "examples", "xml", "discriminator", "externalDocs", "readOnly", "writeOnly", "deprecated",
         "format", "title", "description", "default"}


def to_json_schema(schema: dict[str, Any] | None, _depth: int = 0) -> dict[str, Any]:
    """Convert an OpenAPI 3.0/3.1 or Pydantic-derived schema into conservative JSON Schema (draft-07)."""
    if not isinstance(schema, dict) or _depth > 12:
        return {}
    s = copy.deepcopy(schema)
    nullable = s.pop("nullable", False)
    for k in list(s):
        if k in _DROP:
            s.pop(k)
    # OAS 3.0 boolean exclusiveMinimum/Maximum -> numeric form
    for bound, excl in (("minimum", "exclusiveMinimum"), ("maximum", "exclusiveMaximum")):
        if isinstance(s.get(excl), bool):
            if s.pop(excl) and bound in s:
                s[excl] = s.pop(bound)
            else:
                s.pop(excl, None)
    if isinstance(s.get("properties"), dict):
        s["properties"] = {k: to_json_schema(v, _depth + 1) for k, v in s["properties"].items()}
    if isinstance(s.get("items"), dict):
        s["items"] = to_json_schema(s["items"], _depth + 1)
    for key in ("allOf", "anyOf", "oneOf"):
        if isinstance(s.get(key), list):
            s[key] = [to_json_schema(x, _depth + 1) for x in s[key]]
    if isinstance(s.get("additionalProperties"), dict):
        s["additionalProperties"] = to_json_schema(s["additionalProperties"], _depth + 1)
    if "required" in s and (not isinstance(s["required"], list) or not s["required"]):
        s.pop("required")
    if nullable and isinstance(s.get("type"), str):
        s["type"] = [s["type"], "null"]
    return s


def is_meaningful(schema: dict[str, Any] | None) -> bool:
    """True when the schema asserts something (a type, properties, items or composition)."""
    if not schema:
        return False
    return any(k in schema for k in ("type", "properties", "items", "enum", "allOf", "anyOf", "oneOf"))


def required_properties(schema: dict[str, Any] | None) -> list[str]:
    if not isinstance(schema, dict):
        return []
    req = list(schema.get("required", []) or [])
    for sub in schema.get("allOf", []) or []:
        req += required_properties(sub)
    return list(dict.fromkeys(req))
