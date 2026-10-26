"""Schema-informed synthetic data generation (valid and invalid), reproducible via a seed.

Precedence: explicit example -> default -> enum/const -> constraint-driven synthetic value.
Never invents identifiers that must exist in the target system: a required ``*_id`` field without an example,
enum or fixture raises CannotGenerate so the dependent test is reported BLOCKED.
"""

from __future__ import annotations

import copy
import random
import re
from typing import Any

from faker import Faker

from .schema_analyzer import required_properties

_ID_NAME = re.compile(r"(^|_)id$|[a-z]Id$|^id$", re.I)
_MAX_DEPTH = 6


class CannotGenerate(Exception):
    """A valid value cannot be produced safely from the available schema information."""


def _merge_all_of(schema: dict[str, Any]) -> dict[str, Any]:
    if "allOf" not in schema:
        return schema
    merged = {k: v for k, v in schema.items() if k != "allOf"}
    for sub in schema["allOf"]:
        sub = _merge_all_of(sub)
        for k, v in sub.items():
            if k == "properties":
                merged.setdefault("properties", {}).update(v)
            elif k == "required":
                merged["required"] = list(dict.fromkeys([*merged.get("required", []), *v]))
            else:
                merged.setdefault(k, v)
    return merged


class DataGenerator:
    def __init__(self, seed: int = 1234):
        self.seed = seed
        self.fake = Faker()
        Faker.seed(seed)
        self.rng = random.Random(seed)

    # ------------------------------------------------------------------ valid values

    def valid(self, schema: dict[str, Any] | None, name: str | None = None, depth: int = 0, required: bool = True) -> Any:
        schema = _merge_all_of(schema or {})
        if "example" in schema:
            return copy.deepcopy(schema["example"])
        if "default" in schema and schema["default"] is not None:
            return copy.deepcopy(schema["default"])
        if "const" in schema:
            return schema["const"]
        if schema.get("enum"):
            return schema["enum"][0]
        for key in ("oneOf", "anyOf"):
            if schema.get(key):
                return self.valid(schema[key][0], name, depth, required)
        if depth > _MAX_DEPTH:
            return None
        t = schema.get("type")
        if isinstance(t, list):
            t = next((x for x in t if x != "null"), None)
        if t is None:
            t = "object" if "properties" in schema else "array" if "items" in schema else "string"
        if name and _ID_NAME.search(name) and t in ("string", "integer"):
            raise CannotGenerate(f"'{name}' looks like a reference to an existing resource; supply it via a fixture")
        return getattr(self, f"_gen_{t}", self._gen_string)(schema, name, depth)

    def _gen_object(self, schema: dict[str, Any], name: str | None, depth: int) -> dict[str, Any]:
        props = schema.get("properties", {}) or {}
        required = set(required_properties(schema))
        out: dict[str, Any] = {}
        for prop, sub in props.items():
            is_req = prop in required
            try:
                out[prop] = self.valid(sub, prop, depth + 1, is_req)
            except CannotGenerate:
                if is_req:
                    raise
                continue  # optional and not safely generatable: omit
        return out

    def _gen_array(self, schema: dict[str, Any], name: str | None, depth: int) -> list[Any]:
        n = max(int(schema.get("minItems", 1) or 0), 1) if schema.get("minItems") else 1
        n = min(n, int(schema.get("maxItems", n)))
        if n == 0:
            return []
        return [self.valid(schema.get("items", {}), name, depth + 1, False) for _ in range(n)]

    def _gen_boolean(self, schema: dict[str, Any], name: str | None, depth: int) -> bool:
        return True

    def _gen_integer(self, schema: dict[str, Any], name: str | None, depth: int) -> int:
        lo = schema.get("minimum", schema.get("exclusiveMinimum", None))
        hi = schema.get("maximum", schema.get("exclusiveMaximum", None))
        if "exclusiveMinimum" in schema and "minimum" not in schema and isinstance(lo, (int, float)):
            lo = int(lo) + 1
        if "exclusiveMaximum" in schema and "maximum" not in schema and isinstance(hi, (int, float)):
            hi = int(hi) - 1
        lo = int(lo) if lo is not None else (0 if hi is None else int(hi) - 100)
        hi = int(hi) if hi is not None else lo + 100
        if lo > hi:
            raise CannotGenerate("integer range is empty")
        val = self.rng.randint(lo, min(hi, lo + 1000))
        mult = schema.get("multipleOf")
        if mult:
            val = ((val + mult - 1) // mult) * mult
            if val > hi:
                raise CannotGenerate("no multipleOf value fits the range")
        return val

    def _gen_number(self, schema: dict[str, Any], name: str | None, depth: int) -> float:
        lo = schema.get("minimum", schema.get("exclusiveMinimum"))
        hi = schema.get("maximum", schema.get("exclusiveMaximum"))
        lo_f = float(lo) if lo is not None else (0.0 if hi is None else float(hi) - 100.0)
        hi_f = float(hi) if hi is not None else lo_f + 100.0
        if "exclusiveMinimum" in schema and "minimum" not in schema:
            lo_f += 0.01
        if "exclusiveMaximum" in schema and "maximum" not in schema:
            hi_f -= 0.01
        if lo_f > hi_f:
            raise CannotGenerate("number range is empty")
        return round(self.rng.uniform(lo_f, hi_f), 2)

    def _gen_string(self, schema: dict[str, Any], name: str | None, depth: int) -> str:
        fmt = schema.get("format")
        lo, hi = int(schema.get("minLength", 0) or 0), schema.get("maxLength")
        n = (name or "").lower()
        if fmt == "email" or n.endswith("email"):
            val = self.fake.email()
        elif fmt == "uuid":
            val = self.fake.uuid4()
        elif fmt == "date":
            val = self.fake.date()
        elif fmt == "date-time":
            val = self.fake.date_time().strftime("%Y-%m-%dT%H:%M:%SZ")
        elif fmt in ("uri", "url") or n in ("url", "website"):
            val = self.fake.url()
        elif fmt == "hostname":
            val = self.fake.hostname()
        elif fmt == "ipv4":
            val = self.fake.ipv4()
        elif n in ("name", "full_name", "fullname"):
            val = self.fake.name()
        elif n in ("first_name", "firstname"):
            val = self.fake.first_name()
        elif n in ("last_name", "lastname"):
            val = self.fake.last_name()
        elif n in ("phone", "phone_number", "mobile"):
            val = self.fake.numerify("##########")
        elif n in ("title", "subject"):
            val = self.fake.sentence(nb_words=3).rstrip(".")
        elif n in ("description", "comment", "message", "notes"):
            val = self.fake.sentence()
        else:
            val = self.fake.word()
        pattern = schema.get("pattern")
        if pattern:
            val = self._satisfy_pattern(pattern, val, lo, hi)
        if not pattern:
            while len(val) < lo:
                val += self.fake.word()
            if hi is not None and len(val) > int(hi):
                val = val[: int(hi)]
        return val

    def _satisfy_pattern(self, pattern: str, first: str, lo: int, hi: Any) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise CannotGenerate(f"pattern '{pattern}' is not a valid regular expression: {exc}") from exc
        candidates = [first, self.fake.word(), self.fake.numerify("########"), self.fake.lexify("????????"),
                      self.fake.bothify("??-####"), self.fake.numerify("##"), "A1", "a", "1", self.fake.email()]
        for c in candidates:
            if rx.search(c) and len(c) >= lo and (hi is None or len(c) <= int(hi)):
                return c
        raise CannotGenerate(f"cannot synthesise a value matching pattern '{pattern}'; supply an example or fixture")

    # ------------------------------------------------------------------ invalid variants

    def invalid_variants(self, schema: dict[str, Any], valid_obj: Any, limit: int = 3) -> list[tuple[str, Any, str]]:
        """Return [(description, payload, evidence)] violating the schema in ways the schema itself proves."""
        schema = _merge_all_of(schema or {})
        if not isinstance(valid_obj, dict) or schema.get("type", "object") != "object":
            return []
        props = schema.get("properties", {}) or {}
        out: list[tuple[str, Any, str]] = []
        for prop in required_properties(schema):
            if prop in valid_obj:
                bad = {k: v for k, v in valid_obj.items() if k != prop}
                out.append((f"missing required field '{prop}'", bad, f"schema lists '{prop}' as required"))
        for prop, sub in props.items():
            if prop not in valid_obj:
                continue
            sub = _merge_all_of(sub)
            t = sub.get("type")
            if t in ("integer", "number"):
                bad = dict(valid_obj, **{prop: "not-a-number"})
                out.append((f"'{prop}' has wrong type (string instead of {t})", bad, f"schema declares '{prop}' as {t}"))
                if "minimum" in sub:
                    out.append((f"'{prop}' below minimum", dict(valid_obj, **{prop: sub["minimum"] - 1}), f"schema minimum is {sub['minimum']}"))
                if "maximum" in sub:
                    out.append((f"'{prop}' above maximum", dict(valid_obj, **{prop: sub["maximum"] + 1}), f"schema maximum is {sub['maximum']}"))
            elif t == "string":
                if sub.get("enum"):
                    out.append((f"'{prop}' not in enum", dict(valid_obj, **{prop: "__not_in_enum__"}), f"schema enum is {sub['enum']}"))
                if sub.get("minLength", 0) and int(sub["minLength"]) >= 1:
                    out.append((f"'{prop}' shorter than minLength", dict(valid_obj, **{prop: ""}), f"schema minLength is {sub['minLength']}"))
                if sub.get("maxLength") is not None:
                    out.append((f"'{prop}' longer than maxLength", dict(valid_obj, **{prop: "x" * (int(sub["maxLength"]) + 1)}), f"schema maxLength is {sub['maxLength']}"))
                if sub.get("format") == "email":
                    out.append((f"'{prop}' not an email", dict(valid_obj, **{prop: "not-an-email"}), "schema format is email"))
            elif t == "boolean":
                out.append((f"'{prop}' has wrong type (string instead of boolean)", dict(valid_obj, **{prop: "maybe"}), f"schema declares '{prop}' as boolean"))
        # keep diversity: prefer first occurrence of each kind, cap at limit
        seen: set[str] = set()
        picked: list[tuple[str, Any, str]] = []
        for item in out:
            kind = item[0].split("'")[0] + item[0].split("'")[-1]
            if kind in seen and len(picked) >= 1:
                continue
            seen.add(kind)
            picked.append(item)
            if len(picked) >= limit:
                break
        return picked
