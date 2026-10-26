"""OpenAPI 3.x / Swagger 2.0 discovery from specification files."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from ..errors import DiscoveryError
from ..models.endpoint import (
    HTTP_METHODS,
    Confidence,
    Endpoint,
    Evidence,
    ParamLocation,
    Parameter,
    RequestBody,
    ResponseSpec,
)
from ..models.project import DiscoveryWarning
from ..utils.filesystem import read_text, rel
from .base import Applicability, DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from .normalizer import normalize_path

SPEC_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"]
MAX_REF_DEPTH = 12
BODY_PREFERENCE = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]


class _Resolver:
    """Resolve local `#/...` references safely (cycle- and depth-guarded)."""

    def __init__(self, doc: dict[str, Any]):
        self.doc = doc
        self.unresolved: list[str] = []
        self.recursive: list[str] = []

    def lookup(self, ref: str) -> Any | None:
        if not ref.startswith("#/"):
            self.unresolved.append(ref)
            return None
        node: Any = self.doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                self.unresolved.append(ref)
                return None
        return node

    def resolve(self, node: Any, stack: tuple[str, ...] = ()) -> Any:
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref = node["$ref"]
                if ref in stack or len(stack) >= MAX_REF_DEPTH:
                    self.recursive.append(ref)
                    return {"type": "object", "description": f"(recursive reference {ref} not expanded)"}
                target = self.lookup(ref)
                if target is None:
                    return {"description": f"(unresolved reference {ref})"}
                extra = {k: v for k, v in node.items() if k != "$ref"}
                resolved = self.resolve(copy.deepcopy(target), stack + (ref,))
                if isinstance(resolved, dict) and extra:
                    resolved = {**resolved, **self.resolve(extra, stack)}
                return resolved
            return {k: self.resolve(v, stack) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, stack) for v in node]
        return node


def _load(path: Path) -> dict[str, Any]:
    text = read_text(path)
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise DiscoveryError(f"Cannot parse {path.name}: {exc}") from exc
    if not isinstance(data, dict) or not ("openapi" in data or "swagger" in data):
        raise DiscoveryError(f"{path.name} is not an OpenAPI/Swagger document")
    return data


def _json_media(content: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    if not content:
        return None, None
    for pref in BODY_PREFERENCE:
        if pref in content:
            return pref, content[pref]
    for ct, media in content.items():
        if "json" in ct:
            return ct, media
    ct = next(iter(content))
    return ct, content[ct]


def _example(media: dict[str, Any] | None, schema: dict[str, Any]) -> Any:
    if not media:
        return schema.get("example")
    if "example" in media:
        return media["example"]
    exs = media.get("examples")
    if isinstance(exs, dict) and exs:
        first = next(iter(exs.values()))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    return schema.get("example")


def _security(op: dict[str, Any], doc: dict[str, Any]) -> tuple[list[str], bool | None]:
    sec = op["security"] if "security" in op else doc.get("security")
    if sec is None:
        return [], None  # nothing declared anywhere: unknown, not "public"
    names: list[str] = []
    anonymous_allowed = False
    for req in sec:
        if not req:
            anonymous_allowed = True
        for n in (req or {}):
            if n not in names:
                names.append(n)
    if not sec:
        return [], False
    return names, (not anonymous_allowed)


def _swagger2_to_internal(doc: dict[str, Any]) -> dict[str, Any]:
    """Minimal Swagger 2.0 -> OpenAPI 3 shape conversion for the parts we consume."""
    out = copy.deepcopy(doc)
    out.setdefault("components", {})["schemas"] = out.get("definitions", {})
    out["components"]["securitySchemes"] = out.get("securityDefinitions", {})
    consumes_default = out.get("consumes", ["application/json"])
    produces_default = out.get("produces", ["application/json"])
    for path, item in (out.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for m in SPEC_METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = []
            for p in op.get("parameters", []):
                p = copy.deepcopy(p)
                if p.get("in") == "body":
                    ct = (op.get("consumes") or consumes_default or ["application/json"])[0]
                    op["requestBody"] = {
                        "required": p.get("required", False),
                        "content": {ct: {"schema": p.get("schema", {})}},
                    }
                    continue
                if "schema" not in p:
                    p["schema"] = {k: v for k, v in p.items() if k in ("type", "format", "enum", "items", "minimum", "maximum", "default")}
                params.append(p)
            op["parameters"] = params
            for code, resp in (op.get("responses") or {}).items():
                if isinstance(resp, dict) and "schema" in resp:
                    ct = (op.get("produces") or produces_default or ["application/json"])[0]
                    resp["content"] = {ct: {"schema": resp.pop("schema")}}
    return out


def _convert_param(raw: dict[str, Any]) -> Parameter | None:
    loc = raw.get("in")
    if loc not in ("path", "query", "header", "cookie"):
        return None
    return Parameter(
        name=raw["name"],
        location=ParamLocation(loc),
        required=bool(raw.get("required", False)) or loc == "path",
        schema_def=raw.get("schema") or {},
        example=raw.get("example", (raw.get("schema") or {}).get("example")),
        description=raw.get("description"),
    )


class OpenApiAdapter(DiscoveryAdapter):
    name = "openapi"
    strategy = "openapi"
    supported = ("OpenAPI 3.0.x", "OpenAPI 3.1.x", "Swagger 2.0")
    prerequisites = "A JSON/YAML OpenAPI document inside the scanned folder or supplied with --spec"

    def _spec_files(self, ctx: DiscoveryContext) -> list[Path]:
        if ctx.spec_path:
            return [ctx.spec_path]
        base = ctx.backend_dir
        found = []
        for s in ctx.scan.spec_files:
            p = ctx.root / s.path
            if base == ctx.root or base in p.parents:
                found.append(p)
        return found or [ctx.root / s.path for s in ctx.scan.spec_files]

    def applicable(self, ctx: DiscoveryContext) -> Applicability:
        if ctx.spec_path:
            return Applicability(ctx.spec_path.is_file(), "" if ctx.spec_path.is_file() else f"spec not found: {ctx.spec_path}")
        files = self._spec_files(ctx)
        return Applicability(bool(files), "" if files else "no OpenAPI/Swagger document found in folder")

    def discover(self, ctx: DiscoveryContext) -> DiscoveryOutcome:
        outcome = DiscoveryOutcome()
        files = self._spec_files(ctx)
        if not files:
            raise DiscoveryError("No OpenAPI/Swagger document available")
        for path in files:
            self._discover_one(path, ctx, outcome)
        if not outcome.endpoints:
            raise DiscoveryError("OpenAPI document(s) parsed but contained no operations")
        outcome.limitations.append(
            "Specification-derived: reflects what the document declares, which may be stale or incomplete "
            "relative to the code. Cross-check with source analysis where available."
        )
        outcome.complete = False  # a spec alone is never proof that all routes are documented
        outcome.detail = f"parsed {len(files)} specification file(s)"
        return outcome

    def _discover_one(self, path: Path, ctx: DiscoveryContext, outcome: DiscoveryOutcome) -> None:
        name = rel(path, ctx.root)
        raw = _load(path)
        is_v2 = "swagger" in raw
        validation_note = None
        try:
            from openapi_spec_validator import validate

            validate(raw)
        except Exception as exc:  # validator raises many exception types; record, don't crash
            validation_note = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
            outcome.warnings.append(
                DiscoveryWarning(adapter=self.name, message=f"{name} failed spec validation ({validation_note}); parsed best-effort", source_file=name)
            )
        doc = _swagger2_to_internal(raw) if is_v2 else raw
        resolver = _Resolver(doc)
        paths = doc.get("paths") or {}
        if not paths:
            outcome.warnings.append(DiscoveryWarning(adapter=self.name, message=f"{name} declares no paths", source_file=name))

        base_path = ""
        if is_v2:
            base_path = raw.get("basePath", "") or ""
        else:
            servers = doc.get("servers") or []
            if servers and isinstance(servers[0], dict) and servers[0].get("url"):
                base_path = urlsplit(str(servers[0]["url"])).path.rstrip("/")
        outcome.server_base_path = outcome.server_base_path or base_path
        sec_defs = (doc.get("components") or {}).get("securitySchemes") or {}
        outcome.security_definitions.update(resolver.resolve(sec_defs))

        count = 0
        for p_str, item in paths.items():
            if not isinstance(item, dict):
                continue
            item_r = resolver.resolve(item)
            common = [x for x in item_r.get("parameters", []) if isinstance(x, dict)]
            for m in SPEC_METHODS:
                if m.upper() not in HTTP_METHODS or m not in item_r:
                    continue
                if m in ("head", "options"):
                    continue
                op = item_r[m]
                if not isinstance(op, dict):
                    continue
                ep = self._build_endpoint(p_str, m, op, common, doc, name, resolver)
                outcome.endpoints.append(ep)
                count += 1
        if resolver.unresolved:
            outcome.warnings.append(
                DiscoveryWarning(
                    adapter=self.name,
                    message=f"{name}: unresolved/external references left unexpanded: {sorted(set(resolver.unresolved))[:10]}",
                    source_file=name,
                )
            )
        if resolver.recursive:
            outcome.limitations.append(
                f"{name}: recursive schema references were truncated: {sorted(set(resolver.recursive))[:5]}"
            )
        if count and not any(e.responses for e in outcome.endpoints):
            outcome.warnings.append(
                DiscoveryWarning(adapter=self.name, message=f"{name}: no operation documents responses; spec may be incomplete", source_file=name)
            )

    def _build_endpoint(
        self, path_str: str, method: str, op: dict[str, Any], common: list[dict[str, Any]],
        doc: dict[str, Any], file: str, resolver: _Resolver,
    ) -> Endpoint:
        route, names = normalize_path(path_str)
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for raw in [*common, *[x for x in op.get("parameters", []) if isinstance(x, dict)]]:
            if "name" in raw and "in" in raw:
                merged[(raw["in"], raw["name"])] = raw
        params = [p for p in (_convert_param(r) for r in merged.values()) if p]

        body = None
        unsupported: list[str] = []
        rb = op.get("requestBody")
        if isinstance(rb, dict):
            ct, media = _json_media(rb.get("content") or {})
            schema = (media or {}).get("schema") or {}
            if ct:
                body = RequestBody(content_type=ct, schema_def=schema, required=bool(rb.get("required", False)), example=_example(media, schema))
                if ct not in BODY_PREFERENCE and "json" not in ct:
                    unsupported.append(f"request body content type '{ct}' not supported for generation")

        responses: list[ResponseSpec] = []
        for code, resp in (op.get("responses") or {}).items():
            if not isinstance(resp, dict):
                continue
            ct, media = _json_media(resp.get("content") or {})
            responses.append(
                ResponseSpec(status=str(code), description=str(resp.get("description", "")), content_type=ct, schema_def=(media or {}).get("schema"))
            )

        sec_names, requires_auth = _security(op, doc)
        return Endpoint(
            method=method.upper(),
            route=route,
            original_path=path_str,
            path_param_names=names,
            parameters=params,
            request_body=body,
            responses=responses,
            security_schemes=sec_names,
            requires_auth=requires_auth,
            source_file=file,
            operation_id=op.get("operationId"),
            strategy=self.strategy,
            confidence=Confidence.HIGH,
            evidence=[Evidence(source=file, detail=f"paths.{path_str}.{method}")],
            unsupported=unsupported,
        )
