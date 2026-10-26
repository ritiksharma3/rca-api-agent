"""Route normalization, deduplication and inventory validation."""

from __future__ import annotations

import re

from ..errors import InvalidInventoryError
from ..models.endpoint import (
    HTTP_METHODS,
    Confidence,
    DiscoveryStatus,
    Endpoint,
    EndpointInventory,
    ParamLocation,
    Parameter,
    ValidationStatus,
)

# Order matters: more specific syntaxes first.
_PARAM_SYNTAXES = [
    (re.compile(r"\(\?P<(\w+)>[^)]*\)"), r"{\1}"),  # django re_path
    (re.compile(r"<(?:\w+:)?(\w+)>"), r"{\1}"),  # flask/django <int:id>
    (re.compile(r"\{(\w+)(?::[^}]*)?\??\}"), r"{\1}"),  # {id:int} {id?} (laravel/aspnet)
    (re.compile(r"\{\*(\w+)\}"), r"{\1}"),
    (re.compile(r"(?<=/)\*(\w+)"), r"{\1}"),  # go-style *wildcard
    (re.compile(r"(?<=/):(\w+)\??(?=/|$)"), r"{\1}"),  # express :id
    (re.compile(r"\[(\w+)\]"), r"{\1}"),
]
_PARAM_RE = re.compile(r"\{(\w+)\}")


def normalize_path(path: str) -> tuple[str, list[str]]:
    """Return (normalized template, ordered parameter names). Original names are preserved."""
    p = path.strip()
    for pat, repl in _PARAM_SYNTAXES:
        p = pat.sub(repl, p)
    p = re.sub(r"/{2,}", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return p, _PARAM_RE.findall(p)


def join_paths(*parts: str) -> str:
    joined = "/".join(x.strip("/") for x in parts if x and x.strip("/"))
    return "/" + joined


def _richness(e: Endpoint) -> int:
    return (
        len(e.parameters) + (3 if e.request_body else 0) + len(e.responses)
        + (2 if e.security_schemes else 0) + (1 if e.operation_id else 0)
    )


_CONF = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def dedupe(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Merge records with the same method + normalized route. Distinct methods/versions stay distinct."""
    merged: dict[tuple[str, str], Endpoint] = {}
    for e in endpoints:
        key = (e.method, e.route)
        cur = merged.get(key)
        if cur is None:
            merged[key] = e
            continue
        keep, other = (e, cur) if _richness(e) > _richness(cur) else (cur, e)
        keep.evidence = keep.evidence + [ev for ev in other.evidence if ev not in keep.evidence]
        keep.warnings = list(dict.fromkeys(keep.warnings + other.warnings))
        keep.unsupported = list(dict.fromkeys(keep.unsupported + other.unsupported))
        if _CONF[other.confidence] > _CONF[keep.confidence]:
            keep.confidence = other.confidence
        keep.source_file = keep.source_file or other.source_file
        keep.line = keep.line or other.line
        keep.operation_id = keep.operation_id or other.operation_id
        merged[key] = keep
    return sorted(merged.values(), key=lambda x: (x.route, x.method))


def finalize(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Normalize, declare missing path params, set discovery + validation status."""
    for e in endpoints:
        declared = {p.name for p in e.parameters if p.location == ParamLocation.PATH}
        for name in e.path_param_names:
            if name not in declared:
                e.parameters.append(
                    Parameter(name=name, location=ParamLocation.PATH, required=True, schema_def={"type": "string"})
                )
                if e.strategy != "openapi":
                    e.warnings.append(f"path parameter '{name}' type not established; defaulted to string")
        incomplete = []
        if e.requires_auth is None:
            incomplete.append("auth requirements unknown")
        if not e.responses:
            incomplete.append("no documented responses")
        if incomplete and e.strategy != "openapi":
            e.discovery_status = DiscoveryStatus.PARTIAL
        e.validation_status = ValidationStatus.VALID if not _problems(e) else ValidationStatus.INVALID
    return endpoints


def _problems(e: Endpoint) -> list[str]:
    problems = []
    if e.method not in HTTP_METHODS:
        problems.append(f"unsupported method {e.method}")
    if not e.route.startswith("/"):
        problems.append("route must start with '/'")
    if set(_PARAM_RE.findall(e.route)) != set(e.path_param_names):
        problems.append("path parameter names do not match route template")
    return problems


def validate_inventory(inv: EndpointInventory) -> None:
    """Raise InvalidInventoryError if the inventory is internally inconsistent."""
    errors: list[str] = []
    seen: dict[str, str] = {}
    for e in inv.endpoints:
        for p in _problems(e):
            errors.append(f"{e.method} {e.route}: {p}")
        if e.id in seen:
            errors.append(f"duplicate endpoint id {e.id} ({seen[e.id]} vs {e.method} {e.route})")
        seen[e.id] = f"{e.method} {e.route}"
    if errors:
        raise InvalidInventoryError("Invalid endpoint inventory:\n  - " + "\n  - ".join(errors))
