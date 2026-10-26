"""Adapter registry and the discovery orchestration (priority + fallback + cross-check)."""

from __future__ import annotations

import re

from ..errors import DiscoveryError
from ..models.endpoint import (
    AttemptRecord,
    Discrepancy,
    DiscoverySummary,
    Endpoint,
    EndpointInventory,
)
from ..models.project import DiscoveryWarning
from ..security.redaction import redact_text
from .base import DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from .cli_adapter import LaravelRouteListAdapter
from .normalizer import dedupe, finalize, validate_inventory
from .openapi_adapter import OpenApiAdapter
from .python_static import PythonStaticAdapter
from .static_adapter import TreeSitterStaticAdapter

PRIORITY = {"openapi": 0, "cli": 1, "static": 2}
STRATEGIES = ("auto", "openapi", "cli", "static")


def default_adapters() -> list[DiscoveryAdapter]:
    adapters: list[DiscoveryAdapter] = [
        OpenApiAdapter(), LaravelRouteListAdapter(), PythonStaticAdapter(), TreeSitterStaticAdapter(),
    ]
    return sorted(adapters, key=lambda a: PRIORITY[a.strategy])


def _shape(route: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", route)


def _keys(eps: list[Endpoint]) -> dict[tuple[str, str], Endpoint]:
    return {(e.method, _shape(e.route)): e for e in eps}


def run_discovery(
    ctx: DiscoveryContext,
    strategy: str = "auto",
    adapters: list[DiscoveryAdapter] | None = None,
) -> tuple[EndpointInventory, list[DiscoveryWarning]]:
    """Run adapters by priority; the first that yields endpoints is primary, safe ones cross-check it."""
    if strategy not in STRATEGIES:
        raise DiscoveryError(f"unknown strategy '{strategy}' (choose from {', '.join(STRATEGIES)})")
    adapters = adapters if adapters is not None else default_adapters()
    if ctx.spec_path is not None and strategy == "auto":
        strategy = "openapi"  # an explicit --spec means: use that document
    chosen = [a for a in adapters if strategy == "auto" or a.strategy == strategy]

    attempts: list[AttemptRecord] = []
    warnings: list[DiscoveryWarning] = []
    primary: tuple[DiscoveryAdapter, DiscoveryOutcome] | None = None
    secondaries: list[tuple[DiscoveryAdapter, DiscoveryOutcome]] = []
    pool_potential = []

    for ad in chosen:
        app = ad.applicable(ctx)
        if not app.ok:
            attempts.append(AttemptRecord(adapter=ad.name, outcome="skipped", detail=app.reason))
            continue
        if ad.executes_project_code and not ctx.allow_cli:
            attempts.append(AttemptRecord(adapter=ad.name, outcome="skipped", detail="project-code-executing discovery disabled (--no-cli-discovery)"))
            continue
        if primary is not None:
            if ad.executes_project_code:
                attempts.append(AttemptRecord(adapter=ad.name, outcome="skipped", detail="not run as a cross-check because it executes project code"))
                continue
            try:
                out = ad.discover(ctx)
                secondaries.append((ad, out))
                attempts.append(AttemptRecord(adapter=ad.name, outcome="cross-check", detail=out.detail, endpoint_count=len(out.endpoints)))
            except DiscoveryError as exc:
                attempts.append(AttemptRecord(adapter=ad.name, outcome="failed", detail=redact_text(str(exc))))
            continue
        try:
            out = ad.discover(ctx)
        except DiscoveryError as exc:
            attempts.append(AttemptRecord(adapter=ad.name, outcome="failed", detail=redact_text(str(exc))))
            warnings.append(DiscoveryWarning(adapter=ad.name, severity="warning", message=f"adapter failed, trying next strategy: {redact_text(str(exc))}"))
            continue
        if not out.endpoints:
            pool_potential += out.potential_routes
            attempts.append(AttemptRecord(adapter=ad.name, outcome="empty", detail=out.detail or "no concrete endpoints"))
            warnings += out.warnings
            continue
        primary = (ad, out)
        attempts.append(AttemptRecord(adapter=ad.name, outcome="used", detail=out.detail, endpoint_count=len(out.endpoints)))

    inv = EndpointInventory(
        project_root=str(ctx.root),
        backend_path=ctx.backend.path if ctx.backend else ".",
        framework=ctx.framework,
    )
    inv.discovery = DiscoverySummary(attempts=attempts)
    if primary is None:
        inv.potential_routes = pool_potential
        inv.discovery.limitations.append("No discovery strategy produced a concrete endpoint; the inventory is empty.")
        warnings.append(DiscoveryWarning(adapter="registry", severity="error", message="endpoint discovery failed: no strategy yielded endpoints"))
        return inv, warnings

    p_ad, p_out = primary
    inv.discovery.strategy_used = p_ad.name
    inv.discovery.complete = p_out.complete
    inv.discovery.limitations += p_out.limitations
    inv.server_base_path = p_out.server_base_path
    inv.security_definitions = p_out.security_definitions
    inv.endpoints = finalize(dedupe(p_out.endpoints))
    inv.potential_routes = list(p_out.potential_routes) + pool_potential
    warnings += p_out.warnings

    # cross-source comparison: discrepancies are reported, never silently dropped
    p_keys = _keys(inv.endpoints)
    for s_ad, s_out in secondaries:
        s_eps = dedupe(s_out.endpoints)
        s_keys = _keys(s_eps)
        warnings += s_out.warnings
        for key in sorted(set(s_keys) - set(p_keys)):
            e = s_keys[key]
            inv.discrepancies.append(Discrepancy(
                kind=f"in_{s_ad.name}_not_in_{p_ad.name}", method=e.method, route=e.route,
                detail=f"found by {s_ad.name} ({e.source_file}:{e.line}) but absent from {p_ad.name}; not added to the tested inventory",
            ))
        for key in sorted(set(p_keys) - set(s_keys)):
            e = p_keys[key]
            inv.discrepancies.append(Discrepancy(
                kind=f"in_{p_ad.name}_not_in_{s_ad.name}", method=e.method, route=e.route,
                detail=f"declared by {p_ad.name} but not found by {s_ad.name}; the source may register it dynamically or the declaration may be stale",
            ))
        for pr in s_out.potential_routes:
            if pr not in inv.potential_routes:
                inv.potential_routes.append(pr)
        inv.discovery.limitations += [x for x in s_out.limitations if x not in inv.discovery.limitations]
    if inv.discrepancies:
        warnings.append(DiscoveryWarning(
            adapter="registry",
            message=f"{len(inv.discrepancies)} discrepancy(ies) between discovery sources; the specification or source analysis may be stale or incomplete",
        ))
    if inv.potential_routes:
        warnings.append(DiscoveryWarning(adapter="registry", message=f"{len(inv.potential_routes)} potential route(s) found but not resolved (NOT DISCOVERED)"))
    if not inv.discovery.complete:
        inv.discovery.limitations.append("Discovery completeness cannot be established from this source; the endpoint count is a lower bound.")
    validate_inventory(inv)
    return inv, warnings
