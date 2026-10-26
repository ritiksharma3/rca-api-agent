"""Static analysis of Laravel route files (tree-sitter PHP grammar)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models.endpoint import Confidence, Endpoint, Evidence, ParamLocation, Parameter, PotentialRoute, ResponseSpec
from ..models.project import DiscoveryWarning
from ..utils.filesystem import iter_source_files, read_text, rel
from .base import DiscoveryOutcome
from .normalizer import join_paths, normalize_path
from .ts_common import (
    children_of, first_of, line_of, named_children, parse, singular, string_value, text, walk, ancestors,
)

VERBS = {"get", "post", "put", "patch", "delete", "options"}
RESOURCE_ACTIONS = [
    ("index", "GET", ""), ("create", "GET", "/create"), ("store", "POST", ""), ("show", "GET", "/{id}"),
    ("edit", "GET", "/{id}/edit"), ("update", "PUT", "/{id}"), ("update_patch", "PATCH", "/{id}"),
    ("destroy", "DELETE", "/{id}"),
]
API_ACTIONS_EXCLUDED = {"create", "edit"}


def _args(call: Any) -> list[Any]:
    a = call.child_by_field_name("arguments") or first_of(call, "arguments")
    if a is None:
        return []
    out = []
    for arg in children_of(a, "argument"):
        inner = named_children(arg)
        # `name: value` named args have a name child first; value is last
        out.append(inner[-1] if inner else arg)
    return out


def _method_name(call: Any) -> str:
    n = call.child_by_field_name("name")
    return text(n) if n is not None else ""


def _chain(call: Any) -> tuple[list[tuple[str, list[Any]]], bool]:
    """Walk a fluent Route:: chain from the outermost call inward.

    Returns ([(method, args), ...] outermost first, rooted_in_Route_facade).
    """
    items: list[tuple[str, list[Any]]] = []
    node = call
    while node is not None:
        if node.type == "member_call_expression":
            items.append((_method_name(node), _args(node)))
            node = node.child_by_field_name("object")
        elif node.type == "scoped_call_expression":
            scope = node.child_by_field_name("scope")
            items.append((_method_name(node), _args(node)))
            return items, scope is not None and text(scope) == "Route"
        else:
            return items, False
    return items, False


def _array_pairs(arr: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for el in children_of(arr, "array_element_initializer"):
        kids = named_children(el)
        if len(kids) == 2:
            k = string_value(kids[0])
            if k:
                out[k] = kids[1]
    return out


def _strings_in(node: Any) -> list[str]:
    if node is None:
        return []
    v = string_value(node)
    if v is not None:
        return [v]
    return [s for s in (string_value(n) for n in walk(node)) if s]


def _modifiers(items: list[tuple[str, list[Any]]]) -> tuple[str, list[str], bool]:
    prefix, mws, dynamic = "", [], False
    for meth, args in reversed(items):
        if meth == "prefix" and args:
            v = string_value(args[0])
            if v is None:
                dynamic = True
            else:
                prefix = join_paths(prefix, v)
        elif meth == "middleware" and args:
            mws += _strings_in(args[0]) if args[0].type in ("array_creation_expression",) else [string_value(args[0]) or ""]
        elif meth == "group" and args and args[0].type == "array_creation_expression":
            pairs = _array_pairs(args[0])
            if "prefix" in pairs:
                v = string_value(pairs["prefix"])
                prefix = join_paths(prefix, v) if v is not None else prefix
                dynamic = dynamic or v is None
            if "middleware" in pairs:
                mws += _strings_in(pairs["middleware"])
    return prefix, [m for m in mws if m], dynamic


def _group_context(node: Any) -> tuple[str, list[str], bool]:
    """Prefix / middleware inherited from enclosing Route::...->group(function () {...}) closures."""
    prefix, mws, dynamic = "", [], False
    chains: list[tuple[str, list[str], bool]] = []
    for anc in ancestors(node):
        if anc.type in ("anonymous_function", "arrow_function"):
            arg = anc.parent
            args_node = arg.parent if arg is not None else None
            call = args_node.parent if args_node is not None else None
            if call is not None and call.type in ("member_call_expression", "scoped_call_expression") and _method_name(call) == "group":
                items, rooted = _chain(call)
                if rooted:
                    chains.append(_modifiers(items))
    for p, m, d in reversed(chains):  # outermost group first
        prefix = join_paths(prefix, p) if p else prefix
        mws += m
        dynamic = dynamic or d
    return prefix, mws, dynamic


def _controller_ref(arg: Any | None) -> str | None:
    if arg is None:
        return None
    if arg.type == "array_creation_expression":
        parts = [text(n).replace("::class", "") for n in walk(arg) if n.type in ("class_constant_access_expression",)]
        strs = [string_value(n) for n in walk(arg) if string_value(n)]
        if parts and strs:
            return f"{parts[0]}@{strs[0]}"
        return parts[0] if parts else None
    v = string_value(arg)
    if v:
        return v
    if arg.type == "class_constant_access_expression":
        return text(arg).replace("::class", "")
    return None


def analyze_php(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    files = [
        f for f in iter_source_files(backend_dir, {".php"})
        if "routes" in f.relative_to(backend_dir).parts or f.name.lower().startswith("routes")
    ]
    if not files:
        files = [f for f in iter_source_files(backend_dir, {".php"})]
    analysed = 0
    for f in files:
        src = read_text(f)
        if "Route::" not in src:
            continue
        analysed += 1
        name = rel(f, root)
        tree = parse("php", src)
        default_prefix = ""
        warn_extra: list[str] = []
        parts = f.relative_to(backend_dir).as_posix()
        if parts.endswith("routes/api.php"):
            default_prefix = "/api"
            warn_extra.append("assumed Laravel default '/api' prefix for routes/api.php (RouteServiceProvider/bootstrap may override)")
        elif parts.endswith("routes/web.php"):
            warn_extra.append("routes/web.php uses the web middleware group (session/CSRF); it may not be an API route")
        handled: set[int] = set()
        for node in walk(tree.root_node):
            if node.type not in ("member_call_expression", "scoped_call_expression") or node.id in handled:
                continue
            meth = _method_name(node).lower() if _method_name(node) else ""
            if meth not in VERBS | {"any", "match", "apiresource", "resource"}:
                continue
            inner_items, rooted = _chain(node)
            if not rooted:
                continue
            for inner in walk(node):
                if inner is not node and inner.type in ("member_call_expression", "scoped_call_expression"):
                    handled.add(inner.id)
            # fluent calls applied *after* the verb, e.g. Route::get(...)->middleware('auth')->name('x')
            outer: list[tuple[str, list[Any]]] = []
            cur = node
            while cur.parent is not None and cur.parent.type == "member_call_expression" and cur.parent.child_by_field_name("object") == cur:
                cur = cur.parent
                outer.append((_method_name(cur), _args(cur)))
            items = list(reversed(outer)) + inner_items
            _emit_route(node, meth, items, len(outer), name, default_prefix, warn_extra, outcome)
    return analysed


def _emit_route(
    node: Any, meth: str, items: list[tuple[str, list[Any]]], verb_idx: int, file: str, default_prefix: str,
    warn_extra: list[str], outcome: DiscoveryOutcome,
) -> None:
    # items is outermost-first; the verb call may itself be wrapped (e.g. ->name('x') / ->middleware()).
    verb_args = items[verb_idx][1]
    chain_inner = items[verb_idx:]
    chain_outer = items[:verb_idx]
    pfx_chain, mw_chain, dyn_chain = _modifiers(chain_inner[1:] + chain_outer)
    gp, gmw, gdyn = _group_context(node)
    prefix = join_paths(default_prefix, gp, pfx_chain) if (default_prefix or gp or pfx_chain) else ""
    mws = gmw + mw_chain
    requires_auth = True if any(m == "auth" or m.startswith("auth:") or m.startswith("auth.") for m in mws) else None
    schemes = [m for m in mws if m.startswith("auth")]
    warnings = list(warn_extra)
    if gdyn or dyn_chain:
        warnings.append("a group/prefix value is dynamic; the route prefix may be incomplete")
    if not verb_args:
        return

    if meth in ("apiresource", "resource"):
        base = string_value(verb_args[0])
        if base is None:
            outcome.potential_routes.append(PotentialRoute(description=f"Route::{meth}(...)", reason="resource name is not a static string", source_file=file, line=line_of(node), strategy="static"))
            return
        only, exc = None, None
        for m, a in chain_outer:
            if m == "only" and a:
                only = set(_strings_in(a[0]))
            if m == "except" and a:
                exc = set(_strings_in(a[0]))
        ctrl = _controller_ref(verb_args[1] if len(verb_args) > 1 else None)
        param = singular(base.strip("/").split("/")[-1])
        for action, method, suffix in RESOURCE_ACTIONS:
            act = "update" if action == "update_patch" else action
            if meth == "apiresource" and act in API_ACTIONS_EXCLUDED:
                continue
            if only is not None and act not in only:
                continue
            if exc is not None and act in exc:
                continue
            path = join_paths(prefix, base) + suffix.replace("{id}", "{" + param + "}")
            _add(outcome, file, node, method, path, ctrl, requires_auth, schemes,
                 warnings + [f"expanded from Route::{meth}; parameter name '{param}' is Laravel's default (route-model binding)"], Confidence.MEDIUM)
        return

    path_str = string_value(verb_args[0])
    if path_str is None:
        outcome.potential_routes.append(PotentialRoute(description=f"Route::{meth}(<dynamic>)", reason="route path is not a static string", source_file=file, line=line_of(node), strategy="static"))
        return
    ctrl = _controller_ref(verb_args[1] if len(verb_args) > 1 else None)
    if meth == "match":
        methods = [m.upper() for m in _strings_in(verb_args[0])]
        path_str = string_value(verb_args[1]) or ""
        ctrl = _controller_ref(verb_args[2] if len(verb_args) > 2 else None)
    elif meth == "any":
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        warnings.append("Route::any expanded to the five common methods")
    else:
        methods = [meth.upper()]
    full = join_paths(prefix, path_str) if prefix or path_str else "/"
    for m in methods:
        if m == "OPTIONS":
            continue
        _add(outcome, file, node, m, full, ctrl, requires_auth, schemes, warnings, Confidence.HIGH if ctrl else Confidence.MEDIUM)


def _add(outcome: DiscoveryOutcome, file: str, node: Any, method: str, path: str, ctrl: str | None,
         requires_auth: bool | None, schemes: list[str], warnings: list[str], conf: Confidence) -> None:
    route, names = normalize_path(path)
    outcome.endpoints.append(
        Endpoint(
            method=method, route=route, original_path=path, path_param_names=names,
            parameters=[Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names],
            requires_auth=requires_auth, security_schemes=schemes, source_file=file, line=line_of(node), handler=ctrl,
            strategy="static", confidence=conf,
            warnings=[*warnings, "request/response schemas not established (Laravel validation rules / resources not analysed)"],
            evidence=[Evidence(source=file, detail=f"Route::{method.lower()}('{path}')" + (f" -> {ctrl}" if ctrl else ""), line=line_of(node))],
        )
    )
