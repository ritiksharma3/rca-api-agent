"""Static analysis of Laravel route files (tree-sitter PHP grammar)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


_BASE_PATH = re.compile(r"""^\(?\s*(?:base_path|app_path)\(\s*['"]([^'"]+)['"]\s*\)\s*\)?$""")
_DIR_CONCAT = re.compile(r"""^__DIR__\s*\.\s*['"]([^'"]+)['"]$""")
_INCLUDE_NODES = {"require_expression", "require_once_expression", "include_expression", "include_once_expression"}
MAX_INCLUDE_DEPTH = 8
MAX_FILES = 1500


@dataclass
class _Ctx:
    """What a route file inherits from the place that includes it (prefix, middleware, dynamic-prefix flag)."""

    prefix: str = ""
    mws: list[str] = field(default_factory=list)
    dynamic: bool = False

    def key(self) -> tuple[str, tuple[str, ...]]:
        return self.prefix, tuple(self.mws)


def _include_target(arg: Any, here: Path, root: Path, backend_dir: Path) -> Path | None:
    """File named by `base_path('x.php')`, `__DIR__.'/x.php'` or a plain relative string -- only if it exists inside the project."""
    if arg is None:
        return None
    raw = text(arg).strip()
    rel_path: str | None = None
    base = backend_dir
    m = _BASE_PATH.match(raw)
    if m:
        rel_path = m.group(1)
    else:
        m = _DIR_CONCAT.match(raw)
        if m:
            rel_path, base = m.group(1).lstrip("/\\"), here.parent
        else:
            v = string_value(arg)
            if v and v.endswith(".php"):
                rel_path = v
    if not rel_path:
        return None
    cand = (base / rel_path.lstrip("/\\")).resolve()
    try:
        cand.relative_to(root.resolve())  # never read outside the project
    except ValueError:
        return None
    return cand if cand.is_file() and cand.suffix.lower() == ".php" else None


def analyze_php(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    files = [
        f for f in iter_source_files(backend_dir, {".php"})
        if "routes" in f.relative_to(backend_dir).parts or f.name.lower().startswith("routes")
    ]
    if not files:
        files = [f for f in iter_source_files(backend_dir, {".php"})]
    counted: set[Path] = set()
    done: set[tuple[Path, tuple[str, tuple[str, ...]]]] = set()
    includes = 0

    def scan(f: Path, ctx: _Ctx, depth: int, via: str | None) -> None:
        nonlocal includes
        key = (f.resolve(), ctx.key())
        if key in done or len(done) >= MAX_FILES:
            return
        done.add(key)
        src = read_text(f)
        if "Route::" not in src and "base_path" not in src and "require" not in src and "include" not in src:
            return
        counted.add(f.resolve())
        name = rel(f, root)
        tree = parse("php", src)
        default_prefix = ctx.prefix
        warn_extra: list[str] = []
        if via:
            warn_extra.append(f"included from {via}; prefix/middleware inherited from the including group")
        parts = f.relative_to(backend_dir).as_posix() if f.is_relative_to(backend_dir) else f.name
        if via is None and parts.endswith("routes/api.php"):
            default_prefix = join_paths(ctx.prefix, "/api")
            warn_extra.append("assumed Laravel default '/api' prefix for routes/api.php (RouteServiceProvider/bootstrap may override)")
        elif via is None and parts.endswith("routes/web.php"):
            warn_extra.append("routes/web.php uses the web middleware group (session/CSRF); it may not be an API route")
        handled: set[int] = set()
        for node in walk(tree.root_node):
            if node.id in handled:
                continue
            if node.type in _INCLUDE_NODES:  # require base_path('routes/x.php'); inside the current group
                child = _include_target(first_of(node, "function_call_expression", "binary_expression", "string", "encapsed_string") or (named_children(node) or [None])[0], f, root, backend_dir)
                if child is not None and depth < MAX_INCLUDE_DEPTH:
                    gp, gmw, gd = _group_context(node)
                    includes += 1
                    scan(child, _Ctx(join_paths(default_prefix, gp) if (default_prefix or gp) else "", [*ctx.mws, *gmw], ctx.dynamic or gd), depth + 1, name)
                continue
            if node.type not in ("member_call_expression", "scoped_call_expression"):
                continue
            meth = _method_name(node).lower() if _method_name(node) else ""
            if meth == "group":  # Route::name('x')->group(base_path('a/b/XRoute.php'))
                items, rooted = _chain(node)
                args = items[0][1] if items else []
                if rooted and args and args[0].type not in ("anonymous_function", "arrow_function", "array_creation_expression"):
                    for inner in walk(node):
                        if inner is not node and inner.type in ("member_call_expression", "scoped_call_expression"):
                            handled.add(inner.id)
                    child = _include_target(args[0], f, root, backend_dir)
                    if child is None:
                        outcome.potential_routes.append(PotentialRoute(
                            description=f"Route::...->group({text(args[0])[:60]})", reason="route file path is not static or does not exist inside the project",
                            source_file=name, line=line_of(node), strategy="static"))
                    elif depth < MAX_INCLUDE_DEPTH:
                        gp, gmw, gd = _group_context(node)
                        cp, cmw, cd = _modifiers(items[1:] + [])
                        includes += 1
                        scan(child, _Ctx(join_paths(default_prefix, gp, cp) if (default_prefix or gp or cp) else "",
                                         [*ctx.mws, *gmw, *cmw], ctx.dynamic or gd or cd), depth + 1, name)
                continue
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
            _emit_route(node, meth, items, len(outer), name, default_prefix, warn_extra, outcome, ctx.mws, ctx.dynamic)

    for f in files:
        scan(f, _Ctx(), 0, None)
    if includes:
        outcome.warnings.append(DiscoveryWarning(adapter="laravel-static", message=f"followed {includes} route-file include(s) (->group(base_path(...)) / require); prefix and middleware were inherited from the including group", source_file=None, line=None))
    return len(counted)


def _emit_route(
    node: Any, meth: str, items: list[tuple[str, list[Any]]], verb_idx: int, file: str, default_prefix: str,
    warn_extra: list[str], outcome: DiscoveryOutcome, inherited_mws: list[str] | None = None, inherited_dynamic: bool = False,
) -> None:
    # items is outermost-first; the verb call may itself be wrapped (e.g. ->name('x') / ->middleware()).
    verb_args = items[verb_idx][1]
    chain_inner = items[verb_idx:]
    chain_outer = items[:verb_idx]
    pfx_chain, mw_chain, dyn_chain = _modifiers(chain_inner[1:] + chain_outer)
    gp, gmw, gdyn = _group_context(node)
    prefix = join_paths(default_prefix, gp, pfx_chain) if (default_prefix or gp or pfx_chain) else ""
    mws = [*(inherited_mws or []), *gmw, *mw_chain]
    gdyn = gdyn or inherited_dynamic
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
