"""Static analysis of Express routers (tree-sitter JavaScript / TypeScript grammars)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models.endpoint import Confidence, Endpoint, Evidence, ParamLocation, Parameter, PotentialRoute, RequestBody
from ..models.project import DiscoveryWarning
from ..utils.filesystem import iter_source_files, read_text, rel
from .base import DiscoveryOutcome
from .normalizer import join_paths, normalize_path
from .ts_common import children_of, first_of, line_of, named_children, parse, string_value, text, walk

VERBS = {"get", "post", "put", "patch", "delete", "all"}
AUTH_HINTS = ("auth", "jwt", "token", "verify", "protect", "passport", "guard", "session")
ROUTER_FACTORIES = {"Router", "express", "express.Router"}


def _lang(path: Path) -> str:
    return "typescript" if path.suffix.lower() == ".ts" else "javascript"


def _call_args(call: Any) -> list[Any]:
    a = call.child_by_field_name("arguments")
    return named_children(a) if a is not None else []


def _resolve_module(base: Path, spec: str, root: Path) -> str | None:
    if not spec.startswith("."):
        return None
    cand = (base.parent / spec).resolve()
    for ext in ("", ".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"):
        p = Path(str(cand) + ext)
        if p.is_file():
            return rel(p, root)
    return None


class _File:
    def __init__(self, path: Path, root: Path):
        self.path = path
        self.name = rel(path, root)
        self.src = read_text(path)
        self.tree = parse(_lang(path), self.src)
        self.routers: dict[str, str] = {}  # var -> 'app' | 'router'
        self.imports: dict[str, str] = {}  # local name -> module file
        self.exports: set[str] = set()
        self.root = root
        self._scan()

    def _scan(self) -> None:
        for n in walk(self.tree.root_node):
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                val = n.child_by_field_name("value")
                if name is None or val is None or name.type != "identifier":
                    continue
                if val.type == "call_expression":
                    fn = text(val.child_by_field_name("function"))
                    if fn == "express":
                        self.routers[text(name)] = "app"
                    elif fn in ("express.Router", "Router"):
                        self.routers[text(name)] = "router"
                    elif fn == "require":
                        args = _call_args(val)
                        if args:
                            spec = string_value(args[0])
                            if spec:
                                mod = _resolve_module(self.path, spec, self.root)
                                if mod:
                                    self.imports[text(name)] = mod
                elif val.type == "new_expression" and "Router" in text(val):
                    self.routers[text(name)] = "router"
            elif n.type == "import_statement":
                src = n.child_by_field_name("source") or first_of(n, "string")
                spec = string_value(src) if src is not None else None
                mod = _resolve_module(self.path, spec, self.root) if spec else None
                if mod:
                    for ident in walk(n):
                        if ident.type == "identifier":
                            self.imports[text(ident)] = mod
            elif n.type == "assignment_expression":
                left = text(n.child_by_field_name("left"))
                if left in ("module.exports", "exports.default"):
                    right = n.child_by_field_name("right")
                    if right is not None and right.type == "identifier":
                        self.exports.add(text(right))
            elif n.type == "export_statement" and "default" in text(n)[:20]:
                for ident in children_of(n, "identifier"):
                    self.exports.add(text(ident))


def analyze_express(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    files = []
    for f in iter_source_files(backend_dir, {".js", ".mjs", ".cjs", ".ts"}):
        src = read_text(f)
        if "express" in src or "Router" in src:
            files.append(_File(f, root))
    if not files:
        return 0
    by_name = {f.name: f for f in files}
    # (file, var) -> list of (parent (file,var), mount path)
    edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    routes: list[tuple[_File, str, Any, str, str]] = []  # file, var, call node, verb, path

    for f in files:
        for n in walk(f.tree.root_node):
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                continue
            obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
            if obj is None or prop is None or obj.type != "identifier":
                continue
            var, verb = text(obj), text(prop)
            if var not in f.routers and not (var in ("app", "router") and verb in VERBS | {"use"}):
                continue
            args = _call_args(n)
            if verb == "use":
                if len(args) >= 2:
                    mount = string_value(args[0])
                    child = args[-1]
                    if mount is None:
                        outcome.potential_routes.append(PotentialRoute(description=f"{var}.use(<dynamic>, ...)", reason="mount path is not a static string", source_file=f.name, line=line_of(n), strategy="static"))
                        continue
                    target = None
                    if child.type == "identifier":
                        cname = text(child)
                        if cname in f.routers:
                            target = (f.name, cname)
                        elif cname in f.imports and f.imports[cname] in by_name:
                            tf = by_name[f.imports[cname]]
                            tvar = next(iter(tf.exports), None) or next((v for v, k in tf.routers.items() if k == "router"), None)
                            if tvar:
                                target = (tf.name, tvar)
                    elif child.type == "call_expression" and text(child.child_by_field_name("function")) == "require":
                        ra = _call_args(child)
                        spec = string_value(ra[0]) if ra else None
                        mod = _resolve_module(f.path, spec, root) if spec else None
                        if mod and mod in by_name:
                            tf = by_name[mod]
                            tvar = next(iter(tf.exports), None) or next((v for v, k in tf.routers.items() if k == "router"), None)
                            if tvar:
                                target = (tf.name, tvar)
                    if target:
                        edges.setdefault(target, []).append(((f.name, var), mount))
                    else:
                        outcome.warnings.append(DiscoveryWarning(adapter="express-static", message=f"{var}.use('{mount}', ...) target not resolved statically", source_file=f.name, line=line_of(n)))
                continue
            if verb not in VERBS or not args:
                continue
            path = string_value(args[0])
            if path is None:
                outcome.potential_routes.append(PotentialRoute(description=f"{var}.{verb}(<dynamic>, ...)", reason="route path is not a static string", source_file=f.name, line=line_of(n), strategy="static"))
                continue
            routes.append((f, var, n, verb, path))

    def prefixes(key: tuple[str, str], seen: tuple[tuple[str, str], ...] = ()) -> list[str]:
        if key in seen:
            return [""]
        ps = edges.get(key)
        if not ps:
            return [""]
        out = []
        for parent, mount in ps:
            for pp in prefixes(parent, seen + (key,)):
                out.append(join_paths(pp, mount) if (pp or mount) else "")
        return out or [""]

    for f, var, call, verb, path in routes:
        key = (f.name, var)
        pfxs = prefixes(key)
        mounted = key in edges
        args = _call_args(call)
        handler = args[-1] if len(args) > 1 else None
        middlewares = [text(a) for a in args[1:-1]]
        body_names: list[str] = []
        query_names: list[str] = []
        if handler is not None and handler.type in ("arrow_function", "function_expression", "function"):
            htxt = text(handler)
            body_names = sorted(set(re.findall(r"req\.body\.(\w+)", htxt)))
            for m in re.finditer(r"const\s*\{([^}]*)\}\s*=\s*req\.body", htxt):
                body_names += [x.split(":")[0].split("=")[0].strip() for x in m.group(1).split(",") if x.strip()]
            query_names = sorted(set(re.findall(r"req\.query\.(\w+)", htxt)))
            body_names = sorted(set(n for n in body_names if n))
        requires_auth = True if any(any(h in m.lower() for h in AUTH_HINTS) for m in middlewares) else None
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] if verb == "all" else [verb.upper()]
        for pfx in dict.fromkeys(pfxs):
            full = join_paths(pfx, path) if (pfx or path) else "/"
            route, names = normalize_path(full)
            for m in methods:
                params = [Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names]
                params += [Parameter(name=q, location=ParamLocation.QUERY, required=False, schema_def={"type": "string"}) for q in query_names]
                body = None
                warns = ["response schema and validation rules not established statically"]
                if body_names and m in ("POST", "PUT", "PATCH"):
                    body = RequestBody(schema_def={"type": "object", "properties": {b: {"type": "string"} for b in body_names}}, required=True)
                    warns.append("request body fields inferred from req.body usage; types/required-ness unknown")
                elif m in ("POST", "PUT", "PATCH"):
                    warns.append("request body shape not established")
                if verb == "all":
                    warns.append("app.all expanded to common methods")
                if not mounted and f.routers.get(var) == "router":
                    warns.append(f"router '{var}' mount path not found in analysed code; prefix may be incomplete")
                outcome.endpoints.append(
                    Endpoint(
                        method=m, route=route, original_path=path, path_param_names=names, parameters=params,
                        request_body=body, requires_auth=requires_auth,
                        security_schemes=[x for x in middlewares if any(h in x.lower() for h in AUTH_HINTS)],
                        source_file=f.name, line=line_of(call), handler=text(handler)[:40] if handler is not None and handler.type == "identifier" else None,
                        strategy="static", confidence=Confidence.HIGH if (mounted or f.routers.get(var) == "app") else Confidence.MEDIUM,
                        warnings=warns,
                        evidence=[Evidence(source=f.name, detail=f"{var}.{verb}('{path}')", line=line_of(call))],
                    )
                )
    return len(files)
