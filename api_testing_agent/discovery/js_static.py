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
from .ts_common import children_of, first_of, is_literal, js_literal, line_of, named_children, object_pairs, parse, string_value, text, walk

VERBS = {"get", "post", "put", "patch", "delete", "all"}
AUTH_HINTS = ("auth", "jwt", "token", "verify", "protect", "passport", "guard", "session")
ROUTER_FACTORIES = {"Router", "express", "express.Router"}
# receivers that are routers/apps in Express, Fastify and Koa code even when their creation is not visible (plugin params, injected instances)
RECEIVER_NAMES = ("app", "router", "fastify", "server", "instance", "api")
HOOKS_WITH_AUTH = ("onRequest", "preHandler", "preValidation", "preParsing")
FASTIFY_AUTH_KEYS = ("onRequest", "preHandler", "preValidation", "preParsing")


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
        self.own_prefix: dict[str, str] = {}  # Koa: new Router({prefix}) / router.prefix(...)
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
                    if fn == "express" or fn in ("fastify", "Fastify") or re.fullmatch(r"require\(\s*['\"]fastify['\"]\s*\)", fn):
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
                elif val.type == "new_expression" and "Koa" in text(val.child_by_field_name("constructor") or val) and "Router" not in text(val):
                    self.routers[text(name)] = "app"
                elif val.type == "new_expression" and "Router" in text(val):
                    self.routers[text(name)] = "router"
                    opts = object_pairs(first_of(first_of(val, "arguments") or val, "object")) if val.child_by_field_name("arguments") is not None else {}
                    if "prefix" in opts and string_value(opts["prefix"]):
                        self.own_prefix[text(name)] = string_value(opts["prefix"]) or ""
            elif n.type == "formal_parameters":  # fastify plugins: async function routes(fastify, opts) { fastify.get(...) }
                for p in named_children(n):
                    ident = p if p.type == "identifier" else first_of(p, "identifier")
                    if ident is not None and text(ident) in RECEIVER_NAMES and text(ident) not in self.routers:
                        self.routers[text(ident)] = "router"
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
        if any(k in src for k in ("express", "Router", "fastify", "Fastify", "koa", "Koa")):
            files.append(_File(f, root))
    if not files:
        return 0
    by_name = {f.name: f for f in files}
    # (file, var) -> list of (parent (file,var), mount path)
    edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    routes: list[tuple[_File, str, Any, str, str]] = []  # file, var, call node, verb, path (call node: a verb call, or a fastify .route({...}) call)
    router_auth: dict[tuple[str, str], int] = {}  # (file, var) -> first line of a router-wide auth middleware (`router.use(authenticate)`)
    mount_auth: set[tuple[str, str]] = set()  # routers mounted behind an auth middleware (`app.use('/x', authenticate, xRouter)`)

    def is_auth(name: str) -> bool:
        return any(h in name.lower() for h in AUTH_HINTS)

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
            if var not in f.routers and not (var in RECEIVER_NAMES and verb in VERBS | {"use", "register", "route", "addHook", "prefix"}):
                continue
            args = _call_args(n)
            if verb == "prefix" and args and string_value(args[0]) is not None:  # koa-router: router.prefix('/x')
                f.own_prefix[var] = string_value(args[0]) or ""
                continue
            if verb == "addHook":  # fastify: fastify.addHook('onRequest', authenticate) protects what is registered after it in this plugin
                if len(args) >= 2 and string_value(args[0]) in HOOKS_WITH_AUTH and is_auth(text(args[1])):
                    router_auth[(f.name, var)] = min(router_auth.get((f.name, var), 10**9), line_of(n))
                continue
            if verb == "register":  # fastify: fastify.register(require('./routes/users'), { prefix: '/users' })
                if args:
                    opts = object_pairs(args[1]) if len(args) > 1 else {}
                    mount = string_value(opts["prefix"]) if "prefix" in opts else ""
                    plug = args[0]
                    mod = None
                    if plug.type == "identifier" and text(plug) in f.imports:
                        mod = f.imports[text(plug)]
                    elif plug.type == "call_expression" and text(plug.child_by_field_name("function")) == "require":
                        ra = _call_args(plug)
                        sp = string_value(ra[0]) if ra else None
                        mod = _resolve_module(f.path, sp, root) if sp else None
                    if mod and mod in by_name and mount is not None:
                        for tvar in by_name[mod].routers:
                            edges.setdefault((by_name[mod].name, tvar), []).append(((f.name, var), mount))
                    else:
                        outcome.warnings.append(DiscoveryWarning(adapter="express-static", message=f"{var}.register(...) plugin not resolved statically (only relative require()/import plugins are followed)", source_file=f.name, line=line_of(n)))
                continue
            if verb == "route" and args and args[0].type == "object":  # fastify: fastify.route({ method, url, handler, schema })
                ro = object_pairs(args[0])
                u = string_value(ro["url"]) if "url" in ro else (string_value(ro["path"]) if "path" in ro else None)
                meths = js_literal(ro.get("method"))
                meths = [meths] if isinstance(meths, str) else (meths if isinstance(meths, list) else [])
                if u is None or not meths:
                    outcome.potential_routes.append(PotentialRoute(description=f"{var}.route(<dynamic>)", reason="route method/url is not a static literal", source_file=f.name, line=line_of(n), strategy="static"))
                    continue
                for m_ in meths:
                    routes.append((f, var, n, str(m_).lower(), u))
                continue
            if verb == "use":
                if len(args) == 1 and args[0].type == "call_expression" and text(args[0]).endswith((".routes()", ".middleware()")):
                    continue  # koa: app.use(router.routes()) -- routes are already complete
                if args and string_value(args[0]) is None and args[0].type != "string":  # router.use(authenticate, ...): applies to routes defined after it
                    if any(a.type in ("identifier", "member_expression", "call_expression") and is_auth(text(a).split("(")[0]) for a in args):
                        router_auth[(f.name, var)] = min(router_auth.get((f.name, var), 10**9), line_of(n))
                    continue
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
                    elif child.type == "call_expression" and text(child.child_by_field_name("function")).endswith((".routes", ".middleware")):
                        obj = child.child_by_field_name("function").child_by_field_name("object")  # koa: parent.use('/a', child.routes())
                        if obj is not None and text(obj) in f.routers:
                            target = (f.name, text(obj))
                        elif obj is not None and text(obj) in f.imports and f.imports[text(obj)] in by_name:
                            tf = by_name[f.imports[text(obj)]]
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
                        if any(is_auth(text(a).split("(")[0]) for a in args[1:-1]):
                            mount_auth.add(target)
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
            parent_own = by_name[parent[0]].own_prefix.get(parent[1], "") if parent[0] in by_name else ""
            for pp in prefixes(parent, seen + (key,)):
                out.append(join_paths(pp, parent_own, mount) if (pp or parent_own or mount) else "")
        return out or [""]

    def behind_auth(key: tuple[str, str], seen: tuple[tuple[str, str], ...] = ()) -> bool:
        if key in seen:
            return False
        if key in mount_auth or key in router_auth:
            return True
        return any(behind_auth(parent, seen + (key,)) for parent, _m in edges.get(key, []))

    for f, var, call, verb, path in routes:
        key = (f.name, var)
        pfxs = prefixes(key)
        mounted = key in edges
        args = _call_args(call)
        fopts: dict[str, Any] = {}
        if call.type == "call_expression" and args and args[0].type == "object" and verb in VERBS | {"get", "post", "put", "patch", "delete", "head", "options"} and text(call.child_by_field_name("function")).endswith(".route"):
            fopts = object_pairs(args[0])  # fastify.route({...}): the options object is the route definition
            handler = fopts.get("handler")
            middlewares = [text(v) for k, v in fopts.items() if k in FASTIFY_AUTH_KEYS]
        else:
            if len(args) >= 3 and args[1].type == "object":  # fastify.get('/x', { schema, preHandler }, handler)
                fopts = object_pairs(args[1])
            handler = args[-1] if len(args) > 1 else None
            middlewares = [text(a) for a in args[1:-1] if a.type != "object"] + [text(v) for k, v in fopts.items() if k in FASTIFY_AUTH_KEYS]
        body_names: list[str] = []
        query_names: list[str] = []
        if handler is not None and handler.type in ("arrow_function", "function_expression", "function"):
            htxt = text(handler)
            body_names = sorted(set(re.findall(r"req\.body\.(\w+)", htxt)) | set(re.findall(r"(?:req|request)\.body\.(\w+)", htxt)))
            for m in re.finditer(r"const\s*\{([^}]*)\}\s*=\s*(?:req|request)\.body", htxt):
                body_names += [x.split(":")[0].split("=")[0].strip() for x in m.group(1).split(",") if x.strip()]
            query_names = sorted(set(re.findall(r"(?:req|request)\.query\.(\w+)", htxt)))
            body_names = sorted(set(n for n in body_names if n))
        schema_lit = js_literal(fopts["schema"]) if "schema" in fopts else {}
        schema_lit = schema_lit if isinstance(schema_lit, dict) else {}
        router_wide = key in mount_auth or (key in router_auth and router_auth[key] <= line_of(call)) or any(
            behind_auth(parent) for parent, _m in edges.get(key, []))
        requires_auth = True if router_wide or any(is_auth(m) for m in middlewares) else None
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] if verb == "all" else [verb.upper()]
        for pfx in dict.fromkeys(pfxs):
            own = f.own_prefix.get(var, "")
            full = join_paths(pfx, own, path) if (pfx or own or path) else "/"
            route, names = normalize_path(full)
            for m in methods:
                params = [Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names]
                params += [Parameter(name=q, location=ParamLocation.QUERY, required=False, schema_def={"type": "string"}) for q in query_names]
                body = None
                warns = ["response schema and validation rules not established statically"]
                qs = schema_lit.get("querystring") or schema_lit.get("query")
                if isinstance(qs, dict) and isinstance(qs.get("properties"), dict):
                    params = [p for p in params if p.location != ParamLocation.QUERY]
                    params += [Parameter(name=k, location=ParamLocation.QUERY, required=k in (qs.get("required") or []), schema_def=v if isinstance(v, dict) else {}) for k, v in qs["properties"].items()]
                if isinstance(schema_lit.get("params"), dict) and isinstance(schema_lit["params"].get("properties"), dict):
                    for p in params:
                        if p.location == ParamLocation.PATH and isinstance(schema_lit["params"]["properties"].get(p.name), dict):
                            p.schema_def = schema_lit["params"]["properties"][p.name]
                if isinstance(schema_lit.get("body"), dict) and schema_lit["body"] and m in ("POST", "PUT", "PATCH"):
                    body = RequestBody(schema_def=schema_lit["body"], required=True)
                    warns.append("request body schema taken from the route's JSON schema")
                elif body_names and m in ("POST", "PUT", "PATCH"):
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
                        security_schemes=[x for x in middlewares if is_auth(x)] or (["router-level auth middleware"] if router_wide else []),
                        source_file=f.name, line=line_of(call), handler=text(handler)[:40] if handler is not None and handler.type == "identifier" else None,
                        strategy="static", confidence=Confidence.HIGH if (mounted or f.routers.get(var) == "app") else Confidence.MEDIUM,
                        warnings=warns,
                        evidence=[Evidence(source=f.name, detail=f"{var}.{verb}('{path}')", line=line_of(call))],
                    )
                )
    return len(files)
