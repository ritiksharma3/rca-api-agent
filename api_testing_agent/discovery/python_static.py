"""Syntax-aware static analysis of Python web frameworks using the stdlib ``ast`` module.

Supports FastAPI, Flask (incl. Blueprints) and Django URLconfs. The analysed code is parsed, never imported
or executed. Anything not statically resolvable is recorded as a limitation or a potential route.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import DiscoveryError
from ..models.endpoint import (
    Confidence,
    Endpoint,
    Evidence,
    ParamLocation,
    Parameter,
    PotentialRoute,
    RequestBody,
    ResponseSpec,
)
from ..models.project import DiscoveryWarning
from ..utils.filesystem import iter_source_files, read_text, rel
from .base import Applicability, DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from .normalizer import join_paths, normalize_path

VERBS = {"get", "post", "put", "patch", "delete"}
AUTH_NAME_HINTS = ("auth", "current_user", "get_user", "verify", "token", "secur", "permission", "login_required", "jwt")
FLASK_AUTH_DECORATORS = ("login_required", "jwt_required", "auth_required", "token_required", "require_auth", "requires_auth")
SIMPLE_TYPES = {
    "int": {"type": "integer"}, "float": {"type": "number"}, "str": {"type": "string"}, "bool": {"type": "boolean"},
    "bytes": {"type": "string"}, "dict": {"type": "object"}, "list": {"type": "array", "items": {}},
    "UUID": {"type": "string", "format": "uuid"}, "datetime": {"type": "string", "format": "date-time"},
    "date": {"type": "string", "format": "date"}, "EmailStr": {"type": "string", "format": "email"},
    "Decimal": {"type": "number"}, "Any": {},
}
FIELD_KEYWORDS = {
    "min_length": "minLength", "max_length": "maxLength", "ge": "minimum", "le": "maximum",
    "gt": "exclusiveMinimum", "lt": "exclusiveMaximum", "pattern": "pattern", "regex": "pattern",
}
FLASK_CONVERTERS = {"int": {"type": "integer"}, "float": {"type": "number"}, "uuid": {"type": "string", "format": "uuid"}}


# ------------------------------------------------------------------ helpers


def _const_str(node: ast.AST | None, consts: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _const_str(node.left, consts), _const_str(node.right, consts)
        return a + b if a is not None and b is not None else None
    if isinstance(node, ast.JoinedStr):
        out = ""
        for v in node.values:
            if isinstance(v, ast.Constant):
                out += str(v.value)
            elif isinstance(v, ast.FormattedValue):
                s = _const_str(v.value, consts)
                if s is None:
                    return None
                out += s
        return out
    return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _literal(node: ast.AST | None) -> Any:
    try:
        return ast.literal_eval(node) if node is not None else None
    except (ValueError, SyntaxError):
        return None


def _call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


@dataclass
class _Router:
    key: tuple[str, str]  # (relative file, variable)
    kind: str  # app | router | blueprint
    own_prefix: str = ""
    routes: list["_Route"] = field(default_factory=list)
    from_line: int = 0


@dataclass
class _Route:
    file: str
    line: int
    method: str
    path: str
    func: ast.FunctionDef | ast.AsyncFunctionDef
    decorator: ast.Call
    router_known: bool = True
    status_code: int | None = None
    response_model: ast.AST | None = None
    kind: str = "fastapi"


@dataclass
class _Edge:
    parent: tuple[str, str]
    child: tuple[str, str]
    prefix: str | None  # None = not given
    kind: str


# ------------------------------------------------------------------ model/schema extraction


class _Models:
    """Index of class definitions across the repo, used to turn annotations into JSON schema."""

    def __init__(self) -> None:
        self.classes: dict[str, ast.ClassDef] = {}

    def add(self, tree: ast.AST) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                self.classes.setdefault(n.name, n)

    def is_model(self, name: str) -> bool:
        c = self.classes.get(name)
        if not c:
            return False
        for b in c.bases:
            bn = b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
            if bn in ("BaseModel", "BaseSettings") or self.is_model(bn):
                return True
        return False

    def schema_for_class(self, name: str, depth: int = 0) -> dict[str, Any]:
        cls = self.classes[name]
        props: dict[str, Any] = {}
        required: list[str] = []
        for b in cls.bases:
            bn = b.id if isinstance(b, ast.Name) else ""
            if bn and self.is_model(bn) and depth < 6:
                base = self.schema_for_class(bn, depth + 1)
                props.update(base.get("properties", {}))
                required += base.get("required", [])
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fname = stmt.target.id
                if fname.startswith("_") or fname == "model_config":
                    continue
                schema, optional = self.annotation(stmt.annotation, depth + 1)
                has_default = stmt.value is not None
                if has_default:
                    schema, req = self._apply_default(schema, stmt.value)
                    if req:
                        has_default = False
                props[fname] = schema
                if not has_default and not optional and fname not in required:
                    required.append(fname)
        out: dict[str, Any] = {"type": "object", "properties": props}
        if required:
            out["required"] = required
        return out

    @staticmethod
    def _apply_default(schema: dict[str, Any], value: ast.AST) -> tuple[dict[str, Any], bool]:
        """Apply Field(...) constraints; return (schema, required_flag)."""
        schema = dict(schema)
        required = False
        if isinstance(value, ast.Call) and _call_name(value) in ("Field", "Query", "Path", "Body", "Header"):
            if value.args:
                first = value.args[0]
                if isinstance(first, ast.Constant) and first.value is Ellipsis:
                    required = True
                else:
                    schema["default"] = _literal(first)
            for k in value.keywords:
                if k.arg in FIELD_KEYWORDS:
                    schema[FIELD_KEYWORDS[k.arg]] = _literal(k.value)
                elif k.arg == "default":
                    if isinstance(k.value, ast.Constant) and k.value.value is Ellipsis:
                        required = True
                    else:
                        schema["default"] = _literal(k.value)
                elif k.arg == "default_factory":
                    pass
                elif k.arg in ("example",):
                    schema["example"] = _literal(k.value)
                elif k.arg == "examples":
                    ex = _literal(k.value)
                    if isinstance(ex, list) and ex:
                        schema["example"] = ex[0]
                elif k.arg in ("description",):
                    schema["description"] = _literal(k.value)
        elif isinstance(value, ast.Constant) and value.value is Ellipsis:
            required = True
        else:
            lit = _literal(value)
            if lit is not None:
                schema["default"] = lit
        return schema, required

    def annotation(self, node: ast.AST | None, depth: int = 0) -> tuple[dict[str, Any], bool]:
        """Return (json_schema, is_optional)."""
        if node is None or depth > 8:
            return {}, False
        if isinstance(node, ast.Constant) and node.value is None:
            return {}, True
        if isinstance(node, ast.Name):
            if node.id in SIMPLE_TYPES:
                return dict(SIMPLE_TYPES[node.id]), False
            if self.is_model(node.id):
                return self.schema_for_class(node.id, depth + 1), False
            return {}, False
        if isinstance(node, ast.Attribute):
            return dict(SIMPLE_TYPES.get(node.attr, {})), False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            l_s, l_o = self.annotation(node.left, depth + 1)
            r_s, r_o = self.annotation(node.right, depth + 1)
            if isinstance(node.right, ast.Constant) and node.right.value is None:
                return l_s, True
            if isinstance(node.left, ast.Constant) and node.left.value is None:
                return r_s, True
            return l_s or r_s, l_o or r_o
        if isinstance(node, ast.Subscript):
            base = node.value.id if isinstance(node.value, ast.Name) else node.value.attr if isinstance(node.value, ast.Attribute) else ""
            sl = node.slice
            elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
            if base == "Optional":
                s, _ = self.annotation(elts[0], depth + 1)
                return s, True
            if base == "Union":
                parts = [e for e in elts if not (isinstance(e, ast.Constant) and e.value is None)]
                s, _ = self.annotation(parts[0], depth + 1) if parts else ({}, False)
                return s, len(parts) != len(elts)
            if base in ("List", "list", "Sequence", "Set", "set", "Iterable", "Tuple", "tuple"):
                s, _ = self.annotation(elts[0], depth + 1)
                return {"type": "array", "items": s}, False
            if base in ("Dict", "dict", "Mapping"):
                return {"type": "object"}, False
            if base == "Literal":
                vals = [_literal(e) for e in elts]
                return {"enum": vals}, False
            if base in ("Annotated",):
                s, o = self.annotation(elts[0], depth + 1)
                for extra in elts[1:]:
                    if isinstance(extra, ast.Call):
                        s, _ = self._apply_default(s, extra)
                return s, o
        return {}, False


# ------------------------------------------------------------------ module index / imports


class _Repo:
    def __init__(self, root: Path, files: list[Path]):
        self.root = root
        self.trees: dict[str, ast.Module] = {}
        self.sources: dict[str, str] = {}
        self.syntax_errors: list[tuple[str, str]] = []
        self.models = _Models()
        self.module_index: dict[str, str] = {}
        for f in files:
            r = rel(f, root)
            src = read_text(f)
            try:
                tree = ast.parse(src)
            except SyntaxError as exc:
                self.syntax_errors.append((r, f"{exc.msg} (line {exc.lineno})"))
                continue
            self.trees[r] = tree
            self.sources[r] = src
            self.models.add(tree)
            dotted = r[:-3].replace("/", ".")
            if dotted.endswith(".__init__"):
                dotted = dotted[: -len(".__init__")]
            parts = dotted.split(".")
            for i in range(len(parts)):
                self.module_index.setdefault(".".join(parts[i:]), r)

    def module_file(self, dotted: str) -> str | None:
        return self.module_index.get(dotted)

    def import_map(self, file: str) -> dict[str, tuple[str | None, str | None]]:
        """local name -> (module file, original name in that module or None for module imports)."""
        out: dict[str, tuple[str | None, str | None]] = {}
        tree = self.trees[file]
        pkg = file.rsplit("/", 1)[0].replace("/", ".") if "/" in file else ""
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom):
                mod = n.module or ""
                if n.level:
                    base = pkg.split(".") if pkg else []
                    base = base[: len(base) - (n.level - 1)] if n.level > 1 else base
                    mod = ".".join([*base, mod]) if mod else ".".join(base)
                for a in n.names:
                    local = a.asname or a.name
                    sub = self.module_file(f"{mod}.{a.name}" if mod else a.name)
                    if sub:
                        out[local] = (sub, None)  # imported a submodule
                    else:
                        out[local] = (self.module_file(mod), a.name)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    out[a.asname or a.name.split(".")[0]] = (self.module_file(a.name), None)
        return out


# ------------------------------------------------------------------ FastAPI / Flask analysis


def _param_schema_from_annotation(models: _Models, ann: ast.AST | None, default: ast.AST | None) -> tuple[dict[str, Any], bool]:
    schema, optional = models.annotation(ann)
    required = default is None and not optional
    if default is not None:
        schema, req = models._apply_default(schema, default)
        required = req
    return schema, required


def _unwrap_response_model(node: ast.AST | None, models: _Models) -> dict[str, Any] | None:
    if node is None:
        return None
    s, _ = models.annotation(node)
    return s or None


class _DecoratorAnalyzer:
    def __init__(self, repo: _Repo, outcome: DiscoveryOutcome, framework: str):
        self.repo = repo
        self.outcome = outcome
        self.framework = framework
        self.routers: dict[tuple[str, str], _Router] = {}
        self.edges: list[_Edge] = []

    # pass 1: collect router objects, routes and include edges per file
    def collect(self) -> None:
        for file, tree in self.repo.trees.items():
            consts = self._module_consts(tree)
            self._collect_objects(file, tree, consts)
        for file, tree in self.repo.trees.items():
            consts = self._module_consts(tree)
            self._collect_routes(file, tree, consts)
            self._collect_call_routes(file, tree, consts)
            self._collect_edges(file, tree, consts)

    @staticmethod
    def _module_consts(tree: ast.Module) -> dict[str, str]:
        consts: dict[str, str] = {}
        for n in tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                v = _const_str(n.value, consts)
                if v is not None:
                    consts[n.targets[0].id] = v
        return consts

    def _collect_objects(self, file: str, tree: ast.Module, consts: dict[str, str]) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call):
                cname = _call_name(n.value)
                var = n.targets[0].id
                if cname in ("FastAPI", "Flask", "Quart", "Sanic"):
                    self.routers[(file, var)] = _Router((file, var), "app", "", from_line=n.lineno)
                elif cname in ("APIRouter", "Blueprint"):
                    pfx_node = _kw(n.value, "prefix") or _kw(n.value, "url_prefix")
                    pfx = _const_str(pfx_node, consts) if pfx_node is not None else ""
                    if pfx is None:
                        pfx = ""
                        self.outcome.warnings.append(
                            DiscoveryWarning(adapter="python-static", message=f"router '{var}' prefix is dynamic; routes may be mis-prefixed", source_file=file, line=n.lineno)
                        )
                    self.routers[(file, var)] = _Router((file, var), "router" if cname == "APIRouter" else "blueprint", pfx, from_line=n.lineno)

    def _collect_routes(self, file: str, tree: ast.Module, consts: dict[str, str]) -> None:
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in fn.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name)):
                    continue
                var, attr = dec.func.value.id, dec.func.attr
                if attr not in VERBS | {"route", "api_route", "websocket"}:
                    continue
                if attr == "websocket":
                    continue
                known = (file, var) in self.routers
                path_node = dec.args[0] if dec.args else _kw(dec, "path") or _kw(dec, "rule")
                path = _const_str(path_node, consts)
                if path is None:
                    self.outcome.potential_routes.append(
                        PotentialRoute(
                            description=f"@{var}.{attr}(...) on {fn.name}()",
                            reason="route path is not a static string (dynamic registration)",
                            source_file=file, line=fn.lineno, strategy="static",
                        )
                    )
                    continue
                if not known and not path.startswith("/"):
                    continue  # not a recognisable router/app object
                if attr in VERBS:
                    methods = [attr.upper()]
                else:
                    ml = _literal(_kw(dec, "methods"))
                    if ml is None and _kw(dec, "methods") is not None:
                        self.outcome.potential_routes.append(
                            PotentialRoute(description=f"{path} ({fn.name})", reason="methods list is not a literal", source_file=file, line=fn.lineno, strategy="static")
                        )
                        continue
                    methods = [m.upper() for m in ml] if ml else ["GET"]
                sc = _literal(_kw(dec, "status_code"))
                for m in methods:
                    if m in ("HEAD", "OPTIONS"):
                        continue
                    route = _Route(file, fn.lineno, m, path, fn, dec, known, sc if isinstance(sc, int) else None, _kw(dec, "response_model"),
                                   kind="flask" if attr == "route" or self.framework == "Flask" else "fastapi")
                    if known:
                        self.routers[(file, var)].routes.append(route)
                    else:
                        self.routers.setdefault((file, f"<unknown:{var}>"), _Router((file, f"<unknown:{var}>"), "router", "")).routes.append(route)

    def _collect_call_routes(self, file: str, tree: ast.Module, consts: dict[str, str]) -> None:
        """Imperative registrations: app.add_api_route(path, fn) / app.add_url_rule(rule, ..., view_func)."""
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)):
                continue
            if n.func.attr not in ("add_api_route", "add_url_rule"):
                continue
            var = n.func.value.id
            path = _const_str(n.args[0] if n.args else _kw(n, "path") or _kw(n, "rule"), consts)
            if path is None:
                self.outcome.potential_routes.append(
                    PotentialRoute(
                        description=f"{var}.{n.func.attr}(<dynamic path>)",
                        reason="route registered imperatively with a computed path (dynamic registration)",
                        source_file=file, line=n.lineno, strategy="static",
                    )
                )
                continue
            ml = _literal(_kw(n, "methods"))
            methods = [m.upper() for m in ml] if isinstance(ml, (list, tuple)) else ["GET"]
            target = n.args[1] if len(n.args) > 1 else _kw(n, "endpoint") or _kw(n, "view_func")
            fname = target.id if isinstance(target, ast.Name) else None
            fn = next((f for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == fname), None)
            if fn is None:
                self.outcome.potential_routes.append(
                    PotentialRoute(description=f"{var}.{n.func.attr}('{path}')", reason="handler function could not be resolved", source_file=file, line=n.lineno, strategy="static")
                )
                continue
            dec = ast.Call(func=ast.Attribute(value=ast.Name(id=var), attr="route"), args=[], keywords=[])
            key = (file, var) if (file, var) in self.routers else (file, f"<unknown:{var}>")
            router = self.routers.setdefault(key, _Router(key, "router", ""))
            for m in methods:
                if m not in ("HEAD", "OPTIONS"):
                    router.routes.append(_Route(file, n.lineno, m, path, fn, dec, key[1] == var, None, None,
                                                kind="flask" if n.func.attr == "add_url_rule" else "fastapi"))

    def _resolve_ref(self, file: str, node: ast.AST, imports: dict[str, tuple[str | None, str | None]]) -> tuple[str, str] | None:
        if isinstance(node, ast.Name):
            if (file, node.id) in self.routers:
                return (file, node.id)
            imp = imports.get(node.id)
            if imp and imp[0] and imp[1]:
                return (imp[0], imp[1])
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            imp = imports.get(node.value.id)
            if imp and imp[0] and imp[1] is None:
                return (imp[0], node.attr)
        return None

    def _collect_edges(self, file: str, tree: ast.Module, consts: dict[str, str]) -> None:
        imports = self.repo.import_map(file)
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)):
                continue
            if n.func.attr not in ("include_router", "register_blueprint") or not n.args:
                continue
            parent = (file, n.func.value.id)
            child = self._resolve_ref(file, n.args[0], imports)
            pfx_node = _kw(n, "prefix") or _kw(n, "url_prefix")
            pfx = _const_str(pfx_node, consts) if pfx_node is not None else None
            if child is None or child not in self.routers or parent not in self.routers:
                self.outcome.warnings.append(
                    DiscoveryWarning(adapter="python-static", message=f"{n.func.attr}() target could not be resolved statically", source_file=file, line=n.lineno)
                )
                continue
            self.edges.append(_Edge(parent, child, pfx, n.func.attr))

    # pass 2: compute effective prefixes and emit endpoints
    def prefixes(self, key: tuple[str, str], seen: tuple[tuple[str, str], ...] = ()) -> list[str]:
        r = self.routers[key]
        if key in seen:
            return [r.own_prefix]
        parents = [e for e in self.edges if e.child == key]
        if not parents:
            return [r.own_prefix] if r.kind != "app" else [""]
        out: list[str] = []
        for e in parents:
            own = r.own_prefix
            if e.kind == "register_blueprint" and e.prefix is not None:
                own = ""  # Flask: url_prefix passed at registration overrides the blueprint's own
            for pp in self.prefixes(e.parent, seen + (key,)):
                out.append(join_paths(pp, e.prefix or "", own) if (pp or e.prefix or own) else "")
        return out or [r.own_prefix]

    def emit(self) -> None:
        for key, router in self.routers.items():
            if not router.routes:
                continue
            is_unknown = key[1].startswith("<unknown:")
            pfxs = [""] if is_unknown else self.prefixes(key)
            included = any(e.child == key for e in self.edges)
            for route in router.routes:
                for pfx in dict.fromkeys(pfxs):
                    full = join_paths(pfx, route.path) if (pfx or route.path) else "/"
                    self.outcome.endpoints.append(self._endpoint(route, full, router, included, is_unknown))

    def _endpoint(self, r: _Route, full_path: str, router: _Router, included: bool, unknown_router: bool) -> Endpoint:
        models = self.repo.models
        # keep converter types from Flask-style <int:id> before normalisation
        conv: dict[str, dict[str, Any]] = {}
        for m in re.finditer(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>", full_path):
            if m.group(1) in FLASK_CONVERTERS:
                conv[m.group(2)] = FLASK_CONVERTERS[m.group(1)]
        route, names = normalize_path(full_path)
        fn = r.func
        params: list[Parameter] = []
        body: RequestBody | None = None
        body_props: dict[str, Any] = {}
        body_required: list[str] = []
        requires_auth: bool | None = None
        schemes: list[str] = []
        warnings: list[str] = []
        args = fn.args
        pos = args.posonlyargs + args.args
        defaults: list[ast.AST | None] = [None] * (len(pos) - len(args.defaults)) + list(args.defaults)
        arg_pairs = list(zip(pos, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
        for a, d in arg_pairs:
            if a.arg in ("self", "cls", "request", "response", "background_tasks", "req", "res"):
                continue
            dname = _call_name(d) if isinstance(d, ast.Call) else ""
            if dname in ("Depends", "Security"):
                dep = d.args[0] if d.args else None  # type: ignore[union-attr]
                depn = dep.id if isinstance(dep, ast.Name) else dep.attr if isinstance(dep, ast.Attribute) else ""
                if any(h in depn.lower() for h in AUTH_NAME_HINTS):
                    requires_auth = True
                    schemes.append(f"dependency:{depn}")
                else:
                    warnings.append(f"dependency '{depn}' not analysed; it may enforce auth or validation")
                continue
            ann_name = a.annotation.id if isinstance(a.annotation, ast.Name) else ""
            if a.arg in names:
                s, _ = _param_schema_from_annotation(models, a.annotation, d)
                params.append(Parameter(name=a.arg, location=ParamLocation.PATH, required=True, schema_def=conv.get(a.arg) or s or {"type": "string"}))
                continue
            if ann_name and models.is_model(ann_name):
                body_schema = models.schema_for_class(ann_name)
                body = RequestBody(content_type="application/json", schema_def=body_schema, required=True)
                continue
            if dname == "Body":
                s, req = _param_schema_from_annotation(models, a.annotation, d)
                body_props[a.arg] = s
                if req:
                    body_required.append(a.arg)
                continue
            loc = ParamLocation.HEADER if dname == "Header" else ParamLocation.QUERY
            if r.kind == "fastapi":
                s, req = _param_schema_from_annotation(models, a.annotation, d)
                if s.get("type") in ("object",) and not s.get("properties"):
                    continue
                params.append(Parameter(name=a.arg.replace("_", "-") if loc == ParamLocation.HEADER else a.arg, location=loc, required=req, schema_def=s or {"type": "string"}))
        if body_props and body is None:
            sch: dict[str, Any] = {"type": "object", "properties": body_props}
            if body_required:
                sch["required"] = body_required
            body = RequestBody(schema_def=sch, required=True)
        # path params declared in route but missing from the signature (Flask)
        declared = {p.name for p in params if p.location == ParamLocation.PATH}
        for n in names:
            if n not in declared:
                params.append(Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def=conv.get(n) or {"type": "string"}))
        if r.kind == "flask":
            src = ast.get_source_segment(self.repo.sources[r.file], fn) or ""
            for q in sorted(set(re.findall(r"request\.args(?:\.get)?\s*[\[(]\s*['\"](\w+)['\"]", src))):
                params.append(Parameter(name=q, location=ParamLocation.QUERY, required=False, schema_def={"type": "string"}))
            if r.method in ("POST", "PUT", "PATCH") and re.search(r"request\.(?:get_json|json)\b", src) and body is None:
                warnings.append("handler reads a JSON body but its shape is not statically established")
        # auth via decorators
        for dec in fn.decorator_list:
            dn = dec.id if isinstance(dec, ast.Name) else dec.attr if isinstance(dec, ast.Attribute) else _call_name(dec) if isinstance(dec, ast.Call) else ""
            if dn in FLASK_AUTH_DECORATORS:
                requires_auth = True
                schemes.append(f"decorator:{dn}")
        deps_kw = _kw(r.decorator, "dependencies")
        if isinstance(deps_kw, ast.List):
            for el in deps_kw.elts:
                if isinstance(el, ast.Call) and _call_name(el) in ("Depends", "Security") and el.args:
                    a0 = el.args[0]
                    depn = a0.id if isinstance(a0, ast.Name) else ""
                    if any(h in depn.lower() for h in AUTH_NAME_HINTS):
                        requires_auth = True
                        schemes.append(f"dependency:{depn}")

        responses: list[ResponseSpec] = []
        rm = _unwrap_response_model(r.response_model, models) if r.response_model is not None else None
        ok = r.status_code or (201 if r.method == "POST" and r.kind == "fastapi" and False else 200)
        if r.kind == "fastapi":
            responses.append(ResponseSpec(status=str(ok), description="from decorator/default", content_type="application/json" if rm else None, schema_def=rm))
        if unknown_router:
            warnings.append("decorator target is not a recognised FastAPI/Flask/Blueprint object; route may not be live")
        elif not included and router.kind != "app":
            warnings.append(f"router '{router.key[1]}' is never included/registered in analysed code; prefix may be incomplete")
        conf = Confidence.HIGH if (not unknown_router and (included or router.kind == "app")) else Confidence.MEDIUM
        return Endpoint(
            method=r.method, route=route, original_path=r.path, path_param_names=names, parameters=params,
            request_body=body, responses=responses, security_schemes=schemes, requires_auth=requires_auth,
            source_file=r.file, line=r.line, handler=fn.name, strategy="static", confidence=conf,
            evidence=[Evidence(source=r.file, detail=f"@{router.key[1]} decorator on {fn.name}()", line=r.line)],
            warnings=warnings,
        )


# ------------------------------------------------------------------ Django


class _DjangoAnalyzer:
    def __init__(self, repo: _Repo, outcome: DiscoveryOutcome):
        self.repo = repo
        self.outcome = outcome
        self.included: set[str] = set()
        self.url_files = [f for f in repo.trees if f.endswith("urls.py") or "/urls/" in f]

    def run(self) -> None:
        graph: dict[str, list[tuple[str, str]]] = {}
        for f in self.url_files:
            graph[f] = []
            self._scan_file(f)
        roots = [f for f in self.url_files if f not in self.included] or self.url_files
        settings_roots = set()
        for f, src in self.repo.sources.items():
            m = re.search(r"ROOT_URLCONF\s*=\s*['\"]([\w.]+)['\"]", src)
            if m:
                tgt = self.repo.module_file(m.group(1))
                if tgt:
                    settings_roots.add(tgt)
        roots = list(settings_roots) or roots
        for root in roots:
            self._emit(root, "", set())

    def _patterns(self, file: str) -> list[ast.Call]:
        out: list[ast.Call] = []
        tree = self.repo.trees[file]
        for n in tree.body:
            if isinstance(n, (ast.Assign, ast.AugAssign)):
                tgt = n.targets[0] if isinstance(n, ast.Assign) else n.target
                if isinstance(tgt, ast.Name) and tgt.id == "urlpatterns":
                    val = n.value
                    if isinstance(val, ast.List):
                        out += [e for e in val.elts if isinstance(e, ast.Call)]
                    else:
                        self.outcome.potential_routes.append(
                            PotentialRoute(description=f"urlpatterns in {file}", reason="urlpatterns built dynamically", source_file=file, line=n.lineno, strategy="static")
                        )
        return out

    def _scan_file(self, file: str) -> None:
        for call in self._patterns(file):
            if _call_name(call) == "path" or _call_name(call) == "re_path" or _call_name(call) == "url":
                if len(call.args) >= 2 and isinstance(call.args[1], ast.Call) and _call_name(call.args[1]) == "include" and call.args[1].args:
                    a = call.args[1].args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        tgt = self.repo.module_file(a.value) or self.repo.module_file(a.value + ".urls")
                        if tgt:
                            self.included.add(tgt)

    def _emit(self, file: str, prefix: str, seen: set[str]) -> None:
        if file in seen:
            return
        seen = seen | {file}
        imports = self.repo.import_map(file)
        for call in self._patterns(file):
            cn = _call_name(call)
            if cn not in ("path", "re_path", "url") or len(call.args) < 2:
                continue
            ptn = _const_str(call.args[0], {})
            if ptn is None:
                self.outcome.potential_routes.append(
                    PotentialRoute(description="url pattern", reason="pattern is not a static string", source_file=file, line=call.lineno, strategy="static")
                )
                continue
            if cn in ("re_path", "url"):
                ptn = ptn.lstrip("^").rstrip("$")
            target = call.args[1]
            if isinstance(target, ast.Call) and _call_name(target) == "include":
                a = target.args[0] if target.args else None
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    tgt = self.repo.module_file(a.value) or self.repo.module_file(a.value + ".urls")
                    if tgt:
                        self._emit(tgt, join_paths(prefix, ptn), seen)
                        continue
                self.outcome.potential_routes.append(
                    PotentialRoute(
                        description=f"include() under '{join_paths(prefix, ptn)}'",
                        reason="include() target is not a static module path (e.g. DRF router.urls); routes registered dynamically",
                        source_file=file, line=call.lineno, strategy="static",
                    )
                )
                continue
            full = join_paths(prefix, ptn)
            self._emit_view(file, call, full, target, imports)

    def _emit_view(self, file: str, call: ast.Call, full: str, target: ast.AST, imports: dict[str, tuple[str | None, str | None]]) -> None:
        route, names = normalize_path(full)
        methods: list[str] = []
        warnings: list[str] = []
        conf = Confidence.MEDIUM
        handler = ""
        requires_auth = None
        if isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute) and target.func.attr == "as_view":
            cls_name = target.func.value.id if isinstance(target.func.value, ast.Name) else (target.func.value.attr if isinstance(target.func.value, ast.Attribute) else "")
            handler = cls_name
            cls = self._find_class(cls_name, file, imports)
            if cls is not None:
                bases = [b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else "" for b in cls.bases]
                if any("ViewSet" in b for b in bases):
                    self.outcome.potential_routes.append(
                        PotentialRoute(description=f"{full} ({cls_name})", reason="ViewSet action methods are mapped dynamically", source_file=file, line=call.lineno, strategy="static")
                    )
                    return
                defined = [n.name.upper() for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in VERBS]
                methods = defined
                conf = Confidence.HIGH if defined else Confidence.LOW
                for kw in cls.body:
                    if isinstance(kw, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "permission_classes" for t in kw.targets):
                        src = ast.dump(kw.value)
                        requires_auth = True if "IsAuthenticated" in src else (False if "AllowAny" in src else None)
        else:
            handler = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
            fn = self._find_function(handler, file, imports)
            if fn is not None:
                for dec in fn.decorator_list:
                    if isinstance(dec, ast.Call) and _call_name(dec) in ("api_view", "require_http_methods", "require_methods") and dec.args:
                        ml = _literal(dec.args[0])
                        if isinstance(ml, (list, tuple)):
                            methods = [str(m).upper() for m in ml]
                    elif isinstance(dec, ast.Call) and _call_name(dec) == "require_http_methods":
                        pass
                    dn = dec.id if isinstance(dec, ast.Name) else ""
                    if dn in ("require_GET",):
                        methods = ["GET"]
                    elif dn in ("require_POST",):
                        methods = ["POST"]
                    elif dn == "login_required":
                        requires_auth = True
                if methods:
                    conf = Confidence.HIGH
        if not methods:
            methods = ["GET"]
            conf = Confidence.LOW
            warnings.append("HTTP methods not statically determinable for this Django view; GET assumed")
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            params = [Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names]
            conv = {n: {"type": "integer"} for n in re.findall(r"<int:(\w+)>", full)}
            for p in params:
                if p.name in conv:
                    p.schema_def = conv[p.name]
            self.outcome.endpoints.append(
                Endpoint(
                    method=m, route=route, original_path=full, path_param_names=names, parameters=params,
                    requires_auth=requires_auth, source_file=file, line=call.lineno, handler=handler,
                    strategy="static", confidence=conf, warnings=list(warnings),
                    evidence=[Evidence(source=file, detail=f"url pattern -> {handler}", line=call.lineno)],
                )
            )

    def _find_class(self, name: str, file: str, imports: dict[str, tuple[str | None, str | None]]) -> ast.ClassDef | None:
        for f in [file] + [v[0] for v in imports.values() if v[0]]:
            tree = self.repo.trees.get(f)
            if tree:
                for n in tree.body:
                    if isinstance(n, ast.ClassDef) and n.name == name:
                        return n
        return self.repo.models.classes.get(name)

    def _find_function(self, name: str, file: str, imports: dict[str, tuple[str | None, str | None]]):  # type: ignore[no-untyped-def]
        candidates = [file] + [v[0] for v in imports.values() if v[0]]
        for f in candidates:
            tree = self.repo.trees.get(f)
            if tree:
                for n in tree.body:
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
                        return n
        return None


# ------------------------------------------------------------------ adapter


class PythonStaticAdapter(DiscoveryAdapter):
    name = "python-static"
    strategy = "static"
    supported = ("FastAPI", "Flask", "Django")
    prerequisites = "Python source files (parsed with stdlib ast; nothing is imported or executed)"

    def applicable(self, ctx: DiscoveryContext) -> Applicability:
        if ctx.framework in self.supported:
            return Applicability(True)
        return Applicability(False, f"framework {ctx.framework!r} is not a supported Python framework")

    def discover(self, ctx: DiscoveryContext) -> DiscoveryOutcome:
        files = list(iter_source_files(ctx.backend_dir, {".py"}))
        if not files:
            raise DiscoveryError("no Python files found in backend directory")
        repo = _Repo(ctx.root, files)
        outcome = DiscoveryOutcome()
        for f, msg in repo.syntax_errors:
            outcome.warnings.append(DiscoveryWarning(adapter=self.name, message=f"could not parse: {msg}", source_file=f))
        if ctx.framework == "Django":
            _DjangoAnalyzer(repo, outcome).run()
            outcome.limitations += [
                "Django: HTTP methods for plain function views are not statically determinable (GET assumed, low confidence).",
                "Django: DRF routers/ViewSets, dynamically built urlpatterns and middleware-enforced auth are not resolved.",
            ]
        else:
            an = _DecoratorAnalyzer(repo, outcome, ctx.framework or "FastAPI")
            an.collect()
            an.emit()
            outcome.limitations += [
                "Routes registered dynamically (loops, add_api_route with computed values, plugins) are not discovered.",
                "Auth requirements are inferred only from dependency/decorator names; middleware-level auth is not seen.",
                "Request/response schemas are derived from type annotations in analysed code only.",
            ]
        if not outcome.endpoints and not outcome.potential_routes:
            raise DiscoveryError("no routes found by static analysis")
        outcome.complete = False
        outcome.detail = f"analysed {len(repo.trees)} Python files"
        return outcome
