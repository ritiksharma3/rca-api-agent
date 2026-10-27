"""Static analysis of NestJS controllers (tree-sitter TypeScript grammar).

Reads ``@Controller(...)`` + ``@Get/@Post/...`` decorators, global prefix / URI versioning, guards (``@UseGuards``, ``@Public``,
a global ``APP_GUARD``) and ``@Body() dto: SomeDto`` -- the DTO class is resolved in the project and its class-validator
decorators (``@IsEmail``, ``@IsInt``, ``@Min``, ``@IsOptional`` ...) become a real JSON schema, so no LLM guess is needed.
Nothing is executed or imported.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models.endpoint import Confidence, Endpoint, Evidence, ParamLocation, Parameter, PotentialRoute, RequestBody, ResponseSpec
from ..utils.filesystem import iter_source_files, read_text, rel
from .base import DiscoveryOutcome
from .normalizer import join_paths, normalize_path
from .ts_common import children_of, first_of, line_of, named_children, object_pairs, parse, string_value, text, walk

HTTP = {"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Head": "HEAD", "Options": "OPTIONS", "All": None}
PUBLIC = {"Public", "SkipAuth", "AllowAnonymous", "NoAuth", "IsPublic", "SkipJwtAuth", "Anonymous"}
AUTH = {"UseGuards", "ApiBearerAuth", "ApiSecurity", "ApiBasicAuth", "ApiOAuth2", "Auth", "Authenticated", "Roles", "Permissions"}
ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
MAX_DTO_DEPTH = 3


def _deco(node: Any) -> tuple[str, list[Any]]:
    """('Get', [arg nodes]) for a `decorator` node; works for `@Public` and `@Get(':id')`."""
    inner = first_of(node, "call_expression", "identifier", "member_expression")
    if inner is None:
        return "", []
    if inner.type == "call_expression":
        fn = inner.child_by_field_name("function")
        args = inner.child_by_field_name("arguments")
        return (text(fn) if fn is not None else ""), (named_children(args) if args is not None else [])
    return text(inner), []


def _str_list(node: Any) -> list[str]:
    v = string_value(node)
    if v is not None:
        return [v]
    if node is not None and node.type == "array":
        return [s for s in (string_value(n) for n in named_children(node)) if s is not None]
    return []


_object_pairs = object_pairs


class _Project:
    """Cross-file facts: DTO classes, enums, global prefix / versioning / global guard."""

    def __init__(self, root: Path, backend_dir: Path):
        self.root = root
        self.classes: dict[str, tuple[Any, str]] = {}
        self.enums: dict[str, list[Any]] = {}
        self.prefix = ""
        self.uri_versioning = False
        self.global_guard = False
        self.files: list[Path] = []
        self._trees: dict[Path, Any] = {}
        for f in iter_source_files(backend_dir, {".ts"}):
            if f.name.endswith((".spec.ts", ".d.ts", ".e2e-spec.ts")):
                continue
            src = read_text(f)
            if not src:
                continue
            self.files.append(f)
            m = re.search(r"setGlobalPrefix\(\s*['\"`]([^'\"`]+)['\"`]", src)
            if m:
                self.prefix = m.group(1)
            if "enableVersioning" in src and "VersioningType.URI" in src:
                self.uri_versioning = True
            if "APP_GUARD" in src:
                self.global_guard = True
            if "class " in src or "enum " in src:
                tree = parse("typescript", src)
                self._trees[f] = tree
                for n in walk(tree.root_node):
                    if n.type in ("class_declaration", "abstract_class_declaration"):
                        nm = n.child_by_field_name("name")
                        if nm is not None:
                            self.classes.setdefault(text(nm), (n, src))
                    elif n.type == "enum_declaration":
                        nm = n.child_by_field_name("name")
                        body = n.child_by_field_name("body")
                        if nm is not None and body is not None:
                            self.enums[text(nm)] = [c for c in named_children(body)]

    def tree(self, f: Path) -> Any:
        if f not in self._trees:
            self._trees[f] = parse("typescript", read_text(f))
        return self._trees[f]

    # ------------------------------------------------------------------ DTO -> JSON schema
    def dto_schema(self, name: str, depth: int = 0, seen: tuple[str, ...] = ()) -> dict[str, Any] | None:
        if name not in self.classes or depth > MAX_DTO_DEPTH or name in seen:
            return None
        cls, _src = self.classes[name]
        props: dict[str, Any] = {}
        required: list[str] = []
        heritage = next((text(c) for c in cls.children if c.type == "class_heritage"), "")
        mapped = re.search(r"\b(PartialType|PickType|OmitType|IntersectionType)\(\s*(\w+)", heritage)
        base = mapped.group(2) if mapped else (re.search(r"\bextends\s+(\w+)", heritage).group(1) if re.search(r"\bextends\s+(\w+)", heritage) else None)
        if base:
            parent = self.dto_schema(base, depth + 1, (*seen, name)) or {}
            props.update(parent.get("properties", {}))
            required += [] if (mapped and mapped.group(1) == "PartialType") else parent.get("required", [])
        body = cls.child_by_field_name("body")
        if body is None:
            return {"type": "object", "properties": props, "required": required} if props else None
        for field in children_of(body, "public_field_definition", "property_signature"):
            fname = field.child_by_field_name("name") or first_of(field, "property_identifier")
            if fname is None:
                continue
            decos = [_deco(d) for d in children_of(field, "decorator")]
            ann = first_of(field, "type_annotation")
            optional = any(c.type == "?" for c in field.children) or any(d[0] in ("IsOptional", "ValidateIf") for d in decos)
            schema = self._field_schema(text(ann).lstrip(":").strip() if ann is not None else "", decos, field, depth, (*seen, name))
            props[text(fname)] = schema
            if not optional and not (mapped and mapped.group(1) == "PartialType"):
                required.append(text(fname))
        return {"type": "object", "properties": props, "required": sorted(set(required))} if props else None

    def _field_schema(self, ts_type: str, decos: list[tuple[str, list[Any]]], field: Any, depth: int, seen: tuple[str, ...]) -> dict[str, Any]:
        t = ts_type.strip()
        schema: dict[str, Any] = {}
        if t.endswith("[]") or t.startswith("Array<"):
            inner = t[:-2] if t.endswith("[]") else t[6:-1]
            schema = {"type": "array", "items": self._field_schema(inner, [], field, depth + 1, seen)}
        elif t in ("string", "String"):
            schema = {"type": "string"}
        elif t in ("number", "Number"):
            schema = {"type": "number"}
        elif t in ("boolean", "Boolean"):
            schema = {"type": "boolean"}
        elif t == "Date":
            schema = {"type": "string", "format": "date-time"}
        elif re.fullmatch(r"('[^']*'\s*\|\s*)*'[^']*'", t):
            schema = {"type": "string", "enum": re.findall(r"'([^']*)'", t)}
        elif re.fullmatch(r"\w+", t) and t in self.enums:
            schema = self._enum_schema(t)
        elif re.fullmatch(r"\w+", t):
            schema = self.dto_schema(t, depth + 1, seen) or {}
        nested = next((re.search(r"\(\)\s*=>\s*(\w+)", text(a)) for n, args in decos if n == "Type" for a in args[:1]), None)
        if nested and nested.group(1) in self.classes:
            sub = self.dto_schema(nested.group(1), depth + 1, seen) or {}
            schema = {"type": "array", "items": sub} if schema.get("type") == "array" else sub
        for name, args in decos:
            a = [text(x) for x in args]
            if name == "IsEmail":
                schema.update(type="string", format="email")
            elif name == "IsUUID":
                schema.update(type="string", format="uuid")
            elif name in ("IsUrl", "IsURL"):
                schema.update(type="string", format="uri")
            elif name in ("IsDateString", "IsISO8601"):
                schema.update(type="string", format="date-time")
            elif name == "IsInt":
                schema["type"] = "integer"
            elif name == "IsPositive":
                schema.update(type=schema.get("type", "number"), minimum=1)
            elif name in ("Min", "Max") and a and re.fullmatch(r"-?\d+(\.\d+)?", a[0]):
                schema["minimum" if name == "Min" else "maximum"] = float(a[0]) if "." in a[0] else int(a[0])
            elif name in ("MinLength", "MaxLength") and a and a[0].isdigit():
                schema["minLength" if name == "MinLength" else "maxLength"] = int(a[0])
            elif name == "Length" and a and a[0].isdigit():
                schema["minLength"] = int(a[0])
                if len(a) > 1 and a[1].isdigit():
                    schema["maxLength"] = int(a[1])
            elif name == "IsNotEmpty":
                schema.setdefault("minLength", 1)
            elif name == "IsString":
                schema.setdefault("type", "string")
            elif name == "IsBoolean":
                schema["type"] = "boolean"
            elif name == "IsNumber":
                schema.setdefault("type", "number")
            elif name == "IsArray":
                schema.setdefault("type", "array")
            elif name == "IsIn" and args and args[0].type == "array":
                vals = [string_value(n) if string_value(n) is not None else text(n) for n in named_children(args[0])]
                schema["enum"] = [int(v) if isinstance(v, str) and v.isdigit() else v for v in vals]
            elif name == "IsEnum" and a and a[0] in self.enums:
                schema.update(self._enum_schema(a[0]))
        return schema

    def _enum_schema(self, name: str) -> dict[str, Any]:
        vals: list[Any] = []
        for member in self.enums.get(name, []):
            value = member.child_by_field_name("value")
            if value is not None:
                v = string_value(value)
                vals.append(v if v is not None else (int(text(value)) if text(value).lstrip("-").isdigit() else text(value)))
            else:
                vals.append(len(vals))
        if not vals:
            return {}
        return {"type": "integer" if all(isinstance(v, int) for v in vals) else "string", "enum": vals}


def _class_decorators(cls: Any) -> list[tuple[str, list[Any]]]:
    out = [_deco(d) for d in children_of(cls, "decorator")]
    parent = cls.parent
    if parent is not None and parent.type == "export_statement":
        out += [_deco(d) for d in children_of(parent, "decorator")]
    return out


def _members(body: Any) -> list[tuple[Any, list[tuple[str, list[Any]]]]]:
    """(method_definition, its decorators): decorators are siblings that precede the method inside class_body."""
    out, pending = [], []
    for c in body.children:
        if c.type == "decorator":
            pending.append(_deco(c))
        elif c.type == "method_definition":
            out.append((c, pending))
            pending = []
        elif c.type not in ("{", "}", ";", "comment"):
            pending = []
    return out


def analyze_nest(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    proj = _Project(root, backend_dir)
    analysed = 0
    for f in proj.files:
        src = read_text(f)
        if "@Controller" not in src:
            continue
        analysed += 1
        name = rel(f, root)
        tree = proj.tree(f)
        for cls in (n for n in walk(tree.root_node) if n.type in ("class_declaration", "abstract_class_declaration")):
            cdecos = _class_decorators(cls)
            ctrl = next(((n, a) for n, a in cdecos if n == "Controller"), None)
            body = cls.child_by_field_name("body")
            if ctrl is None or body is None:
                continue
            cls_name = text(cls.child_by_field_name("name"))
            paths, version = [""], None
            if ctrl[1]:
                arg = ctrl[1][0]
                pairs = _object_pairs(arg)
                paths = _str_list(pairs.get("path")) or ([""] if pairs else _str_list(arg) or [""])
                v = string_value(pairs["version"]) if "version" in pairs else None
                version = v
            class_names = {n for n, _ in cdecos}
            class_auth = bool(class_names & AUTH)
            class_public = bool(class_names & PUBLIC)
            guards = [text(a) for n, args in cdecos if n == "UseGuards" for a in args]
            for method, mdecos in _members(body):
                route_decos = [(n, a) for n, a in mdecos if n in HTTP]
                if not route_decos:
                    continue
                mnames = {n for n, _ in mdecos}
                mguards = guards + [text(a) for n, args in mdecos if n == "UseGuards" for a in args]
                public = bool(mnames & PUBLIC) or (class_public and not (mnames & AUTH))
                auth = bool(mnames & AUTH) or class_auth
                requires_auth: bool | None = False if public else (True if (auth or proj.global_guard) else None)
                params_text = text(method.child_by_field_name("parameters")) if method.child_by_field_name("parameters") is not None else ""
                for dname, dargs in route_decos:
                    verbs = [HTTP[dname]] if HTTP[dname] else ALL_METHODS
                    sub_paths = _str_list(dargs[0]) if dargs else [""]
                    code = next((int(text(a[0])) for n, a in mdecos if n == "HttpCode" and a and text(a[0]).isdigit()), None)
                    for cpath in paths:
                        for spath in sub_paths or [""]:
                            vprefix = f"v{version}" if (version and proj.uri_versioning) else ""
                            full = join_paths(proj.prefix, vprefix, cpath, spath)
                            route, pnames = normalize_path(full)
                            for verb in verbs:
                                _emit(outcome, proj, name, cls_name, method, verb, route, full, pnames, params_text, requires_auth,
                                      mguards, code, version if version and not proj.uri_versioning else None, proj.global_guard and not (auth or public))
    for f in proj.files:  # dynamic controller paths are surfaced, never guessed
        src = read_text(f)
        for m in re.finditer(r"@Controller\(\s*(?!['\"`{\[)])([^)\s][^)]*)\)", src):
            outcome.potential_routes.append(PotentialRoute(description=f"@Controller({m.group(1)[:40]})", reason="controller path is not a static string",
                                                           source_file=rel(f, root), line=src[:m.start()].count("\n") + 1, strategy="static"))
    if proj.global_guard:
        outcome.limitations.append("NestJS: a global APP_GUARD was found; routes without @Public()/@SkipAuth() are treated as authenticated (the guard's own logic is not analysed).")
    return analysed


def _emit(outcome: DiscoveryOutcome, proj: _Project, file: str, cls_name: str, method: Any, verb: str, route: str, original: str,
          pnames: list[str], params_text: str, requires_auth: bool | None, guards: list[str], code: int | None,
          unapplied_version: str | None, via_global: bool) -> None:
    params = []
    for n in pnames:
        pm = re.search(r"@Param\(\s*['\"]" + re.escape(n) + r"['\"][^)]*\)\s*\w+\s*:\s*(\w+)", params_text)
        sch: dict[str, Any] = {"type": "integer" if (pm and pm.group(1) == "number") or "ParseIntPipe" in params_text else "string"}
        if "ParseUUIDPipe" in params_text:
            sch = {"type": "string", "format": "uuid"}
        params.append(Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def=sch))
    for qm in re.finditer(r"@Query\(\s*['\"](\w+)['\"]\s*(?:,[^)]*)?\)\s*\w+(\?)?\s*:\s*(\w+)", params_text):
        t = {"number": "integer" if "ParseIntPipe" in params_text else "number", "boolean": "boolean"}.get(qm.group(3), "string")
        params.append(Parameter(name=qm.group(1), location=ParamLocation.QUERY, required=qm.group(2) is None, schema_def={"type": t}))
    qd = re.search(r"@Query\(\s*\)\s*\w+\s*:\s*(\w+)", params_text)
    if qd:
        for pname, psch in ((proj.dto_schema(qd.group(1)) or {}).get("properties", {}).items()):
            params.append(Parameter(name=pname, location=ParamLocation.QUERY, required=False, schema_def=psch or {"type": "string"}))
    body = None
    if verb in ("POST", "PUT", "PATCH"):
        bm = re.search(r"@Body\(\s*\)\s*\w+\s*:\s*(\w+)", params_text)
        if bm:
            sch = proj.dto_schema(bm.group(1))
            if sch:
                body = RequestBody(schema_def=sch, required=True)
        else:
            fields = re.findall(r"@Body\(\s*['\"](\w+)['\"]", params_text)
            if fields:
                body = RequestBody(schema_def={"type": "object", "properties": {f: {} for f in fields}, "required": fields}, required=True)
    status = code if code else (201 if verb == "POST" else 200)
    warns = ["response schema not established statically"]
    if body is None and verb in ("POST", "PUT", "PATCH"):
        warns.append("request body shape not established (no typed @Body() DTO found)")
    if unapplied_version:
        warns.append(f"controller version '{unapplied_version}' found but URI versioning is not enabled in the analysed code; route may need a /v{unapplied_version} prefix")
    if via_global:
        warns.append("treated as authenticated because the project registers a global APP_GUARD")
    outcome.endpoints.append(Endpoint(
        method=verb, route=route, original_path=original, path_param_names=pnames, parameters=params, request_body=body,
        responses=[ResponseSpec(status=str(status), description="Nest default" if not code else "@HttpCode")],
        requires_auth=requires_auth, security_schemes=guards[:3] + (["APP_GUARD"] if via_global else []),
        source_file=file, line=line_of(method), handler=f"{cls_name}.{text(method.child_by_field_name('name'))}",
        strategy="static", confidence=Confidence.HIGH, warnings=warns,
        evidence=[Evidence(source=file, detail=f"@{verb.capitalize()}() in {cls_name}", line=line_of(method))],
    ))
