"""Static analysis for Spring (Java), ASP.NET Core (C#) and Go routers via tree-sitter.

These analyzers are intentionally shallower than the Python/PHP/Express ones: routes and path/query parameters
are extracted, request-body schemas only where a DTO class is found in the repository. Confidence is labelled
accordingly and gaps are recorded as limitations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models.endpoint import Confidence, Endpoint, Evidence, ParamLocation, Parameter, PotentialRoute, RequestBody
from ..utils.filesystem import iter_source_files, read_text, rel
from .base import DiscoveryOutcome
from .normalizer import join_paths, normalize_path
from .ts_common import children_of, first_of, line_of, named_children, parse, string_value, text, walk

JAVA_TYPES = {
    "String": {"type": "string"}, "int": {"type": "integer"}, "Integer": {"type": "integer"}, "long": {"type": "integer"},
    "Long": {"type": "integer"}, "short": {"type": "integer"}, "double": {"type": "number"}, "Double": {"type": "number"},
    "float": {"type": "number"}, "Float": {"type": "number"}, "BigDecimal": {"type": "number"}, "boolean": {"type": "boolean"},
    "Boolean": {"type": "boolean"}, "LocalDate": {"type": "string", "format": "date"},
    "LocalDateTime": {"type": "string", "format": "date-time"}, "UUID": {"type": "string", "format": "uuid"},
}
CS_TYPES = {
    "string": {"type": "string"}, "int": {"type": "integer"}, "long": {"type": "integer"}, "short": {"type": "integer"},
    "double": {"type": "number"}, "float": {"type": "number"}, "decimal": {"type": "number"}, "bool": {"type": "boolean"},
    "Guid": {"type": "string", "format": "uuid"}, "DateTime": {"type": "string", "format": "date-time"},
}


def _annotation_args(ann: Any) -> tuple[list[Any], dict[str, Any]]:
    args_node = first_of(ann, "annotation_argument_list", "attribute_argument_list")
    pos: list[Any] = []
    kw: dict[str, Any] = {}
    if args_node is None:
        return pos, kw
    for c in named_children(args_node):
        if c.type == "element_value_pair":
            k = c.child_by_field_name("key")
            v = c.child_by_field_name("value")
            if k is not None and v is not None:
                kw[text(k)] = v
        elif c.type == "attribute_argument":
            inner = named_children(c)
            if len(inner) == 2 and inner[0].type == "name_equals":
                kw[text(inner[0]).rstrip("= ").strip()] = inner[1]
            elif inner:
                pos.append(inner[-1])
        else:
            pos.append(c)
    return pos, kw


# ------------------------------------------------------------------ Java / Spring


_SPRING_VERB = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "PatchMapping": "PATCH", "DeleteMapping": "DELETE"}
_JAVA_AUTH = {"PreAuthorize", "Secured", "RolesAllowed", "PostAuthorize"}


def _java_annotations(node: Any) -> list[Any]:
    mods = first_of(node, "modifiers")
    return [c for c in mods.children if c.type in ("annotation", "marker_annotation")] if mods is not None else []


def _ann_name(a: Any) -> str:
    n = a.child_by_field_name("name")
    return text(n) if n is not None else text(first_of(a, "identifier"))


def _ann_paths(ann: Any) -> list[str]:
    pos, kw = _annotation_args(ann)
    node = kw.get("value") or kw.get("path") or (pos[0] if pos else None)
    if node is None:
        return [""]
    vals = [string_value(n) for n in walk(node) if n.type in ("string_literal",)]
    return [v for v in vals if v is not None] or [""]


def _java_type_schema(tnode: Any, classes: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    t = text(tnode)
    if t in JAVA_TYPES:
        return dict(JAVA_TYPES[t])
    m = re.match(r"(?:List|Set|Collection)<(\w+)>", t)
    if m:
        inner = JAVA_TYPES.get(m.group(1))
        return {"type": "array", "items": dict(inner) if inner else {}}
    if t in classes and depth < 3:
        return _java_class_schema(t, classes, depth + 1)
    return {}


def _java_class_schema(name: str, classes: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    cls = classes[name]
    body = cls.child_by_field_name("body") or first_of(cls, "class_body")
    props: dict[str, Any] = {}
    required: list[str] = []
    for fld in children_of(body, "field_declaration") if body is not None else []:
        decl = first_of(fld, "variable_declarator")
        tnode = fld.child_by_field_name("type")
        if decl is None or tnode is None:
            continue
        fname = text(decl.child_by_field_name("name"))
        schema = _java_type_schema(tnode, classes, depth)
        for a in _java_annotations(fld):
            an = _ann_name(a)
            pos, kw = _annotation_args(a)
            if an in ("NotNull", "NotBlank", "NotEmpty"):
                required.append(fname)
            elif an == "Size":
                if "min" in kw:
                    schema["minLength"] = int(text(kw["min"]))
                if "max" in kw:
                    schema["maxLength"] = int(text(kw["max"]))
            elif an == "Min" and pos:
                schema["minimum"] = int(text(pos[0]))
            elif an == "Max" and pos:
                schema["maximum"] = int(text(pos[0]))
            elif an == "Email":
                schema["format"] = "email"
        props[fname] = schema
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = sorted(set(required))
    return out


def analyze_spring(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    parsed: list[tuple[str, Any]] = []
    classes: dict[str, Any] = {}
    for f in iter_source_files(backend_dir, {".java"}):
        src = read_text(f)
        tree = parse("java", src)
        parsed.append((rel(f, root), tree))
        for n in walk(tree.root_node):
            if n.type == "class_declaration":
                nm = n.child_by_field_name("name")
                if nm is not None:
                    classes.setdefault(text(nm), n)
    for fname, tree in parsed:
        for cls in (n for n in walk(tree.root_node) if n.type == "class_declaration"):
            anns = _java_annotations(cls)
            names = {_ann_name(a) for a in anns}
            if not names & {"RestController", "Controller"}:
                continue
            prefixes = [""]
            for a in anns:
                if _ann_name(a) == "RequestMapping":
                    prefixes = _ann_paths(a)
            cls_auth = bool(names & _JAVA_AUTH)
            body = cls.child_by_field_name("body") or first_of(cls, "class_body")
            for meth in children_of(body, "method_declaration") if body is not None else []:
                for a in _java_annotations(meth):
                    an = _ann_name(a)
                    if an in _SPRING_VERB:
                        methods = [_SPRING_VERB[an]]
                        partial = False
                    elif an == "RequestMapping":
                        _, kw = _annotation_args(a)
                        ms = [m for m in re.findall(r"RequestMethod\.(\w+)", text(kw["method"]))] if "method" in kw else []
                        methods = [m.upper() for m in ms] or ["GET"]
                        partial = not ms
                    else:
                        continue
                    paths = _ann_paths(a)
                    m_auth = cls_auth or bool({_ann_name(x) for x in _java_annotations(meth)} & _JAVA_AUTH)
                    params, body_schema = _java_params(meth, classes)
                    for pfx in prefixes:
                        for p in paths:
                            full = join_paths(pfx, p) if (pfx or p) else "/"
                            route, pnames = normalize_path(full)
                            plist = [x for x in params if x.location != ParamLocation.PATH]
                            plist += [Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def=next((q.schema_def for q in params if q.location == ParamLocation.PATH and q.name == n), {"type": "string"})) for n in pnames]
                            for m in methods:
                                warns = ["response schema not established statically"]
                                if partial:
                                    warns.append("@RequestMapping without method: GET assumed")
                                outcome.endpoints.append(
                                    Endpoint(
                                        method=m, route=route, original_path=full, path_param_names=pnames, parameters=plist,
                                        request_body=body_schema if m in ("POST", "PUT", "PATCH") else None,
                                        requires_auth=True if m_auth else None, security_schemes=["annotation:authorize"] if m_auth else [],
                                        source_file=fname, line=line_of(meth), handler=text(meth.child_by_field_name("name")),
                                        strategy="static", confidence=Confidence.MEDIUM if partial else Confidence.HIGH, warnings=warns,
                                        evidence=[Evidence(source=fname, detail=f"@{an} on {text(meth.child_by_field_name('name'))}()", line=line_of(meth))],
                                    )
                                )
    return len(parsed)


def _java_params(meth: Any, classes: dict[str, Any]) -> tuple[list[Parameter], RequestBody | None]:
    params: list[Parameter] = []
    body: RequestBody | None = None
    fp = meth.child_by_field_name("parameters") or first_of(meth, "formal_parameters")
    for p in children_of(fp, "formal_parameter") if fp is not None else []:
        tnode = p.child_by_field_name("type")
        name = text(p.child_by_field_name("name"))
        anns = {_ann_name(a): a for a in _java_annotations(p)}
        schema = _java_type_schema(tnode, classes) if tnode is not None else {}
        if "PathVariable" in anns:
            pos, kw = _annotation_args(anns["PathVariable"])
            nm = string_value(pos[0]) if pos and string_value(pos[0]) else (string_value(kw["value"]) if "value" in kw else None) or name
            params.append(Parameter(name=nm, location=ParamLocation.PATH, required=True, schema_def=schema or {"type": "string"}))
        elif "RequestParam" in anns:
            pos, kw = _annotation_args(anns["RequestParam"])
            req = "required" in kw and text(kw["required"]) == "false"
            has_default = "defaultValue" in kw
            nm = string_value(pos[0]) if pos and string_value(pos[0]) else (string_value(kw["value"]) if "value" in kw else None) or name
            params.append(Parameter(name=nm, location=ParamLocation.QUERY, required=not (req or has_default), schema_def=schema or {"type": "string"}))
        elif "RequestBody" in anns:
            body = RequestBody(content_type="application/json", schema_def=schema, required=True)
    return params, body


# ------------------------------------------------------------------ C# / ASP.NET Core


_CS_VERBS = {"HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT", "HttpPatch": "PATCH", "HttpDelete": "DELETE"}
_MINIMAL = {"MapGet": "GET", "MapPost": "POST", "MapPut": "PUT", "MapPatch": "PATCH", "MapDelete": "DELETE"}


def _cs_attrs(node: Any) -> list[Any]:
    out = []
    for lst in children_of(node, "attribute_list"):
        out += children_of(lst, "attribute")
    return out


def _cs_attr_name(a: Any) -> str:
    n = first_of(a, "identifier", "qualified_name")
    return text(n).split(".")[-1] if n is not None else ""


def _cs_template(a: Any) -> str | None:
    pos, kw = _annotation_args(a)
    if pos:
        return string_value(pos[0])
    return ""


def _cs_class_schema(name: str, classes: dict[str, Any]) -> dict[str, Any]:
    cls = classes[name]
    body = first_of(cls, "declaration_list")
    props: dict[str, Any] = {}
    required: list[str] = []
    for prop in children_of(body, "property_declaration") if body is not None else []:
        pname = text(prop.child_by_field_name("name"))
        tnode = prop.child_by_field_name("type")
        t = text(tnode).rstrip("?") if tnode is not None else ""
        schema = dict(CS_TYPES.get(t, {}))
        for a in _cs_attrs(prop):
            an = _cs_attr_name(a)
            pos, kw = _annotation_args(a)
            if an == "Required":
                required.append(pname)
            elif an in ("StringLength", "MaxLength") and pos:
                schema["maxLength"] = int(text(pos[0]))
            elif an == "MinLength" and pos:
                schema["minLength"] = int(text(pos[0]))
            elif an == "Range" and len(pos) >= 2:
                schema["minimum"], schema["maximum"] = float(text(pos[0])), float(text(pos[1]))
            elif an == "EmailAddress":
                schema["format"] = "email"
        props[pname[:1].lower() + pname[1:]] = schema
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = [r[:1].lower() + r[1:] for r in required]
    return out


def analyze_aspnet(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    parsed: list[tuple[str, Any]] = []
    classes: dict[str, Any] = {}
    for f in iter_source_files(backend_dir, {".cs"}):
        tree = parse("csharp", read_text(f))
        parsed.append((rel(f, root), tree))
        for n in walk(tree.root_node):
            if n.type == "class_declaration":
                classes.setdefault(text(n.child_by_field_name("name")), n)
    for fname, tree in parsed:
        for cls in (n for n in walk(tree.root_node) if n.type == "class_declaration"):
            cname = text(cls.child_by_field_name("name"))
            cattrs = {_cs_attr_name(a): a for a in _cs_attrs(cls)}
            bases = text(first_of(cls, "base_list")) if first_of(cls, "base_list") is not None else ""
            if "ApiController" not in cattrs and "ControllerBase" not in bases and "Controller" not in bases:
                continue
            ctrl = cname[:-10] if cname.endswith("Controller") else cname
            base_tpl = _cs_template(cattrs["Route"]) if "Route" in cattrs else ""
            base_tpl = (base_tpl or "").replace("[controller]", ctrl.lower())
            cls_auth = "Authorize" in cattrs and "AllowAnonymous" not in cattrs
            body = first_of(cls, "declaration_list")
            for meth in children_of(body, "method_declaration") if body is not None else []:
                mattrs = _cs_attrs(meth)
                mnames = {_cs_attr_name(a) for a in mattrs}
                mname = text(meth.child_by_field_name("name"))
                for a in mattrs:
                    an = _cs_attr_name(a)
                    if an not in _CS_VERBS:
                        continue
                    tpl = _cs_template(a)
                    if tpl is None:
                        outcome.potential_routes.append(PotentialRoute(description=f"{cname}.{mname}", reason="route template is not a static string", source_file=fname, line=line_of(meth), strategy="static"))
                        continue
                    tpl = tpl.replace("[action]", mname.lower()).replace("[controller]", ctrl.lower())
                    full = tpl if tpl.startswith("/") else join_paths(base_tpl, tpl)
                    route, pnames = normalize_path(full)
                    types = {m.group(2): m.group(1) for m in re.finditer(r"\{(\w+):(\w+)\??\}", full)}
                    types = {v: k for k, v in types.items()}
                    params: list[Parameter] = []
                    req_body = None
                    pl = first_of(meth, "parameter_list")
                    for prm in children_of(pl, "parameter") if pl is not None else []:
                        pname = text(prm.child_by_field_name("name"))
                        ptype = text(prm.child_by_field_name("type")).rstrip("?")
                        pattrs = {_cs_attr_name(x) for x in _cs_attrs(prm)}
                        schema = dict(CS_TYPES.get(ptype, {}))
                        if pname in pnames:
                            params.append(Parameter(name=pname, location=ParamLocation.PATH, required=True, schema_def=schema or {"type": "string"}))
                        elif "FromBody" in pattrs or ptype in classes:
                            if ptype in classes:
                                req_body = RequestBody(schema_def=_cs_class_schema(ptype, classes), required=True)
                        elif schema:
                            params.append(Parameter(name=pname, location=ParamLocation.QUERY, required=False, schema_def=schema))
                    declared = {p.name for p in params if p.location == ParamLocation.PATH}
                    for n in pnames:
                        if n not in declared:
                            params.append(Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}))
                    auth = (cls_auth or "Authorize" in mnames) and "AllowAnonymous" not in mnames
                    outcome.endpoints.append(
                        Endpoint(
                            method=_CS_VERBS[an], route=route, original_path=full, path_param_names=pnames, parameters=params,
                            request_body=req_body if _CS_VERBS[an] in ("POST", "PUT", "PATCH") else None,
                            requires_auth=True if auth else (False if "AllowAnonymous" in mnames else None),
                            security_schemes=["attribute:Authorize"] if auth else [],
                            source_file=fname, line=line_of(meth), handler=f"{cname}.{mname}", strategy="static",
                            confidence=Confidence.HIGH,
                            warnings=["response schema not established statically"],
                            evidence=[Evidence(source=fname, detail=f"[{an}] on {mname}()", line=line_of(meth))],
                        )
                    )
        # Minimal APIs: app.MapGet("/x", ...)
        groups: dict[str, str] = {}
        for n in walk(tree.root_node):
            if n.type == "variable_declarator" and "MapGroup" in text(n):
                m = re.search(r'MapGroup\(\s*"([^"]*)"', text(n))
                if m:
                    groups[text(first_of(n, "identifier"))] = m.group(1)
        for n in walk(tree.root_node):
            if n.type != "invocation_expression":
                continue
            fn = n.child_by_field_name("function") or first_of(n, "member_access_expression")
            if fn is None or fn.type != "member_access_expression":
                continue
            name = text(fn.child_by_field_name("name"))
            if name not in _MINIMAL:
                continue
            recv = text(fn.child_by_field_name("expression"))
            args = first_of(n, "argument_list")
            first = named_children(args)[0] if args is not None and named_children(args) else None
            path = string_value(named_children(first)[0]) if first is not None and named_children(first) else None
            if path is None:
                outcome.potential_routes.append(PotentialRoute(description=f"{recv}.{name}(<dynamic>)", reason="minimal API path is not static", source_file=fname, line=line_of(n), strategy="static"))
                continue
            full = join_paths(groups.get(recv, ""), path)
            route, pnames = normalize_path(full)
            outcome.endpoints.append(
                Endpoint(
                    method=_MINIMAL[name], route=route, original_path=full, path_param_names=pnames, strategy="static",
                    parameters=[Parameter(name=x, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for x in pnames],
                    source_file=fname, line=line_of(n), confidence=Confidence.MEDIUM,
                    warnings=["minimal API: parameters/body/auth not analysed"] + ([] if recv not in groups and recv in ("app", "endpoints") else ([] if recv in groups else [f"receiver '{recv}' group prefix unresolved"])),
                    evidence=[Evidence(source=fname, detail=f"{recv}.{name}('{path}')", line=line_of(n))],
                )
            )
    return len(parsed)


# ------------------------------------------------------------------ Go


_GO_VERBS = {"GET": "GET", "POST": "POST", "PUT": "PUT", "PATCH": "PATCH", "DELETE": "DELETE",
             "Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE"}


def analyze_go(root: Path, backend_dir: Path, outcome: DiscoveryOutcome) -> int:
    count = 0
    for f in iter_source_files(backend_dir, {".go"}):
        src = read_text(f)
        if not re.search(r"gin|echo|chi|mux|HandleFunc|http\.Handle", src):
            continue
        count += 1
        fname = rel(f, root)
        tree = parse("go", src)
        group_prefix: dict[str, str] = {}
        for n in walk(tree.root_node):
            if n.type in ("short_var_declaration", "assignment_statement"):
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is None or right is None:
                    continue
                m = re.search(r'(\w+)\.(?:Group|Route|PathPrefix)\(\s*"([^"]*)"', text(right))
                if m:
                    parent_pfx = group_prefix.get(m.group(1), "")
                    group_prefix[text(left).split(",")[0].strip()] = join_paths(parent_pfx, m.group(2))
        for n in walk(tree.root_node):
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            if fn is None or fn.type != "selector_expression":
                continue
            fld = text(fn.child_by_field_name("field"))
            recv = text(fn.child_by_field_name("operand"))
            args_node = n.child_by_field_name("arguments")
            args = named_children(args_node) if args_node is not None else []
            if not args:
                continue
            path = string_value(args[0])
            methods: list[str]
            if fld in _GO_VERBS:
                methods = [_GO_VERBS[fld]]
            elif fld in ("Handle", "HandleFunc"):
                if path is None:
                    outcome.potential_routes.append(PotentialRoute(description=f"{recv}.{fld}(<dynamic>)", reason="route pattern is not static", source_file=fname, line=line_of(n), strategy="static"))
                    continue
                m = re.match(r"^(GET|POST|PUT|PATCH|DELETE)\s+(/.*)$", path)  # Go 1.22 method patterns
                if m:
                    methods, path = [m.group(1)], m.group(2)
                else:
                    methods = ["GET"]
            else:
                continue
            if path is None:
                outcome.potential_routes.append(PotentialRoute(description=f"{recv}.{fld}(<dynamic>)", reason="route path is not a static string", source_file=fname, line=line_of(n), strategy="static"))
                continue
            if fld in _GO_VERBS and not (recv in group_prefix or recv in ("r", "router", "e", "app", "mux", "api", "v1", "g", "engine") or "Router" in src or "gin" in src or "echo" in src):
                continue
            pfx = group_prefix.get(recv, "")
            # chi: r.Route("/x", func(r chi.Router) { r.Get(...) }) – prefix from enclosing Route() call
            cur = n.parent
            while cur is not None:
                if cur.type == "call_expression":
                    cf = cur.child_by_field_name("function")
                    if cf is not None and cf.type == "selector_expression" and text(cf.child_by_field_name("field")) == "Route":
                        ca = cur.child_by_field_name("arguments")
                        ca_nodes = named_children(ca) if ca is not None else []
                        if ca_nodes and string_value(ca_nodes[0]) is not None:
                            pfx = join_paths(string_value(ca_nodes[0]) or "", pfx)
                cur = cur.parent
            full = join_paths(pfx, path) if (pfx or path) else "/"
            route, pnames = normalize_path(re.sub(r"\*(\w+)", r"{\1}", full))
            warns = ["request/response schemas and auth not analysed for Go handlers"]
            if recv not in group_prefix and pfx == "" and fld in _GO_VERBS and recv not in ("r", "router", "e", "app", "mux", "engine"):
                warns.append(f"receiver '{recv}' prefix could not be resolved")
            for m_ in methods:
                outcome.endpoints.append(
                    Endpoint(
                        method=m_, route=route, original_path=full, path_param_names=pnames, strategy="static",
                        parameters=[Parameter(name=x, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for x in pnames],
                        source_file=fname, line=line_of(n), confidence=Confidence.MEDIUM, warnings=warns,
                        evidence=[Evidence(source=fname, detail=f"{recv}.{fld}('{path}')", line=line_of(n))],
                    )
                )
    return count
