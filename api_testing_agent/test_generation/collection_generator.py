"""Build a Postman Collection v2.1 document, an environment template and a test plan from the inventory."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml
from pydantic import BaseModel, Field

from ..auth.headers import HeaderPlan
from ..auth.provider import AuthResolution
from ..errors import CollectionGenerationError, InvalidInputError
from ..models.endpoint import Endpoint, EndpointInventory, ParamLocation, ValidationStatus
from ..models.execution import BlockedScenario, PlannedRequest, Scenario, TestPlan
from ..security.safety_policy import SafetyPolicy
from .assertions import json_schema_assertion, response_time_assertion, status_assertion
from .schema_analyzer import is_meaningful, to_json_schema
from .test_data import CannotGenerate, DataGenerator

COLLECTION_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
BODY_METHODS = {"POST", "PUT", "PATCH"}
SUPPORTED_BODY_TYPES = ("application/json", "application/x-www-form-urlencoded")
LOGIN_TIER = 3
_ID_NAME = re.compile(r"(^|_)id$|[a-z]Id$|^id$", re.I)


_API_PREFIX = re.compile(r"^(api|v\d+(\.\d+)*|rest|public|internal|services?)$", re.I)
_SESSION_END = re.compile(r"log[-_]?out|sign[-_]?out|revoke|invalidate|end[-_]?session|disconnect", re.I)
_PARAM_SEG = re.compile(r"^\{[^{}]+\}$")
_ID_KEYS = ("id", "_id", "uuid", "guid", "key", "slug")


def resource_of(route: str) -> str:
    """Folder name for a route: its first segment after generic prefixes such as /api/v1."""
    segs = [x for x in route.split("/") if x]
    while len(segs) > 1 and _API_PREFIX.match(segs[0]):
        segs = segs[1:]
    return segs[0] if segs and not _PARAM_SEG.match(segs[0]) else "root"


def is_session_end(method: str, route: str) -> bool:
    """Endpoints that invalidate the token the rest of the run is using (logout ...); they must run last."""
    last = next((x for x in reversed(route.split("/")) if x and not _PARAM_SEG.match(x)), "")
    return method in ("POST", "DELETE", "GET") and bool(_SESSION_END.search(last))


def lifecycle_rank(method: str, route: str) -> int:
    """create (0) -> list/singleton (1) -> read one (2) -> update (3) -> delete (4): a resource is used in the order it lives."""
    segs = [x for x in route.split("/") if x]
    tail_param = bool(segs) and bool(_PARAM_SEG.match(segs[-1]))
    any_param = any(_PARAM_SEG.match(x) for x in segs)
    if method == "POST":
        return 3 if any_param else 0
    if method in ("GET", "HEAD", "OPTIONS"):
        return 2 if tail_param else (1 if not any_param else 2)
    if method == "DELETE":
        return 4
    return 3


def param_prefix(route: str, name: str) -> str:
    """The collection route a path parameter belongs to: /api/v1/products/{id} -> /api/v1/products."""
    i = route.find("{" + name + "}")
    return route[:i].rstrip("/") if i >= 0 else route


def chain_key(prefix: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", re.sub(r"\{(\w+)\}", r"\1", prefix)).strip("_") or "root"


def capture_script(key: str, param: str, listing: bool) -> list[str]:
    """Test-script lines that remember a resource id from a response for the requests that need `/{id}` later."""
    names = list(dict.fromkeys([param, *_ID_KEYS, param.replace("_", "")]))
    pick = ("function pick(o) { if (!o || typeof o !== 'object') { return null; } "
            f"var names = {json.dumps(names)}; "
            "for (var i = 0; i < names.length; i++) { var v = o[names[i]]; if (typeof v === 'string' || typeof v === 'number') { return String(v); } } "
            "return null; }")
    if listing:
        body = [
            "var arr = Array.isArray(j) ? j : null;",
            "if (!arr && j && typeof j === 'object') { var ks = ['data', 'items', 'results', 'content', 'records', 'rows'];",
            "  for (var k = 0; k < ks.length && !arr; k++) { if (Array.isArray(j[ks[k]])) { arr = j[ks[k]]; } }",
            "  if (!arr) { for (var p in j) { if (Array.isArray(j[p])) { arr = j[p]; break; } } } }",
            f"if (arr && arr.length && !pm.collectionVariables.get('cur_{key}')) {{ var sid = pick(arr[0]); if (sid) {{ pm.collectionVariables.set('cur_{key}', sid); }} }}",
        ]
    else:
        body = [
            "var cid = pick(j) || pick(j && j.data) || pick(j && j.result) || pick(j && j.item) || pick(j && j.resource);",
            f"if (cid) {{ pm.collectionVariables.set('id_{key}', cid); pm.collectionVariables.set('cur_{key}', cid); }}",
        ]
    return ["(function () { try {", "  if (pm.response.code < 200 || pm.response.code >= 300) { return; }", "  var j = pm.response.json();",
            "  " + pick, *["  " + ln for ln in body], "} catch (e) { /* not JSON: nothing to remember */ } })();"]


class EndpointFixture(BaseModel):
    path_params: dict[str, Any] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    expected_status: list[int] = Field(default_factory=list)
    generated: bool = False  # body suggested by the agent (LLM), not supplied by the user: free to be made unique per run


class Fixtures(BaseModel):
    """User-supplied test data for resources that must already exist in the target system."""

    path_params: dict[str, Any] = Field(default_factory=dict)
    endpoints: dict[str, EndpointFixture] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> "Fixtures":
        if path is None:
            return cls()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return cls.model_validate(data)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            raise InvalidInputError(f"Cannot load fixtures file {path}: {exc}") from exc


@dataclass
class GenerationOptions:
    policy: SafetyPolicy = field(default_factory=SafetyPolicy)
    auth: AuthResolution | None = None
    fixtures: Fixtures = field(default_factory=Fixtures)
    seed: int = 1234
    headers: HeaderPlan | None = None  # headers the target requires on every request (API key, client version, tenant ...)


@dataclass
class GenerationResult:
    collection: dict[str, Any]
    plan: TestPlan
    environment: dict[str, Any]


@dataclass
class _Built:
    tier: int
    request: PlannedRequest
    item: dict[str, Any]


def _documented_success(ep: Endpoint) -> tuple[list[int], tuple[int, int] | None]:
    codes: list[int] = []
    rng = None
    for r in ep.responses:
        if re.fullmatch(r"2\d\d", r.status):
            codes.append(int(r.status))
        elif r.status.upper() == "2XX":
            rng = (200, 299)
    return sorted(set(codes)), rng


def _documented_client_errors(ep: Endpoint) -> list[int]:
    return sorted({int(r.status) for r in ep.responses if re.fullmatch(r"4\d\d", r.status) and int(r.status) not in (401, 403, 404)})


def _success_schema(ep: Endpoint) -> dict[str, Any] | None:
    for r in sorted(ep.responses, key=lambda x: x.status):
        if re.fullmatch(r"2\d\d", r.status) and r.schema_def and r.content_type and "json" in r.content_type:
            return r.schema_def
    return None


def _param_value(gen: DataGenerator, ep: Endpoint, p: Any, fx: EndpointFixture, glob: Fixtures, loc: ParamLocation) -> Any:
    """Resolve a parameter value without inventing existing resource ids."""
    override = (fx.path_params if loc == ParamLocation.PATH else fx.query if loc == ParamLocation.QUERY else fx.headers)
    if p.name in override:
        return override[p.name]
    if loc == ParamLocation.PATH and p.name in fx.path_params:
        return fx.path_params[p.name]
    if loc == ParamLocation.PATH and p.name in glob.path_params:
        return glob.path_params[p.name]
    if p.example is not None:
        return p.example
    s = p.schema_def or {}
    if "example" in s:
        return s["example"]
    if s.get("default") is not None:
        return s["default"]
    if s.get("enum"):
        return s["enum"][0]
    if loc == ParamLocation.PATH:
        raise CannotGenerate(f"path parameter '{p.name}' needs an existing resource; supply it in the fixtures file")
    return gen.valid(s, p.name, required=True)


class _Generator:
    def __init__(self, inv: EndpointInventory, opts: GenerationOptions):
        self.inv = inv
        self.opts = opts
        self.policy = opts.policy
        self.auth = opts.auth
        self.data = DataGenerator(opts.seed)
        self.built: list[_Built] = []
        self.blocked: list[BlockedScenario] = []
        self.created: set[str] = set()  # chain keys whose id a built POST stores in id_<key> / cur_<key>
        self.listed: set[str] = set()  # chain keys whose first list item a built GET stores in cur_<key>
        self.consumers: dict[str, str] = {}  # chain key -> path parameter name, for every `/<prefix>/{param}` route
        for e in inv.endpoints:
            for n in e.path_param_names:
                if e.route.rstrip("/").endswith("{" + n + "}"):
                    self.consumers.setdefault(chain_key(param_prefix(e.route, n)), n)
        self.creator_routes = {chain_key(e.route) for e in inv.endpoints if e.method == "POST" and not e.path_param_names}

    # ---------------------------------------------------------------- per endpoint
    def run(self) -> None:
        # build in lifecycle order so creators (POST /x) exist before the requests that need `/x/{id}`
        for ep in sorted(self.inv.endpoints, key=lambda e: lifecycle_rank(e.method, e.route)):
            if ep.validation_status == ValidationStatus.INVALID:
                self._block(ep, Scenario.POSITIVE, "INVALID_INVENTORY_ENTRY", "inventory entry failed validation", True)
                continue
            self._endpoint(ep)

    def _block(self, ep: Endpoint, sc: Scenario, code: str, reason: str, required: bool) -> None:
        self.blocked.append(BlockedScenario(endpoint_id=ep.id, scenario=sc, method=ep.method, route=ep.route, required=required, reason_code=code, reason=reason))

    def _endpoint(self, ep: Endpoint) -> None:
        fx = self.opts.fixtures.endpoints.get(f"{ep.method} {ep.route}", EndpointFixture())
        allowed, code, why = self.policy.method_decision(ep.method)
        has_auth = bool(self.auth and self.auth.available)

        # the endpoint the agent logged in through is exercised with the runtime credentials, without a token
        login = self.auth.login if self.auth else None
        if login is not None and login.endpoint_id == ep.id:
            self._login_endpoint(ep, fx, login, allowed, code, why)
            return

        # ----- positive
        if not allowed:
            self._block(ep, Scenario.POSITIVE, code, why, True)
        elif ep.requires_auth and not has_auth:
            self._block(ep, Scenario.POSITIVE, "MISSING_AUTH", f"endpoint requires authentication and no usable credentials are configured ({self.auth.reason if self.auth else 'auth not configured'})", True)
        elif ep.unsupported and ep.request_body and ep.method in BODY_METHODS and ep.request_body.content_type not in SUPPORTED_BODY_TYPES and "json" not in ep.request_body.content_type:
            self._block(ep, Scenario.POSITIVE, "UNSUPPORTED_CONTENT_TYPE", f"request body content type '{ep.request_body.content_type}' is not supported by the generator", True)
        else:
            try:
                req = self._positive(ep, fx, attach_auth=has_auth and ep.requires_auth is not False)
                self.built.append(req)
                self._remember_ids(ep, req)
            except CannotGenerate as exc:
                self._block(ep, Scenario.POSITIVE, "MISSING_FIXTURE", str(exc), True)

        # ----- authentication-required check (evidence: a declared security requirement)
        if ep.requires_auth and allowed:
            try:
                req = self._positive(ep, fx, attach_auth=False, scenario=Scenario.AUTH_REQUIRED)
                self.built.append(req)
            except CannotGenerate as exc:
                self._block(ep, Scenario.AUTH_REQUIRED, "MISSING_FIXTURE", str(exc), False)

        # ----- negative (opt-in)
        if self.policy.allow_negative and allowed and (ep.method in BODY_METHODS or any(p.required and p.location == ParamLocation.QUERY for p in ep.parameters)):
            if ep.requires_auth and not has_auth:
                self._block(ep, Scenario.NEGATIVE, "MISSING_AUTH", "negative tests need credentials for this endpoint", False)
            else:
                try:
                    self.built.extend(self._negatives(ep, fx, attach_auth=has_auth and ep.requires_auth is not False))
                except CannotGenerate as exc:
                    self._block(ep, Scenario.NEGATIVE, "MISSING_FIXTURE", str(exc), False)
        elif not self.policy.allow_negative:
            pass  # negative tests not requested: simply not part of the plan

    def _remember_ids(self, ep: Endpoint, built: _Built) -> None:
        """A POST that creates a resource (or a GET that lists them) stores an id for the `/{id}` requests built after it."""
        if ep.path_param_names or ep.method not in ("POST", "GET") or is_session_end(ep.method, ep.route):
            return
        key = chain_key(ep.route)
        if key not in self.consumers:
            return
        listing = ep.method == "GET"
        built.item["event"][0]["script"]["exec"] += capture_script(key, self.consumers[key], listing)
        (self.listed if listing else self.created).add(key)

    def _chained(self, ep: Endpoint, name: str) -> str | None:
        """`{{var}}` holding the id of a resource this run created (or, for read-only requests, listed); None if none exists."""
        key = chain_key(param_prefix(ep.route, name))
        if key in self.created:
            return "{{id_%s}}" % key if ep.method in ("PUT", "PATCH", "DELETE") else "{{cur_%s}}" % key
        if key in self.listed and ep.method in ("GET", "HEAD", "OPTIONS"):
            return "{{cur_%s}}" % key  # existing data is only ever read, never changed or deleted
        return None

    def _login_endpoint(self, ep: Endpoint, fx: EndpointFixture, login: Any, allowed: bool, code: str, why: str) -> None:
        if not allowed:
            self._block(ep, Scenario.POSITIVE, code, why, True)
            return
        body = {login.username_field: "{{auth_username}}", login.password_field: "{{auth_password}}"}  # filled in by Newman at run time
        ct = "application/x-www-form-urlencoded" if login.content_type == "form" else "application/json"
        try:
            built = self._positive(ep, fx, attach_auth=False, body_override=body, ct_override=ct)
            built.tier = LOGIN_TIER  # a fresh login can invalidate the token the rest of the run is using (single-session servers)
            self.built.append(built)
        except CannotGenerate as exc:
            self._block(ep, Scenario.POSITIVE, "MISSING_FIXTURE", str(exc), True)

    # ---------------------------------------------------------------- request building
    def _resolve_inputs(self, ep: Endpoint, fx: EndpointFixture) -> tuple[dict[str, Any], list[tuple[str, Any]], dict[str, str]]:
        path_vals: dict[str, Any] = {}
        for p in ep.params(ParamLocation.PATH):
            try:
                path_vals[p.name] = _param_value(self.data, ep, p, fx, self.opts.fixtures, ParamLocation.PATH)
            except CannotGenerate as exc:
                chained = self._chained(ep, p.name)
                if chained is None:
                    prefix = param_prefix(ep.route, p.name)
                    if chain_key(prefix) in self.creator_routes:
                        raise CannotGenerate(f"path parameter '{p.name}' needs a resource id; the agent would create one with POST {prefix}, "
                                             "but that was not possible (needs --allow-mutating, working credentials and a generatable body) "
                                             "-- or supply the id in the fixtures file") from exc
                    if ep.method in ("PUT", "PATCH", "DELETE"):
                        raise CannotGenerate(f"path parameter '{p.name}' needs an existing resource; no POST endpoint to create one was found "
                                             "and existing data is never modified or deleted -- supply it in the fixtures file") from exc
                    raise
                path_vals[p.name] = chained
        query: list[tuple[str, Any]] = []
        for p in ep.params(ParamLocation.QUERY):
            if p.name in fx.query:
                query.append((p.name, fx.query[p.name]))
            elif p.required:
                if _ID_NAME.search(p.name) and not (p.example is not None or (p.schema_def or {}).get("enum") or "example" in (p.schema_def or {})):
                    raise CannotGenerate(f"required query parameter '{p.name}' looks like a reference to an existing resource; supply it in fixtures")
                query.append((p.name, _param_value(self.data, ep, p, fx, self.opts.fixtures, ParamLocation.QUERY)))
        headers: dict[str, str] = dict(fx.headers)
        for p in ep.params(ParamLocation.HEADER):
            if p.required and p.name not in headers and p.name.lower() not in ("authorization", "content-type", "accept"):
                headers[p.name] = str(_param_value(self.data, ep, p, fx, self.opts.fixtures, ParamLocation.HEADER))
        return path_vals, query, headers

    def _body(self, ep: Endpoint, fx: EndpointFixture) -> Any:
        if ep.method not in BODY_METHODS or ep.request_body is None:
            return None
        if fx.body is not None:
            return self._protect_account(ep, self._unique(ep, fx.body) if fx.generated else fx.body)
        rb = ep.request_body
        if rb.example is not None:
            return self._protect_account(ep, rb.example)
        if not rb.schema_def:
            if rb.required:
                raise CannotGenerate("request body is required but its schema is not documented; supply a body in the fixtures file")
            return None
        return self._protect_account(ep, self._unique(ep, self.data.valid(rb.schema_def, None, required=True)))

    @staticmethod
    def _unique(ep: Endpoint, body: Any) -> Any:
        """Creating the same record twice is rejected (409 "email already registered"), so e-mail addresses in generated
        POST bodies get a per-request suffix (Postman resolves the dynamic variables when the request is sent)."""
        if ep.method != "POST":
            return body

        def walk(node: Any) -> Any:
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            if isinstance(node, str) and re.fullmatch(r"[^@\s{}]+@[^@\s{}]+\.[A-Za-z]{2,}", node):
                local, _, domain = node.partition("@")
                return f"{local.split('+')[0]}+{{{{$timestamp}}}}{{{{$randomInt}}}}@{domain}"
            return node

        return walk(body)

    def _protect_account(self, ep: Endpoint, body: Any) -> Any:
        """Never let a test change the credentials the run logs in with (PATCH /users/me {password: "<random>"} would lock the account out).

        In update-style bodies the password / username-like fields carry the account's current values instead, and a refresh-token
        field carries the real refresh token returned by the login.
        """
        if not isinstance(body, dict) or not self.auth or not self.auth.available:
            return body
        login, out = self.auth.login, dict(body)
        register_like = bool(re.search(r"regist|signup|sign-up|create[-_]?account", ep.route, re.I))
        update_like = login is not None and not register_like and (
            ep.method in ("PUT", "PATCH") or ep.route.rstrip("/").endswith(("/me", "/profile", "/password", "/change-password")))
        for k in list(out):
            if self.auth.refresh_available and re.fullmatch(r"(?i)refresh[-_]?token", k):
                out[k] = "{{auth_refresh_token}}"
            elif update_like and login is not None:
                if re.fullmatch(r"(?i)(current[-_]?|old[-_]?|new[-_]?)?pass(word|wd)?", k) or k == login.password_field:
                    out[k] = "{{auth_password}}"
                elif k == login.username_field:
                    out[k] = "{{auth_username}}"
        return out

    def _positive(self, ep: Endpoint, fx: EndpointFixture, attach_auth: bool, scenario: Scenario = Scenario.POSITIVE,
                  body_override: Any = None, ct_override: str | None = None) -> _Built:
        path_vals, query, headers = self._resolve_inputs(ep, fx)
        body = body_override if body_override is not None else self._body(ep, fx)
        if scenario == Scenario.AUTH_REQUIRED:
            expected, basis, rng = [401, 403], "inferred: endpoint declares an authentication requirement", None
            desc = "request without credentials must be rejected (401/403)"
            tests = status_assertion(expected, basis)
        else:
            documented, rng = _documented_success(ep)
            if fx.expected_status:
                expected, basis = fx.expected_status, "fixture-provided"
            elif documented:
                expected, basis = documented, "documented"
            elif rng:
                expected, basis = [], "documented: 2XX"
            else:
                expected, basis = [], "inferred: no success status documented, any 2xx accepted"
            desc = "documented success response"
            tests = status_assertion(expected, basis, rng)
            schema = _success_schema(ep)
            if schema and is_meaningful(to_json_schema(schema)):
                tests += json_schema_assertion(to_json_schema(schema))
        tests += response_time_assertion(self.policy.request_timeout_ms)
        item_id = f"{ep.id}|{scenario.value}|0"
        item = self._item(ep, item_id, scenario, path_vals, query, headers, body, attach_auth, tests, desc, ct_override)
        pr = PlannedRequest(item_id=item_id, endpoint_id=ep.id, scenario=scenario, method=ep.method, route=ep.route,
                            required=scenario == Scenario.POSITIVE, expected_statuses=expected if expected else ([] if not rng else []),
                            expected_basis=basis, description=desc)
        if not expected:
            pr.expected_statuses = []
        return _Built(0 if scenario == Scenario.POSITIVE else 1, pr, item)

    def _negatives(self, ep: Endpoint, fx: EndpointFixture, attach_auth: bool) -> list[_Built]:
        path_vals, query, headers = self._resolve_inputs(ep, fx)
        out: list[_Built] = []
        expected = _documented_client_errors(ep) or [400, 422]
        basis = "documented client-error responses" if _documented_client_errors(ep) else "inferred: schema-invalid input should be rejected with 400 or 422"
        variants: list[tuple[str, Any, str, list[tuple[str, Any]]]] = []
        if ep.request_body and ep.method in BODY_METHODS and ep.request_body.schema_def and fx.body is None:
            valid = self._body(ep, fx)
            for d, payload, evidence in self.data.invalid_variants(ep.request_body.schema_def, valid):
                variants.append((d, payload, evidence, query))
        for p in ep.params(ParamLocation.QUERY):
            if p.required and any(k == p.name for k, _ in query):
                variants.append((f"missing required query parameter '{p.name}'", self._body(ep, fx), f"parameter '{p.name}' is declared required", [(k, v) for k, v in query if k != p.name]))
        for n, (d, payload, evidence, q) in enumerate(variants[:3]):
            item_id = f"{ep.id}|{Scenario.NEGATIVE.value}|{n}"
            tests = status_assertion(expected, basis) + response_time_assertion(self.policy.request_timeout_ms)
            desc = f"{d} ({evidence})"
            item = self._item(ep, item_id, Scenario.NEGATIVE, path_vals, q, headers, payload, attach_auth, tests, desc)
            out.append(_Built(2, PlannedRequest(item_id=item_id, endpoint_id=ep.id, scenario=Scenario.NEGATIVE, method=ep.method, route=ep.route,
                                                required=False, expected_statuses=expected, expected_basis=basis, description=desc), item))
        return out

    def _item(self, ep: Endpoint, item_id: str, scenario: Scenario, path_vals: dict[str, Any], query: list[tuple[str, Any]],
              headers: dict[str, str], body: Any, attach_auth: bool, tests: list[str], desc: str,
              ct_override: str | None = None) -> dict[str, Any]:
        path = ep.route
        for k, v in path_vals.items():
            path = path.replace("{" + k + "}", str(v) if str(v).startswith("{{") else quote(str(v), safe=""))
        q = list(query)
        hdrs: list[dict[str, str]] = [{"key": "Accept", "value": "application/json"}]
        if attach_auth and self.auth and self.auth.available:
            if self.auth.header_name:
                hdrs.append({"key": self.auth.header_name, "value": self.auth.header_value_template or ""})
            if self.auth.query_name:
                q.append((self.auth.query_name, self.auth.query_value_template or ""))
        own = {k.lower() for k in headers}
        if self.opts.headers:  # headers the target needs on every call (API key, client version, tenant, idempotency key ...)
            hdrs += [{"key": h.name, "value": h.template} for h in self.opts.headers.headers if h.name.lower() not in own]
        hdrs += [{"key": k, "value": v} for k, v in headers.items()]
        raw_q = "&".join(f"{quote(str(k))}={quote(str(v), safe='{}')}" for k, v in q)
        raw = "{{base_url}}" + path + (("?" + raw_q) if raw_q else "")
        request: dict[str, Any] = {
            "method": ep.method,
            "header": hdrs,
            "url": {
                "raw": raw,
                "host": ["{{base_url}}"],
                "path": [seg for seg in path.split("/") if seg],
                "query": [{"key": str(k), "value": str(v)} for k, v in q],
            },
            "description": desc,
        }
        if body is not None:
            ct = ct_override or (ep.request_body.content_type if ep.request_body else "application/json")
            if "x-www-form-urlencoded" in ct and isinstance(body, dict):
                request["body"] = {"mode": "urlencoded", "urlencoded": [{"key": k, "value": str(v)} for k, v in body.items()]}
                hdrs.append({"key": "Content-Type", "value": "application/x-www-form-urlencoded"})
            else:
                request["body"] = {"mode": "raw", "raw": json.dumps(body, ensure_ascii=False), "options": {"raw": {"language": "json"}}}
                hdrs.append({"key": "Content-Type", "value": "application/json"})
        return {
            "id": item_id,
            "name": f"{ep.method} {ep.route} [{scenario.value}]",
            "request": request,
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": tests}}],
            "protocolProfileBehavior": {"followRedirects": False},
        }

    # ---------------------------------------------------------------- assembly
    def assemble(self) -> GenerationResult:
        budget = max(self.policy.max_requests, 0)
        ordered = sorted(self.built, key=lambda b: b.tier)  # positives first, then auth checks, then negatives
        kept, dropped = ordered[:budget], ordered[budget:]
        plan = TestPlan(requests=[b.request for b in kept], blocked=list(self.blocked))
        for b in dropped:
            plan.skipped_over_budget.append(b.item["name"])
            plan.blocked.append(BlockedScenario(endpoint_id=b.request.endpoint_id, scenario=b.request.scenario, method=b.request.method,
                                                route=b.request.route, required=b.request.required, reason_code="REQUEST_BUDGET",
                                                reason=f"--max-requests={self.policy.max_requests} reached"))
        folders: dict[str, list[_Built]] = {}
        # Newman runs folders and items in order. Within a resource the order is the resource's life: create -> list -> read ->
        # update -> delete; "without credentials" and negative checks come after the positive flow so they cannot disturb it.
        # Endpoints that end the session (logout ...) and the login endpoint's own test run last: both can invalidate the token
        # the rest of the run uses, and Newman's cookie jar would otherwise attach the new session cookie to the "no credentials" checks.
        last: list[_Built] = []
        for b in kept:
            if b.tier == LOGIN_TIER or is_session_end(b.request.method, b.request.route):
                last.append(b)
                continue
            folders.setdefault(resource_of(b.request.route), []).append(b)

        def order(b: _Built) -> tuple[Any, ...]:
            return (b.tier, lifecycle_rank(b.request.method, b.request.route), b.request.route, b.request.method, b.request.scenario.value, b.item["id"])

        last.sort(key=lambda b: (b.tier == LOGIN_TIER, *order(b)))  # logout first (needs the run's token), login test at the very end
        names = sorted(folders, key=lambda n: (n != "auth", n))
        collection = {
            "info": {
                "_postman_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "api-testing-agent:" + self.inv.project_root)),
                "name": "API Testing Agent collection",
                "description": "Generated by api-testing-agent. Contains no secrets; credentials come from the runtime environment.",
                "schema": COLLECTION_SCHEMA,
            },
            "item": [{"name": n, "item": [b.item for b in sorted(folders[n], key=order)]} for n in names]
            + ([{"name": "session-ending and login endpoints (run last)", "item": [b.item for b in last]}] if last else []),
        }
        env_values = [{"key": "base_url", "value": "", "type": "default", "enabled": True}]
        secret_vars = {
            "bearer": ["auth_token"], "login": ["auth_token", "auth_username", "auth_password"],
            "session": ["auth_cookie", "auth_username", "auth_password"], "basic": ["auth_basic"], "api-key": ["api_key"],
        }.get(self.auth.method if self.auth else "", [])
        env_values += [{"key": k, "value": "", "type": "secret", "enabled": True} for k in secret_vars]
        if self.opts.headers:
            env_values += [{"key": h.var, "value": "", "type": "secret" if h.secret else "default", "enabled": True}
                           for h in self.opts.headers.headers if h.dynamic is None]
        environment = {"id": str(uuid.uuid4()), "name": "api-agent environment template", "values": env_values,
                       "_note": "Variable names only. Real values are injected at run time and never written here."}
        validate_collection(collection)
        return GenerationResult(collection, plan, environment)


def generate(inv: EndpointInventory, opts: GenerationOptions | None = None) -> GenerationResult:
    g = _Generator(inv, opts or GenerationOptions())
    g.run()
    return g.assemble()


def subset_collection(collection: dict[str, Any], item_ids: set[str]) -> dict[str, Any]:
    """A copy of the collection holding only the requests whose item id is in `item_ids` (used for the re-login retry)."""

    def keep(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for it in items:
            if "item" in it:
                inner = keep(it["item"])
                if inner:
                    out.append({**it, "item": inner})
            elif it.get("id") in item_ids:
                out.append(it)
        return out

    return {**collection, "item": keep(collection.get("item", []))}


def validate_collection(c: dict[str, Any]) -> None:
    """Structural validation of the Postman v2.1 essentials we rely on."""
    problems: list[str] = []
    if c.get("info", {}).get("schema") != COLLECTION_SCHEMA:
        problems.append("info.schema must be the Postman v2.1.0 schema URL")
    if not c.get("info", {}).get("name"):
        problems.append("info.name is required")
    ids: set[str] = set()

    def walk(items: list[dict[str, Any]], path: str) -> None:
        for it in items:
            if "item" in it:
                if not it.get("name"):
                    problems.append(f"{path}: folder without name")
                walk(it["item"], f"{path}/{it.get('name')}")
                continue
            req = it.get("request")
            if not it.get("name") or not isinstance(req, dict):
                problems.append(f"{path}: request item missing name/request")
                continue
            if req.get("method") not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                problems.append(f"{it['name']}: invalid method")
            url = req.get("url")
            if not (isinstance(url, dict) and url.get("raw")) and not isinstance(url, str):
                problems.append(f"{it['name']}: missing url")
            if it.get("id") in ids:
                problems.append(f"{it['name']}: duplicate item id")
            ids.add(it.get("id", ""))
            if "Bearer " in json.dumps(req.get("header", [])) and "{{" not in json.dumps(req.get("header", [])):
                problems.append(f"{it['name']}: literal credential found in headers")

    walk(c.get("item", []), "")
    if problems:
        raise CollectionGenerationError("Invalid Postman collection:\n  - " + "\n  - ".join(problems))
