"""Framework-independent discovery and runtime behaviour: spec probing, monorepos, Node/Python backends."""

from __future__ import annotations

import json

import httpx
import pytest

from api_testing_agent.discovery import runtime_adapter
from api_testing_agent.discovery.runtime_adapter import probe_runtime_spec
from api_testing_agent.errors import UnsafeTargetError
from api_testing_agent.security.safety_policy import SafetyPolicy

REAL_CLIENT = httpx.Client
SPEC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}}}


def serve(monkeypatch, handler):
    monkeypatch.setattr(runtime_adapter.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "transport"}))


POLICY = SafetyPolicy(approve_target=True)


def test_probe_finds_the_spec_a_framework_publishes_and_ignores_look_alikes(monkeypatch, tmp_path):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=SPEC)
        if request.url.path == "/swagger.json":  # HTML or a non-spec JSON must never be accepted
            return httpx.Response(200, json={"hello": "world"})
        return httpx.Response(404)

    serve(monkeypatch, handler)
    path, note = probe_runtime_spec("http://127.0.0.1:8000/", POLICY, tmp_path / "runtime_spec")
    assert path is not None and json.loads(path.read_text("utf-8"))["paths"]["/items"] and "/openapi.json" in note
    assert all(m for m in seen) and len(seen) <= 3  # stops at the first hit


def test_probe_reports_nothing_found_and_only_reads(monkeypatch, tmp_path):
    methods = set()

    def handler(request):
        methods.add(request.method)
        return httpx.Response(404)

    serve(monkeypatch, handler)
    path, note = probe_runtime_spec("http://127.0.0.1:8000/api", POLICY, tmp_path / "s")
    assert path is None and "no OpenAPI document" in note and methods == {"GET"}


def test_probe_stops_at_the_first_connection_problem(monkeypatch, tmp_path):
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ReadTimeout("hung dev server", request=request)

    serve(monkeypatch, handler)
    path, note = probe_runtime_spec("http://127.0.0.1:8000/", POLICY, tmp_path / "s")
    assert path is None and "stopped" in note and len(calls) == 1, "a hung server must cost one timeout, not one per path"


def test_probe_obeys_target_safety_rules(tmp_path):
    with pytest.raises(UnsafeTargetError):
        probe_runtime_spec("http://127.0.0.1:8000/", SafetyPolicy(approve_target=False), tmp_path / "s")


# ------------------------------------------------------------------ NestJS
from api_testing_agent.discovery.base import DiscoveryContext  # noqa: E402
from api_testing_agent.discovery.static_adapter import TreeSitterStaticAdapter  # noqa: E402
from api_testing_agent.scanner.repository_scanner import scan_repository, select_backend  # noqa: E402
from tests.conftest import write_files  # noqa: E402


def discover_static(tmp_path, files):
    write_files(tmp_path, files)
    scan = scan_repository(tmp_path)
    ctx = DiscoveryContext(root=tmp_path, scan=scan, backend=select_backend(scan))
    ad = TreeSitterStaticAdapter()
    assert ad.applicable(ctx).ok, ad.applicable(ctx).reason
    out = ad.discover(ctx)
    return {(e.method, e.route): e for e in out.endpoints}, out


NEST = {
    "package.json": '{"dependencies": {"@nestjs/core": "^10", "@nestjs/common": "^10"}}',
    "src/main.ts": "async function bootstrap() { const app = await NestFactory.create(AppModule); app.setGlobalPrefix('api'); await app.listen(3000); }\n",
    "src/users/dto/create-user.dto.ts": (
        "import { IsEmail, IsInt, Min, IsOptional, IsString, MinLength, IsEnum } from 'class-validator';\n"
        "export enum Role { Admin = 'admin', User = 'user' }\n"
        "export class CreateUserDto {\n"
        "  @IsEmail() email: string;\n"
        "  @IsString() @MinLength(8) password: string;\n"
        "  @IsInt() @Min(18) age: number;\n"
        "  @IsEnum(Role) role: Role;\n"
        "  @IsOptional() @IsString() nickname?: string;\n"
        "}\n"
        "export class UpdateUserDto extends PartialType(CreateUserDto) {}\n"
    ),
    "src/users/users.controller.ts": (
        "import { Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards, HttpCode } from '@nestjs/common';\n"
        "@Controller('users')\n@UseGuards(JwtAuthGuard)\n"
        "export class UsersController {\n"
        "  @Get() findAll(@Query('page') page?: number) { return []; }\n"
        "  @Get(':id') findOne(@Param('id', ParseIntPipe) id: number) { return 1; }\n"
        "  @Post() create(@Body() dto: CreateUserDto) { return dto; }\n"
        "  @Patch(':id') update(@Param('id') id: string, @Body() dto: UpdateUserDto) { return dto; }\n"
        "  @Delete(':id') @HttpCode(204) remove(@Param('id') id: string) {}\n"
        "  @Public() @Get('count/all') count() { return 1; }\n"
        "}\n"
    ),
    "src/auth/auth.controller.ts": (
        "@Controller({ path: 'auth' })\nexport class AuthController {\n"
        "  @Post('login') login(@Body('email') email: string, @Body('password') password: string) {}\n"
        "  @Get('me') @UseGuards(JwtAuthGuard) me() {}\n"
        "}\n"
    ),
}


def test_nestjs_controllers_prefix_guards_and_dto_schemas(tmp_path):
    by, out = discover_static(tmp_path, NEST)
    assert {("GET", "/api/users"), ("GET", "/api/users/{id}"), ("POST", "/api/users"), ("PATCH", "/api/users/{id}"),
            ("DELETE", "/api/users/{id}"), ("GET", "/api/users/count/all"), ("POST", "/api/auth/login"), ("GET", "/api/auth/me")} <= set(by)
    assert by[("GET", "/api/users")].requires_auth is True, "class-level @UseGuards"
    assert by[("GET", "/api/users/count/all")].requires_auth is False, "@Public() overrides the class guard"
    assert by[("POST", "/api/auth/login")].requires_auth is None and by[("GET", "/api/auth/me")].requires_auth is True
    body = by[("POST", "/api/users")].request_body.schema_def
    assert body["properties"]["email"]["format"] == "email" and body["properties"]["age"] == {"type": "integer", "minimum": 18}
    assert body["properties"]["password"]["minLength"] == 8 and body["properties"]["role"]["enum"] == ["admin", "user"]
    assert set(body["required"]) == {"email", "password", "age", "role"}, "@IsOptional / `?` fields are not required"
    patch = by[("PATCH", "/api/users/{id}")].request_body.schema_def
    assert patch["required"] == [] and "email" in patch["properties"], "PartialType makes every inherited field optional"
    assert by[("GET", "/api/users/{id}")].parameters[0].schema_def == {"type": "integer"}
    assert [p.name for p in by[("GET", "/api/users")].parameters if p.location.value == "query"] == ["page"]
    assert by[("POST", "/api/users")].responses[0].status == "201" and by[("DELETE", "/api/users/{id}")].responses[0].status == "204"
    assert set(by[("POST", "/api/auth/login")].request_body.schema_def["properties"]) == {"email", "password"}


def test_nestjs_global_guard_and_uri_versioning(tmp_path):
    files = {**NEST, "src/app.module.ts": "providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }]\n",
             "src/main.ts": "app.enableVersioning({ type: VersioningType.URI });\n",
             "src/things/things.controller.ts": "@Controller({ path: 'things', version: '2' })\nexport class T {\n  @Get() all() {}\n  @Public() @Get('open') open() {}\n}\n"}
    by, out = discover_static(tmp_path, files)
    assert by[("GET", "/v2/things")].requires_auth is True and by[("GET", "/v2/things/open")].requires_auth is False
    assert any("APP_GUARD" in lim for lim in out.limitations)


# ------------------------------------------------------------------ Fastify / Koa
FASTIFY = {
    "package.json": '{"dependencies": {"fastify": "^4"}}',
    "src/app.js": (
        "const fastify = require('fastify')();\n"
        "fastify.get('/health', async () => ({ ok: true }));\n"
        "fastify.register(require('./routes/users'), { prefix: '/api/users' });\n"
        "fastify.register(require('./routes/orders'), { prefix: '/api/orders' });\n"
    ),
    "src/routes/users.js": (
        "module.exports = async function routes(fastify, opts) {\n"
        "  fastify.addHook('onRequest', fastify.authenticate);\n"
        "  fastify.get('/', async () => []);\n"
        "  fastify.get('/:id', { schema: { params: { type: 'object', properties: { id: { type: 'integer' } } } } }, async (req) => req.params.id);\n"
        "  fastify.post('/', { schema: { body: { type: 'object', required: ['email', 'age'], properties: { email: { type: 'string', format: 'email' }, age: { type: 'integer', minimum: 18 } } } } }, async (req) => req.body);\n"
        "};\n"
    ),
    "src/routes/orders.js": (
        "module.exports = async function (fastify) {\n"
        "  fastify.route({ method: ['GET', 'HEAD'], url: '/', preHandler: [fastify.verifyJwt], handler: async () => [] });\n"
        "  fastify.route({ method: 'POST', url: '/', handler: async (req) => { const { items } = req.body; return items; } });\n"
        "};\n"
    ),
}


def test_fastify_plugins_prefix_hooks_and_route_schemas(tmp_path):
    by, out = discover_static(tmp_path, FASTIFY)
    assert ("GET", "/health") in by and by[("GET", "/health")].requires_auth is None
    assert ("GET", "/api/users") in by and by[("GET", "/api/users")].requires_auth is True, "addHook('onRequest', authenticate) protects the plugin"
    assert by[("GET", "/api/users/{id}")].parameters[0].schema_def == {"type": "integer"}, "schema.params is read"
    body = by[("POST", "/api/users")].request_body.schema_def
    assert body["properties"]["age"]["minimum"] == 18 and body["required"] == ["email", "age"], "schema.body becomes the request schema"
    assert by[("GET", "/api/orders")].requires_auth is True and ("POST", "/api/orders") in by, "fastify.route({...}) with preHandler auth"
    assert by[("POST", "/api/orders")].requires_auth is None
    assert "items" in by[("POST", "/api/orders")].request_body.schema_def["properties"]


KOA = {
    "package.json": '{"dependencies": {"koa": "^2", "@koa/router": "^12"}}',
    "src/server.js": (
        "const Koa = require('koa');\nconst Router = require('@koa/router');\nconst app = new Koa();\n"
        "const api = new Router({ prefix: '/api' });\n"
        "const users = require('./users');\n"
        "api.use('/users', users.routes());\n"
        "api.get('/ping', async (ctx) => { ctx.body = 'pong'; });\n"
        "app.use(api.routes());\n"
    ),
    "src/users.js": (
        "const Router = require('@koa/router');\nconst router = new Router();\nconst { requireAuth } = require('./auth');\n"
        "router.get('/', requireAuth, async (ctx) => {});\n"
        "router.get('/:id', requireAuth, async (ctx) => {});\n"
        "router.post('/', async (ctx) => { const { name } = ctx.request.body; });\n"
        "module.exports = router;\n"
    ),
}


def test_koa_router_prefix_and_nested_routes(tmp_path):
    by, out = discover_static(tmp_path, KOA)
    assert ("GET", "/api/ping") in by
    assert ("GET", "/api/users") in by and by[("GET", "/api/users")].requires_auth is True
    assert ("GET", "/api/users/{id}") in by and ("POST", "/api/users") in by


# ------------------------------------------------------------------ monorepo: React frontend + backend
def _scan(tmp_path, files):
    write_files(tmp_path, files)
    scan = scan_repository(tmp_path)
    return scan, select_backend(scan)


def test_react_frontend_is_not_mistaken_for_the_backend_express(tmp_path):
    scan, backend = _scan(tmp_path, {
        "client/package.json": '{"dependencies": {"react": "^18", "react-dom": "^18", "axios": "^1"}, "devDependencies": {"vite": "^5"}}',
        "client/src/App.jsx": "import axios from 'axios';\nexport default function App() { axios.get('/api/users'); return null; }\n",
        "server/package.json": '{"dependencies": {"express": "^4"}}',
        "server/index.js": "const express = require('express');\nconst app = express();\napp.get('/api/users', (req, res) => res.json([]));\n",
    })
    assert backend.framework == "Express" and backend.path == "server"
    assert not any(c.path == "client" for c in scan.backends)


def test_react_frontend_is_not_mistaken_for_the_backend_fastapi(tmp_path):
    scan, backend = _scan(tmp_path, {
        "web/package.json": '{"dependencies": {"react": "^18", "react-router-dom": "^6"}}',
        "web/src/main.tsx": "import React from 'react';\n",
        "api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): ...\n",
        "api/requirements.txt": "fastapi\nuvicorn\n",
    })
    assert backend.framework == "FastAPI" and backend.path == "api"


def test_two_real_backends_still_require_an_explicit_choice(tmp_path):
    write_files(tmp_path, {
        "web/package.json": '{"dependencies": {"react": "^18"}}',
        "node-api/package.json": '{"dependencies": {"express": "^4"}}',
        "node-api/index.js": "const express = require('express'); const app = express(); app.get('/a', (q, r) => r.end());\n",
        "py-api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/b')\ndef b(): ...\n",
    })
    scan = scan_repository(tmp_path)
    with pytest.raises(Exception, match="--backend"):
        select_backend(scan)
    assert select_backend(scan, backend="py-api").framework == "FastAPI"


# ------------------------------------------------------------------ runtime hardening
import shutil  # noqa: E402
import subprocess  # noqa: E402

from api_testing_agent import pipeline  # noqa: E402
from api_testing_agent.execution.result_parser import parse_newman_report  # noqa: E402
from api_testing_agent.models.execution import PlannedRequest, Scenario, TestPlan, TestStatus  # noqa: E402
from api_testing_agent.test_generation.collection_generator import capture_script  # noqa: E402


def test_unreachable_target_messages_say_what_kind_of_failure_it_is():
    req = httpx.Request("GET", "http://x")
    hung = pipeline._connectivity_cause(httpx.ReadTimeout("timed out", request=req), 10)
    assert "accepted the connection but did not answer within 10s" in hung and "Redis" in hung
    assert "connection refused" in pipeline._connectivity_cause(httpx.ConnectError("refused", request=req), 10)
    assert "could not open a connection within 5s" in pipeline._connectivity_cause(httpx.ConnectTimeout("t", request=req), 5)


def _report(code, headers=None):
    return {"run": {"executions": [{"item": {"id": "i1"}, "response": {"code": code, "header": headers or []},
                                    "assertions": [{"assertion": "status code is 2xx", "error": {"message": f"expected {code} to be within 200..299"}}]}]}}


def _plan(scenario=Scenario.POSITIVE):
    return TestPlan(requests=[PlannedRequest(item_id="i1", endpoint_id="e1", scenario=scenario, method="GET", route="/things", required=True,
                                             expected_statuses=[], expected_basis="inferred", description="d")])


def test_403_and_429_get_actionable_reason_codes():
    r403 = parse_newman_report(_report(403), _plan(), []).scenarios[0]
    assert r403.status == TestStatus.FAIL and r403.reason_code == "FORBIDDEN_FOR_USER" and "role/permission" in r403.reason
    r429 = parse_newman_report(_report(429, [{"key": "Retry-After", "value": "7"}]), _plan(), []).scenarios[0]
    assert r429.reason_code == "RATE_LIMITED" and r429.evidence["retry_after_s"] == 7
    r500 = parse_newman_report(_report(500), _plan(), []).scenarios[0]
    assert r500.reason_code is None, "ordinary failures are not relabelled"
    auth_check = parse_newman_report(_report(403), _plan(Scenario.AUTH_REQUIRED), []).scenarios[0]
    assert auth_check.reason_code is None, "only the positive flow gets the permission hint"


def test_rate_limited_requests_are_retried_once_and_merged(monkeypatch):
    first = parse_newman_report(_report(429, [{"key": "Retry-After", "value": "2"}]), _plan(), [])
    calls = {"sleep": [], "run": 0}
    monkeypatch.setattr(pipeline.time, "sleep", lambda s: calls["sleep"].append(s))

    def fake_run(collection, base_url, env, policy, newman, work_dir, secrets):
        calls["run"] += 1
        ok = {"run": {"executions": [{"item": {"id": "i1"}, "response": {"code": 200, "header": []},
                                      "assertions": [{"assertion": "status code is 2xx"}]}]}}
        return None, ok

    monkeypatch.setattr(pipeline, "run_collection", fake_run)
    gen = type("G", (), {"collection": {"info": {}, "item": [{"name": "f", "item": [{"id": "i1", "name": "n", "request": {}}]}]}})()
    n, notes = pipeline._retry_rate_limited(gen, _plan(), first, "http://x", SafetyPolicy(approve_target=True), "newman", None, [], {}, lambda m: None)
    assert n == 1 and calls == {"sleep": [2], "run": 1}
    assert first.scenarios[0].status == TestStatus.PASS and first.scenarios[0].http_status == 200
    # nothing limited -> no wait, no run
    n2, _ = pipeline._retry_rate_limited(gen, _plan(), first, "http://x", SafetyPolicy(approve_target=True), "newman", None, [], {}, lambda m: None)
    assert n2 == 0 and calls["run"] == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("listing,payload,expected", [
    (True, [{"uuid": "u-top"}], "u-top"),
    (True, {"data": [{"uuid": "u-data"}]}, "u-data"),
    (True, {"success": True, "data": {"data": [{"uuid": "u-nested"}], "meta": {"total": 1}}}, "u-nested"),
    (True, {"result": {"items": [{"id": 7}]}}, "7"),
    (True, {"data": []}, None),
    (False, {"success": True, "data": {"uuid": "u-created", "name": "x"}}, "u-created"),
    (False, {"id": 42}, "42"),
])
def test_generated_capture_script_finds_ids_in_common_envelopes(listing, payload, expected):
    js = "\n".join(capture_script("things", "uuid", listing))
    harness = (
        "const vars = {}; const pm = { response: { code: 200, json: () => (" + json.dumps(payload) + ") },"
        " collectionVariables: { get: (k) => vars[k], set: (k, v) => { vars[k] = v; } } };\n" + js + "\nconsole.log(JSON.stringify(vars));"
    )
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got.get("cur_things") == expected


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_listed_id_never_overwrites_a_created_one_and_failed_responses_capture_nothing():
    js = "\n".join(capture_script("things", "id", True))
    harness = (
        "const vars = {cur_things: 'created'}; const pm = { response: { code: 200, json: () => ({data: [{id: 1}]}) },"
        " collectionVariables: { get: (k) => vars[k], set: (k, v) => { vars[k] = v; } } };\n" + js + "\n"
        "pm.response.code = 500;\n" + "\n".join(capture_script("other", "id", False)) + "\nconsole.log(JSON.stringify(vars));"
    )
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=20)
    assert json.loads(out.stdout) == {"cur_things": "created"}


# ------------------------------------------------------------------ a probed spec is a fallback + cross-check, never the primary
from api_testing_agent.discovery.base import Applicability, DiscoveryAdapter, DiscoveryOutcome  # noqa: E402
from api_testing_agent.discovery.registry import run_discovery  # noqa: E402
from api_testing_agent.models.endpoint import Endpoint  # noqa: E402
from api_testing_agent.models.project import ScanResult  # noqa: E402


class _Fake(DiscoveryAdapter):
    def __init__(self, name, strategy, routes, auth=None):
        self.name, self.strategy, self.routes, self.auth = name, strategy, routes, auth

    def applicable(self, ctx):
        return Applicability(True)

    def discover(self, ctx):
        return DiscoveryOutcome(endpoints=[Endpoint(method="GET", route=r, original_path=r, requires_auth=self.auth, strategy=self.name) for r in self.routes])


def _ctx(tmp_path, probed):
    return DiscoveryContext(root=tmp_path, scan=ScanResult(root=str(tmp_path)), spec_path=tmp_path / "spec.json", spec_from_probe=probed)


def test_probed_spec_does_not_replace_source_analysis(tmp_path):
    adapters = [_Fake("openapi", "openapi", ["/a", "/b", "/extra"]), _Fake("static", "static", ["/a", "/b"], auth=True)]
    inv, _w = run_discovery(_ctx(tmp_path, True), "auto", adapters)
    assert inv.discovery.strategy_used == "static" and {e.route for e in inv.endpoints} == {"/a", "/b"}
    assert all(e.requires_auth for e in inv.endpoints), "auth knowledge from source survives"
    assert any(d.route == "/extra" for d in inv.discrepancies), "what only the spec knows is reported, not silently added or dropped"


def test_probed_spec_rescues_a_stack_without_source_analysis(tmp_path):
    class _Fails(_Fake):
        def discover(self, ctx):
            from api_testing_agent.errors import DiscoveryError
            raise DiscoveryError("no analyzer")

    inv, _w = run_discovery(_ctx(tmp_path, True), "auto", [_Fake("openapi", "openapi", ["/a", "/b"]), _Fails("static", "static", [])])
    assert inv.discovery.strategy_used == "openapi" and len(inv.endpoints) == 2


def test_user_supplied_spec_still_wins(tmp_path):
    adapters = [_Fake("openapi", "openapi", ["/a"]), _Fake("static", "static", ["/a", "/b"])]
    inv, _w = run_discovery(_ctx(tmp_path, False), "auto", adapters)  # explicit --spec: use that document
    assert inv.discovery.strategy_used == "openapi" and [e.route for e in inv.endpoints] == ["/a"]


# ------------------------------------------------------------------ LLM budget handling
from api_testing_agent.auth import llm as llm_mod  # noqa: E402


def test_llm_call_retries_with_an_affordable_token_budget(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-key-123456")
    sent = []

    def fake_post(url, headers=None, json=None, timeout=None, follow_redirects=None):
        sent.append(json["max_tokens"])
        req = httpx.Request("POST", url)
        if json["max_tokens"] > 941:
            return httpx.Response(402, request=req, text='{"error":{"message":"You requested up to 1200 tokens, but can only afford 941."}}')
        return httpx.Response(200, request=req, json={"choices": [{"message": {"content": "{\"ok\": true}"}}]})

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)
    text, note = llm_mod._complete("sys", "user", 1200)
    assert text == '{"ok": true}' and sent == [1200, 921]


def test_llm_out_of_credit_is_explained_and_never_raises(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-key-123456")
    monkeypatch.setattr(llm_mod.httpx, "post", lambda *a, **k: httpx.Response(402, request=httpx.Request("POST", "http://x"), text="payment required"))
    text, note = llm_mod._complete("sys", "user", 300)
    assert text is None and "out of credit" in note and "continuing without it" in note and "sk-test" not in note
