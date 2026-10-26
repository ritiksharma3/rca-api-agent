# pp-api-rca — Autonomous API Testing Agent (V1)

A CLI that takes a **local source-code folder** (any language) and a **target base URL**, then:

1. scans the repo and identifies the likely backend framework (with evidence),
2. discovers endpoints with the best available strategy (OpenAPI → framework CLI → static analysis → `--spec`),
3. writes a validated, framework-independent endpoint inventory,
4. generates a Postman Collection v2.1 with schema-derived assertions,
5. runs it through **Newman**, and
6. writes an evidence-based QA report (`qa-report.json` + `qa-report.html`).

It is deterministic: no LLM, no paid service, no hosted platform.

> **What it does not claim.** Endpoint counts measure route inventory, not behavioral or code-path coverage, and a
> static source scan cannot prove it found every route. Every report says so, and "complete" is only ever claimed when
> the source itself is authoritative (a framework's own route registry).

## Result vocabulary

| Status | Meaning |
|---|---|
| `PASS` | Every *required* assertion generated for the endpoint passed. |
| `FAIL` | A test ran and an assertion (or confirmed behavior) violated its expected result. |
| `BLOCKED` | A prerequisite is missing (credentials, fixture, policy permission, reachable target, Newman) or no valid verdict could be produced. Never reported as PASS. |
| `NOT DISCOVERED` | A potential route/handler was seen in source analysis but could not be resolved to a method + path (e.g. a dynamic registration). It is listed, not tested. |

Discovery status (`DISCOVERED` = method + path established with auth/response details known; `PARTIAL` = route established but details such as the auth requirement are unknown — common for static analysis) and test status are **separate fields**: an endpoint can be discovered but
`BLOCKED` (e.g. a `POST` you did not authorize). Expected values labelled `inferred` (e.g. "an invalid body is rejected
with 400/422") are conventions, not documented behavior — review them before treating a `FAIL` as a defect.

## Installation

Prerequisites: **Python 3.11+**, **Node.js 18+** (Newman). Verified here with Python 3.12, Node 22, Newman 6.2.3.

Windows (PowerShell):

```powershell
cd pp-api-rca
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
npm install --prefix node_tools newman      # local install; or: npm install -g newman
```

Linux / macOS:

```bash
cd pp-api-rca
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
npm install --prefix node_tools newman      # local install; or: npm install -g newman
```

The tool finds Newman in this order: `API_AGENT_NEWMAN` env var → `newman` on `PATH` → `./node_tools/node_modules/.bin/newman`.
`api-agent test` prints install instructions (and still writes a report with every test `BLOCKED`) if Newman is missing.

**Tree-sitter grammars** (used for PHP/JS/TS/Java/C#/Go analysis) are downloaded once on first use by
`tree-sitter-language-pack` and cached. For offline machines, pre-fetch them while online:

```bash
python -c "import tree_sitter_language_pack as t; t.download(['php','javascript','typescript','java','csharp','go'])"
```

## Commands

```
api-agent scan <folder>        languages, framework candidates + evidence, spec files
api-agent discover <folder>    run discovery with fallback; write inventory + warnings
api-agent inventory <folder>   print the normalized endpoint inventory
api-agent generate <folder>    write Postman collection, environment template, test plan (sends nothing)
api-agent test <folder> --base-url URL --approve-target     run everything and report
api-agent report <folder>      rebuild qa-report.* from the last run's artifacts
```

Common options: `--output/-o DIR` (default `./artifacts`), `--backend PATH`, `--framework NAME`,
`--strategy auto|openapi|cli|static`, `--spec FILE`, `--no-cli-discovery`, `--runtime-spec-url URL`.
Run `api-agent <command> --help` for everything. Non-secret settings (`base_url`, backend, timeouts, auth env-var *names*,
approved target origins) are remembered in `<output>/.api-agent.yaml`; **risky permissions are never persisted**.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; no failures |
| 1 | Completed; at least one test `FAIL`ed |
| 2 | Invalid input (bad folder/URL/options, ambiguous backend) |
| 3 | Framework not identified / discovery produced no endpoints |
| 4 | Missing dependency (Node.js / Newman) |
| 5 | Target unsafe (not approved, metadata, needs opt-in) or unreachable |
| 6 | Authentication failed (outranks test failures: the run is not a trustworthy verdict) |
| 7 | Newman could not complete (timeout, crash, invalid collection) |
| 8 | Run completed but nothing could be executed (all `BLOCKED`) |
| 70 | Internal error |

## Walkthrough (bundled local sample API)

`tests/fixtures/sample_api` is a small FastAPI app with known behavior: passing routes, a route whose body violates its
documented schema (`/stats` → FAIL), a route that needs a bearer token (`/users/me`), a route that needs an existing
resource id (`/items/{item_id}`), a mutating route (`POST /items`), and two routes registered in a loop that static
analysis cannot discover (`/dyn/*` → NOT DISCOVERED).

1. Start the sample API (terminal 1, from the project root, venv active):

   ```bash
   python -m uvicorn app.main:app --app-dir tests/fixtures/sample_api --port 8000
   ```

2. Inspect what the tool sees (terminal 2):

   ```bash
   api-agent scan tests/fixtures/sample_api
   api-agent inventory tests/fixtures/sample_api
   ```

3. Read-only smoke run — nothing mutating is sent, and the token-protected / fixture-dependent / POST endpoints come out `BLOCKED`:

   ```bash
   api-agent test tests/fixtures/sample_api --base-url http://127.0.0.1:8000 --approve-target
   ```

4. Full run with credentials, a fixture, mutating and negative tests (bash; PowerShell: `$env:API_AGENT_TOKEN = "demo-token"`):

   ```bash
   printf 'path_params:\n  item_id: 1\n' > fixtures.yaml
   API_AGENT_TOKEN=demo-token api-agent test tests/fixtures/sample_api \
       --base-url http://127.0.0.1:8000 --approve-target \
       --auth bearer --allow-mutating --negative --fixtures fixtures.yaml
   ```

   Expected: `PASS 5 | FAIL 1 | BLOCKED 0 | NOT DISCOVERED 1` and exit code `1` (the deliberate `/stats` failure).
   Open `artifacts/qa-report.html`.

5. Rebuild the report from saved artifacts: `api-agent report tests/fixtures/sample_api`.

Run the automated suite (starts its own sample server on a free port; integration tests need Newman):

```bash
pytest -q
```

## Authentication

Methods: `--auth none | bearer | login | api-key`. Secrets come from **environment variables** (names configurable) or a
hidden interactive prompt (`--prompt-credentials`) — never from flags, config files, source files or Git history.

| Method | Variables (defaults) | Notes |
|---|---|---|
| bearer | `API_AGENT_TOKEN` | `Authorization: Bearer {{auth_token}}` |
| login | `API_AGENT_USERNAME`, `API_AGENT_PASSWORD`, plus `--login-path`, `--login-token-path` (dotted, default `access_token`) | The response must be JSON containing a string token or authentication fails. Redirects are not followed. No automatic refresh in V1 (an `expires_in` is noted in the report). |
| api-key | `API_AGENT_API_KEY`, `--api-key-header` | header (default `X-API-Key`) |

How secrets are handled: the generated collection contains `{{auth_token}}`-style variables only; values reach Newman
through a private temporary environment file that is created with owner-only permissions and **always deleted**, and every
secret value is registered with the redaction layer (logs, exceptions, report, artifacts). Raw Newman output (which can
contain bodies) is deleted after parsing. If an endpoint requires auth and no credentials are available, its positive
test is `BLOCKED` (the unauthenticated "must be rejected" check still runs). Basic Auth and cookie/session flows are not
implemented (extension point: `auth/provider.py`).

## Target safety policy

* `--base-url` is validated (http/https only, host, port, base path; no embedded credentials/query).
* **Approval is mandatory**: `--approve-target` (or a previously approved origin in `.api-agent.yaml`, or an interactive yes).
* Loopback needs only approval. **Private / link-local** hosts additionally need `--allow-private`; **public** hosts need `--allow-public`.
* Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, …) are **always refused**, also after DNS resolution.
* Redirects are never followed (Newman `--ignore-redirects`, httpx `follow_redirects=False`); TLS verification is always on.
* **Read-only first**: `GET` only by default. `--allow-mutating` enables POST/PUT/PATCH, `--negative` adds invalid-input tests,
  `--allow-destructive` enables DELETE and is **refused for public hosts**.
* `--max-requests` is a hard cap (positives are kept before negatives), `--delay-ms` paces requests, `--request-timeout`/`--process-timeout` bound execution.
  Newman runs sequentially; `--concurrency` is validated and recorded but not applied.
* Test data never invents existing ids: path parameters and required `*_id` fields need an example, enum, or a `--fixtures` YAML, otherwise the test is `BLOCKED`.

Fixtures file format:

```yaml
path_params: {item_id: 1}              # applies everywhere
endpoints:
  "POST /orders":
    body: {customer_id: 7, qty: 2}     # explicit body
    query: {}
    headers: {}
    expected_status: [201]             # user-supplied expectation
```

## Discovery strategies and limitations

Priority: **OpenAPI/Swagger document → framework CLI → static analysis → `--spec`/runtime spec.** The first strategy that
yields endpoints is primary; applicable *non-code-executing* strategies then cross-check it and any difference is reported
as a **discrepancy** (never silently dropped, and never merged into the tested inventory).

| Adapter | Handles | Prerequisites / limits |
|---|---|---|
| `openapi` | OpenAPI 3.0/3.1, Swagger 2.0 (JSON/YAML), local `$ref`s, params, bodies, responses, security | External `$ref`s and recursive schemas are recorded, not expanded. A spec is never proof of completeness. Only files that parse and have a top-level `openapi`/`swagger` key are treated as specs. |
| `laravel-route-list` | `php artisan route:list --json` | Needs `php` and installed `vendor/`; **executes project code** (can be disabled with `--no-cli-discovery`); no schemas. Verified with mocked output only — not against a live Laravel app in this environment. |
| `python-static` | FastAPI (routers, prefixes, `include_router`, Pydantic bodies/constraints, `Depends` auth hints), Flask (+Blueprints), Django (`urlpatterns`/`include`, `api_view`, class views) | stdlib `ast`; nothing imported or executed. Dynamic registrations → NOT DISCOVERED. Django function-view methods are guessed (GET, low confidence). DRF routers are not resolved. |
| `tree-sitter-static` | Laravel `routes/*.php`, Express/Router (mounts via `require`/`import`), Spring (`*Mapping`, DTO constraints), ASP.NET Core (attribute routes, minimal APIs), Go (gin/echo/chi/gorilla/net-http) | Syntax-aware, but shallower for Java/C#/Go (no handler analysis; Go groups by variable assignment). Confidence is labelled per endpoint. |
| runtime spec (`--runtime-spec-url`) | Fetch an OpenAPI doc from a server **you** run | Off by default; one GET, same approval rules as test traffic; never starts a server. |

Not supported: NestJS/Fastify/Koa route extraction, Rails, Ruby/Rust frameworks, GraphQL/gRPC/WebSocket, file-upload
(`multipart`) bodies (those scenarios are `BLOCKED: UNSUPPORTED_CONTENT_TYPE`).

## Reading the report

`artifacts/qa-report.json` (stable schema, `schema_version: "1.0"`) and the self-contained `qa-report.html` contain
per-endpoint verdicts with each scenario's expected-vs-actual status, `documented`/`inferred` basis, duration, timestamp and a
size-limited, redacted body snippet *only for failures*; plus blockers, discovery attempts and limitations, unresolved
routes, discrepancies, a manual-review list, tool versions and the effective policy.

Other artifacts: `scan_result.json`, `endpoint_inventory.json`, `discovery_warnings.json`, `postman_collection.json`,
`postman_environment.template.json` (variable names only), `test_plan.json`, `execution_result.json`, `run_meta.json`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| exit 4 "Newman was not found" | `npm install --prefix node_tools newman` or `npm install -g newman`; check `node --version` |
| exit 2 "Multiple backend candidates" | `api-agent scan <folder>`, then `--backend <path>` (and `--framework`) |
| exit 3 | Provide `--spec openapi.yaml`, or `--runtime-spec-url` for a server you run |
| exit 5 "not approved" / "allow-private" | Add `--approve-target` / `--allow-private` for a private network you are authorized to test |
| everything `BLOCKED` with `MISSING_AUTH` | Export the token variable (or `--prompt-credentials`) and pass `--auth` |
| `MISSING_FIXTURE` | Supply `--fixtures` with real ids that exist in the target |
| `tree-sitter grammar … is unavailable` | Pre-fetch grammars (see Installation) |
| spec base path warning | Include the server base path in `--base-url` (e.g. `http://host/api/v1`) |

## Architecture

```
api_testing_agent/
  cli.py  pipeline.py  config.py  errors.py
  scanner/        language + framework detection, multi-backend handling
  discovery/      base (adapter contract), registry (priority/fallback/cross-check), openapi_adapter,
                  cli_adapter, python_static, php_static, js_static, jvm_dotnet_go_static, static_adapter,
                  runtime_adapter, normalizer, coverage
  auth/           pluggable providers (bearer, login, api-key)
  test_generation/ schema_analyzer, test_data (Faker, seeded), assertions, collection_generator
  execution/      newman_runner, result_parser, status_classifier
  reporting/      report_generator + templates/report.html (Jinja2)
  security/       redaction, safety_policy
  models/         Pydantic: endpoint (inventory), project (scan), execution, report
tests/            unit/ (no network, no Newman) · integration/ (local sample API + Newman) · fixtures/sample_api
```

### Adding a discovery adapter

1. Subclass `DiscoveryAdapter` (`discovery/base.py`): set `name`, `strategy` (`openapi|cli|static`), `supported`,
   `prerequisites`, and `executes_project_code` (True if it runs framework code — such adapters are gated and never used as cross-checks).
2. Implement `applicable(ctx)` (cheap; return a reason when not) and `discover(ctx)` returning a `DiscoveryOutcome`
   (`endpoints`, `potential_routes` for anything unresolved, `warnings`, `limitations`, `complete` only if the source is authoritative).
   Raise `DiscoveryError` on failure so the registry falls back to the next strategy.
3. Normalize paths with `normalize_path()` (keeps original parameter names) and record `Evidence` + `Confidence` per endpoint.
4. Register it in `discovery/registry.py::default_adapters()`; add fixture-repo tests in `tests/unit/test_static_analysis.py`.

## Known limitations (V1)

* Discovery can miss dynamically registered, conditional, plugin- or middleware-defined routes; counts are lower bounds unless a framework registry is authoritative.
* Authentication requirements from static analysis are inferred from dependency/decorator/annotation names only.
* Request bodies for Express/Flask are inferred from usage (types unknown); Laravel validation rules are not parsed.
* One global auth method per run; no token refresh; no Basic/cookie auth; no multipart bodies.
* Negative-test expectations (400/422) are inferred unless the spec documents client errors.
* Newman is sequential; the HTML report is our own (Newman's HTML reporter is not used).
* Not yet verified against a live Laravel/Spring/ASP.NET/Go/Express *server*; those analyzers are verified on synthetic source fixtures only.
