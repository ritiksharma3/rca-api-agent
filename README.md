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

Methods: `--auth none | bearer | login | api-key | basic | session`. Secrets come from **environment variables** (names configurable) or a
hidden interactive prompt (`--prompt-credentials`) — never from flags, config files, source files or Git history.

| Method | Variables (defaults) | Notes |
|---|---|---|
| bearer | `API_AGENT_TOKEN` | `Authorization: Bearer {{auth_token}}` |
| login | `API_AGENT_USERNAME`, `API_AGENT_PASSWORD` | **Automatic**: finds the login endpoint, logs in, uses the returned token on every request (see below). `--login-path`, `--login-token-path`, `--login-content-type` override detection. |
| session | same as login | Cookie/session login: the `Set-Cookie` values from the login response are sent as a `Cookie` header. |
| basic | same as login | `Authorization: Basic …` built from the username/password; no login call. |
| api-key | `API_AGENT_API_KEY`, `--api-key-header` | header (default `X-API-Key`) |

### Automatic login (`--auth login`)

```bash
export API_AGENT_USERNAME=admin API_AGENT_PASSWORD=...        # PowerShell: $env:API_AGENT_USERNAME = "admin"
api-agent test ./backend --base-url http://127.0.0.1:8000 --approve-target --auth login --allow-mutating
```

1. **Find the login endpoint** from the discovered endpoints: a POST whose route looks like `login | signin | authenticate | token | session | oauth`,
   whose body has a password-like field (the username/email field name is taken from the schema), and — when documented — whose response has a
   token field. Candidates are tried best-first. JSON and `application/x-www-form-urlencoded` (OAuth2 password flow) bodies are supported.
2. **LLM fallback (optional).** If no candidate works, and `OPENROUTER_API_KEY` is set and you did not pass `--no-llm`, the agent asks an
   OpenRouter model (`OPENROUTER_MODEL`) to pick the login endpoint. It sends only route/method/field names and a few short, redacted handler
   snippets — **never the username, password or any token — but it does send parts of your source**, so use `--no-llm` for code that must not
   leave the machine. A suggestion is only trusted after a real login with it succeeds; the report records that the LLM was used.
3. **Log in and extract the token.** The response differs between servers (`accessToken`, `access_token`, `data.token`, a nested object, a header ...), so the whole
   response is searched: a JWT-shaped value wins, then a key named like a token, and refresh tokens are never mistaken for it. `--login-token-path` (or a path saved from an
   earlier run) is only a *preference*. If nothing is found and the LLM assist is allowed, the model gets the response **shape only** — every value masked as
   `<str:LENGTH>` — and names the key; the answer is verified against the real response. A `tokenType` such as `Bearer` is honoured, and a returned refresh token
   is kept for `POST …/refresh`-style endpoints. Wrong credentials stop immediately (exit 6) instead of being replayed against other endpoints; a 401/400
   that is really a missing header (`INVALID_API_KEY` …) is reported as that, with the server's error code.
4. **Use it everywhere**: every request that needs auth gets `Authorization: Bearer {{auth_token}}`; the value is injected at run time only.
5. **Re-login on 401**: requests that were rejected with 401 although a credential was attached are retried **once** with a fresh login
   (the same endpoint that worked). Still-rejected requests are reported with reason `AUTH_REJECTED_AFTER_RELOGIN`.
6. The detected, non-secret login settings are saved in `<output>/.api-agent.yaml`, so the next run skips detection.

### Required headers, run order and ids

Real APIs usually demand more than a token. The agent handles this in three steps:

1. **Headers.** Header names the backend source reads (`X-API-Key`, `X-Client-Version`, `X-Tenant-ID`, `Idempotency-Key`, `X-Timestamp` … for Express, Flask/FastAPI,
   Django, Laravel/PHP, Go, Spring, ASP.NET) are detected and sent on **every** request, the login call and the "no credentials" checks included. Values never come from
   your source. In order: `--header NAME=VALUE` / `--header NAME=env:VAR` → `API_AGENT_HEADER_<NAME>` in `.env` (e.g. `API_AGENT_HEADER_X_API_KEY`; API-key-like names also
   fall back to `API_AGENT_API_KEY`) → generated per request (idempotency keys and ids → `{{$guid}}`, timestamps → `{{$timestamp}}`) → `1.0.0` for `*-Version` →
   an LLM-suggested *valid example* (e.g. `tenant-acme`) from the few redacted lines that validate the header, **never for key/token/secret/signature headers**. Anything still
   missing is listed with the exact `.env` line to add. Headers needing a computed signature (HMAC, digests, nonces) are reported as unsupported. Values travel through the
   private runtime environment only (`{{hdr_*}}`), never into the collection or reports; the report lists names and provenance.
2. **Order.** The token is obtained **once, first**, and kept in the private temporary environment file (deleted after the run). The requests then run per resource in
   its lifetime: create (`POST`) → list → read one → update → delete; then the "without credentials" checks, then negative tests, so a check can never disturb the flow.
   Session-ending endpoints (`logout`, `signout`, `revoke` …) run **last**, followed by the login endpoint's own test.
3. **Ids.** A `POST /things` response's id is captured (`pm.collectionVariables`) and used by `GET/PATCH/PUT/DELETE /things/{id}`. If nothing is created, the first item of
   `GET /things` is used for **read-only** requests; existing records are never updated or deleted — `PATCH/PUT/DELETE` only touch what this run created. A fixtures
   file still wins over both. Request bodies that static analysis could only guess from field names (`req.body.x`) get a valid example from the LLM (redacted handler source
   only; needs `--allow-mutating`), e-mail values in generated `POST` bodies are made unique per run, and update bodies carry your current password/username instead of random
   values so a test can never lock out the account it logs in with.

The login endpoint's own test uses your credentials and runs **last** (a new login can invalidate the token the rest of the run uses, and
Newman's cookie jar would otherwise leak a session cookie into the "no credentials" checks). The report's *Authentication* section shows the
method, login endpoint, how it was found, and the re-login count — never any token.

How secrets are handled: the generated collection contains `{{auth_token}}`-style variables only; values reach Newman
through a private temporary environment file that is created with owner-only permissions and **always deleted**, and every
secret value is registered with the redaction layer (logs, exceptions, report, artifacts). Raw Newman output (which can
contain bodies) is deleted after parsing. If an endpoint requires auth and no credentials are available, its positive
test is `BLOCKED` (the unauthenticated "must be rejected" check still runs). Basic Auth and `session` covers cookie logins; see the limitations below for what is still missing (extension point: `auth/provider.py`).

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
* One global auth method and one account (e.g. a super-admin) per run, so role-restricted behaviour is not compared across roles.
* Ids are chained within one resource (`/things` → `/things/{id}`). A body field that must reference *another* resource (an order's `productId`) is only filled by the LLM's guess (id `1`) or a fixtures file, not from a product the run created. If the 401 re-login retry re-runs a request, ids captured earlier in the run are not available to it.
* No refresh-token rotation during the run (a returned refresh token is used once, for `…/refresh` endpoints), MFA/CAPTCHA, or logins that need a CSRF token / multi-step handshake; re-login on 401 is a single retry pass.
* Login detection is heuristic (plus the optional LLM fallback); an unusual login endpoint needs `--login-path`. Detection is verified only against the bundled fixture apps.
* No multipart bodies.
* Negative-test expectations (400/422) are inferred unless the spec documents client errors.
* Newman is sequential; the HTML report is our own (Newman's HTML reporter is not used).
* Not yet verified against a live Laravel/Spring/ASP.NET/Go/Express *server*; those analyzers are verified on synthetic source fixtures only.
