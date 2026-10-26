"""api-agent command line interface."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from . import __version__
from .auth.provider import AuthConfig
from .config import ProjectConfig
from .discovery.registry import STRATEGIES
from .errors import (
    EXIT_INTERNAL,
    EXIT_OK,
    AgentError,
    DiscoveryError,
    InvalidInputError,
)
from .pipeline import do_discover, do_report, do_scan, do_test, require_endpoints
from .security.redaction import redact_text
from .security.safety_policy import SafetyPolicy, parse_target
from .test_generation.collection_generator import Fixtures, GenerationOptions

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Autonomous API testing agent: discover endpoints from source, generate a Postman collection, "
    "run it with Newman and produce an evidence-based QA report.",
    epilog="Exit codes: 0 ok | 1 tests failed | 2 invalid input | 3 discovery failed | 4 missing dependency | "
    "5 target unsafe/unreachable | 6 authentication failed | 7 Newman could not complete | "
    "8 nothing could be executed (all BLOCKED) | 70 internal error",
)

FolderArg = Annotated[Path, typer.Argument(help="Local source-code folder to analyse.", show_default=False)]
OutOpt = Annotated[Path, typer.Option("--output", "-o", help="Output directory for artifacts and saved config.")]
BackendOpt = Annotated[Optional[str], typer.Option(help="Backend sub-folder to analyse when several are detected (see `scan`).")]
FrameworkOpt = Annotated[Optional[str], typer.Option(help="Framework name to pick when one folder contains several.")]
StrategyOpt = Annotated[Optional[str], typer.Option(help=f"Discovery strategy: {', '.join(STRATEGIES)}.")]
SpecOpt = Annotated[Optional[Path], typer.Option(help="Use this OpenAPI/Swagger file (JSON or YAML) for discovery.")]
CliDiscOpt = Annotated[bool, typer.Option("--cli-discovery/--no-cli-discovery", help="Allow framework commands (e.g. `php artisan route:list`) that boot project code.")]
RuntimeOpt = Annotated[Optional[str], typer.Option(help="Optional runtime discovery: URL of an OpenAPI document served by a server YOU run. Disabled by default.")]


def _fail(exc: Exception) -> None:
    code = exc.exit_code if isinstance(exc, AgentError) else EXIT_INTERNAL
    label = getattr(exc, "kind", "internal_error")
    typer.secho(f"error [{label}]: {redact_text(str(exc))}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _say(msg: str) -> None:
    typer.secho(msg, err=True, fg=typer.colors.CYAN)


def guarded(fn):  # type: ignore[no-untyped-def]
    """Map tool exceptions to documented exit codes; never leak secrets in messages."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            return fn(*args, **kwargs)
        except typer.Exit:
            raise
        except AgentError as exc:
            _fail(exc)
        except Exception as exc:  # last resort: internal error, redacted
            _fail(exc)

    return wrapper


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"api-agent {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", help="Show version and exit.", callback=_version_cb, is_eager=True)] = False) -> None:
    pass


# ------------------------------------------------------------------------------------------------ scan
@app.command()
@guarded
def scan(folder: FolderArg, output: OutOpt = Path("artifacts")) -> None:
    """Detect languages, framework candidates and spec files (nothing in the repository is executed)."""
    result = do_scan(folder, output, _say)
    typer.echo(f"Scanned {result.files_scanned} files; languages: {result.languages}")
    if not result.backends:
        typer.secho("No backend framework identified.", fg=typer.colors.YELLOW)
    for b in result.backends:
        typer.echo(f"  backend  {b.path:<20} {b.framework:<14} {b.language:<11} confidence={b.confidence.value}")
        for e in b.evidence[:3]:
            typer.echo(f"             evidence: {e.source}{':' + str(e.line) if e.line else ''} - {e.detail}")
    for s in result.spec_files:
        typer.echo(f"  spec     {s.path} ({s.kind} {s.version})")
    for w in result.warnings:
        typer.secho(f"  warning: {w}", fg=typer.colors.YELLOW)
    typer.echo(f"Wrote {output / 'scan_result.json'}")


def _discovery_args(cfg: ProjectConfig, backend, framework, strategy, spec, runtime):  # type: ignore[no-untyped-def]
    return cfg.merged({"backend": backend, "framework": framework, "strategy": strategy,
                       "spec": str(spec) if spec else None, "runtime_spec_url": runtime})


def _print_discovery(run) -> None:  # type: ignore[no-untyped-def]
    inv = run.inventory
    for a in inv.discovery.attempts:
        typer.echo(f"  [{a.outcome:<11}] {a.adapter}: {a.detail}")
    typer.echo(f"Endpoints discovered: {len(inv.endpoints)}  |  potential routes NOT DISCOVERED: {len(inv.potential_routes)}  |  discrepancies: {len(inv.discrepancies)}")
    if not inv.discovery.complete:
        typer.secho("Discovery completeness cannot be established; the count is a lower bound.", fg=typer.colors.YELLOW)
    for w in run.warnings[:8]:
        typer.secho(f"  warning [{w.adapter}]: {w.message}", fg=typer.colors.YELLOW)


# ------------------------------------------------------------------------------------------------ discover
@app.command()
@guarded
def discover(
    folder: FolderArg, output: OutOpt = Path("artifacts"), backend: BackendOpt = None, framework: FrameworkOpt = None,
    strategy: StrategyOpt = None, spec: SpecOpt = None, cli_discovery: CliDiscOpt = True,
    runtime_spec_url: RuntimeOpt = None, timeout: Annotated[float, typer.Option(help="Seconds allowed per discovery command.")] = 60.0,
    approve_target: Annotated[bool, typer.Option(help="Approve the host of --runtime-spec-url.")] = False,
    allow_private: Annotated[bool, typer.Option(help="Allow a private/loopback-adjacent runtime-spec host.")] = False,
) -> None:
    """Discover endpoints with the best available strategy and write the normalized inventory."""
    cfg = _discovery_args(ProjectConfig.load(output), backend, framework, strategy, spec, runtime_spec_url)
    run = do_discover(folder, output, backend=cfg.backend, framework=cfg.framework, strategy=cfg.strategy,
                      spec=cfg.spec, timeout=timeout, allow_cli=cli_discovery, runtime_spec_url=cfg.runtime_spec_url,
                      policy=SafetyPolicy(approve_target=approve_target, allow_private=allow_private), progress=_say)
    cfg.save(output)
    _print_discovery(run)
    typer.echo(f"Wrote {output / 'endpoint_inventory.json'}, scan_result.json, discovery_warnings.json")
    require_endpoints(run)


# ------------------------------------------------------------------------------------------------ inventory
@app.command()
@guarded
def inventory(
    folder: FolderArg, output: OutOpt = Path("artifacts"), backend: BackendOpt = None, framework: FrameworkOpt = None,
    strategy: StrategyOpt = None, spec: SpecOpt = None, cli_discovery: CliDiscOpt = True,
    fresh: Annotated[bool, typer.Option("--fresh/--use-saved", help="Re-run discovery, or print the saved inventory.")] = True,
) -> None:
    """Show the normalized endpoint inventory (runs discovery unless --use-saved)."""
    from .models.endpoint import EndpointInventory
    from .utils.filesystem import read_json

    saved = output / "endpoint_inventory.json"
    if not fresh and saved.exists():
        inv = EndpointInventory.model_validate(read_json(saved))
    else:
        cfg = _discovery_args(ProjectConfig.load(output), backend, framework, strategy, spec, None)
        run = do_discover(folder, output, backend=cfg.backend, framework=cfg.framework, strategy=cfg.strategy,
                          spec=cfg.spec, allow_cli=cli_discovery, progress=_say)
        inv = run.inventory
    typer.echo(f"{'METHOD':<7} {'ROUTE':<40} {'AUTH':<8} {'CONF':<7} {'STATUS':<11} SOURCE")
    for e in inv.endpoints:
        auth = "yes" if e.requires_auth else ("no" if e.requires_auth is False else "unknown")
        src = f"{e.source_file}:{e.line}" if e.source_file and e.line else (e.source_file or "")
        typer.echo(f"{e.method:<7} {e.route:<40} {auth:<8} {e.confidence.value:<7} {e.discovery_status.value:<11} {src}")
    for p in inv.potential_routes:
        typer.secho(f"{'?':<7} {p.description:<40} NOT DISCOVERED - {p.reason}", fg=typer.colors.MAGENTA)
    typer.echo(f"{len(inv.endpoints)} endpoint(s), {len(inv.potential_routes)} unresolved potential route(s). Inventory: {saved}")
    if not inv.endpoints:
        raise typer.Exit(DiscoveryError.exit_code)


# ------------------------------------------------------------------------------------------------ shared policy/auth options
def _policy(approve_target, allow_private, allow_public, allow_mutating, allow_destructive, negative, max_requests,
            delay_ms, concurrency, request_timeout, process_timeout) -> SafetyPolicy:  # type: ignore[no-untyped-def]
    if concurrency < 1:
        raise InvalidInputError("--concurrency must be >= 1")
    if max_requests < 1:
        raise InvalidInputError("--max-requests must be >= 1")
    return SafetyPolicy(
        approve_target=approve_target, allow_private=allow_private, allow_public=allow_public,
        allow_mutating=allow_mutating, allow_destructive=allow_destructive, allow_negative=negative,
        max_requests=max_requests, delay_ms=delay_ms, concurrency=concurrency,
        request_timeout_ms=request_timeout, process_timeout_s=process_timeout,
    )


def _prompt_secrets(auth: AuthConfig) -> None:
    """Interactive, hidden input; values live in this process's environment only."""
    if auth.method == "bearer" and not os.environ.get(auth.token_env):
        os.environ[auth.token_env] = typer.prompt("Bearer token", hide_input=True)
    elif auth.method == "api-key" and not os.environ.get(auth.api_key_env):
        os.environ[auth.api_key_env] = typer.prompt("API key", hide_input=True)
    elif auth.method in ("login", "session", "basic"):
        if not os.environ.get(auth.username_env):
            os.environ[auth.username_env] = typer.prompt("Login username")
        if not os.environ.get(auth.password_env):
            os.environ[auth.password_env] = typer.prompt("Login password", hide_input=True)


# ------------------------------------------------------------------------------------------------ generate
@app.command()
@guarded
def generate(
    folder: FolderArg, output: OutOpt = Path("artifacts"), backend: BackendOpt = None, framework: FrameworkOpt = None,
    strategy: StrategyOpt = None, spec: SpecOpt = None, cli_discovery: CliDiscOpt = True,
    fixtures: Annotated[Optional[Path], typer.Option(help="YAML with test data for pre-existing resources (path ids, bodies).")] = None,
    allow_mutating: Annotated[bool, typer.Option(help="Include POST/PUT/PATCH scenarios.")] = False,
    allow_destructive: Annotated[bool, typer.Option(help="Include DELETE scenarios (never run against public hosts).")] = False,
    negative: Annotated[bool, typer.Option(help="Include negative (invalid input) scenarios.")] = False,
    auth: Annotated[Optional[str], typer.Option(help="none | bearer | login | api-key | basic | session (affects which scenarios can be generated).")] = None,
    seed: Annotated[Optional[int], typer.Option(help="Random seed for reproducible test data.")] = None,
    max_requests: Annotated[Optional[int], typer.Option(help="Maximum requests in the collection.")] = None,
) -> None:
    """Generate the Postman collection, environment template and test plan (no requests are sent)."""
    from .auth.provider import assumed_resolution
    from .pipeline import do_generate

    cfg = _discovery_args(ProjectConfig.load(output), backend, framework, strategy, spec, None).merged(
        {"auth": {"method": auth}, "seed": seed, "max_requests": max_requests, "fixtures": str(fixtures) if fixtures else None})
    run = do_discover(folder, output, backend=cfg.backend, framework=cfg.framework, strategy=cfg.strategy,
                      spec=cfg.spec, allow_cli=cli_discovery, progress=_say)
    require_endpoints(run)
    # assume credentials will exist at test time when an auth method is configured; real check happens in `test`
    assumed = assumed_resolution(cfg.auth)
    policy = SafetyPolicy(allow_mutating=allow_mutating, allow_destructive=allow_destructive, allow_negative=negative, max_requests=cfg.max_requests)
    gen = do_generate(run.inventory, output, GenerationOptions(policy=policy, auth=assumed, fixtures=Fixtures.load(Path(cfg.fixtures) if cfg.fixtures else None), seed=cfg.seed), _say)
    cfg.save(output)
    typer.echo(f"Collection: {len(gen.plan.requests)} request(s); {len(gen.plan.blocked)} scenario(s) would be BLOCKED")
    for b in gen.plan.blocked[:10]:
        typer.echo(f"  BLOCKED {b.method} {b.route} [{b.scenario.value}] {b.reason_code}: {b.reason}")
    typer.echo(f"Wrote {output / 'postman_collection.json'} and postman_environment.template.json, test_plan.json")


# ------------------------------------------------------------------------------------------------ test
@app.command()
@guarded
def test(
    folder: FolderArg,
    base_url: Annotated[str, typer.Option("--base-url", help="Target API base URL (include any base path), e.g. http://127.0.0.1:8000")] = "",
    output: OutOpt = Path("artifacts"), backend: BackendOpt = None, framework: FrameworkOpt = None,
    strategy: StrategyOpt = None, spec: SpecOpt = None, cli_discovery: CliDiscOpt = True, runtime_spec_url: RuntimeOpt = None,
    approve_target: Annotated[bool, typer.Option(help="Confirm this environment may receive test traffic (required).")] = False,
    allow_private: Annotated[bool, typer.Option(help="Opt in to private / link-local network targets.")] = False,
    allow_public: Annotated[bool, typer.Option(help="Opt in to public hosts (only environments you are authorized to test).")] = False,
    allow_mutating: Annotated[bool, typer.Option(help="Permit POST/PUT/PATCH scenarios.")] = False,
    allow_destructive: Annotated[bool, typer.Option(help="Permit DELETE scenarios (refused for public hosts).")] = False,
    negative: Annotated[bool, typer.Option(help="Run negative (invalid input) scenarios.")] = False,
    max_requests: Annotated[Optional[int], typer.Option(help="Hard cap on requests sent.")] = None,
    delay_ms: Annotated[Optional[int], typer.Option(help="Pause between requests (ms).")] = None,
    concurrency: Annotated[int, typer.Option(help="Accepted for policy completeness; Newman runs sequentially.")] = 1,
    request_timeout: Annotated[Optional[int], typer.Option(help="Per-request timeout (ms).")] = None,
    process_timeout: Annotated[Optional[int], typer.Option(help="Overall Newman timeout (s).")] = None,
    auth: Annotated[Optional[str], typer.Option(help="none | bearer | login | api-key | basic | session. 'login' logs in with the username/password env vars and finds the login endpoint itself unless --login-path is given.")] = None,
    token_env: Annotated[Optional[str], typer.Option(help="Env var holding the bearer token.")] = None,
    username_env: Annotated[Optional[str], typer.Option(help="Env var holding the login username.")] = None,
    password_env: Annotated[Optional[str], typer.Option(help="Env var holding the login password.")] = None,
    api_key_env: Annotated[Optional[str], typer.Option(help="Env var holding the API key.")] = None,
    api_key_header: Annotated[Optional[str], typer.Option(help="Header (or query) name for the API key.")] = None,
    login_path: Annotated[Optional[str], typer.Option(help="Login endpoint path or URL (for --auth login).")] = None,
    login_token_path: Annotated[Optional[str], typer.Option(help="Dotted path to the token in the login response, or header:Name. Default: auto-detect.")] = None,
    login_content_type: Annotated[Optional[str], typer.Option(help="json | form. Default: taken from the detected login endpoint (json).")] = None,
    no_llm: Annotated[bool, typer.Option(help="Never use the OpenRouter LLM assist to find the login endpoint (it needs OPENROUTER_API_KEY and sends route/field names and short redacted handler snippets, never credentials).")] = False,
    prompt_credentials: Annotated[bool, typer.Option(help="Prompt (hidden) for missing credentials.")] = False,
    fixtures: Annotated[Optional[Path], typer.Option(help="YAML test data for pre-existing resources.")] = None,
    seed: Annotated[Optional[int], typer.Option(help="Random seed for reproducible test data.")] = None,
) -> None:
    """Discover, generate, execute through Newman and write the QA report. Requires --base-url and --approve-target."""
    cfg = ProjectConfig.load(output)
    cfg = _discovery_args(cfg, backend, framework, strategy, spec, runtime_spec_url).merged({
        "base_url": base_url or None, "max_requests": max_requests, "delay_ms": delay_ms,
        "request_timeout_ms": request_timeout, "process_timeout_s": process_timeout, "seed": seed,
        "fixtures": str(fixtures) if fixtures else None,
        "auth": {"method": auth, "token_env": token_env, "username_env": username_env, "password_env": password_env,
                 "api_key_env": api_key_env, "api_key_header": api_key_header, "login_path": login_path,
                 "login_token_path": login_token_path, "login_content_type": login_content_type,
                 "use_llm": False if no_llm else None},
    })
    if cfg.auth.login_content_type not in (None, "json", "form"):
        raise InvalidInputError("--login-content-type must be 'json' or 'form'")
    if not cfg.base_url:
        raise InvalidInputError("--base-url is required (e.g. --base-url http://127.0.0.1:8000)")
    target = parse_target(cfg.base_url)
    approved = approve_target or target.origin in cfg.approved_targets
    if not approved and sys.stdin.isatty():
        approved = typer.confirm(f"Send test traffic to {target.origin} ({target.klass.value})?", default=False)
    policy = _policy(approved, allow_private, allow_public, allow_mutating, allow_destructive, negative, cfg.max_requests,
                     cfg.delay_ms, concurrency, cfg.request_timeout_ms, cfg.process_timeout_s)
    policy.check_target(target)  # fail fast before any discovery traffic or file churn
    if prompt_credentials:
        _prompt_secrets(cfg.auth)
    if concurrency > 1:
        _say("note: Newman executes sequentially; --concurrency > 1 is recorded but not applied")

    outcome = do_test(
        folder, output, cfg.base_url, policy, cfg.auth, fixtures_path=Path(cfg.fixtures) if cfg.fixtures else None,
        seed=cfg.seed, backend=cfg.backend, framework=cfg.framework, strategy=cfg.strategy, spec=cfg.spec,
        allow_cli=cli_discovery, runtime_spec_url=cfg.runtime_spec_url, use_llm=cfg.auth.use_llm, progress=_say,
    )
    if outcome.login_spec is not None:  # remember what worked (non-secret) so the next run skips detection
        ls = outcome.login_spec
        cfg.auth.login_path, cfg.auth.login_content_type = ls.path, ls.content_type  # type: ignore[assignment]
        cfg.auth.login_username_field, cfg.auth.login_password_field = ls.username_field, ls.password_field
        cfg.auth.login_token_path = ls.token_path or cfg.auth.login_token_path
    if approved and target.origin not in cfg.approved_targets:
        cfg.approved_targets.append(target.origin)
    cfg.save(output)  # only non-secret settings; risky permissions are never persisted
    r = outcome.report
    typer.echo("")
    typer.echo(f"PASS {r.status_counts['PASS']} | FAIL {r.status_counts['FAIL']} | BLOCKED {r.status_counts['BLOCKED']} | NOT DISCOVERED {r.status_counts['NOT DISCOVERED']}")
    for b in r.blockers:
        typer.secho(f"  blocker: {b}", fg=typer.colors.YELLOW)
    for e in outcome.extra_errors:
        typer.secho(f"  error: {redact_text(e)}", fg=typer.colors.RED, err=True)
    typer.echo(f"Report: {outcome.html_path}\n        {outcome.json_path}")
    raise typer.Exit(outcome.exit_code)


# ------------------------------------------------------------------------------------------------ report
@app.command()
@guarded
def report(
    folder: Annotated[Optional[Path], typer.Argument(help="Source folder (accepted for symmetry; artifacts come from --output).")] = None,
    output: OutOpt = Path("artifacts"),
) -> None:
    """Rebuild qa-report.json / qa-report.html from the artifacts of the last `test` run."""
    outcome = do_report(output)
    r = outcome.report
    typer.echo(f"PASS {r.status_counts['PASS']} | FAIL {r.status_counts['FAIL']} | BLOCKED {r.status_counts['BLOCKED']} | NOT DISCOVERED {r.status_counts['NOT DISCOVERED']}")
    typer.echo(f"Report: {outcome.html_path}\n        {outcome.json_path}")
    raise typer.Exit(outcome.exit_code)


if __name__ == "__main__":
    app()
