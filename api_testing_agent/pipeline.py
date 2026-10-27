"""End-to-end orchestration shared by the CLI and the tests."""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from . import __version__
from .auth.headers import HeaderPlan, detect_header_hints, parse_header_flags, resolve_headers
from .auth.provider import AuthConfig, AuthProvider, AuthResolution, LoginSpec, build_provider
from .discovery.base import DiscoveryContext
from .discovery.registry import run_discovery
from .errors import (
    EXIT_EXECUTION,
    AuthenticationError,
    DiscoveryError,
    InvalidInputError,
    MissingDependencyError,
    TargetConnectivityError,
)
from .execution.newman_runner import check_dependencies, log_excerpt, run_collection
from .execution.result_parser import parse_newman_report
from .models.endpoint import EndpointInventory
from .models.execution import ExecutionResult, Scenario, TestPlan, TestStatus
from .models.project import DiscoveryWarning, ScanResult
from .models.report import QAReport
from .reporting.report_generator import build_report, overall_exit, write_reports
from .scanner.repository_scanner import scan_repository, select_backend
from .security.redaction import redact_text
from .security.safety_policy import SafetyPolicy, Target, parse_target
from .test_generation.collection_generator import EndpointFixture, Fixtures, GenerationOptions, GenerationResult, generate, subset_collection
from .utils.filesystem import read_json, write_json

MAX_RATE_LIMIT_WAIT_S = 90  # longest we wait on a Retry-After before the single retry
Progress = Callable[[str], None]


def _noop(_: str) -> None:
    pass


@dataclass
class DiscoveryRun:
    scan: ScanResult
    inventory: EndpointInventory
    warnings: list[DiscoveryWarning]


@dataclass
class TestRunOutcome:
    __test__ = False

    report: QAReport
    exit_code: int
    json_path: Path
    html_path: Path
    extra_errors: list[str] = field(default_factory=list)
    login_spec: LoginSpec | None = None  # non-secret login settings that worked (persisted for the next run)


# ---------------------------------------------------------------------------- scan / discover


def do_scan(folder: str | Path, out_dir: Path, progress: Progress = _noop) -> ScanResult:
    progress(f"Scanning {folder} ...")
    scan = scan_repository(folder)
    write_json(out_dir / "scan_result.json", scan.model_dump(mode="json"))
    return scan


def do_discover(
    folder: str | Path,
    out_dir: Path,
    *,
    backend: str | None = None,
    framework: str | None = None,
    strategy: str = "auto",
    spec: str | Path | None = None,
    timeout: float = 60.0,
    allow_cli: bool = True,
    runtime_spec_url: str | None = None,
    policy: SafetyPolicy | None = None,
    probe_base_url: str | None = None,
    progress: Progress = _noop,
) -> DiscoveryRun:
    scan = do_scan(folder, out_dir, progress)
    root = Path(scan.root)
    spec_path: Path | None = None
    from_probe = False
    if spec:
        spec_path = Path(spec).expanduser()
        if not spec_path.is_file():
            raise InvalidInputError(f"--spec file not found: {spec_path}")
        spec_path = spec_path.resolve()
    if runtime_spec_url:
        from .discovery.runtime_adapter import fetch_runtime_spec

        progress(f"Fetching runtime spec from {runtime_spec_url} (explicitly enabled) ...")
        spec_path = fetch_runtime_spec(runtime_spec_url, policy or SafetyPolicy(), out_dir / "runtime_spec")

    if spec_path is None and probe_base_url and strategy in ("auto", "openapi") and policy is not None:
        from .discovery.runtime_adapter import probe_runtime_spec

        found, note = probe_runtime_spec(probe_base_url, policy, out_dir / "runtime_spec")
        progress(f"Runtime spec: {note}")
        if found is not None:
            spec_path, from_probe = found, True

    selected = None
    if scan.backends or not spec_path:
        selected = select_backend(scan, backend, framework) if (scan.backends or not spec_path) else None
    if selected:
        progress(f"Backend: {selected.framework} ({selected.language}) at '{selected.path}' [{selected.confidence.value} confidence]")
    ctx = DiscoveryContext(root=root, scan=scan, backend=selected, spec_path=spec_path, timeout=timeout, allow_cli=allow_cli, spec_from_probe=from_probe)
    progress(f"Discovering endpoints (strategy={strategy}) ...")
    inv, warns = run_discovery(ctx, strategy)
    for a in inv.discovery.attempts:  # why a preferred strategy was skipped / failed must be visible, not buried in a JSON file
        if a.outcome == "failed":
            first = (a.detail or "").strip().splitlines()[0][:220] if (a.detail or "").strip() else "no detail"
            progress(f"  discovery: {a.adapter} failed ({first}); fell back to the next strategy")
    if inv.discovery.strategy_used:
        progress(f"  discovery: using {inv.discovery.strategy_used} ({len(inv.endpoints)} endpoint(s))")
    write_json(out_dir / "scan_result.json", scan.model_dump(mode="json"))
    write_json(out_dir / "endpoint_inventory.json", inv.model_dump(mode="json"))
    write_json(out_dir / "discovery_warnings.json", [w.model_dump(mode="json") for w in warns])
    return DiscoveryRun(scan, inv, warns)


def require_endpoints(run: DiscoveryRun) -> None:
    if not run.inventory.endpoints:
        raise DiscoveryError(
            "No endpoints were discovered. Attempts: "
            + "; ".join(f"{a.adapter}={a.outcome}" + (f" ({a.detail})" if a.detail else "") for a in run.inventory.discovery.attempts)
            + ". Try --spec <openapi file> or --runtime-spec-url."
        )


# ---------------------------------------------------------------------------- generate


def do_generate(inv: EndpointInventory, out_dir: Path, opts: GenerationOptions, progress: Progress = _noop) -> GenerationResult:
    progress("Generating Postman collection ...")
    gen = generate(inv, opts)
    write_json(out_dir / "postman_collection.json", gen.collection)
    write_json(out_dir / "postman_environment.template.json", gen.environment)
    write_json(out_dir / "test_plan.json", gen.plan.model_dump(mode="json"))
    return gen


# ---------------------------------------------------------------------------- test


def _relogin_and_retry(
    provider: AuthProvider, auth_res: AuthResolution, gen: GenerationResult, plan: TestPlan, execution: ExecutionResult,
    inv: EndpointInventory, base_url: str, policy: SafetyPolicy, newman: str, out_dir: Path, secrets: list[str],
    timeout_s: float, progress: Progress, hdr_plan: HeaderPlan | None = None,
) -> tuple[int, list[str]]:
    """Requests that were rejected with 401 although a credential was attached usually mean the token expired.

    Log in once more and re-run just those requests (whole scenario groups, so negative variants stay together).
    Returns (number of requests retried, notes). Never raises for an authentication problem: the first-pass results stay.
    """
    public = {e.id for e in inv.endpoints if e.requires_auth is False}
    login_id = auth_res.login.endpoint_id if auth_res.login else None
    rejected = {
        (s.endpoint_id, s.scenario) for s in execution.scenarios
        if s.executed and s.http_status == 401 and s.scenario != Scenario.AUTH_REQUIRED
        and s.endpoint_id not in public and s.endpoint_id != login_id
    }
    if not rejected:
        return 0, []
    retry = [p for p in plan.requests if (p.endpoint_id, p.scenario) in rejected]
    progress(f"{len(retry)} request(s) were rejected with 401; logging in again and retrying them once ...")
    try:
        fresh = provider.resolve(base_url, timeout_s)
    except AuthenticationError as exc:
        return 0, [f"re-login failed, first-pass results kept: {redact_text(str(exc), secrets)}"]
    if not fresh.available:
        return 0, ["re-login produced no credential, first-pass results kept"]
    secrets.extend(s for s in fresh.secrets if s not in secrets)
    if hdr_plan is not None:
        fresh.env_vars.update(hdr_plan.env_vars())
    sub_plan = TestPlan(requests=retry)
    res, raw = run_collection(subset_collection(gen.collection, {p.item_id for p in retry}), base_url, fresh.env_vars, policy, newman, out_dir, secrets)
    if raw is None:
        return 0, ["retry run produced no report, first-pass results kept"]
    redone = parse_newman_report(raw, sub_plan, secrets)
    for s in redone.scenarios:
        if s.http_status == 401 and s.status != TestStatus.PASS:
            s.reason_code = "AUTH_REJECTED_AFTER_RELOGIN"
            s.reason = f"still rejected with 401 after logging in again: {s.reason or ''}".strip()[:500]
    execution.scenarios = [s for s in execution.scenarios if (s.endpoint_id, s.scenario) not in rejected] + redone.scenarios
    execution.total_requests_executed = sum(1 for s in execution.scenarios if s.executed)
    execution.total_assertions = sum(len(s.assertions) for s in execution.scenarios)
    execution.failed_assertions = sum(1 for s in execution.scenarios for a in s.assertions if not a.passed and not a.skipped)
    execution.skipped_tests = sum(1 for s in execution.scenarios for a in s.assertions if a.skipped)
    return len(retry), []


def _retry_rate_limited(
    gen: GenerationResult, plan: TestPlan, execution: ExecutionResult, base_url: str, policy: SafetyPolicy, newman: str,
    out_dir: Path, secrets: list[str], env_vars: dict[str, str], progress: Progress,
) -> tuple[int, list[str]]:
    """Requests answered 429 are retried once after the server's Retry-After (capped), then reported as they come out."""
    limited = {(s.endpoint_id, s.scenario) for s in execution.scenarios if s.executed and s.http_status == 429}
    if not limited:
        return 0, []
    waits = [s.evidence.get("retry_after_s") for s in execution.scenarios if s.http_status == 429 and isinstance(s.evidence.get("retry_after_s"), int)]
    wait = min(max(waits or [30]), MAX_RATE_LIMIT_WAIT_S)
    retry = [p for p in plan.requests if (p.endpoint_id, p.scenario) in limited]
    progress(f"{len(retry)} request(s) were rate-limited (429); waiting {wait}s and retrying them once ...")
    time.sleep(wait)
    sub_plan = TestPlan(requests=retry)
    res, raw = run_collection(subset_collection(gen.collection, {p.item_id for p in retry}), base_url, env_vars, policy, newman, out_dir, secrets)
    if raw is None:
        return 0, ["rate-limit retry produced no report, first-pass results kept"]
    redone = parse_newman_report(raw, sub_plan, secrets)
    execution.scenarios = [s for s in execution.scenarios if (s.endpoint_id, s.scenario) not in limited] + redone.scenarios
    execution.total_requests_executed = sum(1 for s in execution.scenarios if s.executed)
    execution.total_assertions = sum(len(s.assertions) for s in execution.scenarios)
    execution.failed_assertions = sum(1 for s in execution.scenarios for a in s.assertions if not a.passed and not a.skipped)
    execution.skipped_tests = sum(1 for s in execution.scenarios for a in s.assertions if a.skipped)
    return len(retry), []


def _preflight(target: Target, timeout_s: float) -> None:
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
            client.get(target.base_url or target.origin)
    except httpx.HTTPError as exc:
        raise TargetConnectivityError(f"Cannot reach {target.origin}: {_connectivity_cause(exc, timeout_s)}") from exc


def _connectivity_cause(exc: httpx.HTTPError, timeout_s: float) -> str:
    """Say what the failure means, not just its exception class: refused vs. slow vs. accepted-but-silent."""
    detail = redact_text(f"{type(exc).__name__}: {exc}")
    if isinstance(exc, httpx.ReadTimeout):
        return (f"the server accepted the connection but did not answer within {timeout_s:g}s. A single-threaded dev server (php -S, "
                "flask run, node with a blocking call) stuck on a dependency such as a database, Redis or an external API is the usual cause; "
                f"check the application's log and that its dependencies are reachable. ({detail})")
    if isinstance(exc, httpx.ConnectTimeout):
        return f"could not open a connection within {timeout_s:g}s; check the host, port, VPN or firewall. ({detail})"
    if isinstance(exc, httpx.ConnectError):
        return f"connection refused or host unreachable; is the server running at that address and port? ({detail})"
    return detail


def _suggest_bodies(inv: EndpointInventory, fixtures: Fixtures, auth_res: AuthResolution, policy: SafetyPolicy, allowed: bool, progress: Progress) -> dict[str, Any]:
    """Static analysis only learns body *field names* (types unknown), so POST/PUT/PATCH bodies are usually rejected as invalid.
    Ask the LLM for a valid example, from the redacted handler source only. Returns names of the endpoints it filled in."""
    if not (allowed and policy.allow_mutating):
        return {}
    login_id = auth_res.login.endpoint_id if auth_res.login else None
    todo = [e for e in inv.endpoints
            if e.method in ("POST", "PUT", "PATCH") and e.request_body is not None and e.id != login_id
            and f"{e.method} {e.route}" not in fixtures.endpoints
            and any("inferred" in w or "not established" in w for w in e.warnings)]
    if not todo:
        return {}
    progress(f"Asking the LLM for example request bodies of {len(todo)} endpoint(s) (redacted handler source only) ...")
    from .auth.llm import suggest_bodies

    bodies, note = suggest_bodies(inv, todo)
    for key, body in bodies.items():
        fx = fixtures.endpoints.setdefault(key, EndpointFixture())
        fx.body, fx.generated = body, True
    if not bodies:
        progress(note)
    return {"endpoints": sorted(bodies), "note": note}


def do_test(
    folder: str | Path,
    out_dir: Path,
    base_url: str,
    policy: SafetyPolicy,
    auth_config: AuthConfig,
    *,
    fixtures_path: Path | None = None,
    seed: int = 1234,
    backend: str | None = None,
    framework: str | None = None,
    strategy: str = "auto",
    spec: str | Path | None = None,
    allow_cli: bool = True,
    runtime_spec_url: str | None = None,
    discovery_timeout: float = 60.0,
    use_llm: bool | None = None,
    header_flags: list[str] | None = None,
    progress: Progress = _noop,
) -> TestRunOutcome:
    explicit_headers = parse_header_flags(header_flags)  # fail on a malformed --header before any traffic
    target = parse_target(base_url)
    policy.check_target(target)
    progress(f"Target: {target.base_url} ({target.klass.value}); mutating={policy.allow_mutating} destructive={policy.allow_destructive} negative={policy.allow_negative}")

    run = do_discover(folder, out_dir, backend=backend, framework=framework, strategy=strategy, spec=spec,
                      timeout=discovery_timeout, allow_cli=allow_cli, runtime_spec_url=runtime_spec_url,
                      policy=policy, probe_base_url=base_url, progress=progress)
    inv = run.inventory
    require_endpoints(run)
    if inv.server_base_path and target.base_path != inv.server_base_path:
        progress(f"WARNING: specification declares server base path '{inv.server_base_path}' but --base-url path is '{target.base_path or '/'}'")

    extra_errors: list[str] = []
    secrets: list[str] = []
    meta: dict[str, Any] = {
        "target": {"base_url": target.base_url, "origin": target.origin, "class": target.klass.value, "resolved_ips": target.ips},
        "policy": {**policy.model_dump(), "note": "newman executes requests sequentially; concurrency > 1 is not applied"},
    }
    execution: ExecutionResult | None = None
    plan = TestPlan()
    exit_override: int | None = None

    # connectivity first: no point generating around an unreachable target, but still emit a report
    connectivity_error: str | None = None
    try:
        progress("Checking target connectivity ...")
        _preflight(target, policy.request_timeout_ms / 1000)
    except TargetConnectivityError as exc:
        connectivity_error = str(exc)
        exit_override = exc.exit_code

    # authentication
    auth_res: AuthResolution = AuthResolution("none", False, "no authentication configured (--auth none)")
    auth_error: str | None = None
    # headers every request needs (API key, client version, tenant ...): found in the source, valued from flags / .env / generators
    llm_allowed = auth_config.use_llm if use_llm is None else use_llm
    hdr_plan = resolve_headers(detect_header_hints(inv), explicit_headers, auth_config.api_key_env, llm_allowed)
    if hdr_plan.headers or hdr_plan.unresolved or hdr_plan.unsupported:
        progress("Request headers: " + ", ".join(f"{h.name} ({h.source})" for h in hdr_plan.headers)
                 + (f"; MISSING: {', '.join(h.name for h in hdr_plan.unresolved)}" if hdr_plan.unresolved else "")
                 + (f"; unsupported (signature): {', '.join(hdr_plan.unsupported)}" if hdr_plan.unsupported else ""))
    if hdr_plan.unresolved:
        progress(hdr_plan.hint_for_missing())
    provider: AuthProvider = build_provider(auth_config, inv, use_llm, policy.delay_ms)
    provider.header_plan = hdr_plan
    if connectivity_error is None and auth_config.method != "none":
        progress(f"Resolving authentication ({auth_config.method}) ...")
        try:
            auth_res = provider.resolve(target.base_url, policy.request_timeout_ms / 1000)
        except AuthenticationError as exc:
            # Login is the first thing that must work: without it nothing else is meaningful, so stop here -- before any LLM
            # call, collection generation or Newman run -- and say exactly why.
            msg = redact_text(str(exc), [*hdr_plan.secrets(), os.environ.get(auth_config.password_env, "")])
            raise AuthenticationError(f"login failed, nothing was tested: {msg}") from exc
    elif auth_config.method != "none":
        auth_res = AuthResolution(auth_config.method, False, "not attempted: target unreachable")
    auth_res.env_vars.update(hdr_plan.env_vars())  # header values reach Newman through the private runtime environment only
    auth_res.secrets = [*auth_res.secrets, *hdr_plan.secrets()]
    secrets = list(auth_res.secrets)
    meta["headers"] = {"headers": hdr_plan.summary(), "notes": hdr_plan.notes, "llm_used": hdr_plan.llm_used}
    meta["auth"] = {
        "method": auth_config.method, "credentials_available": auth_res.available, "reason": auth_res.reason, "notes": auth_res.notes,
        "login_endpoint": auth_res.login.path if auth_res.login else None,
        "login_detected_by": auth_res.login.source if auth_res.login else None,
        "llm_used": auth_res.llm_used or hdr_plan.llm_used, "relogins": 0, "login_requests": auth_res.login_requests,
        "request_headers": hdr_plan.summary(),  # names and provenance only, never values
    }
    meta["auth"]["notes"] = [*meta["auth"]["notes"], *hdr_plan.notes]

    fixtures = Fixtures.load(fixtures_path)
    meta["llm_bodies"] = _suggest_bodies(inv, fixtures, auth_res, policy, llm_allowed, progress)
    gen = do_generate(inv, out_dir, GenerationOptions(policy=policy, auth=auth_res, fixtures=fixtures, seed=seed, headers=hdr_plan), progress)
    plan = gen.plan

    versions: dict[str, str | None] = {"api_testing_agent": __version__, "python": platform.python_version(), "node": None, "newman": None}
    if connectivity_error:
        execution = ExecutionResult(error_kind="CONNECTIVITY", error_detail=connectivity_error)
        extra_errors.append(connectivity_error)
    elif not plan.requests:
        execution = ExecutionResult(error_kind="NOTHING_TO_RUN", error_detail="no executable requests after applying policy, auth and fixtures")
    else:
        try:
            newman, tv = check_dependencies(Path(out_dir))
            versions.update({"node": tv.node, "newman": tv.newman})
            meta["tool_versions"] = versions
            progress(f"Running {len(plan.requests)} request(s) with Newman {tv.newman} ...")
            res, raw = run_collection(gen.collection, target.base_url, auth_res.env_vars, policy, newman, out_dir, secrets)
            if res.timed_out:
                execution = ExecutionResult(error_kind="NEWMAN_TIMEOUT", error_detail=f"Newman exceeded {policy.process_timeout_s}s", newman_version=tv.newman)
            elif raw is None:
                text = (res.stdout + res.stderr).lower()
                kind = "COLLECTION_INVALID" if "collection" in text and ("could not" in text or "invalid" in text or "unable" in text) else "NEWMAN_CRASH"
                execution = ExecutionResult(error_kind=kind, error_detail=f"Newman exited {res.returncode} without a report", newman_version=tv.newman)
            else:
                execution = parse_newman_report(raw, plan, secrets)
                execution.newman_version = tv.newman
                if auth_res.available and auth_res.relogin_supported:
                    retried, notes = _relogin_and_retry(provider, auth_res, gen, plan, execution, inv, target.base_url, policy,
                                                        newman, out_dir, secrets, policy.request_timeout_ms / 1000, progress, hdr_plan)
                    meta["auth"]["relogins"] = 1 if retried else 0
                    meta["auth"]["retried_requests"] = retried
                    meta["auth"]["login_requests"] = getattr(provider, "login_requests", meta["auth"]["login_requests"])
                    meta["auth"]["notes"] = [*meta["auth"]["notes"], *notes]
                limited_retried, limit_notes = _retry_rate_limited(gen, plan, execution, target.base_url, policy, newman, out_dir, secrets,
                                                                   auth_res.env_vars, progress)
                if limited_retried:
                    meta["rate_limited_retried"] = limited_retried
                if limit_notes:
                    meta.setdefault("notes", []).extend(limit_notes)
            execution.newman_exit_code = res.returncode
            execution.log_excerpt = log_excerpt(res, secrets)
        except MissingDependencyError as exc:
            execution = ExecutionResult(error_kind="NEWMAN_MISSING", error_detail=str(exc))
            exit_override = exit_override or exc.exit_code
            extra_errors.append(str(exc))
    meta.setdefault("tool_versions", versions)

    if auth_error:
        extra_errors.append(f"authentication failure: {auth_error}")
    report = build_report(inv, plan, execution, run.scan, run.warnings, meta, secrets)
    if auth_error and not any(b.startswith("authentication failure") for b in report.blockers):
        report.blockers.append(f"authentication failure: {redact_text(auth_error, secrets)}")
    json_path, html_path = write_reports(report, out_dir)
    write_json(out_dir / "execution_result.json", (execution or ExecutionResult()).model_dump(mode="json"))
    write_json(out_dir / "run_meta.json", meta)

    code = overall_exit(report)
    if exit_override and code != EXIT_EXECUTION:
        # supplied credentials that do not work (or an unreachable target / missing Newman) mean the run is not
        # a trustworthy verdict, so that condition outranks ordinary test failures
        code = exit_override
    return TestRunOutcome(report, code, json_path, html_path, extra_errors, login_spec=auth_res.login)


# ---------------------------------------------------------------------------- report from artifacts


def do_report(out_dir: Path) -> TestRunOutcome:
    """Rebuild the QA report from artifacts written by a previous `test` run."""
    needed = ["endpoint_inventory.json", "test_plan.json", "execution_result.json"]
    missing = [n for n in needed if not (out_dir / n).exists()]
    if missing:
        raise InvalidInputError(f"Missing artifacts in {out_dir}: {', '.join(missing)}. Run `api-agent test` first.")
    inv = EndpointInventory.model_validate(read_json(out_dir / "endpoint_inventory.json"))
    plan = TestPlan.model_validate(read_json(out_dir / "test_plan.json"))
    execution = ExecutionResult.model_validate(read_json(out_dir / "execution_result.json"))
    scan = ScanResult.model_validate(read_json(out_dir / "scan_result.json")) if (out_dir / "scan_result.json").exists() else None
    warns = [DiscoveryWarning.model_validate(w) for w in read_json(out_dir / "discovery_warnings.json")] if (out_dir / "discovery_warnings.json").exists() else []
    meta = read_json(out_dir / "run_meta.json") if (out_dir / "run_meta.json").exists() else {}
    report = build_report(inv, plan, execution, scan, warns, meta)
    json_path, html_path = write_reports(report, out_dir)
    return TestRunOutcome(report, overall_exit(report), json_path, html_path)
