"""End-to-end orchestration shared by the CLI and the tests."""

from __future__ import annotations

import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from . import __version__
from .auth.provider import AuthConfig, AuthResolution, build_provider
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
from .models.execution import ExecutionResult, TestPlan
from .models.project import DiscoveryWarning, ScanResult
from .models.report import QAReport
from .reporting.report_generator import build_report, overall_exit, write_reports
from .scanner.repository_scanner import scan_repository, select_backend
from .security.redaction import redact_text
from .security.safety_policy import SafetyPolicy, Target, parse_target
from .test_generation.collection_generator import Fixtures, GenerationOptions, GenerationResult, generate
from .utils.filesystem import read_json, write_json

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
    progress: Progress = _noop,
) -> DiscoveryRun:
    scan = do_scan(folder, out_dir, progress)
    root = Path(scan.root)
    spec_path: Path | None = None
    if spec:
        spec_path = Path(spec).expanduser()
        if not spec_path.is_file():
            raise InvalidInputError(f"--spec file not found: {spec_path}")
        spec_path = spec_path.resolve()
    if runtime_spec_url:
        from .discovery.runtime_adapter import fetch_runtime_spec

        progress(f"Fetching runtime spec from {runtime_spec_url} (explicitly enabled) ...")
        spec_path = fetch_runtime_spec(runtime_spec_url, policy or SafetyPolicy(), out_dir / "runtime_spec")

    selected = None
    if scan.backends or not spec_path:
        selected = select_backend(scan, backend, framework) if (scan.backends or not spec_path) else None
    if selected:
        progress(f"Backend: {selected.framework} ({selected.language}) at '{selected.path}' [{selected.confidence.value} confidence]")
    ctx = DiscoveryContext(root=root, scan=scan, backend=selected, spec_path=spec_path, timeout=timeout, allow_cli=allow_cli)
    progress(f"Discovering endpoints (strategy={strategy}) ...")
    inv, warns = run_discovery(ctx, strategy)
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


def _preflight(target: Target, timeout_s: float) -> None:
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
            client.get(target.base_url or target.origin)
    except httpx.HTTPError as exc:
        raise TargetConnectivityError(
            f"Cannot reach {target.origin}: {redact_text(type(exc).__name__ + ': ' + str(exc))}"
        ) from exc


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
    progress: Progress = _noop,
) -> TestRunOutcome:
    target = parse_target(base_url)
    policy.check_target(target)
    progress(f"Target: {target.base_url} ({target.klass.value}); mutating={policy.allow_mutating} destructive={policy.allow_destructive} negative={policy.allow_negative}")

    run = do_discover(folder, out_dir, backend=backend, framework=framework, strategy=strategy, spec=spec,
                      timeout=discovery_timeout, allow_cli=allow_cli, runtime_spec_url=runtime_spec_url,
                      policy=policy, progress=progress)
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
    if connectivity_error is None and auth_config.method != "none":
        progress(f"Resolving authentication ({auth_config.method}) ...")
        try:
            auth_res = build_provider(auth_config).resolve(target.base_url, policy.request_timeout_ms / 1000)
        except AuthenticationError as exc:
            auth_error = str(exc)
            auth_res = AuthResolution(auth_config.method, False, f"authentication failed: {exc}")
            exit_override = exit_override or exc.exit_code
    elif auth_config.method != "none":
        auth_res = AuthResolution(auth_config.method, False, "not attempted: target unreachable")
    secrets = list(auth_res.secrets)
    meta["auth"] = {"method": auth_config.method, "credentials_available": auth_res.available, "reason": auth_res.reason, "notes": auth_res.notes}

    gen = do_generate(inv, out_dir, GenerationOptions(policy=policy, auth=auth_res, fixtures=Fixtures.load(fixtures_path), seed=seed), progress)
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
    if auth_error and not any("authentication" in b for b in report.blockers):
        report.blockers.append(f"authentication failure: {redact_text(auth_error, secrets)}")
    json_path, html_path = write_reports(report, out_dir)
    write_json(out_dir / "execution_result.json", (execution or ExecutionResult()).model_dump(mode="json"))
    write_json(out_dir / "run_meta.json", meta)

    code = overall_exit(report)
    if exit_override and code != EXIT_EXECUTION:
        # supplied credentials that do not work (or an unreachable target / missing Newman) mean the run is not
        # a trustworthy verdict, so that condition outranks ordinary test failures
        code = exit_override
    return TestRunOutcome(report, code, json_path, html_path, extra_errors)


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
