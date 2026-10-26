"""Build the QA report (JSON contract + HTML via Jinja2)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..discovery.coverage import build_coverage, status_counts
from ..execution.status_classifier import aggregate, blocked_to_results, classify_endpoints
from ..models.endpoint import EndpointInventory
from ..models.execution import ExecutionResult, ScenarioResult, TestPlan, TestStatus
from ..models.project import DiscoveryWarning, ScanResult
from ..models.report import QAReport
from ..security.redaction import redact_obj
from ..utils.filesystem import write_json

TEMPLATE_DIR = Path(__file__).parent / "templates"


def build_report(
    inv: EndpointInventory,
    plan: TestPlan,
    execution: ExecutionResult | None,
    scan: ScanResult | None = None,
    warnings: list[DiscoveryWarning] | None = None,
    meta: dict[str, Any] | None = None,
    secrets: list[str] | None = None,
) -> QAReport:
    meta = meta or {}
    results: list[ScenarioResult] = list(execution.scenarios) if execution else []
    executed_ids = {(r.endpoint_id, r.scenario) for r in results}
    for b in blocked_to_results(plan):
        if (b.endpoint_id, b.scenario) not in executed_ids:
            results.append(b)
    if execution is None or execution.error_kind:
        # nothing ran: every planned request is BLOCKED, never PASS
        reason = (execution.error_detail if execution else "tests were not executed") or "not executed"
        code = (execution.error_kind if execution else "NOT_RUN") or "NOT_RUN"
        have = {(r.endpoint_id, r.scenario) for r in results}
        for pr in plan.requests:
            if (pr.endpoint_id, pr.scenario) not in have:
                results.append(ScenarioResult(
                    endpoint_id=pr.endpoint_id, scenario=pr.scenario, method=pr.method, route=pr.route, required=pr.required,
                    status=TestStatus.BLOCKED, executed=False, reason_code=code, reason=reason,
                    expected_statuses=pr.expected_statuses, expected_basis=pr.expected_basis,
                ))
    verdicts = classify_endpoints(inv, results)
    cov = build_coverage(inv, verdicts)

    blockers: list[str] = []
    if execution and execution.error_kind:
        blockers.append(f"{execution.error_kind}: {execution.error_detail}")
    code_counts = Counter((r.reason_code or "") for r in results if r.status == TestStatus.BLOCKED)
    descriptions = {
        "MISSING_AUTH": "authentication required but credentials unavailable",
        "MISSING_FIXTURE": "test data for an existing resource is required (supply --fixtures)",
        "POLICY_NOT_AUTHORIZED": "blocked by safety policy (mutating/destructive tests not authorized)",
        "CONNECTIVITY": "target could not be reached for the request",
        "REQUEST_BUDGET": "--max-requests budget exhausted",
        "UNSUPPORTED_CONTENT_TYPE": "request body content type not supported by the generator",
    }
    for code, n in code_counts.items():
        if code and code in descriptions:
            blockers.append(f"{n} scenario(s) blocked: {descriptions[code]}")

    manual = [f"{v.method} {v.route}: {', '.join(v.review_reasons)}" for v in verdicts if v.needs_manual_review]
    manual += [f"NOT DISCOVERED: {p.description} ({p.source_file}:{p.line}) - {p.reason}" for p in inv.potential_routes]

    notes = [
        "PASS means every required assertion generated for that endpoint passed; it does not prove the endpoint is correct.",
        "Expected values labelled 'inferred' are conventions, not documented behavior; review them before treating a FAIL as a defect.",
        "Endpoint counts measure route inventory only, not behavioral or code-path coverage.",
        *inv.notes[1:],
    ]
    report = QAReport(
        project={
            "root": inv.project_root, "backend": inv.backend_path, "framework": inv.framework,
            "languages": scan.languages if scan else {}, "detected_backends": [b.model_dump() for b in scan.backends] if scan else [],
        },
        tool_versions=meta.get("tool_versions", {}),
        target=meta.get("target", {}),
        policy=meta.get("policy", {}),
        authentication=meta.get("auth", {}),
        discovery={
            "strategy_used": inv.discovery.strategy_used, "complete": inv.discovery.complete,
            "attempts": [a.model_dump() for a in inv.discovery.attempts], "limitations": inv.discovery.limitations,
            "warnings": [w.model_dump() for w in (warnings or [])], "server_base_path": inv.server_base_path,
        },
        coverage=cov,
        status_counts=status_counts(inv, verdicts),
        execution={
            "ran": execution is not None and not execution.error_kind,
            "newman_exit_code": execution.newman_exit_code if execution else None,
            "requests_executed": execution.total_requests_executed if execution else 0,
            "assertions": execution.total_assertions if execution else 0,
            "failed_assertions": execution.failed_assertions if execution else 0,
            "skipped_tests": execution.skipped_tests if execution else 0,
            "planned_requests": len(plan.requests), "blocked_scenarios": len(plan.blocked),
            "over_budget": plan.skipped_over_budget, "error_kind": execution.error_kind if execution else None,
            "error_detail": execution.error_detail if execution else None,
            "log_excerpt": execution.log_excerpt if execution else "",
        },
        blockers=blockers,
        endpoints=verdicts,
        potential_routes=[p.model_dump() for p in inv.potential_routes],
        discrepancies=[d.model_dump() for d in inv.discrepancies],
        manual_review=manual,
        notes=notes,
    )
    return QAReport.model_validate(redact_obj(report.model_dump(mode="json"), secrets))


def write_reports(report: QAReport, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, html_path = out_dir / "qa-report.json", out_dir / "qa-report.html"
    write_json(json_path, report.model_dump(mode="json"))
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    html_path.write_text(env.get_template("report.html").render(r=report.model_dump(mode="json")), encoding="utf-8")
    return json_path, html_path


def overall_exit(report: QAReport) -> int:
    from ..errors import EXIT_BLOCKED, EXIT_EXECUTION, EXIT_OK, EXIT_TESTS_FAILED

    if report.execution.get("error_kind") in ("NEWMAN_TIMEOUT", "NEWMAN_CRASH", "COLLECTION_INVALID"):
        return EXIT_EXECUTION
    c = report.status_counts
    if c.get("FAIL", 0) > 0:
        return EXIT_TESTS_FAILED
    if c.get("PASS", 0) == 0 and c.get("BLOCKED", 0) > 0:
        return EXIT_BLOCKED
    return EXIT_OK
