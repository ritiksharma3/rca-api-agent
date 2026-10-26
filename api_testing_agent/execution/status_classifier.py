"""Aggregate scenario results into endpoint verdicts, independent of discovery status."""

from __future__ import annotations

from ..models.endpoint import Confidence, EndpointInventory
from ..models.execution import ScenarioResult, TestPlan, TestStatus
from ..models.report import EndpointVerdict


def blocked_to_results(plan: TestPlan) -> list[ScenarioResult]:
    return [
        ScenarioResult(
            endpoint_id=b.endpoint_id, scenario=b.scenario, method=b.method, route=b.route, required=b.required,
            status=TestStatus.BLOCKED, executed=False, reason_code=b.reason_code, reason=b.reason,
        )
        for b in plan.blocked
    ]


def aggregate(scenarios: list[ScenarioResult]) -> tuple[TestStatus, str | None, bool]:
    """(status, reason, suite_complete). FAIL beats BLOCKED beats PASS; unexecuted tests never pass."""
    if not scenarios:
        return TestStatus.BLOCKED, "no test scenarios could be generated for this endpoint", False
    fails = [s for s in scenarios if s.status == TestStatus.FAIL]
    if fails:
        return TestStatus.FAIL, fails[0].reason, False
    required_blocked = [s for s in scenarios if s.required and s.status == TestStatus.BLOCKED]
    has_required_pass = any(s.required and s.status == TestStatus.PASS for s in scenarios)
    if required_blocked or not has_required_pass:
        first = required_blocked[0] if required_blocked else next((s for s in scenarios if s.status == TestStatus.BLOCKED), None)
        reason = f"[{first.reason_code}] {first.reason}" if first else "no required scenario produced a verdict"
        return TestStatus.BLOCKED, reason, False
    optional_blocked = [s for s in scenarios if s.status == TestStatus.BLOCKED]
    return TestStatus.PASS, None, not optional_blocked


def classify_endpoints(inv: EndpointInventory, results: list[ScenarioResult]) -> list[EndpointVerdict]:
    by_ep: dict[str, list[ScenarioResult]] = {}
    for r in results:
        by_ep.setdefault(r.endpoint_id, []).append(r)
    verdicts: list[EndpointVerdict] = []
    for ep in inv.endpoints:
        scs = sorted(by_ep.get(ep.id, []), key=lambda s: (s.scenario.value, s.reason_code or ""))
        status, reason, complete = aggregate(scs)
        review: list[str] = []
        if status == TestStatus.FAIL:
            review.append("test failure")
        if status == TestStatus.BLOCKED:
            review.append("could not be tested")
        if ep.confidence != Confidence.HIGH:
            review.append(f"{ep.confidence.value}-confidence discovery")
        if ep.unsupported:
            review.append("unsupported constructs: " + "; ".join(ep.unsupported))
        if ep.requires_auth is None:
            review.append("authentication requirement unknown")
        if status == TestStatus.PASS and not complete:
            review.append("some optional scenarios were blocked")
        verdicts.append(
            EndpointVerdict(
                endpoint_id=ep.id, method=ep.method, route=ep.route, discovery_status=ep.discovery_status.value,
                discovery_strategy=ep.strategy, confidence=ep.confidence.value,
                source=f"{ep.source_file}:{ep.line}" if ep.source_file and ep.line else ep.source_file,
                test_status=status, reason=reason, suite_complete=complete, scenarios=scs,
                needs_manual_review=bool(review), review_reasons=review,
            )
        )
    return verdicts
