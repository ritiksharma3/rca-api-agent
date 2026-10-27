"""Parse Newman's JSON report into endpoint-scenario results using the planned item ids."""

from __future__ import annotations

from typing import Any

from ..models.execution import (
    AssertionResult,
    ExecutionResult,
    PlannedRequest,
    ScenarioResult,
    TestPlan,
    TestStatus,
)
from ..security.redaction import redact_text, truncate

BODY_SNIPPET = 300


def _body_snippet(response: dict[str, Any], secrets: list[str]) -> str | None:
    stream = response.get("stream")
    data = stream.get("data") if isinstance(stream, dict) else None
    if not isinstance(data, list):
        return None
    try:
        text = bytes(data[:2000]).decode("utf-8", "replace")
    except (TypeError, ValueError):
        return None
    return truncate(redact_text(text, secrets), BODY_SNIPPET)


def _retry_after(response: dict[str, Any]) -> int | None:
    for h in response.get("header") or []:
        if isinstance(h, dict) and str(h.get("key", "")).lower() == "retry-after":
            try:
                return max(int(float(str(h.get("value")))), 0)
            except ValueError:
                return None
    return None


def parse_newman_report(raw: dict[str, Any], plan: TestPlan, secrets: list[str]) -> ExecutionResult:
    result = ExecutionResult()
    run = raw.get("run", {}) if isinstance(raw, dict) else {}
    planned = {p.item_id: p for p in plan.requests}
    seen: set[str] = set()
    total_assertions = failed = skipped = 0

    for ex in run.get("executions", []) or []:
        item_id = (ex.get("item") or {}).get("id")
        pr: PlannedRequest | None = planned.get(item_id)
        if pr is None:
            continue
        seen.add(item_id)
        resp = ex.get("response") or {}
        asserts: list[AssertionResult] = []
        for a in ex.get("assertions", []) or []:
            err = a.get("error")
            ar = AssertionResult(
                name=a.get("assertion", ""), passed=err is None and not a.get("skipped"),
                skipped=bool(a.get("skipped")),
                error=truncate(redact_text((err or {}).get("message", ""), secrets), 400) if err else None,
            )
            asserts.append(ar)
            total_assertions += 1
            failed += 0 if ar.passed or ar.skipped else 1
            skipped += 1 if ar.skipped else 0
        req_err = ex.get("requestError")
        base = dict(
            endpoint_id=pr.endpoint_id, scenario=pr.scenario, method=pr.method, route=pr.route, required=pr.required,
            expected_statuses=pr.expected_statuses, expected_basis=pr.expected_basis, assertions=asserts,
        )
        if req_err or not resp:
            msg = redact_text(str((req_err or {}).get("message") or "no response received"), secrets)
            result.scenarios.append(ScenarioResult(**base, status=TestStatus.BLOCKED, executed=False, reason_code="CONNECTIVITY",
                                                   reason=f"request could not be completed: {msg}"))
            continue
        real = [a for a in asserts if not a.skipped]
        ok = bool(real) and all(a.passed for a in real)
        evidence: dict[str, Any] = {"request": f"{pr.method} {pr.route}", "description": pr.description}
        status = TestStatus.PASS if ok else TestStatus.FAIL
        reason = None
        if not real:
            status, reason = TestStatus.BLOCKED, "no assertions were evaluated, so no verdict can be given"
        elif not ok:
            reason = "; ".join(f"{a.name}: {a.error or 'failed'}" for a in real if not a.passed)[:500]
            snippet = _body_snippet(resp, secrets)
            if snippet:
                evidence["response_body_snippet"] = snippet
        reason_code = None if status != TestStatus.BLOCKED else "NO_ASSERTIONS"
        code = resp.get("code")
        if status == TestStatus.FAIL and pr.scenario.value == "positive":
            if code == 403:
                reason_code = "FORBIDDEN_FOR_USER"
                reason = ("the server answered 403: this account is authenticated but may lack the role/permission this endpoint needs "
                          "(use an account that has it, or treat as a defect if it should be allowed). " + (reason or ""))[:500]
            elif code == 429:
                reason_code = "RATE_LIMITED"
                reason = "the server rate-limited this request (HTTP 429); raise --delay-ms. " + (reason or "")
                evidence["retry_after_s"] = _retry_after(resp)
        result.scenarios.append(
            ScenarioResult(**base, status=status, executed=bool(real), http_status=code,
                           duration_ms=resp.get("responseTime"), reason=reason,
                           reason_code=reason_code, evidence=evidence)
        )

    for pr in plan.requests:  # planned but never reported by Newman
        if pr.item_id not in seen:
            result.scenarios.append(
                ScenarioResult(endpoint_id=pr.endpoint_id, scenario=pr.scenario, method=pr.method, route=pr.route,
                               required=pr.required, status=TestStatus.BLOCKED, executed=False, reason_code="NOT_EXECUTED",
                               reason="Newman did not report this request (run aborted or timed out)",
                               expected_statuses=pr.expected_statuses, expected_basis=pr.expected_basis)
            )
    result.total_requests_executed = len(seen)
    result.total_assertions = total_assertions
    result.failed_assertions = failed
    result.skipped_tests = skipped
    return result
