from __future__ import annotations

import json

from api_testing_agent.errors import EXIT_BLOCKED, EXIT_EXECUTION, EXIT_OK, EXIT_TESTS_FAILED
from api_testing_agent.execution.result_parser import parse_newman_report
from api_testing_agent.execution.status_classifier import aggregate
from api_testing_agent.models.endpoint import Endpoint, EndpointInventory, PotentialRoute
from api_testing_agent.models.execution import (
    BlockedScenario, ExecutionResult, PlannedRequest, Scenario, ScenarioResult, TestPlan, TestStatus,
)
from api_testing_agent.reporting.report_generator import build_report, overall_exit, write_reports


def _ep(method, route):
    return Endpoint(method=method, route=route, original_path=route, strategy="static")


def _planned(ep, scenario=Scenario.POSITIVE, required=True, n=0):
    return PlannedRequest(item_id=f"{ep.id}|{scenario.value}|{n}", endpoint_id=ep.id, scenario=scenario, method=ep.method,
                          route=ep.route, required=required, expected_statuses=[200], expected_basis="documented")


def _exec(item_id, asserts, code=200, err=None, body=b""):
    ex = {"item": {"id": item_id}, "assertions": asserts,
          "response": {"code": code, "responseTime": 12, "stream": {"type": "Buffer", "data": list(body)}} if not err else None}
    if err:
        ex["requestError"] = {"message": err}
    return ex


OK = {"assertion": "status ok"}
BAD = {"assertion": "status ok", "error": {"message": "expected 500 to be one of [200] token=SECRETVALUE1"}}


# ------------------------------------------------------------------ Newman result parsing
def test_parse_pass_fail_connectivity_and_not_reported():
    e1, e2, e3, e4 = (_ep("GET", f"/r{i}") for i in range(4))
    plan = TestPlan(requests=[_planned(e) for e in (e1, e2, e3, e4)])
    raw = {"run": {"executions": [
        _exec(plan.requests[0].item_id, [OK]),
        _exec(plan.requests[1].item_id, [OK, BAD], code=500, body=b'{"detail":"boom","password":"hunter2hunter2"}'),
        _exec(plan.requests[2].item_id, [], err="connect ECONNREFUSED 127.0.0.1:9"),
    ]}}
    res = parse_newman_report(raw, plan, ["SECRETVALUE1"])
    by = {s.route: s for s in res.scenarios}
    assert by["/r0"].status == TestStatus.PASS and by["/r0"].executed
    assert by["/r1"].status == TestStatus.FAIL and by["/r1"].http_status == 500
    assert "SECRETVALUE1" not in json.dumps(res.model_dump(mode="json")) and "hunter2hunter2" not in json.dumps(res.model_dump(mode="json"))
    assert by["/r2"].status == TestStatus.BLOCKED and by["/r2"].reason_code == "CONNECTIVITY" and not by["/r2"].executed
    assert by["/r3"].status == TestStatus.BLOCKED and by["/r3"].reason_code == "NOT_EXECUTED", "an unreported request must never be PASS"
    assert (res.total_requests_executed, res.failed_assertions, res.total_assertions) == (3, 1, 3)


def test_skipped_assertions_do_not_pass_a_test():
    e = _ep("GET", "/s")
    plan = TestPlan(requests=[_planned(e)])
    res = parse_newman_report({"run": {"executions": [_exec(plan.requests[0].item_id, [{"assertion": "x", "skipped": True}])]}}, plan, [])
    assert res.scenarios[0].status == TestStatus.BLOCKED and res.skipped_tests == 1


# ------------------------------------------------------------------ status classification
def _sr(status, required=True, scenario=Scenario.POSITIVE, code=None):
    return ScenarioResult(endpoint_id="x", scenario=scenario, method="GET", route="/x", required=required, status=status,
                          executed=status != TestStatus.BLOCKED, reason_code=code, reason="why")


def test_aggregate_rules():
    P, F, B = TestStatus.PASS, TestStatus.FAIL, TestStatus.BLOCKED
    assert aggregate([_sr(P)])[:3] == (P, None, True)
    assert aggregate([_sr(P), _sr(F, False, Scenario.NEGATIVE)])[0] == F
    assert aggregate([_sr(B, code="MISSING_AUTH"), _sr(P, False, Scenario.AUTH_REQUIRED)])[0] == B, "a passing optional check cannot hide a blocked required one"
    status, _, complete = aggregate([_sr(P), _sr(B, False, Scenario.NEGATIVE, "MISSING_AUTH")])
    assert status == P and complete is False
    assert aggregate([])[0] == B
    assert aggregate([_sr(P, False, Scenario.AUTH_REQUIRED)])[0] == B, "no required scenario passed -> not PASS"


# ------------------------------------------------------------------ reporting
def _inventory():
    a, b, c = _ep("GET", "/ok"), _ep("GET", "/bad"), _ep("POST", "/skipped")
    inv = EndpointInventory(endpoints=[a, b, c], potential_routes=[PotentialRoute(description="app.add_api_route(<dynamic>)", reason="dynamic", source_file="m.py", line=3)])
    plan = TestPlan(
        requests=[_planned(a), _planned(b)],
        blocked=[BlockedScenario(endpoint_id=c.id, scenario=Scenario.POSITIVE, method="POST", route="/skipped", reason_code="POLICY_NOT_AUTHORIZED", reason="POST is mutating")],
    )
    return inv, plan, a, b


def test_report_separates_discovery_from_test_status_and_counts_not_discovered(tmp_path):
    inv, plan, a, b = _inventory()
    ex = ExecutionResult(scenarios=[
        ScenarioResult(endpoint_id=a.id, scenario=Scenario.POSITIVE, method="GET", route="/ok", status=TestStatus.PASS, executed=True, http_status=200),
        ScenarioResult(endpoint_id=b.id, scenario=Scenario.POSITIVE, method="GET", route="/bad", status=TestStatus.FAIL, executed=True, http_status=500, reason="boom"),
    ], total_requests_executed=2)
    rep = build_report(inv, plan, ex, secrets=[])
    assert rep.status_counts == {"PASS": 1, "FAIL": 1, "BLOCKED": 1, "NOT DISCOVERED": 1}
    skipped = next(v for v in rep.endpoints if v.route == "/skipped")
    assert skipped.discovery_status == "DISCOVERED" and skipped.test_status == TestStatus.BLOCKED, "discovered-but-not-run stays discovered"
    assert "POLICY_NOT_AUTHORIZED" in (skipped.reason or "")
    assert rep.coverage.confirmed_routes == 3 and rep.coverage.potential_unresolved == 1 and not rep.coverage.discovery_complete
    assert any("NOT DISCOVERED" in m for m in rep.manual_review)
    jp, hp = write_reports(rep, tmp_path)
    data = json.loads(jp.read_text("utf-8"))
    assert data["schema_version"] == "1.0" and data["status_counts"]["FAIL"] == 1
    html = hp.read_text("utf-8")
    for token in ("PASS", "FAIL", "BLOCKED", "NOT DISCOVERED", "/skipped", "lower bound"):
        assert token in html
    assert overall_exit(rep) == EXIT_TESTS_FAILED


def test_report_when_execution_failed_never_reports_pass():
    inv, plan, *_ = _inventory()
    rep = build_report(inv, plan, ExecutionResult(error_kind="NEWMAN_MISSING", error_detail="newman not installed"))
    assert rep.status_counts["PASS"] == 0 and rep.status_counts["BLOCKED"] == 3
    assert any("NEWMAN_MISSING" in b for b in rep.blockers)
    assert overall_exit(rep) == EXIT_BLOCKED


def test_report_without_execution_object_is_all_blocked():
    inv, plan, *_ = _inventory()
    rep = build_report(inv, plan, None)
    assert rep.status_counts["PASS"] == 0


def test_report_redacts_secrets_everywhere():
    inv, plan, a, _ = _inventory()
    ex = ExecutionResult(scenarios=[ScenarioResult(endpoint_id=a.id, scenario=Scenario.POSITIVE, method="GET", route="/ok", status=TestStatus.FAIL,
                                                  executed=True, reason="got Bearer ABCDEF123456 and TOPSECRETVALUE", evidence={"b": "TOPSECRETVALUE"})],
                         log_excerpt="Authorization: Bearer ABCDEF123456")
    rep = build_report(inv, plan, ex, secrets=["TOPSECRETVALUE"])
    blob = json.dumps(rep.model_dump(mode="json"))
    assert "TOPSECRETVALUE" not in blob and "ABCDEF123456" not in blob


def test_exit_code_semantics():
    inv, plan, a, b = _inventory()
    ok = ExecutionResult(scenarios=[ScenarioResult(endpoint_id=e.id, scenario=Scenario.POSITIVE, method=e.method, route=e.route, status=TestStatus.PASS, executed=True) for e in (a, b)])
    plan.blocked.clear()
    inv.endpoints = [a, b]
    assert overall_exit(build_report(inv, plan, ok)) == EXIT_OK
    assert overall_exit(build_report(inv, plan, ExecutionResult(error_kind="NEWMAN_TIMEOUT", error_detail="t"))) == EXIT_EXECUTION
