"""End-to-end tests against the bundled local FastAPI sample. Need Node + Newman (skipped otherwise)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from api_testing_agent import pipeline
from api_testing_agent.cli import app
from api_testing_agent.errors import MissingDependencyError
from api_testing_agent.execution.newman_runner import find_newman
from tests.conftest import free_port

pytestmark = pytest.mark.integration
runner = CliRunner()
TOKEN = "demo-token"


@pytest.fixture(scope="module", autouse=True)
def _need_newman():
    if find_newman(Path.cwd()) is None:
        pytest.skip("Newman not installed (npm install --prefix node_tools newman)")


def run(sample_api_dir, out, url, *extra, env=None):
    args = ["test", str(sample_api_dir), "--base-url", url, "--approve-target", "-o", str(out), *extra]
    res = runner.invoke(app, args, env=env or {})
    report = out / "qa-report.json"
    return res, (json.loads(report.read_text("utf-8")) if report.exists() else None)


def verdicts(rep):
    return {(e["method"], e["route"]): e for e in rep["endpoints"]}


def test_full_run_pass_fail_blocked_not_discovered(tmp_path, sample_api_dir, sample_server):
    fx = tmp_path / "fixtures.yaml"
    fx.write_text("path_params:\n  item_id: 1\n")
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server, "--auth", "bearer", "--allow-mutating", "--negative",
                   "--fixtures", str(fx), env={"API_AGENT_TOKEN": TOKEN})
    assert res.exit_code == 1, res.output  # a FAIL exists: distinguishable from tool errors (70) and non-execution (7/8)
    v = verdicts(rep)
    assert v[("GET", "/health")]["test_status"] == "PASS"
    assert v[("GET", "/items")]["test_status"] == "PASS"
    assert v[("GET", "/items/{item_id}")]["test_status"] == "PASS"
    assert v[("POST", "/items")]["test_status"] == "PASS"
    assert v[("GET", "/users/me")]["test_status"] == "PASS"
    stats = v[("GET", "/stats")]
    assert stats["test_status"] == "FAIL" and "schema" in stats["reason"]
    assert stats["scenarios"][0]["http_status"] == 200, "expected vs actual: status ok but body violates the documented schema"
    assert rep["status_counts"] == {"PASS": 5, "FAIL": 1, "BLOCKED": 0, "NOT DISCOVERED": 1}
    assert rep["potential_routes"][0]["status"] == "NOT DISCOVERED"
    assert rep["coverage"]["discovery_complete"] is False
    neg = [s for e in rep["endpoints"] for s in e["scenarios"] if s["scenario"] == "negative"]
    assert neg and all(s["status"] == "PASS" and s["http_status"] == 422 for s in neg)
    assert (tmp_path / "out" / "qa-report.html").exists()


def test_secrets_never_reach_artifacts(tmp_path, sample_api_dir, sample_server):
    out = tmp_path / "out"
    run(sample_api_dir, out, sample_server, "--auth", "bearer", env={"API_AGENT_TOKEN": TOKEN})
    for f in out.rglob("*"):
        if f.is_file():
            assert TOKEN not in f.read_text("utf-8", errors="ignore"), f"secret leaked into {f.name}"
    assert not list(out.glob("newman-raw.json")), "raw Newman output (may contain bodies) must be removed"


def test_blocked_by_missing_fixture_auth_and_policy_but_still_discovered(tmp_path, sample_api_dir, sample_server):
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server)
    v = verdicts(rep)
    item = v[("GET", "/items/{item_id}")]
    assert item["test_status"] == "BLOCKED" and "MISSING_FIXTURE" in item["reason"]
    me = v[("GET", "/users/me")]
    assert me["test_status"] == "BLOCKED" and "MISSING_AUTH" in me["reason"]
    assert {s["scenario"]: s["status"] for s in me["scenarios"]}["auth_required"] == "PASS", "the unauthenticated check needs no credentials"
    post = v[("POST", "/items")]
    assert post["test_status"] == "BLOCKED" and "POLICY_NOT_AUTHORIZED" in post["reason"]
    assert post["discovery_status"] in ("DISCOVERED", "PARTIAL"), "discovered-but-not-run keeps its discovery status"
    assert all(s["executed"] is False for s in post["scenarios"])
    assert v[("GET", "/health")]["test_status"] == "PASS"
    assert rep["status_counts"]["FAIL"] == 1 and rep["blockers"]
    assert res.exit_code == 1


def test_unreachable_server_exit_5_and_report_still_written(tmp_path, sample_api_dir):
    res, rep = run(sample_api_dir, tmp_path / "out", f"http://127.0.0.1:{free_port()}")
    assert res.exit_code == 5, res.output
    assert rep["status_counts"]["PASS"] == 0 and rep["status_counts"]["BLOCKED"] == 6
    assert any("CONNECTIVITY" in b or "Cannot reach" in b for b in rep["blockers"])
    assert rep["execution"]["ran"] is False


def test_wrong_credentials_exit_6_with_blocked_not_pass(tmp_path, sample_api_dir, sample_server):
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server, "--auth", "login", "--login-path", "/does-not-exist",
                   env={"API_AGENT_USERNAME": "qa", "API_AGENT_PASSWORD": "pa55word!"})
    assert res.exit_code == 6, res.output
    assert "pa55word!" not in res.output and "pa55word!" not in json.dumps(rep)
    assert verdicts(rep)[("GET", "/users/me")]["test_status"] == "BLOCKED"
    assert any("authentication" in b.lower() for b in rep["blockers"])


def test_collection_that_cannot_execute_is_reported_not_passed(tmp_path, sample_api_dir, sample_server, monkeypatch):
    real = pipeline.generate

    def corrupt(inv, opts):
        gen = real(inv, opts)
        gen.collection["item"] = [{"name": "broken", "id": "zzz", "request": "this-is-not-a-request-object"}]
        return gen

    monkeypatch.setattr(pipeline, "generate", corrupt)
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server)
    assert rep["execution"]["error_kind"] in ("COLLECTION_INVALID", "NEWMAN_CRASH") or rep["execution"]["ran"] is False or rep["status_counts"]["PASS"] == 0
    assert rep["status_counts"]["PASS"] == 0, "nothing executed -> nothing may be PASS"
    assert res.exit_code in (7, 8)


def test_missing_newman_exit_4_with_instructions_and_report(tmp_path, sample_api_dir, sample_server, monkeypatch):
    def nope(*a, **k):
        raise MissingDependencyError("Newman was not found.\nnpm install -g newman")

    monkeypatch.setattr(pipeline, "check_dependencies", nope)
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server)
    assert res.exit_code == 4
    assert rep["execution"]["error_kind"] == "NEWMAN_MISSING" and rep["status_counts"]["PASS"] == 0
    assert "npm install -g newman" in json.dumps(rep["blockers"])


def test_report_command_rebuilds_from_artifacts(tmp_path, sample_api_dir, sample_server):
    out = tmp_path / "out"
    run(sample_api_dir, out, sample_server)
    (out / "qa-report.json").unlink()
    (out / "qa-report.html").unlink()
    res = runner.invoke(app, ["report", "-o", str(out)])
    assert res.exit_code == 1 and (out / "qa-report.json").exists() and (out / "qa-report.html").exists()


def test_request_budget_and_default_read_only(tmp_path, sample_api_dir, sample_server):
    res, rep = run(sample_api_dir, tmp_path / "out", sample_server, "--max-requests", "1")
    assert rep["execution"]["planned_requests"] == 1 and rep["execution"]["requests_executed"] == 1
    assert not any(s["scenario"] == "negative" for e in rep["endpoints"] for s in e["scenarios"] if s["executed"])
    assert rep["policy"]["allow_mutating"] is False and rep["policy"]["allow_destructive"] is False


def test_generate_command_sends_nothing_and_writes_collection(tmp_path, sample_api_dir):
    out = tmp_path / "out"
    res = runner.invoke(app, ["generate", str(sample_api_dir), "-o", str(out)])
    assert res.exit_code == 0, res.output
    col = json.loads((out / "postman_collection.json").read_text())
    assert col["info"]["schema"].endswith("v2.1.0/collection.json")
    assert (out / "postman_environment.template.json").exists()


def test_relative_output_directory_works(tmp_path, sample_api_dir, sample_server, monkeypatch):
    """Regression: Newman runs with cwd=<output>, so relative output paths must be made absolute."""
    monkeypatch.chdir(tmp_path)
    res, rep = run(sample_api_dir, Path("rel-out"), sample_server)
    assert rep is not None and rep["execution"]["ran"] is True and rep["execution"]["requests_executed"] > 0
