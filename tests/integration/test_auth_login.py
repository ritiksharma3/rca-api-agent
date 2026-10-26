"""Automatic login → token → authenticated testing, against live fixture apps with real Newman."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from api_testing_agent.cli import app
from api_testing_agent.execution.newman_runner import find_newman
from tests.conftest import FIXTURES, launch_app

pytestmark = pytest.mark.integration
runner = CliRunner()
CREDS = {"API_AGENT_USERNAME": "admin", "API_AGENT_PASSWORD": "admin123"}


@pytest.fixture(scope="module", autouse=True)
def _need_newman():
    if find_newman(Path.cwd()) is None:
        pytest.skip("Newman not installed (npm install --prefix node_tools newman)")


def run(src: Path, out: Path, url: str, *extra, env=None):
    args = ["test", str(src), "--base-url", url, "--approve-target", "--no-llm", "-o", str(out), *extra]
    res = runner.invoke(app, args, env={**CREDS, **(env or {})})
    report = out / "qa-report.json"
    return res, (json.loads(report.read_text("utf-8")) if report.exists() else None)


def verdicts(rep):
    return {(e["method"], e["route"]): e for e in rep["endpoints"]}


def assert_no_leaks(out: Path, *needles: str):
    for f in out.rglob("*"):
        if f.is_file():
            text = f.read_text("utf-8", errors="ignore")
            for n in needles:
                assert n not in text, f"{n!r} leaked into {f.name}"


def test_auto_login_detects_endpoint_and_tests_protected_routes(tmp_path):
    with launch_app(FIXTURES / "auth_api") as url:
        out = tmp_path / "out"
        res, rep = run(FIXTURES / "auth_api", out, url, "--auth", "login", "--allow-mutating")
    assert res.exit_code == 0, res.output
    v = verdicts(rep)
    for route in ("/secure/a", "/secure/b", "/secure/c", "/secure/d", "/public/ping"):
        assert v[("GET", route)]["test_status"] == "PASS", route
    assert v[("POST", "/auth/login")]["test_status"] == "PASS"
    auth = rep["authentication"]
    assert (auth["login_endpoint"], auth["login_detected_by"], auth["relogins"]) == ("/auth/login", "heuristic", 0)
    assert rep["status_counts"]["BLOCKED"] == 0 and rep["status_counts"]["FAIL"] == 0
    saved = yaml.safe_load((out / ".api-agent.yaml").read_text())
    assert saved["auth"]["login_path"] == "/auth/login" and "admin123" not in json.dumps(saved)
    assert_no_leaks(out, "admin123", "tok-1-abcdefgh")


def test_expired_token_triggers_one_relogin_and_endpoints_recover(tmp_path):
    with launch_app(FIXTURES / "auth_api", env={"AUTH_API_TOKEN_LIMIT": "3"}) as url:
        out = tmp_path / "out"
        res, rep = run(FIXTURES / "auth_api", out, url, "--auth", "login", "--allow-mutating")
    assert res.exit_code == 0, res.output
    auth = rep["authentication"]
    assert auth["relogins"] == 1 and auth["retried_requests"] >= 1
    v = verdicts(rep)
    assert all(v[("GET", f"/secure/{c}")]["test_status"] == "PASS" for c in "abcd")
    assert rep["status_counts"]["FAIL"] == 0
    assert_no_leaks(out, "admin123", "-abcdefgh")


def test_wrong_password_exits_6_and_never_leaks(tmp_path):
    with launch_app(FIXTURES / "auth_api") as url:
        out = tmp_path / "out"
        res, rep = run(FIXTURES / "auth_api", out, url, "--auth", "login", "--allow-mutating", env={"API_AGENT_PASSWORD": "wrong-pass-1"})
    assert res.exit_code == 6, res.output
    assert any("authentication" in b for b in rep["blockers"])
    assert_no_leaks(out, "wrong-pass-1")


def test_no_login_endpoint_and_no_flag_is_a_clear_error(tmp_path, sample_api_dir, sample_server):
    out = tmp_path / "out"
    res, rep = run(sample_api_dir, out, sample_server, "--auth", "login")
    assert res.exit_code == 6
    assert any("--login-path" in b for b in rep["blockers"])


def test_explicit_flags_still_work(tmp_path):
    with launch_app(FIXTURES / "auth_api") as url:
        res, rep = run(FIXTURES / "auth_api", tmp_path / "out", url, "--auth", "login", "--login-path", "/auth/login",
                       "--login-token-path", "access_token", "--allow-mutating")
    assert res.exit_code == 0, res.output
    assert rep["authentication"]["login_detected_by"] == "flag"


def test_session_cookie_login(tmp_path):
    with launch_app(FIXTURES / "session_api") as url:
        out = tmp_path / "out"
        res, rep = run(FIXTURES / "session_api", out, url, "--auth", "session", "--allow-mutating")
    assert res.exit_code == 0, res.output
    assert verdicts(rep)[("GET", "/session/me")]["test_status"] == "PASS"
    assert_no_leaks(out, "admin123", "sess-value-abcdef123456")


def test_basic_auth(tmp_path):
    with launch_app(FIXTURES / "basic_api") as url:
        out = tmp_path / "out"
        res, rep = run(FIXTURES / "basic_api", out, url, "--auth", "basic")
    assert res.exit_code == 0, res.output
    assert verdicts(rep)[("GET", "/basic/me")]["test_status"] == "PASS"
    assert_no_leaks(out, "admin123", "YWRtaW46YWRtaW4xMjM=")
