from __future__ import annotations

import json
import re
import sys

import pytest

from api_testing_agent.discovery import cli_adapter
from api_testing_agent.discovery.base import Applicability, DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from api_testing_agent.discovery.cli_adapter import LaravelRouteListAdapter
from api_testing_agent.discovery.registry import run_discovery
from api_testing_agent.errors import DiscoveryError
from api_testing_agent.models.endpoint import Endpoint
from api_testing_agent.scanner.repository_scanner import scan_repository, select_backend
from api_testing_agent.utils.subprocess_utils import CommandResult, run_command
from tests.conftest import write_files


class FakeAdapter(DiscoveryAdapter):
    def __init__(self, name, strategy, eps=None, fail=None, runs_code=False, ok=True):
        self.name, self.strategy, self._eps, self._fail, self.executes_project_code, self._ok = name, strategy, eps or [], fail, runs_code, ok
        self.called = False

    def applicable(self, ctx):
        return Applicability(self._ok, "" if self._ok else "not applicable")

    def discover(self, ctx):
        self.called = True
        if self._fail:
            raise DiscoveryError(self._fail)
        return DiscoveryOutcome(endpoints=[Endpoint(method=m, route=r, original_path=r, strategy=self.strategy, path_param_names=re.findall(r"\{(\w+)\}", r)) for m, r in self._eps], detail="fake")


@pytest.fixture
def ctx(tmp_path):
    write_files(tmp_path, {"requirements.txt": "fastapi\n", "main.py": "from fastapi import FastAPI\napp = FastAPI()\n"})
    scan = scan_repository(tmp_path)
    return DiscoveryContext(root=tmp_path, scan=scan, backend=select_backend(scan))


# ------------------------------------------------------------------ adapter selection / fallback
def test_falls_back_when_higher_priority_adapter_fails(ctx):
    a = FakeAdapter("spec", "openapi", fail="stale spec is invalid")
    b = FakeAdapter("cli", "cli", fail="exit 1", runs_code=True)
    c = FakeAdapter("static", "static", eps=[("GET", "/a")])
    inv, warns = run_discovery(ctx, adapters=[a, b, c])
    assert inv.discovery.strategy_used == "static"
    outcomes = {x.adapter: x.outcome for x in inv.discovery.attempts}
    assert outcomes == {"spec": "failed", "cli": "failed", "static": "used"}
    assert any("stale spec" in w.message for w in warns)
    assert not inv.discovery.complete


def test_not_applicable_adapters_are_skipped_with_reason(ctx):
    inv, _ = run_discovery(ctx, adapters=[FakeAdapter("a", "openapi", ok=False), FakeAdapter("b", "static", eps=[("GET", "/x")])])
    skipped = next(x for x in inv.discovery.attempts if x.adapter == "a")
    assert skipped.outcome == "skipped" and skipped.detail


def test_code_executing_adapter_respects_disable_flag(ctx):
    cli = FakeAdapter("cli", "cli", eps=[("GET", "/c")], runs_code=True)
    stat = FakeAdapter("static", "static", eps=[("GET", "/s")])
    ctx.allow_cli = False
    inv, _ = run_discovery(ctx, adapters=[cli, stat])
    assert not cli.called and inv.discovery.strategy_used == "static"


def test_cross_check_reports_discrepancies_not_silent_loss(ctx):
    spec = FakeAdapter("spec", "openapi", eps=[("GET", "/documented/{id}"), ("GET", "/stale")])
    static = FakeAdapter("static", "static", eps=[("GET", "/documented/{item_id}"), ("POST", "/undocumented")])
    inv, warns = run_discovery(ctx, adapters=[spec, static])
    kinds = {(d.kind, d.method, d.route) for d in inv.discovery and inv.discrepancies}
    assert ("in_static_not_in_spec", "POST", "/undocumented") in kinds
    assert ("in_spec_not_in_static", "GET", "/stale") in kinds
    assert not any(d.route.startswith("/documented") for d in inv.discrepancies), "param renames must not count as discrepancies"
    assert {e.route for e in inv.endpoints} == {"/documented/{id}", "/stale"}, "secondary-only routes are not silently merged into the tested inventory"
    assert any("discrepanc" in w.message for w in warns)


def test_all_adapters_failing_yields_empty_incomplete_inventory(ctx):
    inv, warns = run_discovery(ctx, adapters=[FakeAdapter("a", "openapi", fail="x"), FakeAdapter("b", "static", fail="y")])
    assert inv.endpoints == [] and inv.discovery.strategy_used is None
    assert any(w.severity == "error" for w in warns)


def test_unknown_strategy_rejected(ctx):
    with pytest.raises(DiscoveryError):
        run_discovery(ctx, strategy="magic")


# ------------------------------------------------------------------ subprocess helper
def test_run_command_timeout_nonzero_and_missing():
    slow = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert slow.timed_out and not slow.ok
    bad = run_command([sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"])
    assert bad.returncode == 3 and "boom" in bad.stderr and not bad.ok
    missing = run_command(["definitely-not-a-real-binary-xyz"])
    assert missing.not_found and not missing.ok


def test_run_command_never_uses_shell_metacharacters():
    res = run_command([sys.executable, "-c", "import sys; print(sys.argv[1])", "a; echo INJECTED && true"])
    assert res.stdout.strip() == "a; echo INJECTED && true"


# ------------------------------------------------------------------ Laravel route:list adapter (CLI mocked)
@pytest.fixture
def laravel(tmp_path, monkeypatch):
    write_files(tmp_path, {"composer.json": '{"require": {"laravel/framework": "^10"}}', "artisan": "<?php\n", "vendor/autoload.php": "<?php\n"})
    scan = scan_repository(tmp_path)
    monkeypatch.setattr(cli_adapter, "which", lambda x: "/usr/bin/php")
    return DiscoveryContext(root=tmp_path, scan=scan, backend=select_backend(scan), timeout=5)


ROUTES = json.dumps([
    {"domain": None, "method": "GET|HEAD", "uri": "api/users/{id}", "name": "users.show", "action": "UserController@show", "middleware": ["api", "Authenticate:sanctum"]},
    {"domain": None, "method": "POST", "uri": "api/users", "name": None, "action": "UserController@store", "middleware": ["api"]},
])


def test_laravel_route_list_parses_json(laravel, monkeypatch):
    monkeypatch.setattr(cli_adapter, "run_command", lambda *a, **k: CommandResult(a[0], 0, "NOTICE\n" + ROUTES, ""))
    out = LaravelRouteListAdapter().discover(laravel)
    by = {(e.method, e.route): e for e in out.endpoints}
    assert set(by) == {("GET", "/api/users/{id}"), ("POST", "/api/users")}, "HEAD must be dropped"
    assert by[("GET", "/api/users/{id}")].requires_auth is True
    assert out.complete, "framework route registry is sufficient evidence of the registered set"


@pytest.mark.parametrize("result,msg", [
    (CommandResult(["php"], 1, "", "Command route:list not defined"), "exited 1"),
    (CommandResult(["php"], None, "", "", timed_out=True), "timed out"),
    (CommandResult(["php"], 0, "<html>not json</html>", ""), "not valid JSON"),
    (CommandResult(["php"], 0, "{}", ""), "unexpected shape"),
    (CommandResult(["php"], None, "", "executable not found: php", not_found=True), "cannot run php"),
])
def test_laravel_route_list_failure_modes_raise_for_fallback(laravel, monkeypatch, result, msg):
    monkeypatch.setattr(cli_adapter, "run_command", lambda *a, **k: result)
    with pytest.raises(DiscoveryError, match=msg):
        LaravelRouteListAdapter().discover(laravel)


def test_laravel_adapter_prerequisites(tmp_path, monkeypatch):
    write_files(tmp_path, {"composer.json": '{"require": {"laravel/framework": "^10"}}', "artisan": "<?php\n"})
    scan = scan_repository(tmp_path)
    ctx = DiscoveryContext(root=tmp_path, scan=scan, backend=select_backend(scan))
    monkeypatch.setattr(cli_adapter, "which", lambda x: None)
    assert "php executable" in LaravelRouteListAdapter().applicable(ctx).reason
    monkeypatch.setattr(cli_adapter, "which", lambda x: "php")
    assert "vendor/autoload.php" in LaravelRouteListAdapter().applicable(ctx).reason
