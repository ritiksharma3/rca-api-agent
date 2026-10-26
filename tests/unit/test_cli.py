from __future__ import annotations

import json

import yaml
from typer.testing import CliRunner

from api_testing_agent import __version__
from api_testing_agent.cli import app
from api_testing_agent.config import CONFIG_NAME, ProjectConfig

runner = CliRunner()


def test_help_lists_all_commands_and_exit_codes():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("scan", "discover", "inventory", "generate", "test", "report"):
        assert cmd in res.output
    assert "Exit codes" in res.output
    assert runner.invoke(app, ["--version"]).output.strip() == f"api-agent {__version__}"
    for cmd in ("scan", "discover", "inventory", "generate", "test", "report"):
        assert runner.invoke(app, [cmd, "--help"]).exit_code == 0


def test_invalid_folder_exit_code_2(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path / "nope"), "-o", str(tmp_path / "out")])
    assert res.exit_code == 2 and "does not exist" in res.output


def test_scan_writes_artifact(tmp_path, sample_api_dir):
    out = tmp_path / "out"
    res = runner.invoke(app, ["scan", str(sample_api_dir), "-o", str(out)])
    assert res.exit_code == 0 and "FastAPI" in res.output
    assert json.loads((out / "scan_result.json").read_text())["backends"][0]["framework"] == "FastAPI"


def test_discover_and_inventory_write_required_artifacts(tmp_path, sample_api_dir):
    out = tmp_path / "out"
    res = runner.invoke(app, ["discover", str(sample_api_dir), "-o", str(out)])
    assert res.exit_code == 0, res.output
    for f in ("scan_result.json", "endpoint_inventory.json", "discovery_warnings.json"):
        assert (out / f).exists()
    inv = json.loads((out / "endpoint_inventory.json").read_text())
    assert len(inv["endpoints"]) == 6 and inv["potential_routes"] and inv["discovery"]["complete"] is False
    res = runner.invoke(app, ["inventory", str(sample_api_dir), "-o", str(out)])
    assert res.exit_code == 0 and "/items/{item_id}" in res.output and "NOT DISCOVERED" in res.output


def test_discovery_failure_exit_code_3(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "readme.txt").write_text("nothing here")
    res = runner.invoke(app, ["discover", str(src), "-o", str(tmp_path / "out")])
    assert res.exit_code == 3 and "framework_not_identified" in res.output


def test_multiple_backends_need_explicit_choice(tmp_path):
    src = tmp_path / "src"
    (src / "a").mkdir(parents=True)
    (src / "b").mkdir()
    (src / "a" / "requirements.txt").write_text("flask")
    (src / "a" / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.get('/x')\ndef x(): ...\n")
    (src / "b" / "requirements.txt").write_text("fastapi")
    (src / "b" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    res = runner.invoke(app, ["discover", str(src), "-o", str(tmp_path / "o")])
    assert res.exit_code == 2 and "--backend" in res.output
    res = runner.invoke(app, ["discover", str(src), "--backend", "a", "-o", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output


def test_test_requires_base_url_and_approval(tmp_path, sample_api_dir):
    out = str(tmp_path / "out")
    res = runner.invoke(app, ["test", str(sample_api_dir), "-o", out])
    assert res.exit_code == 2 and "--base-url" in res.output
    res = runner.invoke(app, ["test", str(sample_api_dir), "--base-url", "http://127.0.0.1:9", "-o", out])
    assert res.exit_code == 5 and "not approved" in res.output
    res = runner.invoke(app, ["test", str(sample_api_dir), "--base-url", "http://169.254.169.254", "--approve-target", "-o", out])
    assert res.exit_code == 5 and "metadata" in res.output
    res = runner.invoke(app, ["test", str(sample_api_dir), "--base-url", "ftp://x", "--approve-target", "-o", out])
    assert res.exit_code == 2


def test_private_and_public_targets_need_opt_in(tmp_path, sample_api_dir):
    out = str(tmp_path / "out")
    res = runner.invoke(app, ["test", str(sample_api_dir), "--base-url", "http://10.1.1.1", "--approve-target", "-o", out])
    assert res.exit_code == 5 and "--allow-private" in res.output
    res = runner.invoke(app, ["test", str(sample_api_dir), "--base-url", "http://8.8.8.8", "--approve-target", "-o", out])
    assert res.exit_code == 5 and "--allow-public" in res.output


def test_report_without_artifacts_is_invalid_input(tmp_path):
    res = runner.invoke(app, ["report", "-o", str(tmp_path / "empty")])
    assert res.exit_code == 2 and "Run `api-agent test` first" in res.output


def test_config_persistence_never_stores_secrets(tmp_path):
    cfg = ProjectConfig().merged({"base_url": "http://127.0.0.1:8000", "auth": {"method": "bearer", "token_env": "MY_TOKEN"}})
    cfg.approved_targets.append("http://127.0.0.1:8000")
    path = cfg.save(tmp_path)
    text = path.read_text()
    assert path.name == CONFIG_NAME and "MY_TOKEN" in text
    data = yaml.safe_load(text)
    assert "allow_mutating" not in data and "allow_destructive" not in data, "risky permissions must be re-granted per run"
    assert ProjectConfig.load(tmp_path).auth.token_env == "MY_TOKEN"
