from __future__ import annotations

import pytest
from typer.testing import CliRunner

from api_testing_agent.cli import app
from api_testing_agent.envfile import ENV_FILE_VAR, is_placeholder, load_env_file, parse_env_text
from api_testing_agent.errors import InvalidInputError

runner = CliRunner()


def test_parse_handles_comments_quotes_export_and_inline_comments():
    text = (
        "# comment\n\nA=plain   # inline comment\nexport B='quoted # kept'\nC=\"dq value\"\nD=\nbad line\n1X=nope\nE=a=b=c\n"
    )
    assert parse_env_text(text) == {"A": "plain", "B": "quoted # kept", "C": "dq value", "D": "", "E": "a=b=c"}


@pytest.mark.parametrize("v", ["", "replace-me", " REPLACE-ME ", "changeme", "<your key>"])
def test_placeholders_detected(v):
    assert is_placeholder(v)
    assert not is_placeholder("s3cr3t-real")


def test_load_sets_missing_keeps_existing_and_skips_placeholders(tmp_path):
    f = tmp_path / ".env"
    f.write_text("API_AGENT_USERNAME=admin\nAPI_AGENT_PASSWORD=pw-from-file\nAPI_AGENT_TOKEN=replace-me\nOTHER=x\n")
    env = {"API_AGENT_PASSWORD": "already-set"}
    res = load_env_file(f, env)
    assert env == {"API_AGENT_PASSWORD": "already-set", "API_AGENT_USERNAME": "admin", "OTHER": "x"}
    assert res.loaded == ["API_AGENT_USERNAME", "OTHER"]
    assert res.kept_existing == ["API_AGENT_PASSWORD"] and res.placeholders == ["API_AGENT_TOKEN"]
    assert "pw-from-file" not in repr(res) and "already-set" not in repr(res), "the result must carry names only"


def test_empty_existing_value_is_replaced(tmp_path):
    f = tmp_path / ".env"
    f.write_text("K=real-value\n")
    env = {"K": ""}
    assert load_env_file(f, env).loaded == ["K"] and env["K"] == "real-value"


def test_env_var_selects_or_disables_the_default_file(tmp_path, monkeypatch):
    f = tmp_path / "custom.env"
    f.write_text("K=v123\n")
    env = {ENV_FILE_VAR: str(f)}
    assert load_env_file(None, env).loaded == ["K"]
    assert load_env_file(None, {ENV_FILE_VAR: ""}).path is None  # explicit empty value disables loading
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("D=1234\n")
    assert load_env_file(None, {}).loaded == ["D"]  # default ./.env


def test_missing_explicit_file_and_oversized_file_are_errors(tmp_path):
    with pytest.raises(InvalidInputError, match="not found"):
        load_env_file(tmp_path / "nope.env", {})
    big = tmp_path / "big.env"
    big.write_text("A=" + "x" * 70_000)
    with pytest.raises(InvalidInputError, match="larger than"):
        load_env_file(big, {})


def test_cli_loads_env_file_and_never_prints_values(tmp_path, monkeypatch):
    monkeypatch.delenv("API_AGENT_USERNAME", raising=False)
    monkeypatch.delenv("API_AGENT_PASSWORD", raising=False)
    f = tmp_path / "creds.env"
    f.write_text("API_AGENT_USERNAME=admin-user-xyz\nAPI_AGENT_PASSWORD=super-secret-pw-123\nAPI_AGENT_TOKEN=replace-me\n")
    (tmp_path / "src").mkdir()
    res = runner.invoke(app, ["--env-file", str(f), "scan", str(tmp_path / "src"), "-o", str(tmp_path / "out")])
    assert "API_AGENT_USERNAME" in res.output and "API_AGENT_TOKEN" in res.output  # names reported
    assert "super-secret-pw-123" not in res.output and "admin-user-xyz" not in res.output
    import os

    assert os.environ["API_AGENT_PASSWORD"] == "super-secret-pw-123"  # loaded for the run
    monkeypatch.delenv("API_AGENT_USERNAME")
    monkeypatch.delenv("API_AGENT_PASSWORD")
