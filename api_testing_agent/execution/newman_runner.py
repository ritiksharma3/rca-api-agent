"""Controlled Newman invocation."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import MissingDependencyError
from ..models.execution import ExecutionResult
from ..security.redaction import redact_text, truncate
from ..security.safety_policy import SafetyPolicy
from ..utils.filesystem import private_temp_dir, write_json
from ..utils.subprocess_utils import CommandResult, run_command, tool_version, which

INSTALL_HELP = (
    "Newman is required to execute the generated collection.\n"
    "  1. Install Node.js 18+ from https://nodejs.org/\n"
    "  2. npm install -g newman        (or: npm install --prefix node_tools newman)\n"
    "  3. Verify with: newman --version\n"
    "You can also point API_AGENT_NEWMAN at the newman executable."
)


def find_newman(project_dir: Path | None = None) -> str | None:
    explicit = os.environ.get("API_AGENT_NEWMAN")
    if explicit and Path(explicit).exists():
        return explicit
    found = which("newman")
    if found:
        return found
    for base in filter(None, [project_dir, Path.cwd(), Path(__file__).resolve().parents[2]]):
        for name in ("newman.cmd", "newman"):
            cand = Path(base) / "node_tools" / "node_modules" / ".bin" / name
            if cand.exists():
                return str(cand)
    return None


@dataclass
class ToolVersions:
    python: str
    node: str | None
    newman: str | None


def check_dependencies(project_dir: Path | None = None) -> tuple[str, ToolVersions]:
    """Return (newman path, versions) or raise MissingDependencyError with actionable instructions."""
    import platform

    if which("node") is None:
        raise MissingDependencyError("Node.js was not found on PATH.\n" + INSTALL_HELP)
    newman = find_newman(project_dir)
    if newman is None:
        raise MissingDependencyError("Newman was not found.\n" + INSTALL_HELP)
    nv = tool_version("node")
    # Newman's first start can be slow on Windows (antivirus scan, cold npm cache), so allow a long timeout and one retry.
    probe = run_command([newman, "--version"], timeout=60)
    if not probe.ok:
        probe = run_command([newman, "--version"], timeout=60)
    text = (probe.stdout or probe.stderr).strip()
    ver = text.splitlines()[0] if probe.ok and text else None
    if ver is None:
        why = "timed out after 60s" if probe.timed_out else redact_text(truncate((probe.stderr or probe.stdout or "no output").strip(), 300))
        raise MissingDependencyError(f"Newman at {newman} could not report a version ({why}).\n" + INSTALL_HELP)
    return newman, ToolVersions(platform.python_version(), nv, ver)


def _write_private(path: Path, data: dict[str, Any]) -> None:
    write_json(path, data)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def run_collection(
    collection: dict[str, Any],
    base_url: str,
    env_secrets: dict[str, str],
    policy: SafetyPolicy,
    newman: str,
    work_dir: Path,
    secrets_to_redact: list[str],
) -> tuple[CommandResult, dict[str, Any] | None]:
    """Run the collection. Credentials go through a private, always-removed environment file."""
    work_dir = work_dir.resolve()  # Newman runs with cwd=work_dir, so every path handed to it must be absolute
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = work_dir / "newman-raw.json"
    if report_path.exists():
        report_path.unlink()
    values = [{"key": "base_url", "value": base_url, "enabled": True}]
    values += [{"key": k, "value": v, "type": "secret", "enabled": True} for k, v in env_secrets.items()]
    with private_temp_dir() as tmp:
        col_path = tmp / "collection.json"
        env_path = tmp / "environment.json"
        write_json(col_path, collection)
        _write_private(env_path, {"name": "runtime", "values": values})
        args = [
            newman, "run", str(col_path), "-e", str(env_path),
            "--reporters", "cli,json", "--reporter-json-export", str(report_path),
            "--timeout-request", str(policy.request_timeout_ms),
            "--timeout", str(policy.process_timeout_s * 1000),
            "--ignore-redirects", "--color", "off", "--disable-unicode",
        ]
        if policy.delay_ms > 0:
            args += ["--delay-request", str(policy.delay_ms)]
        res = run_command(args, cwd=work_dir, timeout=policy.process_timeout_s + 15)
    raw = None
    if report_path.exists():
        try:
            raw = json.loads(report_path.read_text(encoding="utf-8"))
        except ValueError:
            raw = None
        finally:
            # raw output can echo bodies/headers; keep only the sanitized parse in artifacts
            report_path.unlink(missing_ok=True)
    return res, raw


def log_excerpt(res: CommandResult, secrets: list[str], limit: int = 4000) -> str:
    return truncate(redact_text((res.stdout or "") + ("\n" + res.stderr if res.stderr else ""), secrets), limit)


def empty_result(kind: str, detail: str, newman_version: str | None = None) -> ExecutionResult:
    return ExecutionResult(error_kind=kind, error_detail=detail, newman_version=newman_version)
