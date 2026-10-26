"""Controlled subprocess execution (argument lists only, never a shell)."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    not_found: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found


def which(executable: str) -> str | None:
    return shutil.which(executable)


def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: float = 60,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command with an argument list. Never raises for timeout / missing binary."""
    resolved = which(args[0])
    if resolved is None:
        return CommandResult(args, None, "", f"executable not found: {args[0]}", not_found=True)
    full = [resolved, *args[1:]]
    try:
        proc = subprocess.run(
            full,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return CommandResult(args, None, out, err, timed_out=True)
    except OSError as exc:
        return CommandResult(args, None, "", f"failed to start: {exc}", not_found=True)
    return CommandResult(args, proc.returncode, proc.stdout, proc.stderr)


def tool_version(executable: str, flag: str = "--version", timeout: float = 15) -> str | None:
    res = run_command([executable, flag], timeout=timeout)
    if not res.ok:
        return None
    text = (res.stdout or res.stderr).strip()
    return text.splitlines()[0] if text else None
