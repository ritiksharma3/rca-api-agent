"""Minimal `.env` loader (no extra dependency).

Rules: variables already present in the real environment always win; empty and placeholder values (``replace-me`` …)
are treated as *unset* so a template copied from ``.env.example`` can never be used as a real credential; values are
never logged — callers only ever see variable *names*.

Which file: ``--env-file`` > ``API_AGENT_ENV_FILE`` (an empty value disables loading) > ``./.env``.
"""

from __future__ import annotations

import os
import re
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from pathlib import Path

from .errors import InvalidInputError

ENV_FILE_VAR = "API_AGENT_ENV_FILE"
PLACEHOLDERS = {"", "replace-me", "replace_me", "changeme", "change-me", "your-token-here", "todo", "xxx"}
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_ENV_FILE_BYTES = 64_000


@dataclass
class EnvLoad:
    path: Path | None = None
    loaded: list[str] = field(default_factory=list)  # names newly set from the file
    kept_existing: list[str] = field(default_factory=list)  # names already set in the environment (file value ignored)
    placeholders: list[str] = field(default_factory=list)  # names whose value was empty / a template placeholder


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return v in PLACEHOLDERS or (v.startswith("<") and v.endswith(">"))


def parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not _KEY.match(key):
            continue
        if value[:1] in ("'", '"'):
            end = value.find(value[0], 1)
            value = value[1:end] if end != -1 else value[1:]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        out[key] = value
    return out


def resolve_env_path(explicit: Path | None, environ: MutableMapping[str, str] | None = None) -> Path | None:
    env = os.environ if environ is None else environ
    if explicit is not None:
        if not explicit.is_file():
            raise InvalidInputError(f"--env-file not found: {explicit}")
        return explicit
    if ENV_FILE_VAR in env:
        configured = env[ENV_FILE_VAR].strip()
        return Path(configured) if configured and Path(configured).is_file() else None
    default = Path.cwd() / ".env"
    return default if default.is_file() else None


def load_env_file(explicit: Path | None = None, environ: MutableMapping[str, str] | None = None) -> EnvLoad:
    """Load the chosen env file into `environ` (default: the process environment). Returns names only."""
    env = os.environ if environ is None else environ
    result = EnvLoad(path=resolve_env_path(explicit, env))
    if result.path is None:
        return result
    try:
        if result.path.stat().st_size > MAX_ENV_FILE_BYTES:
            raise InvalidInputError(f"{result.path.name} is larger than {MAX_ENV_FILE_BYTES} bytes; refusing to read it")
        values = parse_env_text(result.path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        raise InvalidInputError(f"Cannot read {result.path.name}: {exc.strerror or exc}") from exc
    for name, value in values.items():
        if is_placeholder(value):
            result.placeholders.append(name)
        elif name in env and env[name]:
            result.kept_existing.append(name)
        else:
            env[name] = value
            result.loaded.append(name)
    return result
