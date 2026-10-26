"""Non-secret project configuration persisted between runs.

Never stored: passwords, tokens, API keys, cookies. Auth settings hold only the *names* of environment
variables. Risky permissions (mutating / destructive / negative tests, private/public target opt-ins) are
deliberately NOT persisted: they must be re-granted on every run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .auth.provider import AuthConfig
from .errors import InvalidInputError

CONFIG_NAME = ".api-agent.yaml"
PERSISTED_RUN_FIELDS = (
    "backend", "framework", "strategy", "spec", "base_url", "request_timeout_ms", "process_timeout_s",
    "max_requests", "delay_ms", "seed", "fixtures", "runtime_spec_url",
)


class ProjectConfig(BaseModel):
    backend: str | None = None
    framework: str | None = None
    strategy: str = "auto"
    spec: str | None = None
    runtime_spec_url: str | None = None
    base_url: str | None = None
    approved_targets: list[str] = Field(default_factory=list)  # origins, e.g. http://127.0.0.1:8000
    request_timeout_ms: int = 10_000
    process_timeout_s: int = 300
    max_requests: int = 200
    delay_ms: int = 0
    seed: int = 1234
    fixtures: str | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)

    @classmethod
    def load(cls, out_dir: Path) -> "ProjectConfig":
        path = out_dir / CONFIG_NAME
        if not path.exists():
            return cls()
        try:
            return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        except (OSError, yaml.YAMLError, ValueError) as exc:
            raise InvalidInputError(f"Cannot read {path}: {exc}") from exc

    def save(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / CONFIG_NAME
        data = self.model_dump(mode="json", exclude_none=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return path

    def merged(self, overrides: dict[str, Any]) -> "ProjectConfig":
        """Return a copy with every non-None override applied (CLI beats saved config)."""
        data = self.model_dump()
        auth_over = overrides.pop("auth", None) or {}
        data.update({k: v for k, v in overrides.items() if v is not None})
        data["auth"] = {**data["auth"], **{k: v for k, v in auth_over.items() if v is not None}}
        return ProjectConfig.model_validate(data)
