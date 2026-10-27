"""Discovery adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models.endpoint import Endpoint, PotentialRoute
from ..models.project import BackendCandidate, DiscoveryWarning, ScanResult


@dataclass
class DiscoveryContext:
    root: Path
    scan: ScanResult
    backend: BackendCandidate | None = None
    spec_path: Path | None = None
    timeout: float = 60.0
    allow_cli: bool = True
    spec_from_probe: bool = False  # the spec was fetched from the live target (not given by the user): source analysis still cross-checks it

    @property
    def backend_dir(self) -> Path:
        if self.backend is None or self.backend.path in (".", ""):
            return self.root
        return self.root / self.backend.path

    @property
    def framework(self) -> str | None:
        return self.backend.framework if self.backend else None


@dataclass
class Applicability:
    ok: bool
    reason: str = ""


@dataclass
class DiscoveryOutcome:
    endpoints: list[Endpoint] = field(default_factory=list)
    potential_routes: list[PotentialRoute] = field(default_factory=list)
    warnings: list[DiscoveryWarning] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    complete: bool = False  # True only when the source gives sufficient evidence of completeness
    detail: str = ""
    server_base_path: str = ""
    security_definitions: dict[str, dict[str, Any]] = field(default_factory=dict)


class DiscoveryAdapter(ABC):
    """Contract every discovery strategy implements.

    ``name``            unique id used in evidence and reports
    ``strategy``        'openapi' | 'cli' | 'static' | 'spec'
    ``supported``       frameworks / input formats handled
    ``prerequisites``   human-readable requirements (executables, versions)
    ``executes_project_code``  True when discovery runs framework code (gated, never used for cross-checks)
    """

    name: str = ""
    strategy: str = ""
    supported: tuple[str, ...] = ()
    prerequisites: str = ""
    executes_project_code: bool = False

    @abstractmethod
    def applicable(self, ctx: DiscoveryContext) -> Applicability:
        """Cheap check: can this adapter run here (framework match, executables, files present)?"""

    @abstractmethod
    def discover(self, ctx: DiscoveryContext) -> DiscoveryOutcome:
        """Run discovery. Raise DiscoveryError on failure so the registry can fall back."""
