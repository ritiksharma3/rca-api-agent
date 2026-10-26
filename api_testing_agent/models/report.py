"""QA report model (stable JSON contract for CI)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .endpoint import utcnow
from .execution import ScenarioResult, TestStatus


class EndpointVerdict(BaseModel):
    endpoint_id: str
    method: str
    route: str
    discovery_status: str
    discovery_strategy: str
    confidence: str
    source: str | None = None
    test_status: TestStatus
    reason: str | None = None
    suite_complete: bool = True
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    needs_manual_review: bool = False
    review_reasons: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    confirmed_routes: int = 0
    tested_pass: int = 0
    tested_fail: int = 0
    blocked: int = 0
    potential_unresolved: int = 0
    discrepancies: int = 0
    by_method: dict[str, int] = Field(default_factory=dict)
    discovery_complete: bool = False
    disclaimer: str = (
        "Endpoint counts measure route inventory only. They do not measure behavioral, "
        "business-rule or code-path coverage, and they are not proof that all endpoints were found."
    )


class QAReport(BaseModel):
    schema_version: str = "1.0"
    generated_at: str = Field(default_factory=utcnow)
    project: dict[str, Any] = Field(default_factory=dict)
    tool_versions: dict[str, str | None] = Field(default_factory=dict)
    target: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    authentication: dict[str, Any] = Field(default_factory=dict)  # method, login endpoint, how found, re-logins; never values
    discovery: dict[str, Any] = Field(default_factory=dict)
    coverage: CoverageSummary = Field(default_factory=CoverageSummary)
    status_counts: dict[str, int] = Field(default_factory=dict)
    execution: dict[str, Any] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    endpoints: list[EndpointVerdict] = Field(default_factory=list)
    potential_routes: list[dict[str, Any]] = Field(default_factory=list)
    discrepancies: list[dict[str, Any]] = Field(default_factory=list)
    manual_review: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
