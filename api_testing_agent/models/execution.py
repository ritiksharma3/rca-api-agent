"""Test plan and execution result models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .endpoint import utcnow


class TestStatus(str, Enum):
    __test__ = False  # not a pytest class

    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_DISCOVERED = "NOT DISCOVERED"


class Scenario(str, Enum):
    POSITIVE = "positive"
    AUTH_REQUIRED = "auth_required"
    NEGATIVE = "negative"


class PlannedRequest(BaseModel):
    """One generated Postman request (a scenario of an endpoint)."""

    item_id: str  # Postman item id (stable)
    endpoint_id: str
    scenario: Scenario
    method: str
    route: str
    required: bool = True  # does this scenario's verdict decide the endpoint verdict?
    expected_statuses: list[int] = Field(default_factory=list)
    expected_basis: str = ""  # "documented" | "inferred"
    description: str = ""


class BlockedScenario(BaseModel):
    endpoint_id: str
    scenario: Scenario
    method: str
    route: str
    required: bool = True
    reason_code: str  # MISSING_AUTH | MISSING_FIXTURE | POLICY_NOT_AUTHORIZED | ...
    reason: str


class TestPlan(BaseModel):
    __test__ = False

    requests: list[PlannedRequest] = Field(default_factory=list)
    blocked: list[BlockedScenario] = Field(default_factory=list)
    skipped_over_budget: list[str] = Field(default_factory=list)


class AssertionResult(BaseModel):
    name: str
    passed: bool
    skipped: bool = False
    error: str | None = None


class ScenarioResult(BaseModel):
    endpoint_id: str
    scenario: Scenario
    method: str
    route: str
    required: bool = True
    status: TestStatus
    executed: bool
    http_status: int | None = None
    duration_ms: int | None = None
    timestamp: str = Field(default_factory=utcnow)
    expected_statuses: list[int] = Field(default_factory=list)
    expected_basis: str = ""
    assertions: list[AssertionResult] = Field(default_factory=list)
    reason_code: str | None = None
    reason: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)  # sanitized


class ExecutionResult(BaseModel):
    newman_exit_code: int | None = None
    newman_version: str | None = None
    started_at: str = Field(default_factory=utcnow)
    error_kind: str | None = None  # NEWMAN_MISSING | COLLECTION_INVALID | TIMEOUT | CONNECTIVITY | AUTH | ...
    error_detail: str | None = None
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    total_requests_executed: int = 0
    total_assertions: int = 0
    failed_assertions: int = 0
    skipped_tests: int = 0
    log_excerpt: str = ""  # sanitized, size-limited
