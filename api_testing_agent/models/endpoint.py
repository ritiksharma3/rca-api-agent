"""Framework-independent endpoint inventory models."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH"}
DESTRUCTIVE_METHODS = {"DELETE"}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_endpoint_id(method: str, route: str) -> str:
    digest = hashlib.sha1(f"{method.upper()} {route}".encode()).hexdigest()[:10]
    return f"ep_{digest}"


class ParamLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DiscoveryStatus(str, Enum):
    DISCOVERED = "DISCOVERED"  # method + route established
    PARTIAL = "PARTIAL"  # route established, details (schemas/auth) incomplete


class ValidationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNVALIDATED = "UNVALIDATED"


class Evidence(BaseModel):
    source: str  # file path, command, or document
    detail: str = ""
    line: int | None = None


class Parameter(BaseModel):
    name: str
    location: ParamLocation
    required: bool = False
    schema_def: dict[str, Any] = Field(default_factory=dict)
    example: Any = None
    description: str | None = None


class RequestBody(BaseModel):
    content_type: str = "application/json"
    schema_def: dict[str, Any] = Field(default_factory=dict)
    required: bool = False
    example: Any = None


class ResponseSpec(BaseModel):
    status: str  # "200", "4XX", "default"
    description: str = ""
    content_type: str | None = None
    schema_def: dict[str, Any] | None = None


class Endpoint(BaseModel):
    id: str = ""
    method: str
    route: str  # normalized template: /items/{item_id}
    original_path: str  # as written in the source/spec
    path_param_names: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: RequestBody | None = None
    responses: list[ResponseSpec] = Field(default_factory=list)
    security_schemes: list[str] = Field(default_factory=list)
    requires_auth: bool | None = None  # None = unknown
    source_file: str | None = None
    line: int | None = None
    operation_id: str | None = None
    handler: str | None = None
    strategy: str = ""
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    discovery_status: DiscoveryStatus = DiscoveryStatus.DISCOVERED
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED

    @model_validator(mode="after")
    def _fill(self) -> "Endpoint":
        self.method = self.method.upper()
        if not self.id:
            self.id = make_endpoint_id(self.method, self.route)
        return self

    def params(self, location: ParamLocation) -> list[Parameter]:
        return [p for p in self.parameters if p.location == location]


class PotentialRoute(BaseModel):
    """A route/handler seen in source analysis that could not be resolved to a concrete endpoint."""

    description: str
    reason: str
    source_file: str | None = None
    line: int | None = None
    strategy: str = ""
    status: str = "NOT DISCOVERED"


class AttemptRecord(BaseModel):
    adapter: str
    outcome: str  # "used" | "skipped" | "failed" | "empty" | "cross-check"
    detail: str = ""
    endpoint_count: int = 0


class Discrepancy(BaseModel):
    kind: str
    method: str
    route: str
    detail: str


class DiscoverySummary(BaseModel):
    strategy_used: str | None = None
    attempts: list[AttemptRecord] = Field(default_factory=list)
    complete: bool = False
    limitations: list[str] = Field(default_factory=list)


class EndpointInventory(BaseModel):
    schema_version: str = "1.0"
    generated_at: str = Field(default_factory=utcnow)
    project_root: str = ""
    backend_path: str = ""
    framework: str | None = None
    discovery: DiscoverySummary = Field(default_factory=DiscoverySummary)
    server_base_path: str = ""  # from the spec's servers/basePath, informational
    security_definitions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    endpoints: list[Endpoint] = Field(default_factory=list)
    potential_routes: list[PotentialRoute] = Field(default_factory=list)
    discrepancies: list[Discrepancy] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=lambda: [
            "Endpoint counts measure route inventory only, not behavioral or code-path coverage."
        ]
    )
