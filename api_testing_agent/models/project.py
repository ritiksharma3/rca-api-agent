"""Scan result models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .endpoint import Confidence, Evidence, utcnow


class BackendCandidate(BaseModel):
    path: str  # relative to scan root ("." for root)
    language: str
    framework: str
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(default_factory=list)


class SpecCandidate(BaseModel):
    path: str  # relative to scan root
    kind: str  # "openapi" | "swagger"
    version: str | None = None


class ScanResult(BaseModel):
    schema_version: str = "1.0"
    generated_at: str = Field(default_factory=utcnow)
    root: str
    files_scanned: int = 0
    languages: dict[str, int] = Field(default_factory=dict)  # language -> file count
    backends: list[BackendCandidate] = Field(default_factory=list)
    spec_files: list[SpecCandidate] = Field(default_factory=list)
    multiple_backends: bool = False
    selected_backend: str | None = None
    warnings: list[str] = Field(default_factory=list)


class DiscoveryWarning(BaseModel):
    adapter: str
    severity: str = "warning"  # "info" | "warning" | "error"
    message: str
    source_file: str | None = None
    line: int | None = None
