"""Coverage assessment: separates discovery evidence from test outcomes. Never claims completeness."""

from __future__ import annotations

from collections import Counter

from ..models.endpoint import EndpointInventory
from ..models.execution import TestStatus
from ..models.report import CoverageSummary, EndpointVerdict


def build_coverage(inv: EndpointInventory, verdicts: list[EndpointVerdict]) -> CoverageSummary:
    counts = Counter(v.test_status for v in verdicts)
    return CoverageSummary(
        confirmed_routes=len(inv.endpoints),
        tested_pass=counts[TestStatus.PASS],
        tested_fail=counts[TestStatus.FAIL],
        blocked=counts[TestStatus.BLOCKED],
        potential_unresolved=len(inv.potential_routes),
        discrepancies=len(inv.discrepancies),
        by_method=dict(sorted(Counter(e.method for e in inv.endpoints).items())),
        discovery_complete=inv.discovery.complete,
    )


def status_counts(inv: EndpointInventory, verdicts: list[EndpointVerdict]) -> dict[str, int]:
    counts = Counter(v.test_status.value for v in verdicts)
    return {
        TestStatus.PASS.value: counts[TestStatus.PASS.value],
        TestStatus.FAIL.value: counts[TestStatus.FAIL.value],
        TestStatus.BLOCKED.value: counts[TestStatus.BLOCKED.value],
        TestStatus.NOT_DISCOVERED.value: len(inv.potential_routes),
    }
