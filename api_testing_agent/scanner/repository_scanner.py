"""Static repository scan. Never executes repository code."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..errors import FrameworkNotIdentifiedError, InvalidInputError
from ..models.project import BackendCandidate, ScanResult, SpecCandidate
from ..utils.filesystem import iter_source_files, read_text, rel, validate_folder
from .framework_detector import detect_backends
from .language_detector import count_languages

SPEC_SUFFIXES = {".json", ".yaml", ".yml"}


def _spec_kind(path: Path) -> SpecCandidate | None:
    """A file is a spec candidate only if it parses and has a top-level openapi/swagger key."""
    try:
        head = read_text(path)[:4000].lower()
    except OSError:
        return None
    if "openapi" not in head and "swagger" not in head:
        return None
    try:
        text = read_text(path)
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    if "openapi" in data:
        return SpecCandidate(path="", kind="openapi", version=str(data["openapi"]))
    if "swagger" in data:
        return SpecCandidate(path="", kind="swagger", version=str(data["swagger"]))
    return None


def scan_repository(folder: str | Path) -> ScanResult:
    root = validate_folder(folder)
    all_files = list(iter_source_files(root))
    result = ScanResult(root=str(root), files_scanned=len(all_files))
    result.languages = count_languages(all_files)

    for f in all_files:
        if f.suffix.lower() in SPEC_SUFFIXES:
            cand = _spec_kind(f)
            if cand:
                cand.path = rel(f, root)
                result.spec_files.append(cand)

    result.backends = detect_backends(root, all_files)
    paths = {b.path for b in result.backends}
    result.multiple_backends = len(result.backends) > 1
    if len(paths) > 1:
        result.warnings.append(
            f"Multiple backend locations detected ({', '.join(sorted(paths))}); select one with --backend."
        )
    elif len(result.backends) > 1:
        result.warnings.append(
            "Several frameworks detected in the same location; select one with --framework or accept all."
        )
    if not result.backends:
        result.warnings.append(
            "No backend framework identified. Provide an OpenAPI document (--spec) or check the folder."
        )
    return result


def select_backend(
    scan: ScanResult, backend: str | None = None, framework: str | None = None
) -> BackendCandidate:
    """Pick the backend to analyse: explicit selection, or the only candidate. Never guesses."""
    cands = scan.backends
    if backend:
        norm = backend.replace("\\", "/").strip("/") or "."
        cands = [c for c in cands if c.path == norm]
        if not cands:
            raise InvalidInputError(
                f"--backend '{backend}' does not match a detected backend. Detected: "
                + ", ".join(sorted({c.path for c in scan.backends}))
            )
    if framework:
        cands = [c for c in cands if c.framework.lower() == framework.lower()]
        if not cands:
            raise InvalidInputError(f"--framework '{framework}' not detected there.")
    if not cands:
        raise FrameworkNotIdentifiedError("No backend framework identified in this folder.")
    if len(cands) > 1:
        # Unambiguous rule: a single highest-confidence candidate wins; ties require explicit choice.
        rank = {"high": 3, "medium": 2, "low": 1}
        top = max(rank[c.confidence.value] for c in cands)
        best = [c for c in cands if rank[c.confidence.value] == top]
        if len(best) == 1 and len({c.path for c in cands}) == 1:
            scan.selected_backend = best[0].path
            return best[0]
        listing = "; ".join(f"{c.path} ({c.framework})" for c in cands)
        raise InvalidInputError(
            f"Multiple backend candidates: {listing}. Choose one with --backend <path> [--framework <name>]."
        )
    scan.selected_backend = cands[0].path
    return cands[0]
