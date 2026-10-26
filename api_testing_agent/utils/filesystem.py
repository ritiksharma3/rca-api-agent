"""Filesystem helpers."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..errors import InvalidInputError

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target", "bin", "obj", ".gradle",
    ".idea", ".vscode", "site-packages", ".next", ".nuxt", "coverage", "out", ".cache",
    "bower_components", ".terraform", "migrations", "artifacts",
}
GENERATED_MARKERS = (".min.js", ".bundle.js", ".generated.", ".g.cs", "_pb2.py", ".designer.cs")
MAX_FILE_BYTES = 1_500_000


def validate_folder(folder: str | Path) -> Path:
    p = Path(folder).expanduser()
    if not p.exists():
        raise InvalidInputError(f"Folder does not exist: {p}")
    if not p.is_dir():
        raise InvalidInputError(f"Not a directory: {p}")
    return p.resolve()


def iter_source_files(root: Path, suffixes: set[str] | None = None) -> Iterator[Path]:
    """Walk root, skipping dependency/build/VCS dirs and generated or oversized files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in sorted(filenames):
            if any(m in name for m in GENERATED_MARKERS):
                continue
            path = Path(dirpath) / name
            if suffixes is not None and path.suffix.lower() not in suffixes:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@contextmanager
def private_temp_dir(prefix: str = "api-agent-") -> Iterator[Path]:
    """Temp directory that is always removed, even on error."""
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)
