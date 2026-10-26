"""Language detection by file extension."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

SUFFIX_LANGUAGE = {
    ".py": "python",
    ".php": "php",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
}


def language_of(path: Path) -> str | None:
    return SUFFIX_LANGUAGE.get(path.suffix.lower())


def count_languages(paths: list[Path]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for p in paths:
        lang = language_of(p)
        if lang:
            counter[lang] += 1
    return dict(counter.most_common())
