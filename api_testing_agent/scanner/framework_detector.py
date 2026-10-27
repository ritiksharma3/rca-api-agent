"""Framework detection from manifests, config files and source conventions.

Detections are *candidates with evidence*, not proof. Nothing in the scanned repository is executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models.endpoint import Confidence, Evidence
from ..models.project import BackendCandidate
from ..utils.filesystem import read_text, rel

MANIFEST_NAMES = {
    "composer.json", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod",
    "manage.py", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "artisan",
}
MANIFEST_SUFFIXES = {".csproj"}

# framework key -> (language, display name)
FRAMEWORKS = {
    "fastapi": ("python", "FastAPI"),
    "flask": ("python", "Flask"),
    "django": ("python", "Django"),
    "laravel": ("php", "Laravel"),
    "express": ("javascript", "Express"),
    "fastify": ("javascript", "Fastify"),
    "nestjs": ("javascript", "NestJS"),
    "koa": ("javascript", "Koa"),
    "spring": ("java", "Spring"),
    "aspnet": ("csharp", "ASP.NET Core"),
    "gin": ("go", "Gin"),
    "echo": ("go", "Echo"),
    "chi": ("go", "chi"),
    "gorilla": ("go", "gorilla/mux"),
    "nethttp": ("go", "net/http"),
}


@dataclass
class _Signals:
    evidence: dict[str, list[Evidence]] = field(default_factory=dict)
    manifest_hit: set[str] = field(default_factory=set)

    def add(self, fw: str, source: str, detail: str, manifest: bool = False, line: int | None = None) -> None:
        self.evidence.setdefault(fw, []).append(Evidence(source=source, detail=detail, line=line))
        if manifest:
            self.manifest_hit.add(fw)


def is_manifest(path: Path) -> bool:
    return path.name in MANIFEST_NAMES or path.suffix in MANIFEST_SUFFIXES


def _owner(path: Path, roots: list[Path], scan_root: Path) -> Path:
    best = scan_root
    for r in roots:
        if r == path.parent or r in path.parents:
            if len(r.parts) > len(best.parts):
                best = r
    return best


_SOURCE_RULES: dict[str, list[tuple[str, re.Pattern[str], str]]] = {
    ".py": [
        ("fastapi", re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)", re.M), "imports fastapi"),
        ("flask", re.compile(r"^\s*(?:from\s+flask\b|import\s+flask\b)", re.M), "imports flask"),
        ("django", re.compile(r"^\s*(?:from\s+django\b|import\s+django\b)", re.M), "imports django"),
    ],
    ".php": [
        ("laravel", re.compile(r"Illuminate\\Support\\Facades\\Route|Route::(?:get|post|put|patch|delete|apiResource|resource|prefix|group)\b"), "Laravel Route facade usage"),
    ],
    ".js": [
        ("express", re.compile(r"""require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]"""), "imports express"),
        ("fastify", re.compile(r"""require\(\s*['"]fastify['"]\s*\)|from\s+['"]fastify['"]"""), "imports fastify"),
        ("koa", re.compile(r"""require\(\s*['"](?:koa-router|@koa/router|koa)['"]\s*\)|from\s+['"](?:koa-router|@koa/router|koa)['"]"""), "imports koa / koa-router"),
    ],
    ".java": [
        ("spring", re.compile(r"@(?:RestController|RequestMapping|GetMapping|PostMapping)\b"), "Spring MVC annotations"),
    ],
    ".cs": [
        ("aspnet", re.compile(r"\[ApiController\]|:\s*ControllerBase\b|MapGet\(|MapPost\("), "ASP.NET controller / minimal API usage"),
    ],
    ".go": [
        ("gin", re.compile(r"github\.com/gin-gonic/gin"), "imports gin"),
        ("echo", re.compile(r"github\.com/labstack/echo"), "imports echo"),
        ("chi", re.compile(r"github\.com/go-chi/chi"), "imports chi"),
        ("gorilla", re.compile(r"github\.com/gorilla/mux"), "imports gorilla/mux"),
        ("nethttp", re.compile(r"\bhttp\.HandleFunc\(|\bmux\.HandleFunc\("), "net/http HandleFunc registration"),
    ],
}
_SOURCE_RULES[".mjs"] = _SOURCE_RULES[".js"]
_SOURCE_RULES[".cjs"] = _SOURCE_RULES[".js"]
_SOURCE_RULES[".ts"] = _SOURCE_RULES[".js"] + [
    ("nestjs", re.compile(r"@nestjs/common"), "imports @nestjs/common"),
]


def _scan_manifest(path: Path, root: Path, sig: _Signals) -> None:
    name = path.name
    text = read_text(path)
    low = text.lower()
    src = rel(path, root)
    if name == "composer.json" and "laravel/framework" in low:
        sig.add("laravel", src, "requires laravel/framework", manifest=True)
    elif name == "artisan":
        sig.add("laravel", src, "artisan entrypoint present", manifest=True)
    elif name == "manage.py" and "django" in low:
        sig.add("django", src, "manage.py references django", manifest=True)
    elif name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
        for fw, pat in (("fastapi", r"\bfastapi\b"), ("flask", r"\bflask\b"), ("django", r"\bdjango\b")):
            if re.search(pat, low):
                sig.add(fw, src, f"declares {fw} dependency", manifest=True)
    elif name == "package.json":
        for fw, pkg in (("express", '"express"'), ("fastify", '"fastify"'), ("nestjs", '"@nestjs/core"'), ("koa", '"koa-router"'), ("koa", '"@koa/router"')):
            if pkg in low:
                sig.add(fw, src, f"package.json depends on {pkg.strip(chr(34))}", manifest=True)
    elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        if "spring-boot" in low or "spring-web" in low or "springframework" in low:
            sig.add("spring", src, "build file depends on Spring", manifest=True)
    elif name == "go.mod":
        for fw, mod in (("gin", "gin-gonic/gin"), ("echo", "labstack/echo"), ("chi", "go-chi/chi"), ("gorilla", "gorilla/mux")):
            if mod in low:
                sig.add(fw, src, f"go.mod requires {mod}", manifest=True)
    elif path.suffix == ".csproj" and "microsoft.net.sdk.web" in low:
        sig.add("aspnet", src, "csproj uses Microsoft.NET.Sdk.Web", manifest=True)


def detect_backends(root: Path, files: list[Path]) -> list[BackendCandidate]:
    manifests = [f for f in files if is_manifest(f)]
    roots = sorted({m.parent for m in manifests}, key=lambda p: len(p.parts))
    signals: dict[Path, _Signals] = {}

    for m in manifests:
        owner = _owner(m, roots, root)
        _scan_manifest(m, root, signals.setdefault(owner, _Signals()))

    for f in files:
        rules = _SOURCE_RULES.get(f.suffix.lower())
        if not rules:
            continue
        text = read_text(f)
        owner = _owner(f, roots, root)
        for fw, pat, detail in rules:
            m = pat.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                signals.setdefault(owner, _Signals()).add(fw, rel(f, root), detail, line=line)

    candidates: list[BackendCandidate] = []
    for owner, sig in sorted(signals.items(), key=lambda kv: str(kv[0])):
        for fw, evidence in sig.evidence.items():
            has_manifest = fw in sig.manifest_hit
            src_hits = sum(1 for e in evidence if e.line is not None)
            if has_manifest and src_hits:
                conf = Confidence.HIGH
            elif has_manifest or src_hits >= 2:
                conf = Confidence.MEDIUM
            else:
                conf = Confidence.LOW
            lang, display = FRAMEWORKS[fw]
            candidates.append(
                BackendCandidate(
                    path=rel(owner, root) if owner != root else ".",
                    language=lang,
                    framework=display,
                    confidence=conf,
                    evidence=evidence[:6],
                )
            )
    # Go net/http and Flask-in-Django style overlaps are kept; the user can pick via --backend.
    return candidates
