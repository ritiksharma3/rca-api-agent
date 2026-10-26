"""Static-analysis adapters: tree-sitter based (PHP, JS/TS, Java, C#, Go). Python lives in python_static."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..errors import DiscoveryError
from .base import Applicability, DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from .jvm_dotnet_go_static import analyze_aspnet, analyze_go, analyze_spring
from .js_static import analyze_express
from .php_static import analyze_php
from .python_static import PythonStaticAdapter

Analyzer = Callable[[Path, Path, DiscoveryOutcome], int]

_DISPATCH: dict[str, tuple[Analyzer, list[str]]] = {
    "Laravel": (analyze_php, [
        "Only routes declared with the Route facade in analysed files; routes added by packages/service providers are not seen.",
        "Request validation rules and API resources are not analysed; body schemas are not established.",
    ]),
    "Express": (analyze_express, [
        "Router mounts are resolved through require()/import of relative modules and same-file identifiers only.",
        "Body/query fields are inferred from req.body/req.query usage in inline handlers; types and required-ness are unknown.",
    ]),
    "Spring": (analyze_spring, [
        "Spring: only annotation-declared routes; functional (RouterFunction) routes, meta-annotations and inherited mappings are not resolved.",
    ]),
    "ASP.NET Core": (analyze_aspnet, [
        "ASP.NET: attribute routing and simple minimal-API Map* calls only; conventional routing and route constraints beyond {name:type} are not resolved.",
    ]),
    "Gin": (analyze_go, []),
    "Echo": (analyze_go, []),
    "chi": (analyze_go, []),
    "gorilla/mux": (analyze_go, []),
    "net/http": (analyze_go, []),
}
_GO_LIMIT = (
    "Go: route groups are resolved by variable assignment within a file; handlers are not analysed, so "
    "request/response schemas and auth are unknown."
)


class TreeSitterStaticAdapter(DiscoveryAdapter):
    name = "tree-sitter-static"
    strategy = "static"
    supported = tuple(_DISPATCH)
    prerequisites = "tree-sitter-language-pack (grammars may download on first use)"

    def applicable(self, ctx: DiscoveryContext) -> Applicability:
        if ctx.framework in _DISPATCH:
            return Applicability(True)
        return Applicability(False, f"no tree-sitter analyzer for framework {ctx.framework!r}")

    def discover(self, ctx: DiscoveryContext) -> DiscoveryOutcome:
        fn, limits = _DISPATCH[ctx.framework or ""]
        outcome = DiscoveryOutcome()
        analysed = fn(ctx.root, ctx.backend_dir, outcome)
        if analysed == 0:
            raise DiscoveryError("no relevant source files found for static analysis")
        outcome.limitations += limits
        if fn is analyze_go:
            outcome.limitations.append(_GO_LIMIT)
        outcome.limitations.append("Dynamic registrations, conditional routes and custom middleware are not resolved.")
        if not outcome.endpoints and not outcome.potential_routes:
            raise DiscoveryError("static analysis found no routes")
        outcome.complete = False
        outcome.detail = f"analysed {analysed} source files"
        return outcome


__all__ = ["TreeSitterStaticAdapter", "PythonStaticAdapter"]
