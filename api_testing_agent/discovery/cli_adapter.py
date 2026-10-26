"""Framework-native route listing commands.

Only commands that actually exist are implemented. Currently: Laravel ``php artisan route:list --json``.
There is no universal route-list command for Django, Express, Spring, .NET or Go, so those are not faked here.
"""

from __future__ import annotations

import json
import re

from ..errors import DiscoveryError
from ..models.endpoint import Confidence, Endpoint, Evidence, ParamLocation, Parameter
from ..security.redaction import redact_text, truncate
from ..utils.subprocess_utils import run_command, which
from .base import Applicability, DiscoveryAdapter, DiscoveryContext, DiscoveryOutcome
from .normalizer import normalize_path


class LaravelRouteListAdapter(DiscoveryAdapter):
    name = "laravel-route-list"
    strategy = "cli"
    supported = ("Laravel",)
    prerequisites = "php on PATH; Laravel app with installed dependencies (vendor/) supporting `route:list --json`"
    executes_project_code = True  # artisan boots the application

    def applicable(self, ctx: DiscoveryContext) -> Applicability:
        if ctx.framework != "Laravel":
            return Applicability(False, "not a Laravel project")
        if not (ctx.backend_dir / "artisan").is_file():
            return Applicability(False, "artisan not found")
        if which("php") is None:
            return Applicability(False, "php executable not found on PATH")
        if not (ctx.backend_dir / "vendor" / "autoload.php").is_file():
            return Applicability(False, "vendor/autoload.php missing (run `composer install` yourself; the tool never installs dependencies)")
        return Applicability(True)

    def discover(self, ctx: DiscoveryContext) -> DiscoveryOutcome:
        res = run_command(["php", "artisan", "route:list", "--json"], cwd=ctx.backend_dir, timeout=ctx.timeout)
        if res.not_found:
            raise DiscoveryError(f"cannot run php: {res.stderr}")
        if res.timed_out:
            raise DiscoveryError(f"`php artisan route:list --json` timed out after {ctx.timeout}s")
        if res.returncode != 0:
            raise DiscoveryError(
                f"`php artisan route:list --json` exited {res.returncode}: "
                + truncate(redact_text((res.stderr or res.stdout).strip()), 400)
            )
        # artisan may print notices before the JSON; locate the JSON array
        match = re.search(r"\[\s*[\{\]]", res.stdout)
        try:
            rows = json.loads(res.stdout[match.start():] if match else res.stdout)
        except ValueError as exc:
            raise DiscoveryError(f"route:list output is not valid JSON ({exc})") from exc
        if not isinstance(rows, list):
            raise DiscoveryError("route:list JSON has unexpected shape (expected a list)")
        outcome = DiscoveryOutcome()
        for row in rows:
            if not isinstance(row, dict) or "uri" not in row or "method" not in row:
                outcome.limitations.append("a route:list row had an unexpected shape and was skipped")
                continue
            uri = "/" + str(row["uri"]).lstrip("/")
            route, names = normalize_path(uri)
            mws = [str(m) for m in (row.get("middleware") or [])]
            auth = any(m.startswith("auth") or "Authenticate" in m for m in mws)
            for m in str(row["method"]).split("|"):
                m = m.strip().upper()
                if m in ("HEAD", "OPTIONS", ""):
                    continue
                outcome.endpoints.append(
                    Endpoint(
                        method=m, route=route, original_path=uri, path_param_names=names,
                        parameters=[Parameter(name=n, location=ParamLocation.PATH, required=True, schema_def={"type": "string"}) for n in names],
                        requires_auth=True if auth else None,
                        security_schemes=[x for x in mws if x.startswith("auth") or "Authenticate" in x],
                        handler=str(row.get("action") or "") or None, operation_id=row.get("name") or None,
                        strategy=self.strategy, confidence=Confidence.HIGH,
                        evidence=[Evidence(source="php artisan route:list --json", detail=str(row.get("action") or ""))],
                        warnings=["request/response schemas not available from route:list"],
                    )
                )
        if not outcome.endpoints:
            raise DiscoveryError("route:list returned no routes")
        outcome.limitations.append(
            "route:list reports registered routes (authoritative for what the framework serves) but carries no "
            "request/response schemas; closures registered conditionally at runtime are only seen if booted."
        )
        outcome.complete = True  # the framework's own registry is sufficient evidence of the registered route set
        outcome.detail = f"{len(rows)} route rows"
        return outcome
