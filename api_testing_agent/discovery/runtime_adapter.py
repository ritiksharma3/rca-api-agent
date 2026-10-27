"""Optional runtime discovery: fetch an OpenAPI document that a *user-provided* running server publishes.

Disabled unless --runtime-spec-url is given. It never starts a server and never probes for routes; it performs a
single GET of the stated URL under the same target-safety rules as test traffic, then hands the document to the
OpenAPI adapter.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from ..errors import DiscoveryError
from ..security.redaction import redact_text
from ..security.safety_policy import SafetyPolicy, parse_target

MAX_SPEC_BYTES = 8_000_000


def fetch_runtime_spec(url: str, policy: SafetyPolicy, dest: Path, timeout_s: float = 10.0) -> Path:
    target = parse_target(url)
    policy.check_target(target)  # approval + private/public opt-ins apply to discovery traffic as well
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
            resp = client.get(url, headers={"Accept": "application/json, application/yaml"})
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"cannot fetch runtime spec: {redact_text(type(exc).__name__ + ': ' + str(exc))}") from exc
    if resp.is_redirect:
        raise DiscoveryError("runtime spec URL redirected; redirects are not followed")
    if resp.status_code != 200:
        raise DiscoveryError(f"runtime spec URL returned HTTP {resp.status_code}")
    if len(resp.content) > MAX_SPEC_BYTES:
        raise DiscoveryError("runtime spec is unreasonably large")
    suffix = ".yaml" if url.lower().endswith((".yaml", ".yml")) else ".json"
    dest = dest.with_suffix(suffix)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(resp.content)
    return dest


# Where common frameworks publish their OpenAPI document: FastAPI, NestJS+Swagger, Spring (springdoc), ASP.NET (Swashbuckle),
# swagger-jsdoc/Express, Laravel (L5-Swagger / Scribe / Scramble), Django (drf-spectacular / drf-yasg).
WELL_KNOWN_SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/docs-json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/api/openapi.json", "/api/swagger.json", "/api-json", "/docs/api-docs.json", "/docs.openapi", "/api/schema/?format=json",
)
PROBE_TIMEOUT_S = 4.0


def _is_openapi(doc: object) -> bool:
    return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths"), dict) and bool(doc["paths"])


def probe_runtime_spec(base_url: str, policy: SafetyPolicy, dest: Path) -> tuple[Path | None, str]:
    """Look for an OpenAPI document the *test target itself* publishes. Read-only GETs of fixed, well-known paths; same target-safety
    rules as test traffic. Returns (file, note). A connection failure stops the probe at once (a hung server must not cost N timeouts)."""
    target = parse_target(base_url)
    policy.check_target(target)
    roots = list(dict.fromkeys([target.base_url.rstrip("/"), target.origin.rstrip("/")]))
    tried = 0
    try:
        with httpx.Client(timeout=PROBE_TIMEOUT_S, follow_redirects=False, verify=True) as client:
            for root in roots:
                for path in WELL_KNOWN_SPEC_PATHS:
                    url = root + path
                    tried += 1
                    try:
                        resp = client.get(url, headers={"Accept": "application/json"})
                    except httpx.HTTPError as exc:
                        return None, f"spec probe stopped: {type(exc).__name__} from the target"
                    if resp.status_code != 200 or len(resp.content) > MAX_SPEC_BYTES or "json" not in resp.headers.get("content-type", "").lower():
                        continue
                    try:
                        doc = resp.json()
                    except ValueError:
                        continue
                    if _is_openapi(doc):
                        dest = dest.with_suffix(".json")
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(resp.content)
                        return dest, f"found an OpenAPI document published by the target at {path} ({len(doc['paths'])} paths)"
    except httpx.HTTPError as exc:  # pragma: no cover - client construction problems
        return None, f"spec probe failed: {type(exc).__name__}"
    return None, f"no OpenAPI document found at {tried} well-known path(s)"
