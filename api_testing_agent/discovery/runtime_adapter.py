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
