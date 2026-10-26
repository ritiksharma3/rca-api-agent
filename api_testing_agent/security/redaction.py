"""Secret redaction for logs, exceptions, artifacts and reports."""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "apikey",
    "api_key", "token", "access_token", "refresh_token", "id_token", "password", "passwd", "secret",
    "client_secret", "x-auth-token", "x-csrf-token", "session", "sessionid",
}
_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic|token)?\s*[^\s,;\"']+"), r"\1" + REDACTED),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer " + REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), REDACTED),
    (
        re.compile(
            r"(?i)((?:password|passwd|secret|token|api[_-]?key|access_token)[\"']?\s*[:=]\s*[\"']?)[^\s\"',&}]+"
        ),
        r"\1" + REDACTED,
    ),
]


def is_sensitive_key(key: str) -> bool:
    return key.strip().lower() in SENSITIVE_KEYS


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    """Remove known secret values and common credential patterns from text."""
    if not text:
        return text
    for s in sorted({s for s in (secrets or []) if s and len(s) >= 4}, key=len, reverse=True):
        text = text.replace(s, REDACTED)
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_obj(obj: Any, secrets: list[str] | None = None) -> Any:
    """Recursively redact a JSON-like structure (sensitive keys + secret values in strings)."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if is_sensitive_key(str(k)) else redact_obj(v, secrets)) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_obj(v, secrets) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    return obj


def truncate(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated {len(text) - limit} chars]"
