"""Request headers the target requires on (almost) every call: API keys, client version, tenant id, idempotency keys ...

The names are found by scanning the backend source for header reads (``req.get('X-API-Key')``, ``request.headers.get(...)``,
``$request->header(...)``, ``r.Header.Get(...)`` ...). Values are never taken from source code. They come from, in order:

1. ``--header NAME=VALUE`` / ``--header NAME=env:VAR``
2. the environment: ``API_AGENT_HEADER_<NAME>`` (``X-API-Key`` -> ``API_AGENT_HEADER_X_API_KEY``; API-key-like names also
   fall back to ``API_AGENT_API_KEY``)
3. built-in generators for values that must be fresh per request (idempotency keys, request ids, timestamps)
4. a conservative default for ``*-Version`` headers
5. an optional LLM suggestion of a *valid example* from the few lines around the header check -- never for secret-like
   headers (keys, tokens, signatures), which must be supplied by the user

Header values travel to Newman through the private runtime environment (``{{hdr_*}}`` variables) so they are never written
to the collection or the reports. Headers needing a computed signature (HMAC, digests, nonces) are reported as unsupported.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..envfile import is_placeholder
from ..errors import InvalidInputError
from ..security.redaction import redact_text
from ..utils.filesystem import iter_source_files, read_text

if TYPE_CHECKING:  # pragma: no cover
    from ..models.endpoint import EndpointInventory

ENV_PREFIX = "API_AGENT_HEADER_"
SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".py", ".php", ".java", ".kt", ".cs", ".go"}
MAX_SOURCE_FILES = 400
SNIPPET_RADIUS = 8
SNIPPET_CHARS = 700

_NAME = r"([A-Za-z][A-Za-z0-9_-]{1,59})"
_READ_PATTERNS = [
    re.compile(r"\b(?:req|request)\.(?:get|header)\(\s*['\"]" + _NAME + r"['\"]"),  # express / koa
    re.compile(r"\b(?:req|request)\.headers\[\s*['\"]" + _NAME + r"['\"]\s*\]"),  # node + flask/django
    re.compile(r"\brequest\.headers\.get\(\s*['\"]" + _NAME + r"['\"]"),  # flask / starlette / fastapi
    re.compile(r"\brequest\.META\.get\(\s*['\"]HTTP_" + _NAME + r"['\"]"),  # django
    re.compile(r"->(?:header|headers->get)\(\s*['\"]" + _NAME + r"['\"]"),  # laravel / symfony
    re.compile(r"\$_SERVER\[\s*['\"]HTTP_" + _NAME + r"['\"]\s*\]"),  # plain php
    re.compile(r"\.Header\.Get\(\s*\"" + _NAME + r"\""),  # go
    re.compile(r"@RequestHeader\(\s*(?:(?:name|value)\s*=\s*)?\"" + _NAME + r"\""),  # spring
    re.compile(r"\bgetHeader\(\s*\"" + _NAME + r"\""),  # servlet
    re.compile(r"\bHeaders(?:\.TryGetValue\(|\[)\s*\"" + _NAME + r"\""),  # asp.net
    re.compile(r"\b(\w+)\s*:\s*[\w\[\], |.]+?\s*=\s*Header\("),  # fastapi parameter  x_api_key: str = Header(...)
]
_STANDARD = {
    "authorization", "proxy-authorization", "content-type", "content-length", "content-encoding", "accept", "accept-language",
    "accept-encoding", "user-agent", "host", "cookie", "origin", "referer", "connection", "cache-control", "if-none-match",
    "if-modified-since", "upgrade", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip",
    "x-requested-with", "x-http-method-override", "x-csrf-token", "x-xsrf-token", "range", "te", "dnt",
}
_OPTIONAL = re.compile(r"request[-_]?id|correlation|trace|span|b3|forwarded", re.I)  # optional diagnostics, not requirements
_COMPUTED = re.compile(r"signature|hmac|digest|nonce|sig$|checksum", re.I)  # cannot be produced without a signing secret
_SECRET = re.compile(r"key|token|secret|password|passwd|credential|auth|signature|session", re.I)
_UUID_LIKE = re.compile(r"idempotenc|request[-_]?uuid|message[-_]?id|^x-id$", re.I)
_TIMESTAMP = re.compile(r"timestamp|request[-_]?time|^x-date$", re.I)
_API_KEY = re.compile(r"api[-_]?key|apikey", re.I)
_VERSION = re.compile(r"version", re.I)
_VALUE_OK = re.compile(r"^[A-Za-z0-9._:/+=\-]{1,64}$")

DYNAMIC_UUID = "{{$guid}}"
DYNAMIC_TIMESTAMP = "{{$timestamp}}"


@dataclass
class HeaderHint:
    name: str
    file: str = ""
    line: int = 0
    snippet: str = ""


@dataclass
class ResolvedHeader:
    name: str
    var: str  # Newman environment variable that carries the value
    value: str | None = None  # None for dynamic headers
    dynamic: str | None = None  # Postman dynamic variable, e.g. {{$guid}}
    source: str = ""  # flag | env | builtin | default | llm
    secret: bool = False

    @property
    def template(self) -> str:
        return self.dynamic or f"{{{{{self.var}}}}}"

    def probe_value(self) -> str:
        """Concrete value for requests the agent itself sends (the login call)."""
        if self.dynamic == DYNAMIC_UUID:
            return str(uuid.uuid4())
        if self.dynamic == DYNAMIC_TIMESTAMP:
            return str(int(time.time()))
        return self.value or ""


@dataclass
class HeaderPlan:
    headers: list[ResolvedHeader] = field(default_factory=list)
    unresolved: list[HeaderHint] = field(default_factory=list)  # the target reads them but no value is available
    unsupported: list[str] = field(default_factory=list)  # need a computed signature
    notes: list[str] = field(default_factory=list)
    llm_used: bool = False

    def env_vars(self) -> dict[str, str]:
        return {h.var: h.value for h in self.headers if h.value is not None}

    def secrets(self) -> list[str]:
        return [h.value for h in self.headers if h.secret and h.value]

    def probe_headers(self) -> dict[str, str]:
        return {h.name: h.probe_value() for h in self.headers}

    def summary(self) -> list[dict[str, object]]:
        """Names and provenance only -- never values."""
        out: list[dict[str, object]] = [{"name": h.name, "source": h.source, "status": "sent"} for h in self.headers]
        out += [{"name": h.name, "source": None, "status": "missing", "found_in": f"{h.file}:{h.line}" if h.file else None} for h in self.unresolved]
        out += [{"name": n, "source": None, "status": "unsupported (needs a computed signature)"} for n in self.unsupported]
        return out

    def hint_for_missing(self) -> str:
        if not self.unresolved:
            return ""
        lines = [f"  {ENV_PREFIX}{header_env_suffix(h.name)}=<value>   # {h.name}" for h in self.unresolved]
        return "the target reads header(s) with no value available; add to .env (or use --header NAME=VALUE):\n" + "\n".join(lines)


def header_env_suffix(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()


def _var_name(name: str) -> str:
    return "hdr_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _normalise(raw: str) -> str:
    name = raw.replace("_", "-")
    if name.isupper() or name.islower():  # HTTP_X_API_KEY / x-api-key style -> X-Api-Key
        name = "-".join(p.capitalize() for p in name.split("-"))
    return name


def _snippet(lines: list[str], idx: int) -> str:
    start = max(idx - SNIPPET_RADIUS, 0)
    return redact_text("\n".join(lines[start:idx + SNIPPET_RADIUS + 1]))[:SNIPPET_CHARS]


def detect_header_hints(inv: "EndpointInventory | None", project_root: str | Path | None = None, backend_path: str = "") -> list[HeaderHint]:
    """Header names the backend source reads. Names only come from literals in code; nothing is executed."""
    root = Path(project_root or (inv.project_root if inv else "") or ".")
    base = root / (backend_path or (inv.backend_path if inv else "") or "")
    if not base.is_dir():
        return []
    found: dict[str, HeaderHint] = {}
    for n, path in enumerate(iter_source_files(base, SOURCE_SUFFIXES)):
        if n >= MAX_SOURCE_FILES:
            break
        text = read_text(path)
        if not text or not any(tok in text for tok in ("eader", "HTTP_", "META")):
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            for pat in _READ_PATTERNS:
                for m in pat.finditer(line):
                    name = _normalise(m.group(1))
                    low = name.lower()
                    if low in _STANDARD or _OPTIONAL.search(low) or low.startswith("http-") or len(low) < 3:
                        continue
                    if low not in found:
                        try:
                            rel = str(path.relative_to(base)).replace("\\", "/")
                        except ValueError:
                            rel = path.name
                        found[low] = HeaderHint(name=name, file=rel, line=idx + 1, snippet=_snippet(lines, idx))
    return sorted(found.values(), key=lambda h: h.name.lower())


def parse_header_flags(values: list[str] | None) -> dict[str, str]:
    """``NAME=VALUE`` or ``NAME=env:VAR`` -> {name: value}. Env references are resolved here."""
    out: dict[str, str] = {}
    for raw in values or []:
        name, sep, value = raw.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,59}", name):
            raise InvalidInputError(f"--header expects NAME=VALUE or NAME=env:VAR, got '{raw.split('=')[0]}'")
        if value.lower().startswith("env:"):
            var = value[4:].strip()
            value = os.environ.get(var, "")
            if is_placeholder(value):
                raise InvalidInputError(f"--header {name}: environment variable {var} is not set")
        if "\r" in value or "\n" in value:
            raise InvalidInputError(f"--header {name}: value must be a single line")
        out[name.lower()] = value
    return out


def resolve_headers(
    hints: list[HeaderHint], explicit: dict[str, str] | None = None, api_key_env: str = "API_AGENT_API_KEY",
    use_llm: bool = True, environ: dict[str, str] | None = None,
) -> HeaderPlan:
    env = os.environ if environ is None else environ
    explicit = {k.lower(): v for k, v in (explicit or {}).items()}
    plan = HeaderPlan()
    names = {h.name.lower(): h for h in hints}
    for low in explicit:  # headers the user asked for even if detection did not see them
        names.setdefault(low, HeaderHint(name=low))
    pending: list[HeaderHint] = []
    for low, hint in sorted(names.items()):
        name = hint.name if low not in explicit or hint.file else _canonical(hint.name)
        if _COMPUTED.search(low) and low not in explicit:
            plan.unsupported.append(name)
            continue
        secret = bool(_SECRET.search(low))
        rh = ResolvedHeader(name=name, var=_var_name(name), secret=secret)
        value = explicit.get(low)
        if value:
            rh.value, rh.source = value, "flag"
        else:
            value = env.get(ENV_PREFIX + header_env_suffix(name), "")
            if not value and _API_KEY.search(low):
                value = env.get(api_key_env, "")
            if value and not is_placeholder(value):
                rh.value, rh.source = value, "env"
        if rh.value is None:
            if _UUID_LIKE.search(low):
                rh.dynamic, rh.source = DYNAMIC_UUID, "builtin"
            elif _TIMESTAMP.search(low):
                rh.dynamic, rh.source = DYNAMIC_TIMESTAMP, "builtin"
            elif _VERSION.search(low) and not secret:
                rh.value, rh.source = "1.0.0", "default"
                plan.notes.append(f"{name}: no value supplied, assuming 1.0.0 (set {ENV_PREFIX}{header_env_suffix(name)} to change)")
        if rh.value is None and rh.dynamic is None:
            if not secret and use_llm and hint.snippet:
                pending.append(hint)
                continue
            plan.unresolved.append(hint)
            continue
        plan.headers.append(rh)
    if pending:
        from .llm import suggest_header_values

        suggestions, note = suggest_header_values(pending)
        if note:
            plan.notes.append(note)
        for hint in pending:
            val = suggestions.get(hint.name)
            if val:
                plan.headers.append(ResolvedHeader(name=hint.name, var=_var_name(hint.name), value=val, source="llm"))
                plan.llm_used = True
                plan.notes.append(f"{hint.name}: value suggested by the LLM from the check in {hint.file}:{hint.line}")
            else:
                plan.unresolved.append(hint)
    plan.headers.sort(key=lambda h: h.name.lower())
    return plan


def _canonical(low: str) -> str:
    return "-".join(p if p.upper() == p and len(p) <= 3 else p.capitalize() for p in low.split("-"))


def value_is_acceptable(value: object) -> bool:
    return isinstance(value, str) and bool(_VALUE_OK.match(value))
