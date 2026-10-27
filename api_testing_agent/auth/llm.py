"""Optional LLM assist for finding the login endpoint (OpenRouter, OpenAI-compatible API).

Only used when heuristics found nothing that works, a key is configured and the user did not pass ``--no-llm``.
What is sent: endpoint routes/methods, body/response *field names* and short, redacted source snippets of the likeliest
handlers. Credentials, tokens and environment values are never part of the prompt. Source code does leave the machine on
this path, which is why it is opt-out and recorded in the report. A suggestion is trusted only after a real login with
it succeeds.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..models.endpoint import Endpoint, EndpointInventory
from ..security.redaction import redact_text
from .detector import endpoint_summary, login_like, match_endpoint
from .provider import AuthConfig, LoginSpec

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "anthropic/claude-sonnet-4.5"  # override with OPENROUTER_MODEL
MAX_ENDPOINTS = 150
MAX_SNIPPETS = 4
SNIPPET_LINES = 45
SNIPPET_CHARS = 2500
_FIELD_OK = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,40}$")
_HEADER_OK = re.compile(r"^header:[A-Za-z0-9\-]{1,40}$", re.I)
_AUTHISH = re.compile(r"auth|login|sign|token|session|user|account", re.I)

SYSTEM_PROMPT = (
    "You help an API test tool log in. Given the list of HTTP endpoints of a backend (plus some handler source), "
    "identify the single endpoint that exchanges a username/email and password for a credential. "
    "Reply with ONLY a JSON object, no prose: "
    '{"found": true|false, "login_path": "/path", "content_type": "json"|"form", "username_field": "...", '
    '"password_field": "...", "token_path": "dotted.path.in.json.response or header:Header-Name or null"}. '
    "login_path must be one of the listed routes. Never invent endpoints. If unsure, reply {\"found\": false}."
)


@dataclass
class LLMResult:
    specs: list[LoginSpec] = field(default_factory=list)
    note: str = ""


def _snippet(ep: Endpoint, inv: EndpointInventory) -> str | None:
    if not ep.source_file:
        return None
    roots = [Path(p).resolve() for p in (inv.project_root, str(Path(inv.project_root) / inv.backend_path) if inv.backend_path else "") if p]
    for root in roots:
        cand = (root / ep.source_file).resolve() if not Path(ep.source_file).is_absolute() else Path(ep.source_file).resolve()
        try:
            cand.relative_to(root)  # never read outside the project
        except ValueError:
            continue
        if cand.is_file():
            try:
                lines = cand.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return None
            start = max((ep.line or 1) - 6, 0)
            return redact_text("\n".join(lines[start:start + SNIPPET_LINES]))[:SNIPPET_CHARS]
    return None


def build_prompt(inv: EndpointInventory) -> str:
    eps = inv.endpoints[:MAX_ENDPOINTS]
    listing = [endpoint_summary(e) for e in eps]
    likely = [e for e in eps if e.method == "POST" and _AUTHISH.search(e.route)][:MAX_SNIPPETS]
    parts = ["Endpoints (JSON):", json.dumps(listing, separators=(",", ":"))]
    for e in likely:
        snip = _snippet(e, inv)
        if snip:
            parts += [f"\nHandler source for POST {e.route}:", snip]
    return "\n".join(parts)


def _validate(obj: object, inv: EndpointInventory | None, config: AuthConfig) -> LoginSpec | None:
    if not isinstance(obj, dict) or obj.get("found") is False:
        return None
    path = obj.get("login_path")
    if not isinstance(path, str) or not path.startswith("/") or "://" in path or ".." in path or len(path) > 200:
        return None  # relative, same-origin paths only
    ep = match_endpoint(inv, path)
    if ep is None and not login_like(path):
        return None  # unknown to the inventory and not login-shaped: do not send credentials there
    ct = obj.get("content_type")
    ct = ct if ct in ("json", "form") else (config.login_content_type or "json")
    user_f, pass_f = obj.get("username_field"), obj.get("password_field")
    user_f = user_f if isinstance(user_f, str) and _FIELD_OK.match(user_f) else config.login_username_field
    pass_f = pass_f if isinstance(pass_f, str) and _FIELD_OK.match(pass_f) else config.login_password_field
    tp = obj.get("token_path")
    tp = tp if isinstance(tp, str) and (_FIELD_OK.match(tp) or _HEADER_OK.match(tp)) else None
    return LoginSpec(
        path=path, content_type=ct, username_field=user_f, password_field=pass_f,
        token_path=config.login_token_path or tp, source="llm", endpoint_id=ep.id if ep else None,
    )


def parse_reply(text: str) -> object:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


def suggest_login(inv: EndpointInventory | None, config: AuthConfig, timeout_s: float = 30.0) -> LLMResult:
    """Ask the LLM for the login endpoint. Never raises: any failure just yields no suggestion."""
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key or inv is None or not inv.endpoints:
        return LLMResult(note="LLM assist skipped: OPENROUTER_API_KEY not set" if not key else "LLM assist skipped: no endpoints")
    model = os.environ.get("OPENROUTER_MODEL", "").strip() or DEFAULT_MODEL
    payload = {
        "model": model, "temperature": 0, "max_tokens": 300,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": build_prompt(inv)}],
    }
    try:
        resp = httpx.post(OPENROUTER_URL, headers={"Authorization": f"Bearer {key}"}, json=payload, timeout=timeout_s, follow_redirects=False)
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
        return LLMResult(note=f"LLM assist failed: {redact_text(type(exc).__name__, [key])}")
    spec = _validate(parse_reply(text if isinstance(text, str) else ""), inv, config)
    if spec is None:
        return LLMResult(note=f"LLM ({model}) did not identify a usable login endpoint")
    return LLMResult(specs=[spec], note=f"LLM ({model}) suggested {spec.path}")


# ---------------------------------------------------------------------------------------------- shared small helpers
def _complete(system: str, user: str, max_tokens: int, timeout_s: float = 30.0) -> tuple[str | None, str]:
    """One chat completion. Returns (text, note); never raises."""
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        return None, "LLM assist skipped: OPENROUTER_API_KEY not set"
    model = os.environ.get("OPENROUTER_MODEL", "").strip() or DEFAULT_MODEL
    payload = {"model": model, "temperature": 0, "max_tokens": max_tokens,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    try:
        resp = httpx.post(OPENROUTER_URL, headers={"Authorization": f"Bearer {key}"}, json=payload, timeout=timeout_s, follow_redirects=False)
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
        return None, f"LLM assist failed: {redact_text(type(exc).__name__, [key])}"
    return (text if isinstance(text, str) else None), f"LLM ({model})"


HEADER_PROMPT = (
    "You help an API test tool send valid requests. For each HTTP header below you get the few lines of backend source that "
    "read or validate it. Reply with ONLY a JSON object {\"values\": {\"Header-Name\": \"example\"}} giving one realistic value "
    "that would pass that validation (match any regex, prefix or format shown). Use only letters, digits and . _ : / + = -. "
    "Omit a header when you cannot tell. Never invent secrets, keys or tokens."
)


def suggest_header_values(hints: list) -> tuple[dict[str, str], str]:
    """Example values for non-secret request headers from short, redacted source snippets. Names/snippets only leave the machine."""
    from .headers import value_is_acceptable

    parts = []
    for h in hints[:12]:
        parts.append(f"### {h.name}\n{h.snippet}")
    text, note = _complete(HEADER_PROMPT, "\n\n".join(parts), 400)
    if text is None:
        return {}, note
    obj = parse_reply(text)
    values = obj.get("values") if isinstance(obj, dict) else None
    allowed = {h.name for h in hints}
    out = {k: v for k, v in (values or {}).items() if k in allowed and value_is_acceptable(v)} if isinstance(values, dict) else {}
    return out, note


TOKEN_PROMPT = (
    "An API test tool logged in and needs to find the credential in the JSON response. Below is the response SHAPE: every "
    "string value was replaced by <str:LENGTH>. Reply with ONLY a JSON object {\"token_path\": \"dotted.path\"} naming the key "
    "that holds the access/bearer token (not the refresh token, not an id). Use {\"token_path\": null} if there is none."
)


def mask_shape(obj: object, depth: int = 0) -> object:
    """JSON structure with every scalar value masked, so no token, id or personal data is ever sent."""
    if depth > 5:
        return "<deep>"
    if isinstance(obj, dict):
        return {str(k)[:40]: mask_shape(v, depth + 1) for k, v in list(obj.items())[:25]}
    if isinstance(obj, list):
        return [mask_shape(obj[0], depth + 1)] if obj else []
    if isinstance(obj, str):
        return f"<str:{len(obj)}>"
    if isinstance(obj, bool):
        return "<bool>"
    if isinstance(obj, (int, float)):
        return "<num>"
    return None


def suggest_token_path(body: object) -> tuple[str | None, str]:
    """Ask which key of the login response holds the token. Only the masked shape is sent. Verified by the caller."""
    text, note = _complete(TOKEN_PROMPT, json.dumps(mask_shape(body), separators=(",", ":")), 100)
    if text is None:
        return None, note
    obj = parse_reply(text)
    path = obj.get("token_path") if isinstance(obj, dict) else None
    return (path if isinstance(path, str) and _FIELD_OK.match(path) else None), note


BODY_PROMPT = (
    "You help an API test tool build valid requests. For each endpoint below you get the backend handler source. "
    "Reply with ONLY a JSON object {\"bodies\": {\"METHOD /route\": {...}}} holding one example JSON request body per endpoint that "
    "satisfies the handler's validation (required fields, types, formats, non-empty arrays). Use realistic values. When a field "
    "refers to another existing record, use the id 1. Never include real credentials: use the placeholder Passw0rd! for passwords. "
    "Omit an endpoint when it takes no JSON body or you cannot tell. Use EXACTLY the key from each '###' heading as the JSON key, "
    "even if comments in the source mention a different route."
)
MAX_BODY_ENDPOINTS = 12
MAX_BODY_CHARS = 2000


def _body_ok(obj: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if isinstance(obj, dict):
        return len(obj) <= 30 and all(isinstance(k, str) and len(k) <= 60 and _body_ok(v, depth + 1) for k, v in obj.items())
    if isinstance(obj, list):
        return len(obj) <= 10 and all(_body_ok(v, depth + 1) for v in obj)
    if isinstance(obj, str):
        return len(obj) <= 200 and "{{" not in obj  # never let a suggestion smuggle in template variables
    return obj is None or isinstance(obj, (bool, int, float))


def _ask_bodies(parts: dict[str, str]) -> tuple[dict[str, object], str | None, str]:
    text, note = _complete(BODY_PROMPT, "\n\n".join(parts.values()), 1200, timeout_s=60.0)
    if text is None:
        return {}, None, note
    obj = parse_reply(text)
    bodies = obj.get("bodies") if isinstance(obj, dict) else None
    good = {k: v for k, v in bodies.items() if isinstance(v, dict) and v and _body_ok(v) and len(json.dumps(v)) <= MAX_BODY_CHARS} if isinstance(bodies, dict) else {}
    ok = {k: v for k, v in good.items() if k in parts}
    if not ok and len(parts) == 1 and len(good) == 1:  # one endpoint asked, one body given under a key copied from a source comment
        ok = {next(iter(parts)): next(iter(good.values()))}
    return ok, text, note


def suggest_bodies(inv: EndpointInventory, endpoints: list[Endpoint]) -> tuple[dict[str, object], str]:
    """Example request bodies for endpoints whose body could only be inferred from field names. Redacted handler snippets are sent."""
    parts: dict[str, str] = {}
    for ep in endpoints[:MAX_BODY_ENDPOINTS]:
        snip = _snippet(ep, inv)
        if snip:
            parts[f"{ep.method} {ep.route}"] = f"### {ep.method} {ep.route}\n{snip}"
    if not parts:
        return {}, "LLM body assist skipped: no handler source available"
    out, _text, note = _ask_bodies(parts)
    missing = {k: v for k, v in parts.items() if k not in out}
    if missing and _text is not None:  # models sometimes skip look-alike handlers: ask once more for just those
        more, _t, _n = _ask_bodies(missing)
        out.update(more)
    return out, note
