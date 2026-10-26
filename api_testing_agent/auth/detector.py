"""Heuristic login-endpoint detection over the endpoint inventory (no network, no LLM)."""

from __future__ import annotations

import re
from typing import Any

from ..models.endpoint import Endpoint, EndpointInventory
from .provider import AuthConfig, LoginSpec

_STRONG_ROUTE = re.compile(r"log[-_]?in|sign[-_]?in|authenticate", re.I)
_WEAK_ROUTE = re.compile(r"/token\b|/session|/auth\b|/auth/|/oauth", re.I)
_NOT_LOGIN = re.compile(r"log[-_]?out|sign[-_]?out|refresh|regist|sign[-_]?up|reset|forgot|verify|confirm|revoke|change", re.I)
_USER_FIELDS = {"username", "email", "login", "userid", "user", "identifier", "emailaddress", "loginid", "userlogin", "usernameoremail"}
_PASS_FIELDS = {"password", "passwd", "pass", "pwd", "userpassword"}
_TOKEN_KEYS = ("access_token", "accesstoken", "token", "id_token", "jwt", "auth_token", "authtoken")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _body_fields(ep: Endpoint) -> list[str]:
    schema = ep.request_body.schema_def if ep.request_body else {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return list(props) if isinstance(props, dict) else []


def _response_token_path(ep: Endpoint) -> str | None:
    """Token location from a documented 2xx JSON response schema, if one is declared."""
    for r in ep.responses:
        if not (r.status.startswith("2") and isinstance(r.schema_def, dict)):
            continue
        props = r.schema_def.get("properties")
        if not isinstance(props, dict):
            continue
        for k in props:
            if k.lower() in _TOKEN_KEYS:
                return k
        data = props.get("data")
        if isinstance(data, dict) and isinstance(data.get("properties"), dict):
            for k in data["properties"]:
                if k.lower() in _TOKEN_KEYS:
                    return f"data.{k}"
    return None


def score_endpoint(ep: Endpoint) -> int:
    """How likely this endpoint is a username/password login. 0 means not a candidate."""
    if ep.method != "POST" or _NOT_LOGIN.search(ep.route):
        return 0
    fields = {_norm(f) for f in _body_fields(ep)}
    has_pass, has_user = bool(fields & _PASS_FIELDS), bool(fields & _USER_FIELDS)
    route = 0
    if _STRONG_ROUTE.search(ep.route):
        route = 3
    elif _WEAK_ROUTE.search(ep.route):
        route = 2
    if not route:  # a credential-shaped body alone is not enough (e.g. POST /users may be registration)
        return 0
    score = route + (4 if has_pass else 0) + (2 if has_user else 0) + (1 if _response_token_path(ep) else 0)
    return score if score >= 3 else 0


def _pick(fields: list[str], wanted: set[str], default: str) -> str:
    return next((f for f in fields if _norm(f) in wanted), default)


def rank_login_candidates(inv: EndpointInventory, config: AuthConfig) -> list[LoginSpec]:
    """Login candidates best-first. CLI overrides in `config` (fields, content type, token path) take precedence."""
    out: list[LoginSpec] = []
    for ep in inv.endpoints:
        s = score_endpoint(ep)
        if not s:
            continue
        fields = _body_fields(ep)
        form = bool(ep.request_body and "x-www-form-urlencoded" in ep.request_body.content_type)
        out.append(LoginSpec(
            path=ep.route,
            content_type=config.login_content_type or ("form" if form else "json"),
            username_field=_pick(fields, _USER_FIELDS, config.login_username_field),
            password_field=_pick(fields, _PASS_FIELDS, config.login_password_field),
            token_path=config.login_token_path or _response_token_path(ep),
            source="heuristic", endpoint_id=ep.id, score=s,
        ))
    return sorted(out, key=lambda x: -x.score)


def match_endpoint(inv: EndpointInventory | None, path: str) -> Endpoint | None:
    """The POST inventory endpoint whose route equals `path` (ignoring a trailing slash), if any."""
    if inv is None or path.startswith(("http://", "https://")):
        return None
    want = "/" + path.strip("/")
    return next((e for e in inv.endpoints if e.method == "POST" and "/" + e.route.strip("/") == want), None)


def login_like(route: str) -> bool:
    """Loose route test used to sanity-check LLM suggestions that are not in the inventory."""
    return bool((_STRONG_ROUTE.search(route) or _WEAK_ROUTE.search(route)) and not _NOT_LOGIN.search(route))


def endpoint_summary(ep: Endpoint) -> dict[str, Any]:
    """Compact, credential-free description of an endpoint for an LLM prompt."""
    resp = next((r for r in ep.responses if r.status.startswith("2") and r.schema_def), None)
    return {
        "method": ep.method, "route": ep.route, "body_fields": _body_fields(ep),
        "body_content_type": ep.request_body.content_type if ep.request_body else None,
        "response_fields": list((resp.schema_def or {}).get("properties", {}))[:12] if resp else [],
        "requires_auth": ep.requires_auth,
    }
