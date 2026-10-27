"""Pluggable authentication providers.

Secrets are read from environment variables (or an interactive prompt by the CLI) and live only in memory.
They are handed to Newman through a short-lived private environment file that is always removed, and they
are registered with the redaction layer so they can never appear in logs, exceptions or reports.

``login`` / ``session`` can work out the login endpoint themselves (heuristics over the endpoint inventory, then an
optional LLM pass in ``auth/llm.py`` that never sees credentials). Explicit CLI flags always win.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import httpx
from pydantic import BaseModel

from ..errors import AuthenticationError
from ..security.redaction import redact_text
from .headers import ENV_PREFIX

if TYPE_CHECKING:  # pragma: no cover
    from .headers import HeaderPlan
    from ..models.endpoint import EndpointInventory

AuthMethod = Literal["none", "bearer", "login", "api-key", "basic", "session"]

# Token locations tried (in order) when the login response format was not specified or documented.
TOKEN_PATHS = (
    "access_token", "accessToken", "token", "id_token", "jwt", "auth_token", "authToken",
    "data.access_token", "data.accessToken", "data.token", "result.access_token", "result.token",
    "header:Authorization", "header:X-Auth-Token", "header:X-Access-Token",
)
MAX_LOGIN_CANDIDATES = 4


class AuthConfig(BaseModel):
    """Non-secret authentication settings (safe to persist). Secrets are named by env var, never stored."""

    method: AuthMethod = "none"
    token_env: str = "API_AGENT_TOKEN"
    username_env: str = "API_AGENT_USERNAME"
    password_env: str = "API_AGENT_PASSWORD"
    api_key_env: str = "API_AGENT_API_KEY"
    login_path: str | None = None  # path relative to base URL, or a full http(s) URL; None = auto-detect
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_token_path: str | None = None  # dotted path into the JSON response, or "header:Name"; None = auto-detect
    login_content_type: Literal["json", "form"] | None = None  # None = taken from the detected endpoint (default json)
    use_llm: bool = True  # allow the OpenRouter assist when heuristics cannot find the login endpoint
    api_key_header: str = "X-API-Key"
    api_key_in: Literal["header", "query"] = "header"
    header_scheme: str = "Bearer"


@dataclass
class LoginSpec:
    """How to log in: which endpoint, what body, where the credential comes back."""

    path: str
    content_type: str = "json"  # json | form
    username_field: str = "username"
    password_field: str = "password"
    token_path: str | None = None
    source: str = "flag"  # flag | heuristic | llm
    endpoint_id: str | None = None  # inventory endpoint this corresponds to (None if not in the inventory)
    score: int = 0


@dataclass
class AuthResolution:
    """Outcome of resolving credentials: either usable values or a reason they are unavailable."""

    method: str
    available: bool
    reason: str | None = None  # why unavailable (for BLOCKED reporting) – never contains secrets
    env_vars: dict[str, str] = field(default_factory=dict)  # runtime variables for Newman (contain secrets)
    secrets: list[str] = field(default_factory=list)  # values to redact everywhere
    header_name: str | None = None
    header_value_template: str | None = None  # e.g. "Bearer {{auth_token}}"
    query_name: str | None = None
    query_value_template: str | None = None
    notes: list[str] = field(default_factory=list)
    login: LoginSpec | None = None  # the login that worked (login/session only)
    relogin_supported: bool = False  # a fresh credential can be obtained by calling the provider again
    llm_used: bool = False
    login_requests: int = 0  # login POSTs sent so far (they count against the request budget)
    refresh_available: bool = False  # the login response also returned a refresh token (kept in env var auth_refresh_token)


class AuthProvider(ABC):
    name = ""

    header_plan: "HeaderPlan | None" = None  # headers every request needs (API key, client version ...), set by the pipeline

    def __init__(self, config: AuthConfig):
        self.config = config

    @abstractmethod
    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        """Obtain usable credentials or explain why they are unavailable."""


def _dig(data: Any, dotted: str) -> Any:
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _jwt_exp(token: str) -> float | None:
    """Expiry (epoch seconds) from an unverified JWT payload, if the token is one."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return float(exp) if isinstance(exp, (int, float)) else None


def _clean_token(value: str) -> str:
    v = value.strip()
    return v.split(None, 1)[1] if v.lower().startswith("bearer ") and len(v.split(None, 1)) == 2 else v


def _find_token(resp: httpx.Response, body: Any, token_path: str | None) -> tuple[str, str] | None:
    """Locate the credential in a login response -> (token, where). A configured path is tried first, but it is only a
    preference: servers name and nest tokens differently (and a saved path can go stale), so the response is scanned if it misses."""
    for p in ((token_path,) if token_path else ()) + TOKEN_PATHS:
        value = resp.headers.get(p[7:]) if p.lower().startswith("header:") else _dig(body, p)
        if isinstance(value, str) and len(_clean_token(value)) >= 8:
            return _clean_token(value), p
    if isinstance(body, (dict, list)):  # last resort: scan the whole response for something token-shaped
        return _scan_for_token(body)
    return None


def _extract_token(resp: httpx.Response, body: Any, token_path: str | None) -> str | None:
    found = _find_token(resp, body, token_path)
    return found[0] if found else None


_JWT_SHAPE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_HEADER_PROBLEM = re.compile(r"api[\s_-]?key|header|client[\s_-]?version|tenant|x-[a-z]", re.I)
MAX_SCAN_DEPTH = 4


def _scan_for_token(body: Any) -> tuple[str, str] | None:
    """The most token-looking string in the response that is not a refresh token -> (token, dotted path)."""
    jwt_like: list[tuple[str, str]] = []
    named: list[tuple[str, str]] = []

    def walk(node: Any, key: str, path: str, depth: int) -> None:
        if depth > MAX_SCAN_DEPTH:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k), f"{path}.{k}" if path else str(k), depth + 1)
        elif isinstance(node, list):
            for v in node[:5]:
                walk(v, key, path, depth + 1)
        elif isinstance(node, str) and "refresh" not in key.lower():
            if _JWT_SHAPE.match(node):
                jwt_like.append((node, path))
            elif len(node) >= 8 and re.search(r"token|jwt|bearer", key, re.I) and not re.search(r"type|expires", key, re.I):
                named.append((node, path))

    walk(body, "", "", 0)
    return (jwt_like or named or [None])[0]


def _find_refresh_token(body: Any) -> str | None:
    """A refresh token returned next to the access token, so `POST /auth/refresh`-style endpoints can be tested with a real one."""
    def walk(node: Any, depth: int) -> str | None:
        if depth > MAX_SCAN_DEPTH or not isinstance(node, dict):
            return None
        for k, v in node.items():
            if isinstance(v, str) and len(v) >= 8 and re.fullmatch(r"(?i)refresh[-_]?token", str(k)):
                return v
        for v in node.values():
            found = walk(v, depth + 1)
            if found:
                return found
        return None

    return walk(body, 0)


def _scheme(body: Any, default: str) -> str:
    """Authorization scheme: what the server says (``tokenType`` / ``token_type``) else the configured default."""
    if isinstance(body, dict):
        for k in ("tokenType", "token_type"):
            v = body.get(k)
            if isinstance(v, str) and re.fullmatch(r"[A-Za-z]{3,20}", v):
                return v.capitalize() if v.lower() == "bearer" else v
    return default


def _error_detail(resp: httpx.Response, secrets: list[str]) -> str:
    """Short, redacted description of an error response ({"error": {"code": ..., "message": ...}} and common variants)."""
    try:
        body = resp.json()
    except ValueError:
        return ""
    err = body.get("error", body) if isinstance(body, dict) else None
    if isinstance(err, str):
        text = err
    elif isinstance(err, dict):
        text = " - ".join(str(err[k]) for k in ("code", "error", "message", "detail") if isinstance(err.get(k), (str, int)))
    else:
        text = ""
    return redact_text(text, secrets)[:160]


class NoAuthProvider(AuthProvider):
    name = "none"

    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        return AuthResolution(method="none", available=False, reason="no authentication configured (--auth none)")


class BearerProvider(AuthProvider):
    name = "bearer"

    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        token = os.environ.get(self.config.token_env, "").strip()
        if not token:
            return AuthResolution("bearer", False, f"environment variable {self.config.token_env} is not set")
        return AuthResolution(
            "bearer", True, env_vars={"auth_token": token}, secrets=[token],
            header_name="Authorization", header_value_template=f"{self.config.header_scheme} {{{{auth_token}}}}",
        )


class ApiKeyProvider(AuthProvider):
    name = "api-key"

    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        key = os.environ.get(self.config.api_key_env, "").strip()
        if not key:
            return AuthResolution("api-key", False, f"environment variable {self.config.api_key_env} is not set")
        res = AuthResolution("api-key", True, env_vars={"api_key": key}, secrets=[key])
        if self.config.api_key_in == "header":
            res.header_name, res.header_value_template = self.config.api_key_header, "{{api_key}}"
        else:
            res.query_name, res.query_value_template = self.config.api_key_header, "{{api_key}}"
        return res


class BasicProvider(AuthProvider):
    """HTTP Basic: the header is built here from the username/password env vars; no login call is made."""

    name = "basic"

    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        user = os.environ.get(self.config.username_env, "")
        pwd = os.environ.get(self.config.password_env, "")
        if not user or not pwd:
            return AuthResolution(
                "basic", False,
                f"environment variables {self.config.username_env} / {self.config.password_env} are not both set",
            )
        encoded = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        return AuthResolution(
            "basic", True, env_vars={"auth_basic": encoded}, secrets=[pwd, encoded],
            header_name="Authorization", header_value_template="Basic {{auth_basic}}",
        )


class LoginProvider(AuthProvider):
    """Log in with the username/password and use the returned bearer token on every request.

    The login endpoint comes from (1) ``--login-path``, else (2) heuristics over the endpoint inventory, else (3) an
    optional LLM suggestion. Calling ``resolve`` again re-uses the endpoint that worked, giving a fresh token.
    """

    name = "login"
    cookie_mode = False

    def __init__(self, config: AuthConfig, inventory: "EndpointInventory | None" = None, use_llm: bool | None = None,
                 delay_ms: int = 0):
        super().__init__(config)
        self.inventory = inventory
        self.use_llm = config.use_llm if use_llm is None else use_llm
        self.delay_s = max(delay_ms, 0) / 1000  # same pacing as test traffic (--delay-ms)
        self.login_requests = 0  # every login POST this provider sent, across resolve() calls
        self.spec: LoginSpec | None = None  # the spec that worked
        self.llm_used = False
        self._cookie_fallback: tuple[LoginSpec, str, list[str]] | None = None  # (spec, Cookie header, secrets)
        self._token_llm_tried = False

    # ------------------------------------------------------------------ candidates
    @staticmethod
    def _login_url(base_url: str, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    def _explicit_spec(self) -> LoginSpec | None:
        c = self.config
        if not c.login_path:
            return None
        from .detector import match_endpoint

        ep = match_endpoint(self.inventory, c.login_path) if self.inventory else None
        return LoginSpec(
            path=c.login_path, content_type=c.login_content_type or "json", username_field=c.login_username_field,
            password_field=c.login_password_field, token_path=c.login_token_path, source="flag",
            endpoint_id=ep.id if ep else None,
        )

    def _heuristic_specs(self) -> list[LoginSpec]:
        if self.inventory is None:
            return []
        from .detector import rank_login_candidates

        return rank_login_candidates(self.inventory, self.config)[:MAX_LOGIN_CANDIDATES]

    # ------------------------------------------------------------------ one attempt
    def _attempt(self, spec: LoginSpec, base_url: str, user: str, pwd: str, timeout_s: float, secrets: list[str]) -> AuthResolution:
        url = self._login_url(base_url, spec.path)
        payload = {spec.username_field: user, spec.password_field: pwd}
        headers = self.header_plan.probe_headers() if self.header_plan else {}
        if self.login_requests and self.delay_s:
            time.sleep(self.delay_s)
        self.login_requests += 1
        try:
            with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
                resp = client.post(url, headers=headers, **({"data": payload} if spec.content_type == "form" else {"json": payload}))
                cookies = [(c.name, c.value) for c in client.cookies.jar]
        except httpx.HTTPError as exc:
            raise AuthenticationError(f"login request failed: {redact_text(type(exc).__name__ + ': ' + str(exc), secrets)}") from exc
        if resp.is_redirect:
            raise AuthenticationError("login endpoint redirected; redirects are not followed for safety")
        if resp.status_code >= 400:
            detail = _error_detail(resp, [*secrets, *headers.values()])
            header_problem = bool(_HEADER_PROBLEM.search(detail))
            if resp.status_code in (401, 403) and not header_problem:
                err = AuthenticationError(f"login endpoint {spec.path} rejected the credentials (HTTP {resp.status_code}{detail and ': ' + detail})")
                err.credentials_rejected = True  # type: ignore[attr-defined]
                raise err
            hint = ("; a required request header is probably missing or wrong -- supply it with --header NAME=VALUE or "
                    f"{ENV_PREFIX}<NAME> in .env" if header_problem else "")
            raise AuthenticationError(f"login endpoint {spec.path} returned HTTP {resp.status_code}{detail and ': ' + detail}{hint}")
        try:
            body: Any = resp.json()
        except ValueError:
            body = None
        cookie_header = "; ".join(f"{n}={v}" for n, v in cookies)
        cookie_secrets = [cookie_header, *[v for _, v in cookies if len(v) >= 4]] if cookie_header else []

        if self.cookie_mode:
            if not cookie_header:
                raise AuthenticationError(f"login at {spec.path} set no session cookie")
            return self._cookie_resolution(spec, user, pwd, secrets, cookie_header, cookie_secrets)

        found = _find_token(resp, body, spec.token_path)
        token = found[0] if found else None
        if found:
            spec.token_path = found[1]
        if not token and body is not None and not self.cookie_mode and self.use_llm and not spec.token_path and not self._token_llm_tried:
            self._token_llm_tried = True
            from .llm import suggest_token_path

            path, _note = suggest_token_path(body)  # only the masked shape of the response is sent
            token = _extract_token(resp, body, path) if path else None
            if token:
                spec.token_path, self.llm_used = path, True
        if token:
            return self._token_resolution(spec, user, pwd, secrets, token, body)
        if cookie_header:  # token-less login that set a session: usable only if no candidate yields a token
            self._cookie_fallback = (spec, cookie_header, cookie_secrets)
        if body is None and not cookie_header:
            raise AuthenticationError("login response is not valid JSON")
        keys = ", ".join(sorted(body)[:12]) if isinstance(body, dict) else type(body).__name__
        raise AuthenticationError(f"login response has no usable token (response keys: {keys}); pass --login-token-path if it is unusual")

    def _token_resolution(self, spec: LoginSpec, user: str, pwd: str, secrets: list[str], token: str, body: Any) -> AuthResolution:
        secrets = [*secrets, token]
        res = AuthResolution(
            self.name, True, env_vars={"auth_token": token, "auth_username": user, "auth_password": pwd}, secrets=secrets,
            header_name="Authorization", header_value_template=f"{_scheme(body, self.config.header_scheme)} {{{{auth_token}}}}",
            login=spec, relogin_supported=True, llm_used=self.llm_used,
        )
        refresh = _find_refresh_token(body)
        if refresh:
            res.env_vars["auth_refresh_token"] = refresh
            res.secrets.append(refresh)
            res.refresh_available = True
        expires = next((body[k] for k in ("expires_in", "expiresIn") if isinstance(body, dict) and isinstance(body.get(k), (int, float))), None)
        if not isinstance(expires, (int, float)):
            exp = _jwt_exp(token)
            expires = exp - time.time() if exp else None
        if isinstance(expires, (int, float)):
            res.notes.append(f"token expires in about {int(expires)}s; if requests are rejected with 401 the agent logs in again once and retries them")
        return res

    def _cookie_resolution(self, spec: LoginSpec, user: str, pwd: str, secrets: list[str], cookie_header: str, cookie_secrets: list[str]) -> AuthResolution:
        res = AuthResolution(
            self.name if self.cookie_mode else "login", True,
            env_vars={"auth_cookie": cookie_header, "auth_username": user, "auth_password": pwd}, secrets=[*secrets, *cookie_secrets],
            header_name="Cookie", header_value_template="{{auth_cookie}}", login=spec, relogin_supported=True, llm_used=self.llm_used,
        )
        if not self.cookie_mode:
            res.notes.append("login returned no token; using the session cookie it set")
        return res

    # ------------------------------------------------------------------ resolve
    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        res = self._resolve(base_url, timeout_s)
        res.login_requests = self.login_requests
        return res

    def _resolve(self, base_url: str, timeout_s: float) -> AuthResolution:
        user = os.environ.get(self.config.username_env, "")
        pwd = os.environ.get(self.config.password_env, "")
        if not user or not pwd:
            return AuthResolution(
                self.name, False,
                f"environment variables {self.config.username_env} / {self.config.password_env} are not both set",
            )
        secrets = [pwd]
        explicit = self._explicit_spec()
        specs = [self.spec] if self.spec else ([explicit] if explicit else self._heuristic_specs())
        failures: list[str] = []
        last: AuthenticationError | None = None
        tried_llm = bool(self.spec) or explicit is not None or not self.use_llm
        while True:
            for spec in specs:
                try:
                    res = self._attempt(spec, base_url, user, pwd, timeout_s, secrets)
                    self.spec = spec
                    return res
                except AuthenticationError as exc:
                    last = exc
                    failures.append(redact_text(str(exc), secrets))
                    if getattr(exc, "credentials_rejected", False):
                        raise  # wrong credentials: stop immediately rather than risk locking the account on other endpoints
            if tried_llm:
                break
            tried_llm = True
            from .llm import suggest_login

            known = {s.path for s in specs}
            suggested = [s for s in suggest_login(self.inventory, self.config).specs if s.path not in known]
            if not suggested:
                break
            self.llm_used, specs = True, suggested[:2]
        if self._cookie_fallback:
            spec, cookie_header, cookie_secrets = self._cookie_fallback
            self.spec = spec
            return self._cookie_resolution(spec, user, pwd, secrets, cookie_header, cookie_secrets)
        if explicit is not None and last is not None:
            raise last
        if not failures:
            raise AuthenticationError(
                "no login endpoint could be detected from the discovered endpoints; pass --login-path "
                "(and --login-token-path / --login-content-type if needed)"
            )
        raise AuthenticationError(f"login failed on {len(failures)} candidate endpoint(s): " + "; ".join(failures[:3]))


class SessionProvider(LoginProvider):
    """Cookie/session login: log in, capture Set-Cookie, send it as a Cookie header on every request."""

    name = "session"
    cookie_mode = True


def assumed_resolution(config: AuthConfig) -> AuthResolution:
    """Placeholder used by `generate` (no network): assume credentials will exist at test time."""
    m = config.method
    if m == "none":
        return AuthResolution("none", False, "no auth configured")
    res = AuthResolution(m, True, refresh_available=m in ("login", "session"))
    if m in ("bearer", "login"):
        res.header_name, res.header_value_template = "Authorization", f"{config.header_scheme} {{{{auth_token}}}}"
    elif m == "basic":
        res.header_name, res.header_value_template = "Authorization", "Basic {{auth_basic}}"
    elif m == "session":
        res.header_name, res.header_value_template = "Cookie", "{{auth_cookie}}"
    elif m == "api-key":
        res.header_name, res.header_value_template = config.api_key_header, "{{api_key}}"
    return res


def build_provider(config: AuthConfig, inventory: "EndpointInventory | None" = None, use_llm: bool | None = None,
                   delay_ms: int = 0) -> AuthProvider:
    if config.method == "login":
        return LoginProvider(config, inventory, use_llm, delay_ms)
    if config.method == "session":
        return SessionProvider(config, inventory, use_llm, delay_ms)
    providers: dict[str, type[AuthProvider]] = {
        "none": NoAuthProvider, "bearer": BearerProvider, "api-key": ApiKeyProvider, "basic": BasicProvider,
    }
    return providers[config.method](config)
