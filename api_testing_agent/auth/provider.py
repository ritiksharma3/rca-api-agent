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

if TYPE_CHECKING:  # pragma: no cover
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


class AuthProvider(ABC):
    name = ""

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


def _extract_token(resp: httpx.Response, body: Any, token_path: str | None) -> str | None:
    """Pull the credential out of a login response. An explicit path is strict; otherwise common locations are scanned."""
    paths = (token_path,) if token_path else TOKEN_PATHS
    for p in paths:
        value = resp.headers.get(p[7:]) if p.lower().startswith("header:") else _dig(body, p)
        if isinstance(value, str) and len(_clean_token(value)) >= 8:
            return _clean_token(value)
    if token_path is None and isinstance(body, dict):  # last resort: any top-level / data.* key that looks like a token
        for scope in (body, body.get("data") if isinstance(body.get("data"), dict) else {}):
            for k, v in scope.items():
                if "token" in k.lower() and "refresh" not in k.lower() and isinstance(v, str) and len(v) >= 8:
                    return v
    return None


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

    def __init__(self, config: AuthConfig, inventory: "EndpointInventory | None" = None, use_llm: bool | None = None):
        super().__init__(config)
        self.inventory = inventory
        self.use_llm = config.use_llm if use_llm is None else use_llm
        self.spec: LoginSpec | None = None  # the spec that worked
        self.llm_used = False
        self._cookie_fallback: tuple[LoginSpec, str, list[str]] | None = None  # (spec, Cookie header, secrets)

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
        try:
            with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
                resp = client.post(url, **({"data": payload} if spec.content_type == "form" else {"json": payload}))
                cookies = [(c.name, c.value) for c in client.cookies.jar]
        except httpx.HTTPError as exc:
            raise AuthenticationError(f"login request failed: {redact_text(type(exc).__name__ + ': ' + str(exc), secrets)}") from exc
        if resp.is_redirect:
            raise AuthenticationError("login endpoint redirected; redirects are not followed for safety")
        if resp.status_code in (401, 403):
            err = AuthenticationError(f"login endpoint {spec.path} rejected the credentials (HTTP {resp.status_code})")
            err.credentials_rejected = True  # type: ignore[attr-defined]
            raise err
        if resp.status_code >= 400:
            raise AuthenticationError(f"login endpoint {spec.path} returned HTTP {resp.status_code}")
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

        token = _extract_token(resp, body, spec.token_path)
        if token:
            return self._token_resolution(spec, user, pwd, secrets, token, body)
        if cookie_header:  # token-less login that set a session: usable only if no candidate yields a token
            self._cookie_fallback = (spec, cookie_header, cookie_secrets)
        if body is None and not cookie_header:
            raise AuthenticationError("login response is not valid JSON")
        where = f"'{spec.token_path}'" if spec.token_path else "any common location"
        raise AuthenticationError(f"login response has no usable string token at {where} (check --login-token-path)")

    def _token_resolution(self, spec: LoginSpec, user: str, pwd: str, secrets: list[str], token: str, body: Any) -> AuthResolution:
        secrets = [*secrets, token]
        res = AuthResolution(
            self.name, True, env_vars={"auth_token": token, "auth_username": user, "auth_password": pwd}, secrets=secrets,
            header_name="Authorization", header_value_template=f"{self.config.header_scheme} {{{{auth_token}}}}",
            login=spec, relogin_supported=True, llm_used=self.llm_used,
        )
        expires = body.get("expires_in") if isinstance(body, dict) else None
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
    res = AuthResolution(m, True)
    if m in ("bearer", "login"):
        res.header_name, res.header_value_template = "Authorization", f"{config.header_scheme} {{{{auth_token}}}}"
    elif m == "basic":
        res.header_name, res.header_value_template = "Authorization", "Basic {{auth_basic}}"
    elif m == "session":
        res.header_name, res.header_value_template = "Cookie", "{{auth_cookie}}"
    elif m == "api-key":
        res.header_name, res.header_value_template = config.api_key_header, "{{api_key}}"
    return res


def build_provider(config: AuthConfig, inventory: "EndpointInventory | None" = None, use_llm: bool | None = None) -> AuthProvider:
    if config.method == "login":
        return LoginProvider(config, inventory, use_llm)
    if config.method == "session":
        return SessionProvider(config, inventory, use_llm)
    providers: dict[str, type[AuthProvider]] = {
        "none": NoAuthProvider, "bearer": BearerProvider, "api-key": ApiKeyProvider, "basic": BasicProvider,
    }
    return providers[config.method](config)
