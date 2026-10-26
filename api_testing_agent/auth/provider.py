"""Pluggable authentication providers.

Secrets are read from environment variables (or an interactive prompt by the CLI) and live only in memory.
They are handed to Newman through a short-lived private environment file that is always removed, and they
are registered with the redaction layer so they can never appear in logs, exceptions or reports.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from pydantic import BaseModel

from ..errors import AuthenticationError, InvalidInputError
from ..security.redaction import redact_text

AuthMethod = Literal["none", "bearer", "login", "api-key"]


class AuthConfig(BaseModel):
    """Non-secret authentication settings (safe to persist). Secrets are named by env var, never stored."""

    method: AuthMethod = "none"
    token_env: str = "API_AGENT_TOKEN"
    username_env: str = "API_AGENT_USERNAME"
    password_env: str = "API_AGENT_PASSWORD"
    api_key_env: str = "API_AGENT_API_KEY"
    login_path: str | None = None  # path relative to base URL, or a full http(s) URL
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_token_path: str = "access_token"  # dotted path into the JSON login response
    api_key_header: str = "X-API-Key"
    api_key_in: Literal["header", "query"] = "header"
    header_scheme: str = "Bearer"


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


class LoginProvider(AuthProvider):
    """POST credentials to a configured login endpoint and extract a bearer token from the response."""

    name = "login"

    def _login_url(self, base_url: str) -> str:
        lp = self.config.login_path or ""
        if lp.startswith(("http://", "https://")):
            return lp
        return base_url.rstrip("/") + "/" + lp.lstrip("/")

    def resolve(self, base_url: str, timeout_s: float = 10.0) -> AuthResolution:
        if not self.config.login_path:
            raise InvalidInputError("--auth login requires --login-path")
        user = os.environ.get(self.config.username_env, "")
        pwd = os.environ.get(self.config.password_env, "")
        if not user or not pwd:
            return AuthResolution(
                "login", False,
                f"environment variables {self.config.username_env} / {self.config.password_env} are not both set",
            )
        secrets = [pwd]
        url = self._login_url(base_url)
        try:
            with httpx.Client(timeout=timeout_s, follow_redirects=False, verify=True) as client:
                resp = client.post(url, json={self.config.login_username_field: user, self.config.login_password_field: pwd})
        except httpx.HTTPError as exc:
            raise AuthenticationError(f"login request failed: {redact_text(type(exc).__name__ + ': ' + str(exc), secrets)}") from exc
        if resp.is_redirect:
            raise AuthenticationError("login endpoint redirected; redirects are not followed for safety")
        if resp.status_code >= 400:
            raise AuthenticationError(f"login endpoint returned HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise AuthenticationError("login response is not valid JSON") from exc
        token = _dig(body, self.config.login_token_path)
        if not isinstance(token, str) or len(token) < 8:
            raise AuthenticationError(
                f"login response has no usable string token at '{self.config.login_token_path}' "
                "(check --login-token-path)"
            )
        secrets.append(token)
        res = AuthResolution(
            "login", True, env_vars={"auth_token": token}, secrets=secrets,
            header_name="Authorization", header_value_template=f"{self.config.header_scheme} {{{{auth_token}}}}",
        )
        expires = body.get("expires_in") if isinstance(body, dict) else None
        if isinstance(expires, (int, float)):
            res.notes.append(f"token reports expires_in={int(expires)}s; no automatic refresh is performed in V1")
        return res


def build_provider(config: AuthConfig) -> AuthProvider:
    providers: dict[str, type[AuthProvider]] = {
        "none": NoAuthProvider, "bearer": BearerProvider, "login": LoginProvider, "api-key": ApiKeyProvider,
    }
    return providers[config.method](config)
