"""Target validation and execution safety policy."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel

from ..errors import InvalidInputError, UnsafeTargetError
from ..models.endpoint import DESTRUCTIVE_METHODS, MUTATING_METHODS

METADATA_HOSTS = {"metadata.google.internal", "metadata.goog", "instance-data"}
METADATA_IPS = {
    ipaddress.ip_address(x)
    for x in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200", "169.254.170.2")
}


class TargetClass(str, Enum):
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link-local"
    PUBLIC = "public"
    METADATA = "metadata"


@dataclass
class Target:
    url: str
    scheme: str
    host: str
    port: int
    base_path: str
    ips: list[str] = field(default_factory=list)
    klass: TargetClass = TargetClass.PUBLIC

    @property
    def origin(self) -> str:
        default = (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if default else f":{self.port}")

    @property
    def base_url(self) -> str:
        return self.origin + self.base_path


def _classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> TargetClass:
    if ip in METADATA_IPS:
        return TargetClass.METADATA
    if ip.is_loopback:
        return TargetClass.LOOPBACK
    if ip.is_link_local:
        return TargetClass.LINK_LOCAL
    if ip.is_private:
        return TargetClass.PRIVATE
    return TargetClass.PUBLIC


# most restrictive first
_ORDER = [TargetClass.METADATA, TargetClass.LINK_LOCAL, TargetClass.PUBLIC, TargetClass.PRIVATE, TargetClass.LOOPBACK]


def parse_target(url: str, resolve: bool = True) -> Target:
    """Validate scheme / host / port / base path and classify the destination."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise InvalidInputError(f"Invalid base URL: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise InvalidInputError(f"Base URL scheme must be http or https, got '{parts.scheme or 'none'}'")
    if not parts.hostname:
        raise InvalidInputError("Base URL has no hostname")
    if parts.username or parts.password:
        raise InvalidInputError("Credentials must not be embedded in the base URL")
    if parts.query or parts.fragment:
        raise InvalidInputError("Base URL must not contain a query string or fragment")
    host = parts.hostname.lower()
    port = port or (443 if parts.scheme == "https" else 80)
    base_path = parts.path.rstrip("/")

    if host in METADATA_HOSTS:
        raise UnsafeTargetError(f"Refusing cloud metadata host '{host}'")
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        if host == "localhost":
            ips = [ipaddress.ip_address("127.0.0.1")]
        elif resolve:
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                raise InvalidInputError(f"Cannot resolve host '{host}': {exc}") from exc
            ips = sorted({ipaddress.ip_address(i[4][0]) for i in infos}, key=str)
    classes = [_classify_ip(i) for i in ips] or [TargetClass.PUBLIC]
    if TargetClass.METADATA in classes:
        raise UnsafeTargetError(f"Refusing '{host}': resolves to a cloud metadata address")
    klass = min(classes, key=_ORDER.index)
    return Target(url, parts.scheme, host, port, base_path, [str(i) for i in ips], klass)


class SafetyPolicy(BaseModel):
    approve_target: bool = False
    allow_private: bool = False
    allow_public: bool = False
    allow_mutating: bool = False  # POST / PUT / PATCH
    allow_destructive: bool = False  # DELETE
    allow_negative: bool = False
    max_requests: int = 200
    delay_ms: int = 0
    concurrency: int = 1
    request_timeout_ms: int = 10_000
    process_timeout_s: int = 300

    def check_target(self, target: Target) -> None:
        if not self.approve_target:
            raise UnsafeTargetError(
                f"Target {target.origin} is not approved. Re-run with --approve-target to confirm "
                "this environment may receive test traffic."
            )
        if target.klass in (TargetClass.PRIVATE, TargetClass.LINK_LOCAL) and not self.allow_private:
            raise UnsafeTargetError(
                f"{target.origin} is a {target.klass.value} address; pass --allow-private to opt in."
            )
        if target.klass == TargetClass.PUBLIC and not self.allow_public:
            raise UnsafeTargetError(
                f"{target.origin} looks like a public host; pass --allow-public to opt in "
                "(only for environments you are authorized to test)."
            )
        if self.allow_destructive and target.klass == TargetClass.PUBLIC:
            raise UnsafeTargetError(
                "Destructive tests are never run against public hosts (possible production)."
            )

    def method_decision(self, method: str) -> tuple[bool, str, str]:
        """(allowed, reason_code, reason) for a scenario that would send this method."""
        m = method.upper()
        if m in DESTRUCTIVE_METHODS and not self.allow_destructive:
            return False, "POLICY_NOT_AUTHORIZED", "DELETE is a destructive method; enable --allow-destructive"
        if m in MUTATING_METHODS and not self.allow_mutating:
            return False, "POLICY_NOT_AUTHORIZED", f"{m} is mutating; enable --allow-mutating"
        return True, "", ""
