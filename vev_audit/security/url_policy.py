"""URL and network-destination validation (SSRF protection).

Two layers use this module:

* :func:`UrlPolicy.validate_url` checks user-submitted URLs before a scan is queued.
* :class:`~vev_audit.security.egress_proxy.EgressProxy` calls
  :meth:`UrlPolicy.resolve_allowed` for *every* connection the headless browser
  makes (redirects, sub-resources, iframes, WebSockets), so a public page cannot
  pivot the scanner into a private network.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

MAX_URL_LENGTH = 2048
# "javascript:alert(1)", "mailto:x" — a scheme without "//". "example.com:8080" (digits after ':') is a host:port.
_BARE_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+-]*:(?!\d)")

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    ".home.arpa",
    ".svc",
    ".cluster.local",
)

# Ranges that ``ipaddress.is_global`` does not reject on every Python version.
_EXTRA_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "192.0.0.0/24",
        "198.18.0.0/15",  # benchmarking
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved
        "255.255.255.255/32",
        "64:ff9b:1::/48",
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class UrlValidationError(ValueError):
    """Raised when a URL or destination is not allowed."""


async def default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_ip(ip: IPAddress) -> bool:
    """Return True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not is_public_ip(embedded):
            return False
        if ip.scope_id:
            return False
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED_NETWORKS if net.version == ip.version)


def normalize_hostname(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise UrlValidationError("URL must include a hostname.")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlValidationError("Hostname is not a valid internationalised domain name.") from exc


@dataclass
class UrlPolicy:
    allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443})
    allow_private_networks: bool = False
    resolver: Resolver = default_resolver
    extra_blocked_hosts: frozenset[str] = field(default_factory=frozenset)

    # -- hostname / IP rules -------------------------------------------------
    def check_hostname(self, host: str) -> None:
        if self.allow_private_networks:
            return
        if host in BLOCKED_HOSTNAMES or host in self.extra_blocked_hosts or host.endswith(BLOCKED_SUFFIXES):
            raise UrlValidationError(f"Host '{host}' refers to a local or internal network.")
        if "." not in host and ":" not in host:
            raise UrlValidationError(f"Host '{host}' is not a fully-qualified public domain.")

    def check_ip(self, ip: IPAddress) -> None:
        if self.allow_private_networks:
            return
        if not is_public_ip(ip):
            raise UrlValidationError(f"Address {ip} is private, loopback, link-local or reserved.")

    def check_port(self, port: int) -> None:
        if port not in self.allowed_ports:
            allowed = ", ".join(str(p) for p in sorted(self.allowed_ports))
            raise UrlValidationError(f"Port {port} is not allowed (allowed: {allowed}).")

    async def resolve_allowed(self, host: str, port: int) -> list[str]:
        """Validate a destination and return the vetted IP addresses to connect to.

        Every resolved address must be public; a hostname that resolves to a mix of
        public and private addresses is rejected (a common DNS-rebinding trick).
        """
        host = normalize_hostname(host.strip("[]"))
        self.check_port(port)
        literal = _parse_ip(host)
        if literal is not None:
            self.check_ip(literal)
            return [str(literal)]
        self.check_hostname(host)
        try:
            addresses = await self.resolver(host, port)
        except (socket.gaierror, OSError) as exc:
            raise UrlValidationError(f"Could not resolve host '{host}'.") from exc
        if not addresses:
            raise UrlValidationError(f"Could not resolve host '{host}'.")
        for addr in addresses:
            if "%" in addr:  # zone-scoped IPv6 (fe80::1%eth0) is always link-local
                if not self.allow_private_networks:
                    raise UrlValidationError(f"Address {addr} is a scoped link-local address.")
                continue
            self.check_ip(ipaddress.ip_address(addr))
        return addresses

    # -- full URL validation -------------------------------------------------
    def parse_url(self, raw: str) -> tuple[str, str, int]:
        """Syntactic validation. Returns ``(normalized_url, host, port)``."""
        if not isinstance(raw, str):
            raise UrlValidationError("URL must be a string.")
        candidate = raw.strip()
        if not candidate:
            raise UrlValidationError("Please enter a URL.")
        if len(candidate) > MAX_URL_LENGTH:
            raise UrlValidationError("URL is too long.")
        if any(ch in candidate for ch in "\x00\r\n\t "):
            raise UrlValidationError("URL contains invalid whitespace or control characters.")
        if "://" not in candidate:
            if _BARE_SCHEME.match(candidate):
                raise UrlValidationError("Only http:// and https:// URLs can be scanned.")
            candidate = "https://" + candidate
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise UrlValidationError("Only http:// and https:// URLs can be scanned.")
        if parts.username or parts.password or "@" in parts.netloc:
            raise UrlValidationError("URLs with embedded credentials are not allowed.")
        if not parts.hostname:
            raise UrlValidationError("URL must include a hostname.")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise UrlValidationError("URL has an invalid port.") from exc
        host = normalize_hostname(parts.hostname)
        literal = _parse_ip(host)
        if literal is not None:
            self.check_ip(literal)
        else:
            self.check_hostname(host)
        self.check_port(port)
        default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        display_host = f"[{host}]" if isinstance(literal, ipaddress.IPv6Address) else host
        netloc = display_host if default_port else f"{display_host}:{port}"
        normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
        return normalized, host, port

    async def validate_url(self, raw: str) -> str:
        """Full validation including DNS resolution. Returns the normalised URL."""
        normalized, host, port = self.parse_url(raw)
        await self.resolve_allowed(host, port)
        return normalized


def _parse_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Legacy IPv4 forms browsers still accept: 2130706433, 0x7f.1, 017700000001 ...
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    if all(ch in "0123456789abcdefx." for ch in host):
        return ipaddress.IPv4Address(packed)
    return None
