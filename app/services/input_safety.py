"""Input safety: URL validation and SSRF destination controls (PRD FR-03, FR-04).

PHANTOM fetches one user-supplied URL. Everything in this module exists to make
that operation safe:

- Only http/https schemes are allowed; a bare domain defaults to HTTPS.
- Credentials (user:pass@host), non-default ports, and malformed or ambiguous
  hosts (percent-encoded, control characters, integer/hex IP shorthands) are
  rejected.
- Hostnames that look internal (localhost, *.local, *.internal, *.home.arpa)
  are rejected outright.
- Every IP address a hostname resolves to is checked against the IANA
  special-purpose ranges (loopback, private, link-local, CGNAT, multicast,
  documentation, ULA, ...) before a connection is made.
- Redirects are followed manually: each hop is re-validated the same way, and
  the chain is capped.

Residual risk: DNS answers are checked once per hop before connecting, not
re-checked inside the socket layer. A DNS rebinding attack that flips an
answer between check and connect is therefore theoretically possible; the
single-user, read-only, header-only nature of the check keeps that window
low-value. This is documented in the README limitations.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse

Resolver = Callable[[str], list[str]]

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_SCHEME = "https"
MAX_REDIRECTS = 5

# Hosts (or hostname suffixes) that are internal by naming convention.
BLOCKED_HOST_NAMES = {"localhost", "localhost.localdomain"}
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")

# IANA special-purpose and non-public ranges. Anything matching is refused.
BLOCKED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        # IPv4
        "0.0.0.0/8",  # this network
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local (incl. cloud metadata 169.254.169.254)
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # 6to4 relay anycast (deprecated)
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved (incl. broadcast)
        # IPv6
        "::/128",  # unspecified
        "::1/128",  # loopback
        "::ffff:0:0/96",  # IPv4-mapped (handled explicitly as well)
        "64:ff9b::/96",  # NAT64 well-known prefix
        "100::/64",  # discard-only
        "2001::/32",  # Teredo
        "2001:2::/48",  # benchmarking
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "fc00::/7",  # unique-local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
]

def default_resolver(host: str) -> list[str]:
    """System DNS resolution; failures become safe, user-facing errors."""
    try:
        return [
            info[4][0]
            for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ]
    except socket.gaierror as exc:
        raise SafeInputError("The website host could not be resolved.") from exc


DEFAULT_RESOLVER: Resolver = default_resolver


class SafeInputError(ValueError):
    """User input failed validation; safe to show the reason to the user."""


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 -> 127.0.0.1
    return any(addr in network for network in BLOCKED_NETWORKS)


def _normalize_host(host: str) -> str:
    """Lower-case, strip brackets from IPv6 literals, IDNA-encode, sanity-check."""
    host = host.strip().strip("[]").lower()
    if not host:
        raise SafeInputError("The URL has no host.")
    if len(host) > 253:
        raise SafeInputError("The URL host is too long.")
    if any(char in host for char in ("%", "@", " ", "\t", "\n", "\r", "\\", "\x00")):
        raise SafeInputError("The URL host contains unsupported characters.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SafeInputError("The URL host is not a valid domain name.") from exc
    if host in BLOCKED_HOST_NAMES or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise SafeInputError(f"Refusing to check an internal host name ({host}).")
    return host


def _rebuild_url(parsed) -> str:
    """Rebuild a URL with a normalized, lower-cased host (and valid IPv6 braces)."""
    host = _normalize_host(parsed.hostname or "")
    netloc = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError as exc:
        raise SafeInputError("The URL has an invalid port.") from exc
    if port:
        netloc = f"{netloc}:{port}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, ""))


def normalize_url(raw_url: str) -> str:
    """Normalize a user-supplied URL string or raise SafeInputError.

    Bare domains get https:// (PRD §3.2). The result is safe to hand to
    validate_url().
    """
    raw = (raw_url or "").strip()
    if not raw:
        raise SafeInputError("Enter a website URL to check.")
    if any(char.isspace() or ord(char) < 0x20 for char in raw):
        raise SafeInputError("The URL contains whitespace or control characters.")
    if "://" not in raw:
        raw = f"{DEFAULT_SCHEME}://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SafeInputError("Only http and https URLs are supported.")
    if not parsed.netloc:
        raise SafeInputError("The URL has no host.")
    if parsed.username or parsed.password:
        raise SafeInputError("URLs with embedded credentials are not supported.")
    try:
        port_is_valid = parsed.port is None or 0 < parsed.port <= 65535
    except ValueError as exc:  # e.g. http://host:99999/ — out of range
        raise SafeInputError("The URL has an invalid port.") from exc
    if not port_is_valid:
        raise SafeInputError("The URL has an invalid port.")
    return _rebuild_url(parsed)


def validate_url(
    url: str,
    resolver: Resolver = DEFAULT_RESOLVER,
) -> str:
    """Validate scheme, host, and every DNS answer for `url`.

    Returns the (host-normalized) URL. Raises SafeInputError with a message
    that is safe to show the user.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SafeInputError("Only http and https URLs are supported.")
    if parsed.username or parsed.password:
        raise SafeInputError("URLs with embedded credentials are not supported.")

    host = _normalize_host(parsed.hostname or "")
    is_ip_literal = False
    try:
        ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if _ip_is_blocked(host):
            raise SafeInputError("Refusing to check a private or reserved address.")
    else:
        if not any(part for part in host.split(".")):  # e.g. "http://."
            raise SafeInputError("The URL host is malformed.")
        for ip in resolver(host):
            if _ip_is_blocked(ip):
                raise SafeInputError(
                    "Refusing to check a host that resolves to a private or reserved address."
                )

    return _rebuild_url(parsed)


def resolve_and_validate_hop(
    url: str,
    resolver: Resolver = DEFAULT_RESOLVER,
) -> str:
    """Validate one request hop, including a fresh DNS check of its host.

    Used for the initial URL and again for every redirect destination.
    """
    normalized = normalize_url(url)
    return validate_url(normalized, resolver=resolver)


def resolve_redirect(location: str, base_url: str) -> str:
    """Resolve a possibly-relative Location header value against the current URL."""
    if not location:
        raise SafeInputError("A redirect response had no destination.")
    candidate = urljoin(base_url, location)
    if urlparse(candidate).scheme not in ALLOWED_SCHEMES:
        raise SafeInputError("A redirect used an unsupported scheme.")
    return candidate
