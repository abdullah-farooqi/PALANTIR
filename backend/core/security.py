import hmac
import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse
from core.config import settings

# RFC 1123 hostname validation
HOSTNAME_REGEX = re.compile(
    r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])"
    r"(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]))*$"
)

# Known cloud metadata service hostnames
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

# Dangerous internal service ports that must never be probed via loopback
FORBIDDEN_LOOPBACK_PORTS = {
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    5432,  # PostgreSQL
    6379,  # Redis
    8000,  # Palantir Backend (prevents recursive denial-of-service loops)
    2375,  # Docker Daemon HTTP
    2376,  # Docker Daemon HTTPS
}


def verify_webhook_secret(secret_header: Optional[str]) -> bool:
    """
    Verifies the X-PALANTIR-Secret webhook header using constant-time comparison
    (hmac.compare_digest) to prevent timing attacks.
    """
    if not secret_header or not isinstance(secret_header, str):
        return False
    if not settings.PALANTIR_WEBHOOK_SECRET:
        return False
    return hmac.compare_digest(
        secret_header.encode("utf-8"),
        settings.PALANTIR_WEBHOOK_SECRET.encode("utf-8"),
    )


def validate_netdata_url(url: str) -> str:
    """
    Strict SSRF and URI validation for Netdata sensor endpoints.

    Protections:
    - Enforces http or https scheme (blocks file://, gopher://, dict://, etc.).
    - Disallows embedded user credentials (user:pass@host).
    - Blocks access to cloud metadata services (169.254.169.254, fe80::/10, fd00:ec2::254, GCP metadata).
    - Prevents loopback port scanning against sensitive internal infrastructure (PostgreSQL, Redis, Docker).
    - Validates hostname syntax against RFC 1123 standards.
    - Strips query parameters, fragments, and trailing slashes for canonical base URLs.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Invalid URL scheme: only 'http' and 'https' are permitted")

    if not parsed.hostname:
        raise ValueError("Invalid URL: missing hostname")

    if parsed.username or parsed.password:
        raise ValueError("Invalid URL: embedded user credentials are not allowed")

    # Determine port
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port: must be between 1 and 65535")

    hostname_lower = parsed.hostname.lower()

    if hostname_lower in BLOCKED_HOSTNAMES:
        raise ValueError("Access to cloud metadata endpoints is forbidden")

    is_ip = False
    try:
        ip = ipaddress.ip_address(hostname_lower)
        is_ip = True
    except ValueError:
        # libc accepts abbreviated and octal IPv4 forms such as 127.1 and
        # 0177.0.0.1. Treat those as IP literals too, instead of allowing them
        # through hostname checks with different semantics at connect time.
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(hostname_lower))
            is_ip = True
        except (OSError, OverflowError):
            pass

    if is_ip:
        # Unmap IPv4-mapped IPv6 address (e.g. ::ffff:169.254.169.254)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Block cloud metadata / link-local addresses
        if ip.is_link_local:
            raise ValueError("Access to link-local / cloud metadata IP addresses is forbidden")

        # Block AWS IMDSv2 IPv6 metadata address fd00:ec2::254
        if str(ip).lower() == "fd00:ec2::254":
            raise ValueError("Access to cloud metadata endpoints is forbidden")

        # Block loopback access to sensitive infrastructure ports
        if ip.is_loopback and port in FORBIDDEN_LOOPBACK_PORTS:
            raise ValueError(f"Loopback access to sensitive port {port} is forbidden")
    else:
        # Validate hostname syntax
        if not HOSTNAME_REGEX.match(hostname_lower):
            raise ValueError("Invalid hostname format")

        if hostname_lower in ("localhost",) and port in FORBIDDEN_LOOPBACK_PORTS:
            raise ValueError(f"Loopback access to sensitive port {port} is forbidden")

    # Construct clean canonical base URL
    normalized = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}"
    if parsed.port:
        normalized += f":{parsed.port}"
    if parsed.path and parsed.path.rstrip("/"):
        normalized += parsed.path.rstrip("/")

    return normalized
