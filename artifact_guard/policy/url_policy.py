"""URL validation and SSRF protection policy."""

import asyncio
import ipaddress
from urllib.parse import urlsplit, urlunsplit

from shared.logging import get_logger

logger = get_logger(__name__)


ALLOWED_SCHEMES = {"http", "https"}

# Ports that should never be accessed
BLOCKED_PORTS = {
    22,     # SSH
    23,     # Telnet
    2375,   # Docker API (unencrypted)
    2376,   # Docker API (encrypted)
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # Elasticsearch
    9300,   # Elasticsearch cluster
    27017,  # MongoDB
    11211,  # Memcached
    1433,   # MSSQL
    1521,   # Oracle
    5984,   # CouchDB
}

# Private IP ranges to block
PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private
    ipaddress.ip_network("172.16.0.0/12"),    # Private
    ipaddress.ip_network("192.168.0.0/16"),   # Private
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
]

# Cloud metadata endpoints to block
METADATA_ENDPOINTS = {
    "169.254.169.254",  # AWS, GCP, Azure
    "metadata.google.internal",  # GCP
    "169.254.170.2",  # ECS task metadata
}


class UnsafeUrlError(ValueError):
    """Raised when URL is unsafe or invalid."""
    pass


def _is_ip_blocked(ip_str: str) -> bool:
    """Check if IP address should be blocked."""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check against private ranges
        for network in PRIVATE_RANGES:
            if ip in network:
                return True
        
        # Check metadata endpoints
        if ip_str in METADATA_ENDPOINTS:
            return True
            
        return False
    except ValueError:
        return True  # Invalid IP


async def normalize_and_validate_url(raw_url: str) -> str:
    """
    Normalize and validate URL, protecting against SSRF attacks.
    
    This function:
    1. Validates URL format and length
    2. Checks scheme whitelist
    3. Blocks credentials in URL
    4. Blocks dangerous ports
    5. Resolves DNS and validates all IPs are public
    6. Returns normalized URL
    
    Raises:
        UnsafeUrlError: If URL is unsafe or invalid
    """
    
    # Length check
    if len(raw_url) > 4096:
        raise UnsafeUrlError("URL exceeds maximum length of 4096 characters")
    
    # Parse URL
    parsed = urlsplit(raw_url.strip())
    
    # Scheme validation
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Unsupported URL scheme: {parsed.scheme}")
    
    # Block credentials in URL
    if parsed.username or parsed.password:
        raise UnsafeUrlError("Credentials in URL are prohibited")
    
    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("Hostname is missing")
    
    # Port validation
    port = parsed.port
    if port and port in BLOCKED_PORTS:
        raise UnsafeUrlError(f"Destination port {port} is blocked")
    
    # Normalize hostname (IDNA encoding)
    try:
        normalized_host = hostname.rstrip(".").encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as e:
        raise UnsafeUrlError(f"Invalid hostname encoding: {e}")
    
    # DNS resolution with validation
    target_port = port or (443 if parsed.scheme == "https" else 80)
    
    loop = asyncio.get_running_loop()
    try:
        addresses = await loop.getaddrinfo(
            normalized_host,
            target_port,
            type=0,  # Any socket type
            proto=0,  # Any protocol
        )
    except OSError as e:
        raise UnsafeUrlError(f"DNS resolution failed: {e}")
    
    if not addresses:
        raise UnsafeUrlError("DNS returned no addresses")
    
    # Validate all resolved IPs
    validated_ips = []
    for address in addresses:
        ip_str = address[4][0]
        
        if _is_ip_blocked(ip_str):
            logger.warning(
                "blocked_ip_in_dns_response",
                hostname=normalized_host,
                ip=ip_str,
                reason="non_public_destination"
            )
            continue
        
        validated_ips.append(ip_str)
    
    if not validated_ips:
        raise UnsafeUrlError(
            "All resolved IPs are in blocked ranges. "
            "This may indicate an SSRF attempt."
        )
    
    # Build normalized URL
    netloc = normalized_host
    if port:
        netloc = f"{normalized_host}:{port}"
    
    normalized_url = urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.query,
        "",  # Fragment is not sent to server
    ))
    
    logger.info(
        "url_validated",
        original_host=hostname,
        normalized_host=normalized_host,
        validated_ips=validated_ips[:3],  # Log first 3 IPs only
        port=target_port,
    )
    
    return normalized_url


def is_safe_redirect(current_url: str, redirect_url: str) -> bool:
    """
    Check if a redirect URL is safe relative to current URL.
    
    Prevents redirects to internal resources after initial validation.
    """
    try:
        current_parsed = urlsplit(current_url)
        redirect_parsed = urlsplit(redirect_url)
        
        # Block scheme changes
        if redirect_parsed.scheme and redirect_parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return False
        
        # For relative URLs (no netloc), they're inherently safe
        if not redirect_parsed.netloc:
            return True
        
        # For absolute URLs, validate the destination
        if redirect_parsed.hostname != current_parsed.hostname:
            # Cross-origin redirect - needs re-validation
            return False
        
        return True
        
    except Exception:
        return False
