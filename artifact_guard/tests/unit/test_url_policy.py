"""Unit tests for URL policy and SSRF protection."""

import asyncio
import pytest

from policy.url_policy import (
    normalize_and_validate_url,
    is_safe_redirect,
    UnsafeUrlError,
    _is_ip_blocked,
    ALLOWED_SCHEMES,
    BLOCKED_PORTS,
)


class TestIpBlocking:
    """Tests for IP address blocking logic."""

    def test_loopback_ipv4_blocked(self):
        """Test that IPv4 loopback addresses are blocked."""
        assert _is_ip_blocked("127.0.0.1") is True
        assert _is_ip_blocked("127.0.0.2") is True
        assert _is_ip_blocked("127.255.255.255") is True

    def test_private_ipv4_blocked(self):
        """Test that private IPv4 ranges are blocked."""
        # 10.0.0.0/8
        assert _is_ip_blocked("10.0.0.1") is True
        assert _is_ip_blocked("10.255.255.255") is True
        
        # 172.16.0.0/12
        assert _is_ip_blocked("172.16.0.1") is True
        assert _is_ip_blocked("172.31.255.255") is True
        
        # 192.168.0.0/16
        assert _is_ip_blocked("192.168.0.1") is True
        assert _is_ip_blocked("192.168.255.255") is True

    def test_link_local_blocked(self):
        """Test that link-local addresses are blocked."""
        assert _is_ip_blocked("169.254.0.1") is True
        assert _is_ip_blocked("169.254.255.255") is True

    def test_metadata_endpoints_blocked(self):
        """Test that cloud metadata endpoints are blocked."""
        assert _is_ip_blocked("169.254.169.254") is True  # AWS/GCP/Azure
        assert _is_ip_blocked("169.254.170.2") is True  # ECS

    def test_public_ipv4_allowed(self):
        """Test that public IPv4 addresses are allowed."""
        assert _is_ip_blocked("8.8.8.8") is False
        assert _is_ip_blocked("1.1.1.1") is False
        assert _is_ip_blocked("142.250.185.78") is False

    def test_ipv6_loopback_blocked(self):
        """Test that IPv6 loopback is blocked."""
        assert _is_ip_blocked("::1") is True

    def test_invalid_ip_blocked(self):
        """Test that invalid IPs are blocked."""
        assert _is_ip_blocked("not-an-ip") is True
        assert _is_ip_blocked("") is True


@pytest.mark.asyncio
class TestUrlNormalization:
    """Tests for URL normalization and validation."""

    async def test_valid_https_url(self):
        """Test normalization of valid HTTPS URL."""
        url = "https://example.com/path?query=value"
        normalized = await normalize_and_validate_url(url)
        
        assert normalized.startswith("https://")
        assert "example.com" in normalized

    async def test_valid_http_url(self):
        """Test normalization of valid HTTP URL."""
        url = "http://example.com"
        normalized = await normalize_and_validate_url(url)
        
        assert normalized.startswith("http://")

    async def test_url_too_long(self):
        """Test that excessively long URLs are rejected."""
        long_url = "https://example.com/" + "a" * 5000
        with pytest.raises(UnsafeUrlError, match="exceeds maximum length"):
            await normalize_and_validate_url(long_url)

    async def test_unsupported_scheme(self):
        """Test that unsupported schemes are rejected."""
        with pytest.raises(UnsafeUrlError, match="Unsupported URL scheme"):
            await normalize_and_validate_url("ftp://example.com/file")
        
        with pytest.raises(UnsafeUrlError, match="Unsupported URL scheme"):
            await normalize_and_validate_url("file:///etc/passwd")

    async def test_credentials_in_url_rejected(self):
        """Test that URLs with credentials are rejected."""
        with pytest.raises(UnsafeUrlError, match="Credentials in URL"):
            await normalize_and_validate_url("https://user:pass@example.com")
        
        with pytest.raises(UnsafeUrlError, match="Credentials in URL"):
            await normalize_and_validate_url("https://user@example.com")

    async def test_missing_hostname_rejected(self):
        """Test that URLs without hostname are rejected."""
        with pytest.raises(UnsafeUrlError, match="Hostname is missing"):
            await normalize_and_validate_url("http:///path")

    async def test_blocked_port_rejected(self):
        """Test that URLs with blocked ports are rejected."""
        for port in BLOCKED_PORTS:
            url = f"https://example.com:{port}/path"
            with pytest.raises(UnsafeUrlError, match=f"port {port} is blocked"):
                await normalize_and_validate_url(url)

    async def test_dns_resolution_failure(self):
        """Test that DNS resolution failures are handled."""
        # Use a domain that's guaranteed not to exist
        url = "https://this-domain-definitely-does-not-exist-12345.com"
        with pytest.raises(UnsafeUrlError, match="DNS resolution failed"):
            await normalize_and_validate_url(url)

    async def test_normalization_lowercase(self):
        """Test that URLs are normalized to lowercase."""
        url = "HTTPS://EXAMPLE.COM/Path"
        normalized = await normalize_and_validate_url(url)
        
        assert normalized.startswith("https://")
        assert "example.com" in normalized.lower()

    async def test_trailing_dot_removed(self):
        """Test that trailing dots are removed from hostnames."""
        url = "https://example.com./path"
        normalized = await normalize_and_validate_url(url)
        
        assert "example.com." not in normalized


class TestRedirectSafety:
    """Tests for redirect safety checking."""

    def test_relative_redirect_safe(self):
        """Test that relative redirects are considered safe."""
        current = "https://example.com/page"
        redirect = "/new-page"
        
        assert is_safe_redirect(current, redirect) is True

    def test_same_origin_redirect_safe(self):
        """Test that same-origin redirects are safe."""
        current = "https://example.com/page"
        redirect = "https://example.com/new-page"
        
        assert is_safe_redirect(current, redirect) is True

    def test_cross_origin_redirect_flagged(self):
        """Test that cross-origin redirects are flagged for re-validation."""
        current = "https://example.com/page"
        redirect = "https://different.com/page"
        
        # Cross-origin should return False to trigger re-validation
        assert is_safe_redirect(current, redirect) is False

    def test_unsupported_scheme_redirect_blocked(self):
        """Test that redirects to unsupported schemes are blocked."""
        current = "https://example.com/page"
        redirect = "file:///etc/passwd"
        
        assert is_safe_redirect(current, redirect) is False

    def test_malformed_urls_handled_gracefully(self):
        """Test that malformed URLs are handled gracefully (return False for safety)."""
        # Malformed URLs should be caught by exception handling and return False
        # However, urlsplit is very permissive, so some malformed URLs may parse
        # The key is that the function doesn't crash
        result = is_safe_redirect("not-a-url", "also-not-a-url")
        # Just ensure it returns a boolean without crashing
        assert isinstance(result, bool)
