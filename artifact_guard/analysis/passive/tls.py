"""TLS/SSL certificate analysis module."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import ssl
import socket
import asyncio


@dataclass
class TlsInfo:
    """TLS certificate information."""

    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial_number: int | None = None
    version: int | None = None
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    days_until_expiry: int | None = None
    signature_algorithm: str | None = None
    san_domains: list[str] | None = None


async def fetch_tls_info(hostname: str, port: int = 443) -> TlsInfo | None:
    """Fetch TLS certificate information for a hostname."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, _fetch_tls_info_sync, hostname, port
        )
    except Exception:
        return None


def _fetch_tls_info_sync(hostname: str, port: int) -> TlsInfo | None:
    """Synchronous TLS info fetching."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return None

                return parse_cert(cert, hostname)
    except Exception:
        return None


def parse_cert(cert: dict[str, Any], hostname: str) -> TlsInfo:
    """Parse certificate dictionary into TlsInfo."""
    subject = None
    issuer = None
    not_before = None
    not_after = None
    san_domains = []

    # Extract subject
    subject_parts = []
    for rdn in cert.get("subject", ()):
        for name, value in rdn:
            subject_parts.append(f"{name}={value}")
    subject = ", ".join(subject_parts) if subject_parts else None

    # Extract issuer
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for name, value in rdn:
            issuer_parts.append(f"{name}={value}")
    issuer = ", ".join(issuer_parts) if issuer_parts else None

    # Extract dates
    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")

    if not_before_str:
        try:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_before = not_before.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    if not_after_str:
        try:
            not_after = datetime.strptime(not_afterStr, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    # Check SAN (Subject Alternative Names)
    san_extension = cert.get("subjectAltName", [])
    for name_type, value in san_extension:
        if name_type == "DNS":
            san_domains.append(value)

    # Check if self-signed
    is_self_signed = subject == issuer if subject and issuer else False

    # Check expiry
    is_expired = False
    is_expiring_soon = False
    days_until_expiry = None

    if not_after:
        now = datetime.now(timezone.utc)
        delta = not_after - now
        days_until_expiry = delta.days
        is_expired = days_until_expiry < 0
        is_expiring_soon = 0 <= days_until_expiry <= 30

    return TlsInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        is_self_signed=is_self_signed,
        is_expired=is_expired,
        is_expiring_soon=is_expiring_soon,
        days_until_expiry=days_until_expiry,
        san_domains=san_domains if san_domains else None,
    )


class TlsAnalyzer:
    """TLS certificate analyzer."""

    name = "tls_analyzer"

    async def analyze(self, context) -> list:  # noqa: ANN003
        """Analyze TLS certificate for indicators."""
        from domain.indicators import Indicator  # noqa: PLC0415

        indicators: list[Indicator] = []

        if not context.hostname:
            return indicators

        # Only analyze HTTPS URLs
        if context.artifact.type.value != "url" or not context.artifact.value.startswith(
            "https://"
        ):
            return indicators

        try:
            tls_info = await fetch_tls_info(context.hostname)

            if not tls_info:
                indicators.append(
                    Indicator(
                        name="tls_fetch_failed",
                        score=0.15,
                        severity="low",
                        explanation="Could not retrieve TLS certificate",
                        evidence_ids=[],
                    )
                )
                return indicators

            # Check for self-signed certificate
            if tls_info.is_self_signed:
                indicators.append(
                    Indicator(
                        name="self_signed_certificate",
                        score=0.4,
                        severity="medium",
                        explanation="Certificate is self-signed",
                        evidence_ids=[],
                    )
                )

            # Check for expired certificate
            if tls_info.is_expired:
                indicators.append(
                    Indicator(
                        name="expired_certificate",
                        score=0.5,
                        severity="high",
                        explanation="Certificate has expired",
                        evidence_ids=[],
                    )
                )

            # Check for expiring soon
            if tls_info.is_expiring_soon and not tls_info.is_expired:
                indicators.append(
                    Indicator(
                        name="certificate_expiring_soon",
                        score=0.2,
                        severity="low",
                        explanation=f"Certificate expires in {tls_info.days_until_expiry} days",
                        evidence_ids=[],
                    )
                )

            # Check for certificate validity period (very short or very long)
            if tls_info.not_before and tls_info.not_after:
                validity_days = (tls_info.not_after - tls_info.not_before).days
                if validity_days < 30:
                    indicators.append(
                        Indicator(
                            name="short_validity_certificate",
                            score=0.3,
                            severity="medium",
                            explanation=f"Certificate valid for only {validity_days} days",
                            evidence_ids=[],
                        )
                    )
                elif validity_days > 825:  # More than ~27 months
                    indicators.append(
                        Indicator(
                            name="long_validity_certificate",
                            score=0.1,
                            severity="low",
                            explanation=f"Certificate valid for {validity_days} days (>27 months)",
                            evidence_ids=[],
                        )
                    )

            # Check if hostname matches certificate SAN
            if tls_info.san_domains:
                if context.hostname not in tls_info.san_domains:
                    # Check for wildcard
                    wildcard_match = any(
                        san.startswith("*.") and context.hostname.endswith(san[1:])
                        for san in tls_info.san_domains
                    )
                    if not wildcard_match:
                        indicators.append(
                            Indicator(
                                name="hostname_mismatch",
                                score=0.35,
                                severity="medium",
                                explanation="Hostname does not match certificate SAN",
                                evidence_ids=[],
                            )
                        )

        except Exception as e:
            indicators.append(
                Indicator(
                    name="tls_analysis_error",
                    score=0.1,
                    severity="low",
                    explanation=f"TLS analysis failed: {str(e)}",
                    evidence_ids=[],
                )
            )

        return indicators


__all__ = ["TlsAnalyzer", "fetch_tls_info", "TlsInfo"]
