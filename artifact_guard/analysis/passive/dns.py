"""Passive DNS analysis module.

Performs passive DNS lookups to detect suspicious infrastructure:
- Fast-flux networks (multiple IPs changing rapidly)
- Suspicious TLDs
- Missing email security records (SPF/DMARC)
- DNS resolution errors
"""

import asyncio
from dataclasses import dataclass
from typing import Protocol

import dns.asyncresolver
import dns.rdatatype

from domain.analysis import AnalysisContext
from domain.indicators import Indicator, Severity, IndicatorCategory


class DNSResolver(Protocol):
    """Protocol for DNS resolver."""

    async def resolve(self, hostname: str) -> list[str]:
        """Resolve hostname to IP addresses."""
        ...


@dataclass
class DnsRecord:
    """DNS record data."""

    record_type: str
    value: str
    ttl: int


@dataclass
class DnsResult:
    """DNS resolution result."""

    a_records: list[str]
    aaaa_records: list[str]
    mx_records: list[str]
    ns_records: list[str]
    txt_records: list[str]
    cname: str | None = None


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".date", ".bid", ".loan",
    ".racing", ".win", ".download", ".stream", ".faith", ".trade"
}

FAST_FLUX_THRESHOLD = 5  # Number of unique IPs for a single domain


async def resolve_dns(hostname: str) -> DnsResult:
    """Resolve DNS records for a hostname."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    a_records: list[str] = []
    aaaa_records: list[str] = []
    mx_records: list[str] = []
    ns_records: list[str] = []
    txt_records: list[str] = []
    cname: str | None = None

    try:
        # A records
        try:
            answers = await resolver.resolve(hostname, "A")
            a_records = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # AAAA records
        try:
            answers = await resolver.resolve(hostname, "AAAA")
            aaaa_records = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = await resolver.resolve(hostname, "MX")
            mx_records = [str(rdata.exchange) for rdata in answers]
        except Exception:
            pass

        # NS records
        try:
            answers = await resolver.resolve(hostname, "NS")
            ns_records = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # TXT records
        try:
            answers = await resolver.resolve(hostname, "TXT")
            txt_records = [str(rdata).strip('"') for rdata in answers]
        except Exception:
            pass

        # CNAME
        try:
            answers = await resolver.resolve(hostname, "CNAME")
            if answers:
                cname = str(answers[0])
        except Exception:
            pass

    except Exception:
        pass

    return DnsResult(
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records,
        ns_records=ns_records,
        txt_records=txt_records,
        cname=cname,
    )


class DnsAnalyzer:
    """Passive DNS analyzer."""

    name = "dns_analyzer"

    async def analyze(self, context: AnalysisContext) -> list[Indicator]:
        """Analyze DNS records for indicators."""
        indicators: list[Indicator] = []

        hostname = context.hostname
        if not hostname:
            return indicators

        try:
            result = await resolve_dns(hostname)

            # Check for suspicious TLDs
            tld = "." + hostname.split(".")[-1].lower()
            if tld in SUSPICIOUS_TLDS:
                indicators.append(
                    Indicator(
                        name="suspicious_tld",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.3,
                        confidence=0.9,
                        explanation=f"Domain uses suspicious TLD: {tld}",
                        evidence_ids=[],
                    )
                )

            # Check for fast-flux network (many A records)
            if len(result.a_records) >= FAST_FLUX_THRESHOLD:
                indicators.append(
                    Indicator(
                        name="fast_flux_detected",
                        category=IndicatorCategory.NETWORK,
                        severity=Severity.HIGH,
                        score=0.7,
                        confidence=0.8,
                        explanation=f"Domain has {len(result.a_records)} A records, possible fast-flux network",
                        evidence_ids=[],
                    )
                )

            # Check for missing email security records
            has_spf = any("v=spf" in txt.lower() for txt in result.txt_records)
            has_dmarc = any("v=dmarc" in txt.lower() for txt in result.txt_records)

            if not has_spf and not has_dmarc:
                indicators.append(
                    Indicator(
                        name="missing_email_security",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.15,
                        confidence=0.7,
                        explanation="Domain lacks SPF and DMARC records",
                        evidence_ids=[],
                    )
                )

            # Check for multiple MX records pointing to different providers
            if len(result.mx_records) > 3:
                indicators.append(
                    Indicator(
                        name="multiple_mx_records",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.1,
                        confidence=0.6,
                        explanation=f"Domain has {len(result.mx_records)} MX records",
                        evidence_ids=[],
                    )
                )

            # Store DNS results in context for further analysis
            context.dns_records = [
                DnsRecord(record_type="A", value=r, ttl=0) for r in result.a_records
            ] + [
                DnsRecord(record_type="AAAA", value=r, ttl=0) for r in result.aaaa_records
            ]
            context.resolved_ips = result.a_records + result.aaaa_records

        except Exception as e:
            indicators.append(
                Indicator(
                    name="dns_resolution_error",
                    category=IndicatorCategory.NETWORK,
                    severity=Severity.LOW,
                    score=0.2,
                    confidence=0.5,
                    explanation=f"DNS resolution failed: {str(e)}",
                    evidence_ids=[],
                )
            )

        return indicators


__all__ = ["DnsAnalyzer", "resolve_dns", "DnsResult"]
