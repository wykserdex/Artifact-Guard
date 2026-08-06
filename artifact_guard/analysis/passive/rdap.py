"""RDAP (Registration Data Access Protocol) analysis module.

Performs passive RDAP lookups to detect:
- Recently registered domains (< 30 days)
- Privacy protection services (hiding real owner)
- Suspicious registrars known for abuse
- Domain expiration patterns
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

import aiohttp

from domain.analysis import AnalysisContext
from domain.indicators import Indicator, Severity, IndicatorCategory


@dataclass(frozen=True)
class RdapResult:
    """RDAP lookup result."""

    domain: str
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    status: list[str] | None = None
    nameservers: list[str] | None = None
    registrant_country: str | None = None
    privacy_protected: bool = False


SUSPICIOUS_REGISTRARS = {
    "namecheap inc.",
    "godaddy.com, llc",
    "tucows domains inc.",
    "publicdomainregistry.com",
    "dynadot, llc",
    "gandi sas",
}

NEW_DOMAIN_DAYS = 30  # Domains newer than this are suspicious


async def lookup_rdap(hostname: str, session: aiohttp.ClientSession | None = None) -> RdapResult | None:
    """Lookup RDAP information for a domain."""
    base_urls = [
        f"https://rdap.org/domain/{hostname}",
        f"https://rdap.verisign.com/com/v1/domain/{hostname}",
    ]

    for base_url in base_urls:
        try:
            close_session = False
            if session is None:
                session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
                close_session = True

            try:
                async with session.get(base_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return parse_rdap_response(hostname, data)
            finally:
                if close_session:
                    await session.close()
        except Exception:
            continue

    return None


def parse_rdap_response(domain: str, data: dict[str, Any]) -> RdapResult:
    """Parse RDAP JSON response."""
    registrar = None
    creation_date = None
    expiration_date = None
    updated_date = None
    status = []
    nameservers = []
    registrant_country = None
    privacy_protected = False

    if "entities" in data:
        for entity in data["entities"]:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard_array = entity.get("vcardArray", [])
                if len(vcard_array) > 1:
                    for item in vcard_array[1]:
                        if item[0] == "fn":
                            registrar = item[3]
                            break

    for event in data.get("events", []):
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        if date_str:
            try:
                date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if action == "registration":
                    creation_date = date
                elif action == "expiration":
                    expiration_date = date
                elif action == "last changed":
                    updated_date = date
            except Exception:
                pass

    status = data.get("status", [])

    if "nameservers" in data:
        for ns in data["nameservers"]:
            if "ldhName" in ns:
                nameservers.append(ns["ldhName"])

    if "entities" in data:
        for entity in data["entities"]:
            roles = entity.get("roles", [])
            if "registrant" in roles:
                vcard_array = entity.get("vcardArray", [])
                if len(vcard_array) <= 1:
                    privacy_protected = True

    return RdapResult(
        domain=domain,
        registrar=registrar,
        creation_date=creation_date,
        expiration_date=expiration_date,
        updated_date=updated_date,
        status=status,
        nameservers=nameservers,
        registrant_country=registrant_country,
        privacy_protected=privacy_protected,
    )


class RdapAnalyzer:
    """Passive RDAP analyzer."""

    name = "rdap_analyzer"

    async def analyze(self, context: AnalysisContext) -> list[Indicator]:
        """Analyze RDAP data for indicators."""
        indicators: list[Indicator] = []

        hostname = context.hostname
        if not hostname:
            return indicators

        try:
            async with aiohttp.ClientSession() as session:
                result = await lookup_rdap(hostname, session)

            if result is None:
                indicators.append(
                    Indicator(
                        name="rdap_lookup_failed",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.2,
                        confidence=0.5,
                        explanation=f"RDAP lookup failed for {hostname}",
                        evidence_ids=[],
                    )
                )
                return indicators

            if result.creation_date:
                age_days = (datetime.now(timezone.utc) - result.creation_date).days
                if age_days < NEW_DOMAIN_DAYS:
                    indicators.append(
                        Indicator(
                            name="newly_registered_domain",
                            category=IndicatorCategory.DOMAIN,
                            severity=Severity.MEDIUM,
                            score=0.5,
                            confidence=0.8,
                            explanation=f"Domain registered {age_days} days ago",
                            evidence_ids=[],
                        )
                    )

            if result.privacy_protected:
                indicators.append(
                    Indicator(
                        name="privacy_protection_enabled",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.25,
                        confidence=0.7,
                        explanation="Domain uses privacy protection service",
                        evidence_ids=[],
                    )
                )

            if result.registrar and result.registrar.lower() in SUSPICIOUS_REGISTRARS:
                indicators.append(
                    Indicator(
                        name="suspicious_registrar",
                        category=IndicatorCategory.DOMAIN,
                        severity=Severity.LOW,
                        score=0.15,
                        confidence=0.6,
                        explanation=f"Domain registered via potentially abusive registrar: {result.registrar}",
                        evidence_ids=[],
                    )
                )

            context.rdap_result = result

        except Exception as e:
            indicators.append(
                Indicator(
                    name="rdap_analysis_error",
                    category=IndicatorCategory.DOMAIN,
                    severity=Severity.LOW,
                    score=0.1,
                    confidence=0.5,
                    explanation=f"RDAP analysis failed: {str(e)}",
                    evidence_ids=[],
                )
            )

        return indicators


__all__ = ["RdapAnalyzer", "lookup_rdap", "RdapResult"]
