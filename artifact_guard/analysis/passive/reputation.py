"""Reputation Analysis Module.

Checks domain and IP reputation against known threat intelligence:
- Local blocklists
- Known malicious IP ranges
- Brand impersonation detection
"""

from dataclasses import dataclass, field
import ipaddress

from domain.analysis import AnalysisContext
from domain.indicators import Indicator, Severity, IndicatorCategory


# Local blocklists (in production, these would be fetched from threat intel feeds)
KNOWN_MALICIOUS_DOMAINS = {
    "example-phishing.com",
    "fake-bank-login.net",
    "crypto-scam.xyz",
}

KNOWN_MALICIOUS_IP_RANGES = [
    ipaddress.ip_network("185.220.101.0/24"),  # Example TOR exit nodes
    ipaddress.ip_network("45.154.98.0/24"),     # Example bulletproof hosting
]

# Reputable brands that are commonly impersonated
PROTECTED_BRANDS = {
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "paypal": ["paypal.com"],
    "sberbank": ["sberbank.ru", "sber.ru"],
    "yandex": ["yandex.ru", "ya.ru"],
}


@dataclass(frozen=True)
class ReputationResult:
    """Reputation check result."""

    domain: str
    is_malicious: bool = False
    is_suspicious: bool = False
    threat_categories: list[str] = field(default_factory=list)
    brand_impersonation: str | None = None
    safe_browsing_status: str = "unknown"
    virustotal_score: tuple[int, int] | None = None  # (malicious, total)


def check_domain_blocklist(domain: str) -> bool:
    """Check if domain is in local blocklist."""
    return domain.lower() in KNOWN_MALICIOUS_DOMAINS


def check_ip_reputation(ip_str: str) -> bool:
    """Check if IP is in known malicious ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in KNOWN_MALICIOUS_IP_RANGES:
            if ip in network:
                return True
    except ValueError:
        pass
    return False


def detect_brand_impersonation(domain: str) -> str | None:
    """Detect if domain impersonates a protected brand."""
    domain_lower = domain.lower()
    
    for brand, legitimate_domains in PROTECTED_BRANDS.items():
        # Check for exact match (legitimate)
        if domain_lower in legitimate_domains:
            return None
        
        # Check for brand name in domain with suspicious patterns
        if brand in domain_lower:
            # Check for typosquatting patterns
            for legit in legitimate_domains:
                if legit != domain_lower:
                    # Brand mentioned but not legitimate domain
                    return brand
    
    return None


class ReputationAnalyzer:
    """Reputation analyzer."""

    name = "reputation_analyzer"

    async def analyze(self, context: AnalysisContext) -> list[Indicator]:
        """Analyze domain/IP reputation."""
        indicators: list[Indicator] = []

        hostname = context.hostname
        if not hostname:
            return indicators

        # Check local blocklist
        if check_domain_blocklist(hostname):
            indicators.append(
                Indicator(
                    name="known_malicious_domain",
                    category=IndicatorCategory.REPUTATION,
                    severity=Severity.CRITICAL,
                    score=0.95,
                    confidence=0.99,
                    explanation=f"Domain {hostname} is in known blocklist",
                    evidence_ids=[],
                )
            )
            return indicators  # No need to continue

        # Check resolved IPs
        for ip in context.resolved_ips or []:
            if check_ip_reputation(ip):
                indicators.append(
                    Indicator(
                        name="malicious_ip_detected",
                        category=IndicatorCategory.REPUTATION,
                        severity=Severity.HIGH,
                        score=0.7,
                        confidence=0.85,
                        explanation=f"Resolved IP {ip} is in known malicious range",
                        evidence_ids=[],
                    )
                )

        # Check for brand impersonation
        brand = detect_brand_impersonation(hostname)
        if brand:
            indicators.append(
                Indicator(
                    name="brand_impersonation",
                    category=IndicatorCategory.REPUTATION,
                    severity=Severity.HIGH,
                    score=0.6,
                    confidence=0.75,
                    explanation=f"Domain may be impersonating {brand}",
                    evidence_ids=[],
                )
            )

        # Store reputation result in context
        context.reputation_result = ReputationResult(
            domain=hostname,
            is_malicious=check_domain_blocklist(hostname),
            brand_impersonation=brand,
        )

        return indicators


__all__ = ["ReputationAnalyzer", "ReputationResult", "check_domain_blocklist", "check_ip_reputation"]
