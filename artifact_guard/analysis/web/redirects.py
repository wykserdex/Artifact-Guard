"""Redirect chain analysis for phishing detection."""

from urllib.parse import urljoin, urlparse

from domain.indicators import Indicator
from policy.url_policy import is_safe_redirect, validate_url_safety


class RedirectAnalyzer:
    """Analyzes redirect chains for suspicious patterns."""
    
    name = "redirect_analyzer"
    
    MAX_REDIRECTS = 10
    SUSPICIOUS_REDIRECT_COUNT = 5
    
    def analyze(self, redirects: list[str]) -> list[Indicator]:
        """Analyze redirect chain."""
        indicators = []
        
        if not redirects:
            return indicators
        
        # Check redirect count
        if len(redirects) > self.SUSPICIOUS_REDIRECT_COUNT:
            indicators.append(Indicator(
                name="excessive_redirects",
                score=0.6,
                severity="medium",
                explanation=f"URL redirects {len(redirects)} times (threshold: {self.SUSPICIOUS_REDIRECT_COUNT})",
                evidence_ids=[],
            ))
        
        # Check each redirect for safety
        for i, redirect_url in enumerate(redirects):
            try:
                if not is_safe_redirect(redirect_url):
                    indicators.append(Indicator(
                        name="unsafe_redirect",
                        score=0.8,
                        severity="high",
                        explanation=f"Redirect #{i+1} leads to unsafe destination: {redirect_url[:50]}",
                        evidence_ids=[],
                    ))
            except Exception:
                pass
        
        # Check for domain changes
        if len(redirects) > 1:
            initial_domain = urlparse(redirects[0]).netloc
            final_domain = urlparse(redirects[-1]).netloc
            
            if initial_domain != final_domain:
                indicators.append(Indicator(
                    name="domain_change_redirect",
                    score=0.4,
                    severity="low",
                    explanation=f"Redirect chain changes domain from {initial_domain} to {final_domain}",
                    evidence_ids=[],
                ))
        
        return indicators
