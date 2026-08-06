"""Homoglyph Detection Module.

Detects homoglyph attacks where attackers use visually similar characters
from different Unicode scripts to create deceptive domain names:
- Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
- Greek 'ο' (U+03BF) vs Latin 'o' (U+006F)
- Various lookalike characters across scripts
"""

from dataclasses import dataclass, field

from domain.analysis import AnalysisContext
from domain.indicators import Indicator, Severity, IndicatorCategory


# Homoglyph mappings: character -> list of lookalikes
HOMOGLYPHS = {
    "a": ["а", "ɑ", "α", "a"],  # Cyrillic, Latin alpha, Greek alpha, fullwidth
    "b": ["Ь", "ь", "ƅ", "b"],  # Cyrillic soft sign, Latin ƅ
    "c": ["с", "ϲ", "¢", "c"],  # Cyrillic es, Greek lunate sigma
    "e": ["е", "ε", "ё", "e"],  # Cyrillic ie, Greek epsilon
    "h": ["һ", "н", "ɦ", "h"],  # Cyrillic shche, en
    "i": ["і", "ι", "ï", "i"],  # Cyrillic i, Greek iota
    "k": ["к", "κ", "ķ", "k"],  # Cyrillic ka, Greek kappa
    "m": ["м", "ᴍ", "m"],  # Cyrillic em
    "n": ["п", "ν", "ո", "n"],  # Cyrillic el/pi, Greek nu, Armenian no
    "o": ["о", "ο", "օ", "o"],  # Cyrillic o, Greek omicron, Armenian oh
    "p": ["р", "ρ", "p"],  # Cyrillic er, Greek rho
    "r": ["г", "ѓ", "ʀ", "r"],  # Cyrillic ge
    "s": ["ѕ", "σ", "s"],  # Cyrillic dze, Greek sigma
    "u": ["ս", "υ", "u"],  # Armenian yun, Greek upsilon
    "x": ["х", "χ", "×", "x"],  # Cyrillic ha, Greek chi, multiplication sign
    "y": ["у", "γ", "y"],  # Cyrillic u, Greek gamma
}


def normalize_domain(domain: str) -> str:
    """Normalize domain by replacing homoglyphs with canonical ASCII."""
    result = []
    for char in domain.lower():
        replaced = False
        for canonical, lookalikes in HOMOGLYPHS.items():
            if char in lookalikes and char != canonical:
                result.append(canonical)
                replaced = True
                break
        if not replaced:
            result.append(char)
    return "".join(result)


def detect_homoglyphs(domain: str) -> list[tuple[int, str, str]]:
    """Detect homoglyph characters in domain.
    
    Returns list of (position, original_char, canonical_char) tuples.
    """
    findings = []
    for i, char in enumerate(domain.lower()):
        for canonical, lookalikes in HOMOGLYPHS.items():
            if char in lookalikes and char != canonical:
                findings.append((i, char, canonical))
                break
    return findings


def is_mixed_script(domain: str) -> bool:
    """Check if domain contains characters from multiple scripts."""
    import unicodedata
    
    scripts = set()
    for char in domain:
        if char.isascii():
            continue
        try:
            script = unicodedata.name(char, "").split()[0]
            scripts.add(script)
        except Exception:
            pass
    
    return len(scripts) > 1


class HomoglyphAnalyzer:
    """Homoglyph detection analyzer."""

    name = "homoglyph_analyzer"

    async def analyze(self, context: AnalysisContext) -> list[Indicator]:
        """Analyze domain for homoglyph attacks."""
        indicators: list[Indicator] = []

        hostname = context.hostname
        if not hostname:
            return indicators

        # Remove TLD for analysis
        parts = hostname.split(".")
        if len(parts) < 2:
            return indicators
        
        domain_part = ".".join(parts[:-1])
        
        # Detect homoglyphs
        homoglyph_findings = detect_homoglyphs(domain_part)
        
        if homoglyph_findings:
            chars_found = [f"'{orig}'→'{canon}'" for _, orig, canon in homoglyph_findings]
            indicators.append(
                Indicator(
                    name="homoglyph_domain",
                    category=IndicatorCategory.DOMAIN,
                    severity=Severity.HIGH,
                    score=0.8,
                    confidence=0.95,
                    explanation=f"Homoglyph characters detected: {', '.join(chars_found)}",
                    evidence_ids=[],
                )
            )
        
        # Check for mixed script
        if is_mixed_script(domain_part):
            indicators.append(
                Indicator(
                    name="mixed_script_domain",
                    category=IndicatorCategory.DOMAIN,
                    severity=Severity.MEDIUM,
                    score=0.5,
                    confidence=0.8,
                    explanation="Domain contains characters from multiple Unicode scripts",
                    evidence_ids=[],
                )
            )
        
        # Store normalized domain in context
        normalized = normalize_domain(domain_part)
        if normalized != domain_part:
            context.normalized_hostname = normalized + "." + parts[-1]
            indicators.append(
                Indicator(
                    name="domain_normalization_applied",
                    category=IndicatorCategory.DOMAIN,
                    severity=Severity.LOW,
                    score=0.1,
                    confidence=0.9,
                    explanation=f"Domain normalized from '{hostname}' to '{context.normalized_hostname}'",
                    evidence_ids=[],
                )
            )

        return indicators


__all__ = ["HomoglyphAnalyzer", "detect_homoglyphs", "normalize_domain", "is_mixed_script"]
