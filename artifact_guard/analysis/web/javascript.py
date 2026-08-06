"""JavaScript analysis for obfuscation and suspicious patterns."""

import re
from typing import Optional

from domain.indicators import Indicator


class JavaScriptAnalyzer:
    """Analyze JavaScript for suspicious patterns."""
    
    name = "javascript_analyzer"
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        (r"eval\s*\(", "eval_usage", 0.7),
        (r"document\.write\s*\(", "document_write", 0.5),
        (r"fromCharCode\s*\(", "fromcharcode_obfuscation", 0.6),
        (r"atob\s*\(", "base64_decode", 0.4),
        (r"\\x[0-9a-fA-F]{2}", "hex_encoding", 0.5),
        (r"\\u[0-9a-fA-F]{4}", "unicode_encoding", 0.4),
        (r"setTimeout\s*\(\s*[\"']", "string_timeout", 0.6),
        (r"setInterval\s*\(\s*[\"']", "string_interval", 0.6),
        (r"window\.location\s*=", "location_redirect", 0.3),
        (r"document\.cookie", "cookie_access", 0.4),
        (r"localStorage\.", "localstorage_access", 0.3),
        (r"XMLHttpRequest|fetch\s*\(", "network_request", 0.2),
    ]
    
    OBFUSCATION_INDICATORS = [
        r"[a-zA-Z]\w{50,}",  # Very long variable names
        r"_0x[a-fA-F0-9]{4,}",  # Hex variable names
        r"\$\w{10,}",  # jQuery-style long names
    ]
    
    def analyze(self, html: str) -> list[Indicator]:
        """Analyze HTML for suspicious JavaScript."""
        indicators = []
        
        # Extract inline scripts
        inline_scripts = self._extract_inline_scripts(html)
        
        # Count external scripts
        external_count = len(re.findall(r'<script[^>]+src\s*=', html))
        
        suspicious_found = []
        obfuscation_detected = False
        
        # Check each inline script
        for script in inline_scripts:
            # Check for suspicious patterns
            for pattern, name, score in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, script, re.IGNORECASE):
                    suspicious_found.append((name, score))
            
            # Check for obfuscation
            for obs_pattern in self.OBFUSCATION_INDICATORS:
                if re.search(obs_pattern, script):
                    obfuscation_detected = True
                    break
        
        # Generate indicators
        if suspicious_found:
            # Group by pattern type
            pattern_counts = {}
            for name, score in suspicious_found:
                if name not in pattern_counts:
                    pattern_counts[name] = {"count": 0, "score": score}
                pattern_counts[name]["count"] += 1
            
            for pattern_name, data in pattern_counts.items():
                indicators.append(Indicator(
                    name=f"suspicious_js_{pattern_name}",
                    score=min(0.9, data["score"] * (1 + 0.2 * (data["count"] - 1))),
                    severity="high" if data["score"] > 0.6 else "medium",
                    explanation=f"Found {data['count']} instance(s) of {pattern_name.replace('_', ' ')}",
                    evidence_ids=[],
                ))
        
        if obfuscation_detected:
            indicators.append(Indicator(
                name="js_obfuscation",
                score=0.6,
                severity="high",
                explanation="JavaScript code shows signs of obfuscation",
                evidence_ids=[],
            ))
        
        # High number of inline scripts
        if len(inline_scripts) > 5:
            indicators.append(Indicator(
                name="excessive_inline_scripts",
                score=0.3,
                severity="low",
                explanation=f"Page has {len(inline_scripts)} inline scripts",
                evidence_ids=[],
            ))
        
        return indicators
    
    def _extract_inline_scripts(self, html: str) -> list[str]:
        """Extract inline JavaScript from HTML."""
        scripts = []
        pattern = r'<script[^>]*>(.*?)</script>'
        
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        for match in matches:
            # Skip if it looks like an external script reference
            if 'src=' not in match and match.strip():
                scripts.append(match)
        
        return scripts
