"""YARA rule-based malware detection."""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """Single YARA rule match."""

    rule_name: str
    namespace: str
    strings: List[tuple]  # (offset, identifier, matched_data)
    tags: List[str]
    meta: dict


@dataclass
class YaraAnalysisResult:
    """Result of YARA scan."""

    matches: List[YaraMatch]
    total_rules: int
    scan_duration_ms: float
    is_malicious: bool
    threat_names: List[str]


class YaraAnalyzer:
    """Scan files using YARA rules."""

    # Default embedded rules for common threats
    DEFAULT_RULES = r"""
    rule Suspicious_Executable {
        meta:
            description = "Detects suspicious executable patterns"
            threat_level = "medium"
        strings:
            $mz_header = "MZ"
            $pe_header = "PE\x00\x00"
            $upx = "UPX!"
        condition:
            $mz_header at 0 and $pe_header and $upx
    }

    rule Potential_Macro_Document {
        meta:
            description = "Detects Office documents with macro indicators"
            threat_level = "high"
        strings:
            $vba = "VBA" nocase
            $macro = "Macro" nocase
            $autoexec = "AutoExec" nocase
        condition:
            any of them
    }

    rule Suspicious_PowerShell {
        meta:
            description = "Detects PowerShell obfuscation patterns"
            threat_level = "high"
        strings:
            $ps1 = "-encodedcommand" nocase
            $ps2 = "-enc " nocase
            $ps3 = "FromBase64String" nocase
            $ps4 = "Invoke-Expression" nocase
        condition:
            any of them
    }

    rule Generic_Crypter {
        meta:
            description = "Detects generic crypter/packer patterns"
            threat_level = "medium"
        strings:
            $crypt1 = "Decrypt" nocase
            $crypt2 = "Unpack" nocase
            $crypt3 = "Payload" nocase
        condition:
            any of them
    }
    """

    def __init__(self, custom_rules_path: Optional[Path] = None):
        """Initialize YARA analyzer with optional custom rules."""
        self.rules = None
        self.custom_rules_path = custom_rules_path
        
        if not YARA_AVAILABLE:
            raise RuntimeError("YARA library not installed. Install with: pip install yara-python")

        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile YARA rules from default and custom sources."""
        rules_source = self.DEFAULT_RULES
        
        # Load custom rules if provided
        if self.custom_rules_path and self.custom_rules_path.exists():
            with open(self.custom_rules_path, "r") as f:
                rules_source += "\n\n" + f.read()

        try:
            self.rules = yara.compile(source=rules_source)
            self._rules_count = len(list(self.rules))  # Count rules manually
        except yara.SyntaxError as e:
            raise ValueError(f"YARA syntax error: {str(e)}")

    async def analyze(self, file_path: Path) -> YaraAnalysisResult:
        """Scan file with YARA rules."""
        import time
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        start_time = time.time()
        
        # Run YARA scan in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            None, 
            self._scan_file, 
            file_path
        )
        
        scan_duration = (time.time() - start_time) * 1000  # Convert to ms
        
        threat_names = [match.rule_name for match in matches]
        is_malicious = len(matches) > 0

        return YaraAnalysisResult(
            matches=matches,
            total_rules=self._rules_count,
            scan_duration_ms=scan_duration,
            is_malicious=is_malicious,
            threat_names=threat_names,
        )

    def _scan_file(self, file_path: Path) -> List[YaraMatch]:
        """Perform actual YARA scan (blocking operation)."""
        try:
            matches = self.rules.match(str(file_path))
            
            result = []
            for match in matches:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    strings=[(s.offset, s.identifier, s.matched_data.decode('utf-8', errors='ignore')) 
                            for s in match.strings],
                    tags=match.tags,
                    meta=dict(match.meta),
                )
                result.append(yara_match)
            
            return result
            
        except Exception as e:
            # Return empty list on scan errors
            return []
