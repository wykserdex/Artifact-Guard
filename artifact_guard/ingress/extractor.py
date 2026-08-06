"""Artifact extractor for parsing messages from untilscam_v3."""

import re
from typing import Any
from urllib.parse import urlparse

from shared.events import ArtifactType
from domain.artifact import RawArtifact
from shared.logging import get_logger

logger = get_logger(__name__)


class ArtifactExtractor:
    """Extracts artifacts from text messages."""

    # URL pattern supporting http, https, and common schemes
    URL_PATTERN = re.compile(
        r'\b(?:https?://|ftp://|ftps://)?'
        r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
        r'(?:/[^\s]*)?',
        re.IGNORECASE,
    )

    # Domain pattern (without scheme)
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        re.IGNORECASE,
    )

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b',
        re.IGNORECASE,
    )

    def __init__(self, extract_urls: bool = True, extract_domains: bool = True):
        self.extract_urls = extract_urls
        self.extract_domains = extract_domains

    def extract_from_text(self, text: str) -> list[RawArtifact]:
        """Extract all artifacts from a text message.
        
        Args:
            text: Input text to scan
            
        Returns:
            List of extracted raw artifacts
        """
        artifacts = []

        # Extract URLs first (more specific)
        if self.extract_urls:
            urls = self.URL_PATTERN.findall(text)
            for url in urls:
                # Validate it's actually a URL with a domain
                parsed = urlparse(url if "://" in url else f"http://{url}")
                if parsed.netloc:
                    artifact_type = ArtifactType.URL if parsed.scheme in ["http", "https"] else ArtifactType.TEXT
                    artifacts.append(
                        RawArtifact(
                            artifact_type=artifact_type,
                            value=url,
                            context=self._get_context(text, url),
                        )
                    )

        # Extract standalone domains (not part of URLs or emails)
        if self.extract_domains:
            domains = self.DOMAIN_PATTERN.findall(text)
            emails = set(self.EMAIL_PATTERN.findall(text))
            
            for domain in domains:
                # Skip if it's part of an email
                if any(domain in email for email in emails):
                    continue
                
                # Skip if already extracted as URL
                if any(domain in artifact.value for artifact in artifacts):
                    continue

                artifacts.append(
                    RawArtifact(
                        artifact_type=ArtifactType.DOMAIN,
                        value=domain,
                        context=self._get_context(text, domain),
                    )
                )

        return artifacts

    def _get_context(self, text: str, artifact_value: str, max_length: int = 200) -> str | None:
        """Extract surrounding context for an artifact.
        
        Args:
            text: Full text
            artifact_value: The artifact value to find context for
            max_length: Maximum context length
            
        Returns:
            Context string or None
        """
        try:
            pos = text.find(artifact_value)
            if pos == -1:
                return None

            start = max(0, pos - 50)
            end = min(len(text), pos + len(artifact_value) + 50)

            context = text[start:end].strip()
            if len(context) > max_length:
                context = context[:max_length] + "..."

            return context
        except Exception:
            return None

    def extract_from_dict(self, data: dict[str, Any]) -> RawArtifact | None:
        """Extract artifact from a structured dictionary.
        
        Expected format:
        {
            "artifact_type": "url" | "domain" | "file" | "text",
            "value": "...",
            "context_excerpt": "..."  # optional
        }
        
        Args:
            data: Dictionary with artifact data
            
        Returns:
            RawArtifact or None if invalid
        """
        try:
            artifact_type_str = data.get("artifact_type")
            value = data.get("value")

            if not artifact_type_str or not value:
                logger.warning(f"Missing artifact_type or value in data: {data}")
                return None

            artifact_type = ArtifactType(artifact_type_str.lower())
            context = data.get("context_excerpt")

            return RawArtifact(
                artifact_type=artifact_type,
                value=value,
                context=context,
            )
        except ValueError as e:
            logger.warning(f"Invalid artifact type in data: {data}, error: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to extract artifact from dict: {e}")
            return None
