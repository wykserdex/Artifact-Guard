"""Web renderer client for safe page analysis."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class RenderResult:
    """Result of page rendering."""
    final_url: str
    title: str
    html: str
    screenshot: bytes
    redirects: list[str]
    load_time_ms: int
    status_code: int
    content_type: str


@dataclass
class FormInfo:
    """Information about a form on the page."""
    action: str
    method: str
    inputs: list[dict]
    has_password_field: bool
    has_credit_card_field: bool
    suspicious_action: bool


@dataclass
class JavaScriptInfo:
    """Information about JavaScript on the page."""
    inline_scripts: int
    external_scripts: int
    suspicious_patterns: list[str]
    obfuscation_detected: bool


@dataclass
class VisualInfo:
    """Visual analysis results."""
    logo_detected: Optional[str]
    brand_similarity: float
    suspicious_visual_elements: list[str]
