"""Configuration for Artifact Guard service."""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    """Application configuration loaded from environment variables."""
    
    # Broker settings
    redis_host: str = field(default_factory=lambda: os.getenv("REDIS_HOST", "localhost"))
    redis_port: int = field(default_factory=lambda: int(os.getenv("REDIS_PORT", "6379")))
    redis_db: int = field(default_factory=lambda: int(os.getenv("REDIS_DB", "0")))
    redis_password: str | None = field(default_factory=lambda: os.getenv("REDIS_PASSWORD"))
    
    # Database settings
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5432/artifact_guard"
        )
    )
    
    # Object storage
    object_storage_endpoint: str = field(
        default_factory=lambda: os.getenv("OBJECT_STORAGE_ENDPOINT", "http://localhost:9000")
    )
    object_storage_bucket: str = field(
        default_factory=lambda: os.getenv("OBJECT_STORAGE_BUCKET", "artifacts")
    )
    object_storage_access_key: str = field(
        default_factory=lambda: os.getenv("OBJECT_STORAGE_ACCESS_KEY", "")
    )
    object_storage_secret_key: str = field(
        default_factory=lambda: os.getenv("OBJECT_STORAGE_SECRET_KEY", "")
    )
    
    # Security
    encryption_key: bytes = field(
        default_factory=lambda: os.getenv("ENCRYPTION_KEY", "").encode() or b"default-key-32-bytes-long!!"
    )
    jwt_secret: str = field(default_factory=lambda: os.getenv("JWT_SECRET", "dev-secret"))
    
    # Analysis limits
    max_url_length: int = 4096
    max_file_size: int = 25 * 1024 * 1024  # 25 MB
    max_archive_files: int = 100
    max_unpacked_size: int = 100 * 1024 * 1024  # 100 MB
    max_archive_depth: int = 2
    max_compression_ratio: int = 100
    max_html_size: int = 5 * 1024 * 1024  # 5 MB
    
    # Renderer settings
    renderer_timeout_ms: int = 15000
    renderer_viewport_width: int = 1280
    renderer_viewport_height: int = 900
    renderer_max_redirects: int = 10
    
    # Scoring thresholds
    threshold_high_risk: float = 0.85
    threshold_suspicious: float = 0.55
    threshold_manual_review: float = 0.30
    
    # Retention (days)
    evidence_retention_days: int = 90
    analysis_retention_days: int = 365
    
    # Feature flags
    enable_active_analysis: bool = field(
        default_factory=lambda: os.getenv("ENABLE_ACTIVE_ANALYSIS", "true").lower() == "true"
    )
    enable_ocr: bool = field(
        default_factory=lambda: os.getenv("ENABLE_OCR", "false").lower() == "true"
    )
    enable_antivirus: bool = field(
        default_factory=lambda: os.getenv("ENABLE_ANTIVIRUS", "true").lower() == "true"
    )
    
    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_format: str = field(default_factory=lambda: os.getenv("LOG_FORMAT", "json"))


config = Config()
