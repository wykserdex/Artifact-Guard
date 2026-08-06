"""Ingress module for artifact intake and processing."""

from ingress.consumer import ConsumerService
from ingress.deduplication import DeduplicationService
from ingress.extractor import ArtifactExtractor

__all__ = ["ConsumerService", "DeduplicationService", "ArtifactExtractor"]
