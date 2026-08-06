"""Hashing utilities for deduplication and integrity."""

import hashlib
from uuid import UUID


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of binary data."""
    return hashlib.sha256(data).hexdigest()


def compute_file_hash(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_idempotency_key(
    artifact_type: str,
    normalized_value: str,
    policy_version: str = "v1",
) -> str:
    """
    Compute idempotency key for deduplication.
    
    Prevents duplicate analysis of the same artifact.
    """
    key_material = f"{artifact_type}:{normalized_value}:{policy_version}"
    return hashlib.sha256(key_material.encode("utf-8")).hexdigest()


def secure_hash(value: str, salt: str | None = None) -> str:
    """
    Compute a secure hash of a value with optional salt.
    
    Used for hashing sensitive identifiers like chat IDs.
    """
    if salt is None:
        # In production, use a configured secret salt
        salt = "default-salt-change-in-production"
    
    key_material = f"{salt}:{value}"
    return hashlib.sha256(key_material.encode("utf-8")).hexdigest()


def uuid_to_hex(uuid_obj: UUID) -> str:
    """Convert UUID to hex string without hyphens."""
    return uuid_obj.hex


def hex_to_uuid(hex_str: str) -> UUID:
    """Convert hex string back to UUID."""
    return UUID(hex=hex_str)
