"""Unit tests for hashing utilities."""

import pytest
from uuid import UUID, uuid4

from shared.hashing import (
    compute_sha256,
    compute_file_hash,
    compute_idempotency_key,
    secure_hash,
    uuid_to_hex,
    hex_to_uuid,
)


class TestComputeSha256:
    """Tests for SHA-256 computation."""

    def test_sha256_empty_bytes(self):
        """Test SHA-256 of empty bytes."""
        result = compute_sha256(b"")
        
        # SHA-256 of empty string
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result == expected

    def test_sha256_known_value(self):
        """Test SHA-256 with known input/output."""
        result = compute_sha256(b"hello world")
        
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert result == expected

    def test_sha256_deterministic(self):
        """Test that SHA-256 is deterministic."""
        data = b"test data for hashing"
        
        result1 = compute_sha256(data)
        result2 = compute_sha256(data)
        
        assert result1 == result2

    def test_sha256_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = compute_sha256(b"hello")
        hash2 = compute_sha256(b"world")
        
        assert hash1 != hash2

    def test_sha256_hex_format(self):
        """Test that result is proper hex string."""
        result = compute_sha256(b"test")
        
        # Should be 64 hex characters
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestIdempotencyKey:
    """Tests for idempotency key computation."""

    def test_idempotency_key_deterministic(self):
        """Test that same inputs produce same key."""
        key1 = compute_idempotency_key("url", "https://example.com", "v1")
        key2 = compute_idempotency_key("url", "https://example.com", "v1")
        
        assert key1 == key2

    def test_idempotency_key_different_artifact_types(self):
        """Test that different artifact types produce different keys."""
        key_url = compute_idempotency_key("url", "example.com", "v1")
        key_domain = compute_idempotency_key("domain", "example.com", "v1")
        
        assert key_url != key_domain

    def test_idempotency_key_different_values(self):
        """Test that different values produce different keys."""
        key1 = compute_idempotency_key("url", "https://example.com", "v1")
        key2 = compute_idempotency_key("url", "https://different.com", "v1")
        
        assert key1 != key2

    def test_idempotency_key_different_policy_versions(self):
        """Test that different policy versions produce different keys."""
        key_v1 = compute_idempotency_key("url", "https://example.com", "v1")
        key_v2 = compute_idempotency_key("url", "https://example.com", "v2")
        
        assert key_v1 != key_v2

    def test_idempotency_key_default_policy_version(self):
        """Test default policy version."""
        key1 = compute_idempotency_key("url", "https://example.com")
        key2 = compute_idempotency_key("url", "https://example.com", "v1")
        
        assert key1 == key2

    def test_idempotency_key_hex_format(self):
        """Test that key is proper hex string."""
        key = compute_idempotency_key("url", "https://example.com")
        
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)


class TestSecureHash:
    """Tests for secure hashing with salt."""

    def test_secure_hash_deterministic_with_same_salt(self):
        """Test that same value and salt produce same hash."""
        salt = "test-salt"
        value = "sensitive-data"
        
        hash1 = secure_hash(value, salt)
        hash2 = secure_hash(value, salt)
        
        assert hash1 == hash2

    def test_secure_hash_different_salts(self):
        """Test that different salts produce different hashes."""
        value = "sensitive-data"
        
        hash1 = secure_hash(value, "salt-1")
        hash2 = secure_hash(value, "salt-2")
        
        assert hash1 != hash2

    def test_secure_hash_different_values(self):
        """Test that different values produce different hashes."""
        salt = "test-salt"
        
        hash1 = secure_hash("value-1", salt)
        hash2 = secure_hash("value-2", salt)
        
        assert hash1 != hash2

    def test_secure_hash_default_salt(self):
        """Test that default salt is used when not provided."""
        hash1 = secure_hash("test-value")
        hash2 = secure_hash("test-value", "default-salt-change-in-production")
        
        assert hash1 == hash2

    def test_secure_hash_hex_format(self):
        """Test that result is proper hex string."""
        result = secure_hash("test")
        
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestUuidConversion:
    """Tests for UUID conversion utilities."""

    def test_uuid_to_hex_basic(self):
        """Test basic UUID to hex conversion."""
        test_uuid = UUID("12345678-1234-5678-1234-567812345678")
        hex_result = uuid_to_hex(test_uuid)
        
        assert hex_result == "12345678123456781234567812345678"

    def test_uuid_to_hex_no_hyphens(self):
        """Test that hex result has no hyphens."""
        test_uuid = uuid4()
        hex_result = uuid_to_hex(test_uuid)
        
        assert "-" not in hex_result
        assert len(hex_result) == 32

    def test_hex_to_uuid_roundtrip(self):
        """Test that hex to UUID converts back correctly."""
        original = uuid4()
        hex_str = uuid_to_hex(original)
        recovered = hex_to_uuid(hex_str)
        
        assert original == recovered

    def test_hex_to_uuid_from_known_hex(self):
        """Test converting known hex string to UUID."""
        hex_str = "12345678123456781234567812345678"
        result = hex_to_uuid(hex_str)
        
        assert str(result) == "12345678-1234-5678-1234-567812345678"

    def test_uuid_conversion_preserves_value(self):
        """Test that UUID value is preserved through conversion."""
        for _ in range(10):
            original = uuid4()
            hex_str = uuid_to_hex(original)
            recovered = hex_to_uuid(hex_str)
            assert original == recovered


class TestFileHash:
    """Tests for file hashing."""

    def test_compute_file_hash(self, tmp_path):
        """Test computing hash of a file."""
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"hello world")
        
        result = compute_file_hash(str(test_file))
        
        # Should match SHA-256 of "hello world"
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert result == expected

    def test_compute_file_hash_different_content(self, tmp_path):
        """Test that different file content produces different hash."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        
        file1.write_bytes(b"content 1")
        file2.write_bytes(b"content 2")
        
        hash1 = compute_file_hash(str(file1))
        hash2 = compute_file_hash(str(file2))
        
        assert hash1 != hash2

    def test_compute_file_hash_deterministic(self, tmp_path):
        """Test that file hash is deterministic."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")
        
        hash1 = compute_file_hash(str(test_file))
        hash2 = compute_file_hash(str(test_file))
        
        assert hash1 == hash2
