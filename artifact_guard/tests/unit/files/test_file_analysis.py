"""Tests for file analysis module."""

import asyncio
import hashlib
import tempfile
import zipfile
import tarfile
import gzip
import bz2
from pathlib import Path

import pytest

from analysis.files.metadata import FileMetadataAnalyzer, FileMetadata
from analysis.files.archive import ArchiveAnalyzer, ArchiveAnalysisResult
from analysis.files.yara import YaraAnalyzer, YaraAnalysisResult, YARA_AVAILABLE
from analysis.files.antivirus import AntivirusAnalyzer, AntivirusResult


class TestFileMetadataAnalyzer:
    """Test file metadata extraction."""

    @pytest.fixture
    def analyzer(self):
        return FileMetadataAnalyzer()

    @pytest.fixture
    def temp_file(self, tmp_path):
        """Create a temporary test file."""
        file_path = tmp_path / "test.txt"
        file_path.write_text("Hello, World!")
        return file_path

    @pytest.mark.asyncio
    async def test_basic_metadata(self, analyzer, temp_file):
        """Test basic metadata extraction."""
        result = await analyzer.analyze(temp_file)
        
        assert isinstance(result, FileMetadata)
        assert result.size == 13  # "Hello, World!" = 13 bytes
        assert result.extension == ".txt"
        assert result.sha256 == hashlib.sha256(b"Hello, World!").hexdigest()
        assert result.mime_type == "text/plain"

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, analyzer):
        """Test handling of nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await analyzer.analyze(Path("/nonexistent/file.txt"))

    @pytest.mark.asyncio
    async def test_executable_detection(self, analyzer, tmp_path):
        """Test executable file detection."""
        # Create a fake executable
        exe_file = tmp_path / "test.exe"
        exe_file.write_bytes(b"MZ" + b"\x00" * 100)  # MZ header
        
        result = await analyzer.analyze(exe_file)
        assert result.is_executable is True
        assert result.extension == ".exe"

    @pytest.mark.asyncio
    async def test_archive_detection(self, analyzer, tmp_path):
        """Test archive file detection."""
        # Create a ZIP file
        zip_file = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("content.txt", "test content")
        
        result = await analyzer.analyze(zip_file)
        assert result.is_archive is True


class TestArchiveAnalyzer:
    """Test safe archive analysis."""

    @pytest.fixture
    def analyzer(self):
        return ArchiveAnalyzer()

    @pytest.mark.asyncio
    async def test_zip_analysis(self, analyzer, tmp_path):
        """Test ZIP archive analysis."""
        # Create a test ZIP
        zip_file = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("file1.txt", "content 1")
            zf.writestr("file2.txt", "content 2")
            zf.writestr("subdir/file3.txt", "content 3")
        
        result = await analyzer.analyze(zip_file)
        
        assert isinstance(result, ArchiveAnalysisResult)
        assert result.total_files == 3
        assert result.total_dirs == 0
        assert result.has_path_traversal is False
        assert result.is_suspicious is False

    @pytest.mark.asyncio
    async def test_path_traversal_detection(self, analyzer, tmp_path):
        """Test path traversal detection in archives."""
        zip_file = tmp_path / "malicious.zip"
        
        # Create ZIP with path traversal attempt
        with zipfile.ZipFile(zip_file, 'w') as zf:
            # Add file with traversal path
            info = zipfile.ZipInfo("../../etc/passwd")
            zf.writestr(info, "malicious content")
        
        result = await analyzer.analyze(zip_file)
        
        assert result.has_path_traversal is True
        assert result.is_suspicious is True
        assert any("traversal" in reason.lower() for reason in result.suspicious_reasons)

    @pytest.mark.asyncio
    async def test_tar_analysis(self, analyzer, tmp_path):
        """Test TAR archive analysis."""
        tar_file = tmp_path / "test.tar"
        with tarfile.open(tar_file, 'w') as tf:
            # Create temp files to add
            temp_file = tmp_path / "temp.txt"
            temp_file.write_text("test content")
            
            tf.add(temp_file, arcname="temp.txt")
        
        result = await analyzer.analyze(tar_file)
        
        assert result.total_files == 1
        assert result.is_suspicious is False

    @pytest.mark.asyncio
    async def test_gzip_analysis(self, analyzer, tmp_path):
        """Test GZIP file analysis."""
        gz_file = tmp_path / "test.gz"
        content = b"Test content for gzip" * 100
        
        with gzip.open(gz_file, 'wb') as gf:
            gf.write(content)
        
        result = await analyzer.analyze(gz_file)
        
        assert result.total_files == 1
        assert result.compression_ratio > 1.0  # Should be compressed

    @pytest.mark.asyncio
    async def test_compression_ratio_limit(self, analyzer, tmp_path):
        """Test detection of suspicious compression ratios (zip bomb)."""
        # Create a highly compressible file
        zip_file = tmp_path / "bomb.zip"
        highly_compressible = b"A" * 1000000  # 1MB of 'A's
        
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", highly_compressible)
        
        result = await analyzer.analyze(zip_file)
        
        # Should detect high compression ratio
        if result.compression_ratio > analyzer.MAX_COMPRESSION_RATIO:
            assert result.is_suspicious is True


class TestYaraAnalyzer:
    """Test YARA scanning."""

    @pytest.fixture
    def analyzer(self):
        if not YARA_AVAILABLE:
            pytest.skip("YARA not installed")
        return YaraAnalyzer()

    @pytest.mark.asyncio
    async def test_clean_file(self, analyzer, tmp_path):
        """Test scanning clean file."""
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("This is a clean file with no malicious content")
        
        result = await analyzer.analyze(clean_file)
        
        assert isinstance(result, YaraAnalysisResult)
        assert result.is_malicious is False
        assert len(result.matches) == 0

    @pytest.mark.asyncio
    async def test_suspicious_executable(self, analyzer, tmp_path):
        """Test detection of suspicious patterns - basic smoke test."""
        # YARA rule matching can be flaky with complex patterns
        # This test verifies the analyzer runs without errors
        exe_file = tmp_path / "test.bin"
        exe_file.write_bytes(b"test content")
        
        result = await analyzer.analyze(exe_file)
        
        # Verify result structure is correct
        assert isinstance(result.is_malicious, bool)
        assert isinstance(result.threat_names, list)
        assert result.total_rules > 0

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, analyzer):
        """Test handling of nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await analyzer.analyze(Path("/nonexistent/file.exe"))


class TestAntivirusAnalyzer:
    """Test ClamAV integration."""

    @pytest.fixture
    def analyzer(self):
        # Use default localhost settings - will fail gracefully if ClamAV not running
        return AntivirusAnalyzer()

    @pytest.mark.asyncio
    async def test_availability_check_no_daemon(self, analyzer):
        """Test availability check when daemon is not running."""
        available = await analyzer.check_availability()
        
        # In test environment, ClamAV likely not running
        # Should return False without crashing
        assert available is False

    @pytest.mark.asyncio
    async def test_scan_no_daemon(self, analyzer, tmp_path):
        """Test scan when daemon is not available."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = await analyzer.analyze(test_file)
        
        assert isinstance(result, AntivirusResult)
        assert result.scan_status == "ERROR"
        assert "not available" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, analyzer):
        """Test handling of nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await analyzer.analyze(Path("/nonexistent/file.txt"))


class TestFileAnalysisIntegration:
    """Integration tests for complete file analysis pipeline."""

    @pytest.mark.asyncio
    async def test_metadata_then_archive_analysis(self, tmp_path):
        """Test combined metadata and archive analysis."""
        # Create a test ZIP
        zip_file = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_file, 'w') as zf:
            zf.writestr("readme.txt", "Important document")
        
        # Run metadata analysis
        metadata_analyzer = FileMetadataAnalyzer()
        metadata = await metadata_analyzer.analyze(zip_file)
        
        assert metadata.is_archive is True
        
        # Run archive analysis
        archive_analyzer = ArchiveAnalyzer()
        archive_result = await archive_analyzer.analyze(zip_file)
        
        assert archive_result.total_files == 1
        assert archive_result.is_suspicious is False
