"""Safe archive extraction with protection against zip bombs and path traversal."""

import zipfile
import tarfile
import gzip
import bz2
import lzma
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import io


@dataclass
class ArchiveEntry:
    """Information about an extracted archive entry."""

    name: str
    size: int
    compressed_size: int
    is_dir: bool
    safe_path: Path


@dataclass
class ArchiveAnalysisResult:
    """Result of archive analysis."""

    total_files: int
    total_dirs: int
    total_size: int
    compression_ratio: float
    max_depth: int
    entries: List[ArchiveEntry]
    has_path_traversal: bool = False
    has_symlinks: bool = False
    is_suspicious: bool = False
    suspicious_reasons: List[str] = None

    def __post_init__(self):
        if self.suspicious_reasons is None:
            self.suspicious_reasons = []


class ArchiveAnalyzer:
    """Safely analyze and extract archives with limits."""

    # Limits to prevent zip bombs and resource exhaustion
    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
    MAX_ARCHIVE_FILES = 100
    MAX_UNPACKED_SIZE = 100 * 1024 * 1024  # 100 MB
    MAX_ARCHIVE_DEPTH = 2
    MAX_COMPRESSION_RATIO = 100  # Ratio of uncompressed/compressed

    async def analyze(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze archive without full extraction."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Determine archive type
        mime_type = self._detect_archive_type(file_path)
        
        if mime_type == "application/zip":
            return await self._analyze_zip(file_path)
        elif mime_type in ["application/x-tar", "application/x-gtar"]:
            return await self._analyze_tar(file_path)
        elif mime_type in ["application/gzip", "application/x-gzip"]:
            return await self._analyze_gzip(file_path)
        elif mime_type in ["application/x-bzip2", "application/x-bzip"]:
            return await self._analyze_bzip2(file_path)
        elif mime_type in ["application/x-xz"]:
            return await self._analyze_xz(file_path)
        else:
            raise ValueError(f"Unsupported archive type: {mime_type}")

    def _detect_archive_type(self, file_path: Path) -> str:
        """Detect archive type from magic bytes."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(20)
                
                if header.startswith(b"PK"):
                    return "application/zip"
                elif header[:2] == b"\x1f\x8b":
                    return "application/gzip"
                elif header[:3] == b"BZh":
                    return "application/x-bzip2"
                elif header[:6] == b"\xfd7zXZ\x00":
                    return "application/x-xz"
                elif header[:2] == b"\x1f\x9d" or header[:2] == b"\x1f\xa0":
                    return "application/x-compress"
                # Check for tar (ustar at offset 257)
                with open(file_path, "rb") as f2:
                    f2.seek(257)
                    tar_magic = f2.read(5)
                    if tar_magic == b"ustar":
                        return "application/x-tar"
                        
        except Exception:
            pass
        
        # Fallback to extension
        ext = file_path.suffix.lower()
        if ext == ".zip":
            return "application/zip"
        elif ext in [".tar"]:
            return "application/x-tar"
        elif ext in [".gz", ".tgz"]:
            return "application/gzip"
        elif ext == ".bz2":
            return "application/x-bzip2"
        elif ext == ".xz":
            return "application/x-xz"
        
        return "application/octet-stream"

    async def _analyze_zip(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze ZIP archive safely."""
        entries: List[ArchiveEntry] = []
        total_size = 0
        total_compressed = 0
        max_depth = 0
        has_path_traversal = False
        has_symlinks = False
        suspicious_reasons = []

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist():
                    # Check file count limit
                    if len(entries) >= self.MAX_ARCHIVE_FILES:
                        suspicious_reasons.append(f"Too many files (>={self.MAX_ARCHIVE_FILES})")
                        break

                    # Calculate depth
                    depth = info.filename.count("/") + info.filename.count("\\")
                    max_depth = max(max_depth, depth)

                    # Check for path traversal
                    if ".." in info.filename or info.filename.startswith("/"):
                        has_path_traversal = True
                        suspicious_reasons.append(f"Path traversal detected: {info.filename}")
                        continue  # Skip creating safe_path for malicious entries

                    # Check for symlinks
                    if info.external_attr & 0xA000 == 0xA000:  # Symlink
                        has_symlinks = True
                        suspicious_reasons.append(f"Symlink detected: {info.filename}")
                        continue  # Skip creating safe_path for symlinks

                    # Check compression ratio (only for non-malicious entries)
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > self.MAX_COMPRESSION_RATIO:
                            suspicious_reasons.append(
                                f"Suspicious compression ratio {ratio:.1f} for {info.filename}"
                            )

                    # Create safe path
                    safe_path = self._safe_extract_path(Path("/tmp/safe_extract"), info.filename)

                    entry = ArchiveEntry(
                        name=info.filename,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                        is_dir=info.is_dir(),
                        safe_path=safe_path,
                    )
                    entries.append(entry)
                    total_size += info.file_size
                    total_compressed += info.compress_size

        except zipfile.BadZipFile as e:
            suspicious_reasons.append(f"Corrupted ZIP: {str(e)}")

        # Check depth limit
        if max_depth > self.MAX_ARCHIVE_DEPTH:
            suspicious_reasons.append(f"Archive depth {max_depth} exceeds limit {self.MAX_ARCHIVE_DEPTH}")

        compression_ratio = total_size / total_compressed if total_compressed > 0 else 0

        return ArchiveAnalysisResult(
            total_files=len([e for e in entries if not e.is_dir]),
            total_dirs=len([e for e in entries if e.is_dir]),
            total_size=total_size,
            compression_ratio=compression_ratio,
            max_depth=max_depth,
            entries=entries,
            has_path_traversal=has_path_traversal,
            has_symlinks=has_symlinks,
            is_suspicious=len(suspicious_reasons) > 0,
            suspicious_reasons=suspicious_reasons,
        )

    async def _analyze_tar(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze TAR archive safely."""
        entries: List[ArchiveEntry] = []
        total_size = 0
        max_depth = 0
        has_path_traversal = False
        has_symlinks = False
        suspicious_reasons = []

        try:
            with tarfile.open(file_path, "r:*") as tf:
                for member in tf.getmembers():
                    if len(entries) >= self.MAX_ARCHIVE_FILES:
                        suspicious_reasons.append(f"Too many files (>={self.MAX_ARCHIVE_FILES})")
                        break

                    depth = member.name.count("/") + member.name.count("\\")
                    max_depth = max(max_depth, depth)

                    if ".." in member.name or member.name.startswith("/"):
                        has_path_traversal = True
                        suspicious_reasons.append(f"Path traversal detected: {member.name}")

                    if member.issym() or member.islnk():
                        has_symlinks = True
                        suspicious_reasons.append(f"Symlink detected: {member.name}")

                    safe_path = self._safe_extract_path(Path("/tmp/safe_extract"), member.name)

                    entry = ArchiveEntry(
                        name=member.name,
                        size=member.size,
                        compressed_size=member.size,  # TAR doesn't compress by default
                        is_dir=member.isdir(),
                        safe_path=safe_path,
                    )
                    entries.append(entry)
                    total_size += member.size

        except tarfile.TarError as e:
            suspicious_reasons.append(f"Corrupted TAR: {str(e)}")

        if max_depth > self.MAX_ARCHIVE_DEPTH:
            suspicious_reasons.append(f"Archive depth {max_depth} exceeds limit {self.MAX_ARCHIVE_DEPTH}")

        return ArchiveAnalysisResult(
            total_files=len([e for e in entries if not e.is_dir]),
            total_dirs=len([e for e in entries if e.is_dir]),
            total_size=total_size,
            compression_ratio=1.0,
            max_depth=max_depth,
            entries=entries,
            has_path_traversal=has_path_traversal,
            has_symlinks=has_symlinks,
            is_suspicious=len(suspicious_reasons) > 0,
            suspicious_reasons=suspicious_reasons,
        )

    async def _analyze_gzip(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze GZIP file safely."""
        try:
            with gzip.open(file_path, "rb") as gf:
                # Read limited amount to estimate size
                total_size = 0
                chunk_count = 0
                while chunk := gf.read(8192):
                    total_size += len(chunk)
                    chunk_count += 1
                    if chunk_count > self.MAX_UNPACKED_SIZE // 8192:
                        break

            compressed_size = file_path.stat().st_size
            ratio = total_size / compressed_size if compressed_size > 0 else 0

            return ArchiveAnalysisResult(
                total_files=1,
                total_dirs=0,
                total_size=total_size,
                compression_ratio=ratio,
                max_depth=0,
                entries=[],
                is_suspicious=ratio > self.MAX_COMPRESSION_RATIO,
                suspicious_reasons=[f"High compression ratio: {ratio:.1f}"] if ratio > self.MAX_COMPRESSION_RATIO else [],
            )
        except Exception as e:
            return ArchiveAnalysisResult(
                total_files=0,
                total_dirs=0,
                total_size=0,
                compression_ratio=0,
                max_depth=0,
                entries=[],
                is_suspicious=True,
                suspicious_reasons=[f"Error reading GZIP: {str(e)}"],
            )

    async def _analyze_bzip2(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze BZIP2 file safely."""
        # Similar to GZIP but for BZIP2
        try:
            with bz2.open(file_path, "rb") as bf:
                total_size = 0
                chunk_count = 0
                while chunk := bf.read(8192):
                    total_size += len(chunk)
                    chunk_count += 1
                    if chunk_count > self.MAX_UNPACKED_SIZE // 8192:
                        break

            compressed_size = file_path.stat().st_size
            ratio = total_size / compressed_size if compressed_size > 0 else 0

            return ArchiveAnalysisResult(
                total_files=1,
                total_dirs=0,
                total_size=total_size,
                compression_ratio=ratio,
                max_depth=0,
                entries=[],
                is_suspicious=ratio > self.MAX_COMPRESSION_RATIO,
                suspicious_reasons=[f"High compression ratio: {ratio:.1f}"] if ratio > self.MAX_COMPRESSION_RATIO else [],
            )
        except Exception as e:
            return ArchiveAnalysisResult(
                total_files=0,
                total_dirs=0,
                total_size=0,
                compression_ratio=0,
                max_depth=0,
                entries=[],
                is_suspicious=True,
                suspicious_reasons=[f"Error reading BZIP2: {str(e)}"],
            )

    async def _analyze_xz(self, file_path: Path) -> ArchiveAnalysisResult:
        """Analyze XZ file safely."""
        # Similar implementation for XZ
        try:
            with lzma.open(file_path, "rb") as xf:
                total_size = 0
                chunk_count = 0
                while chunk := xf.read(8192):
                    total_size += len(chunk)
                    chunk_count += 1
                    if chunk_count > self.MAX_UNPACKED_SIZE // 8192:
                        break

            compressed_size = file_path.stat().st_size
            ratio = total_size / compressed_size if compressed_size > 0 else 0

            return ArchiveAnalysisResult(
                total_files=1,
                total_dirs=0,
                total_size=total_size,
                compression_ratio=ratio,
                max_depth=0,
                entries=[],
                is_suspicious=ratio > self.MAX_COMPRESSION_RATIO,
                suspicious_reasons=[f"High compression ratio: {ratio:.1f}"] if ratio > self.MAX_COMPRESSION_RATIO else [],
            )
        except Exception as e:
            return ArchiveAnalysisResult(
                total_files=0,
                total_dirs=0,
                total_size=0,
                compression_ratio=0,
                max_depth=0,
                entries=[],
                is_suspicious=True,
                suspicious_reasons=[f"Error reading XZ: {str(e)}"],
            )

    def _safe_extract_path(self, root: Path, member_name: str) -> Path:
        """Ensure extracted path is within root directory (prevent Zip Slip)."""
        root = root.resolve()
        # Normalize the member name to prevent traversal
        safe_name = member_name.replace("\\", "/").lstrip("/")
        target = (root / safe_name).resolve()

        # Ensure the target is within root
        try:
            target.relative_to(root)
        except ValueError:
            raise ValueError(f"Archive path traversal detected: {member_name}")

        return target
