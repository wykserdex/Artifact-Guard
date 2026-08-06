"""Safe file metadata extraction without opening files in GUI apps."""

import hashlib
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import magic


@dataclass
class FileMetadata:
    """Extracted file metadata."""

    file_path: str
    size: int
    sha256: str
    mime_type: str
    magic_mime: str
    extension: str
    is_archive: bool = False
    is_executable: bool = False
    contains_macros: bool = False


class FileMetadataAnalyzer:
    """Extract metadata from files safely."""

    # Dangerous MIME types that need extra scrutiny
    DANGEROUS_MIME_TYPES = {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
        "application/java-archive",
        "application/x-shellscript",
        "application/x-python-bytecode",
    }

    # Office documents that can contain macros
    MACRO_CAPABLE_MIME_TYPES = {
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }

    # Archive types
    ARCHIVE_MIME_TYPES = {
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-xz",
    }

    async def analyze(self, file_path: Path) -> FileMetadata:
        """Analyze file metadata without opening it in GUI applications."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Get basic info
        size = file_path.stat().st_size
        extension = file_path.suffix.lower()

        # Calculate SHA-256
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        sha256 = sha256_hash.hexdigest()

        # Detect MIME type by extension
        mime_type, _ = mimetypes.guess_type(str(file_path))
        mime_type = mime_type or "application/octet-stream"

        # Detect MIME type by content (magic bytes)
        magic_mime = "application/octet-stream"
        try:
            magic_mime = magic.from_file(str(file_path), mime=True)
        except Exception:
            # Fallback to extension-based detection
            pass

        # Check if archive
        is_archive = (
            magic_mime in self.ARCHIVE_MIME_TYPES
            or mime_type in self.ARCHIVE_MIME_TYPES
        )

        # Check if executable
        is_executable = (
            magic_mime in self.DANGEROUS_MIME_TYPES
            or mime_type in self.DANGEROUS_MIME_TYPES
            or extension in [".exe", ".dll", ".so", ".bin", ".sh", ".bat", ".cmd"]
        )

        # Check if potentially contains macros (static check only)
        contains_macros = False
        if magic_mime in self.MACRO_CAPABLE_MIME_TYPES or mime_type in self.MACRO_CAPABLE_MIME_TYPES:
            # Static check: look for macro indicators in first bytes
            # This is a simplified check; real macro detection requires more sophisticated parsing
            try:
                with open(file_path, "rb") as f:
                    header = f.read(1024)
                    # Simple heuristic: VBA projects often have specific signatures
                    if b"VBA" in header or b"Macro" in header:
                        contains_macros = True
            except Exception:
                pass

        return FileMetadata(
            file_path=str(file_path),
            size=size,
            sha256=sha256,
            mime_type=mime_type,
            magic_mime=magic_mime,
            extension=extension,
            is_archive=is_archive,
            is_executable=is_executable,
            contains_macros=contains_macros,
        )
