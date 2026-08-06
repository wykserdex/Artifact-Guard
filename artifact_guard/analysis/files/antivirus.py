"""ClamAV antivirus integration for file scanning."""

import asyncio
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class AntivirusResult:
    """Result of antivirus scan."""

    is_infected: bool
    virus_name: Optional[str]
    scan_status: str  # OK, ERROR, NOT_FOUND
    error_message: Optional[str] = None


class AntivirusAnalyzer:
    """Scan files using ClamAV daemon (clamd)."""

    def __init__(
        self,
        clamd_host: str = "localhost",
        clamd_port: int = 3310,
        timeout: float = 30.0,
    ):
        """Initialize ClamAV client."""
        self.clamd_host = clamd_host
        self.clamd_port = clamd_port
        self.timeout = timeout
        self._available = None

    async def check_availability(self) -> bool:
        """Check if ClamAV daemon is available."""
        if self._available is not None:
            return self._available

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.clamd_host, self.clamd_port),
                timeout=self.timeout,
            )
            
            # Send PING command
            writer.write(b"nPING\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            self._available = response.strip() == b"PONG"
            return self._available
            
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            self._available = False
            return False

    async def analyze(self, file_path: Path) -> AntivirusResult:
        """Scan file with ClamAV."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Check availability first
        available = await self.check_availability()
        if not available:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="ERROR",
                error_message="ClamAV daemon not available",
            )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.clamd_host, self.clamd_port),
                timeout=self.timeout,
            )

            # Send file for scanning using zINSTREAM protocol
            file_size = file_path.stat().st_size
            
            # Send stream header
            header = f"zINSTREAM\0{file_size}\0".encode()
            writer.write(header)
            
            # Send file content in chunks
            chunk_size = 8192
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    # Prepend chunk size as 4-byte network order integer
                    size_bytes = len(chunk).to_bytes(4, byteorder='big')
                    writer.write(size_bytes + chunk)
                    await writer.drain()
            
            # Send zero-length chunk to signal end
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            return self._parse_response(response.decode().strip())
            
        except asyncio.TimeoutError:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="ERROR",
                error_message="Scan timeout",
            )
        except Exception as e:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="ERROR",
                error_message=str(e),
            )

    def _parse_response(self, response: str) -> AntivirusResult:
        """Parse ClamAV response string."""
        # Expected formats:
        # stream: OK
        # stream: VirusName FOUND
        # stream: ERROR reason
        
        if ": OK" in response:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="OK",
            )
        elif " FOUND" in response:
            # Extract virus name
            parts = response.split(": ")
            virus_name = parts[1].replace(" FOUND", "") if len(parts) > 1 else "Unknown"
            return AntivirusResult(
                is_infected=True,
                virus_name=virus_name,
                scan_status="OK",
            )
        elif ": ERROR" in response or "ERROR" in response:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="ERROR",
                error_message=response,
            )
        else:
            return AntivirusResult(
                is_infected=False,
                virus_name=None,
                scan_status="ERROR",
                error_message=f"Unexpected response: {response}",
            )

    async def get_version(self) -> Optional[str]:
        """Get ClamAV version string."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.clamd_host, self.clamd_port),
                timeout=self.timeout,
            )
            
            writer.write(b"nVERSION\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            return response.decode().strip()
            
        except Exception:
            return None

    async def get_stats(self) -> Optional[str]:
        """Get ClamAV statistics."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.clamd_host, self.clamd_port),
                timeout=self.timeout,
            )
            
            writer.write(b"nSTATS\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.readuntil(b"\nEND"), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            return response.decode().strip()
            
        except Exception:
            return None
