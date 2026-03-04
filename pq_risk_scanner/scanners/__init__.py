"""Scanner orchestrator — auto-detects file type and dispatches to the correct scanner."""

from __future__ import annotations

from pathlib import Path
from typing import List

from pq_risk_scanner.models import CryptographicFinding
from pq_risk_scanner.scanners.code_scanner import scan_source_file
from pq_risk_scanner.scanners.config_scanner import scan_config_file
from pq_risk_scanner.scanners.pem_scanner import scan_pem_file

_PEM_EXTENSIONS = {".pem", ".crt", ".cer", ".key", ".pub"}
_CONFIG_NAMES = {"nginx.conf", "httpd.conf", "sshd_config", "ssh_config"}
_CONFIG_EXTENSIONS = {".conf", ".cfg"}
_SOURCE_EXTENSIONS = {".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".c", ".cpp", ".cs"}


def _classify_file(path: Path) -> str:
    """Return 'pem', 'config', 'source', or 'unknown'."""
    if path.suffix.lower() in _PEM_EXTENSIONS:
        return "pem"

    # Check by content header for PEM files without standard extension
    try:
        head = path.read_bytes(
        )[:64]
        if b"-----BEGIN" in head:
            return "pem"
    except (OSError, UnicodeDecodeError):
        pass

    if path.name.lower() in _CONFIG_NAMES or path.suffix.lower() in _CONFIG_EXTENSIONS:
        return "config"

    if path.suffix.lower() in _SOURCE_EXTENSIONS:
        return "source"

    # Heuristic: if file name contains 'ssh' or 'tls' treat as config
    if any(kw in path.name.lower() for kw in ("ssh", "tls", "ssl", "cipher")):
        return "config"

    return "unknown"


def scan_path(target: Path, recursive: bool = True) -> List[CryptographicFinding]:
    """Scan a file or directory and return all cryptographic findings.

    Args:
        target: Path to a file or directory.
        recursive: If *target* is a directory, scan recursively.

    Returns:
        Aggregated list of ``CryptographicFinding`` objects.
    """
    if target.is_file():
        return _scan_single_file(target)

    if not target.is_dir():
        return []

    findings: List[CryptographicFinding] = []
    glob_pattern = "**/*" if recursive else "*"
    for child in sorted(target.glob(glob_pattern)):
        if child.is_file():
            findings.extend(_scan_single_file(child))
    return findings


def _scan_single_file(path: Path) -> List[CryptographicFinding]:
    """Dispatch a single file to the appropriate scanner."""
    file_type = _classify_file(path)

    if file_type == "pem":
        return scan_pem_file(path)
    if file_type == "config":
        return scan_config_file(path)
    if file_type == "source":
        return scan_source_file(path)

    return []
