"""Scanner orchestrator — auto-detects file type and dispatches to the correct scanner."""

from __future__ import annotations

from pathlib import Path
import fnmatch
from typing import List

from pq_risk_scanner.models import CryptographicFinding
from pq_risk_scanner.scanners.code_scanner import scan_source_file
from pq_risk_scanner.scanners.config_scanner import scan_config_file
from pq_risk_scanner.scanners.jwt_scanner import scan_jwt_file
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


def _load_pqignore(target: Path) -> List[str]:
    """Load ignore patterns from a .pqignore file in the target directory."""
    ignore_file = target / ".pqignore"
    if not ignore_file.is_file():
        return []
    
    patterns = []
    try:
        with ignore_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def _is_ignored(path: Path, base_dir: Path, ignore_patterns: List[str]) -> bool:
    """Check if a path matches any of the ignore patterns."""
    if not ignore_patterns:
        return False
        
    try:
        rel_path = path.relative_to(base_dir).as_posix()
    except ValueError:
        rel_path = path.as_posix()
        
    for pattern in ignore_patterns:
        # Match exact filename or glob pattern on relative path
        if fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(rel_path, pattern):
            return True
        # Match directory prefixes (e.g., node_modules will match node_modules/...)
        dir_prefix = pattern.rstrip("/") + "/"
        if rel_path.startswith(dir_prefix) or f"/{dir_prefix}" in f"/{rel_path}":
            return True
    return False


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

    ignore_patterns = _load_pqignore(target)
    findings: List[CryptographicFinding] = []
    glob_pattern = "**/*" if recursive else "*"
    for child in sorted(target.glob(glob_pattern)):
        if child.is_file():
            if not _is_ignored(child, target, ignore_patterns):
                findings.extend(_scan_single_file(child))
    return findings


def _scan_single_file(path: Path) -> List[CryptographicFinding]:
    """Dispatch a single file to the appropriate scanner."""
    file_type = _classify_file(path)

    findings = []
    if file_type == "pem":
        findings.extend(scan_pem_file(path))
    elif file_type == "config":
        findings.extend(scan_config_file(path))
        findings.extend(scan_jwt_file(path))
    elif file_type == "source":
        findings.extend(scan_source_file(path))
        findings.extend(scan_jwt_file(path))

    return findings
