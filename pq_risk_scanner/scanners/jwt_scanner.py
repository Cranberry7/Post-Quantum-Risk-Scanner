"""Scanner for discovering JWTs and extracting their cryptographic headers."""

import base64
import json
import re
from pathlib import Path
from typing import List

from pq_risk_scanner.models import AlgorithmFamily, CryptographicFinding, UsageContext

# Matches standard compact JWTs header.payload.signature
JWT_PATTERN = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)

def _decode_b64url(s: str) -> str:
    # Add base64 padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8")

def scan_jwt_content(content: str, source_file: str) -> List[CryptographicFinding]:
    """Scan string content for hardcoded JWTs."""
    findings = []
    
    for i, line in enumerate(content.splitlines(), start=1):
        for match in JWT_PATTERN.finditer(line):
            header_b64 = match.group(1)
            try:
                header_json = _decode_b64url(header_b64)
                header = json.loads(header_json)
                
                alg = header.get("alg")
                if not alg or alg.upper() == "NONE":
                    continue
                    
                family = AlgorithmFamily.SIGNATURE
                if alg.startswith("HS"):
                    family = AlgorithmFamily.HASH
                elif alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
                    family = AlgorithmFamily.SIGNATURE
                    
                finding = CryptographicFinding(
                    algorithm=alg,
                    key_size=None,
                    source_file=source_file,
                    usage_context=UsageContext.JWT,
                    algorithm_family=family,
                    line_number=i,
                    raw_match=match.group(0)[:30] + "..."  # Truncate to avoid printing full tokens
                )
                findings.append(finding)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
                
    return findings

def scan_jwt_file(path: Path) -> List[CryptographicFinding]:
    """Read file and extract JWT findings."""
    try:
        content = path.read_text(encoding="utf-8")
        return scan_jwt_content(content, path.name)
    except OSError:
        return []
