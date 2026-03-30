"""JSON reporter for CI/CD integration."""

import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional

from pq_risk_scanner.models import AnalysisResult


class _CustomEncoder(json.JSONEncoder):
    """Handles encoding dataclasses and enums to JSON."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj):
            return asdict(obj)
        return super().default(obj)


def generate_json_report(results: List[AnalysisResult], output_path: Optional[Path] = None) -> str:
    """Generate a JSON report of the analysis results.
    
    If output_path is provided, writes the JSON to the file.
    Returns the serialized JSON string.
    """
    json_data = json.dumps(results, cls=_CustomEncoder, indent=2)
    
    if output_path:
        output_path.write_text(json_data, encoding="utf-8")
        
    return json_data
