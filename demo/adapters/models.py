"""
ECDAT Demo Discovery Adapter Models.

Defines the representation of scanner adapters and their implementation status.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class CapabilityClassification(str, Enum):
    """
    Three-Tier Capability Classification defined in D0 Section 18:
    - LIVE: Implemented in existing core and used by demo.
    - CONTROLLED_DEMO: Deterministic demonstration wrapper/scenario.
    - ARCHITECTURAL: Future capability shown only to explain product direction.
    """
    LIVE = "LIVE"
    CONTROLLED_DEMO = "CONTROLLED_DEMO"
    ARCHITECTURAL = "ARCHITECTURAL"


@dataclass(frozen=True)
class AdapterStatusInfo:
    """Status metadata for an external scanner discovery adapter."""
    adapter_id: str
    scanner_name: str
    scanner_version: str
    status: CapabilityClassification
    description: str
    supported_formats: List[str] = field(default_factory=list)
    limitations: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "status": self.status.value,
            "description": self.description,
            "supported_formats": list(self.supported_formats),
            "limitations": self.limitations,
        }
