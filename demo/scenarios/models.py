"""
ECDAT Demo Scenario Models.

Defines the structure and classification of controlled demonstration scenarios.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class ScenarioClassification(str, Enum):
    """Honest capability classification conforming to D0 Section 18."""
    LIVE = "LIVE"                          # Backed by real scanner output & fully supported adapter
    CONTROLLED_DEMO = "CONTROLLED_DEMO"    # Curated benchmark scenario for deterministic demonstration
    ARCHITECTURAL = "ARCHITECTURAL"        # Future architecture / not yet live


@dataclass(frozen=True)
class DemoScenario:
    """
    Metadata and file reference for a controlled demonstration scenario.
    Grounded in existing benchmark fixtures.
    """
    scenario_id: str
    name: str
    description: str
    target_name: str
    adapter_id: str
    fixture_path: Path
    classification: ScenarioClassification
    expected_primary_family: str
    expected_min_assets: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "target_name": self.target_name,
            "adapter_id": self.adapter_id,
            "fixture_path": str(self.fixture_path),
            "classification": self.classification.value,
            "expected_primary_family": self.expected_primary_family,
            "expected_min_assets": self.expected_min_assets,
            "metadata": dict(self.metadata),
        }
