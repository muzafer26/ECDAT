"""
ECDAT Canonical Finding Domain Model.

Represents an ECDAT interpretation of one or more immutable empirical observations.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
import uuid

from product.core.evidence.evidence import EvidenceLocation, SourceLocation
from .algorithm import AlgorithmIdentity
from .role import CryptographicRole
from .parameters import AlgorithmParameters
from .confidence import ConfidenceLevel, DispositionStatus
from .observation import ObservationType


class FrozenIdTuple(tuple):
    """
    Immutable tuple representing an ID collection.
    Rejects in-place mutation and is equality-compatible with lists and tuples.
    """
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, (list, tuple)):
            return tuple(self) == tuple(other)
        return False

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


@dataclass(frozen=True)
class Finding:
    """
    ECDAT canonical representation of a discovery finding.
    
    Invariants:
    - Immutable after creation (frozen=True).
    - References one or more evidence records via evidence_ids (FrozenIdTuple).
    - Preserves evidence-backed algorithm identity, role, parameters, and location.
    - Tracks ECDAT analytical confidence independently from disposition status.
    """
    finding_id: str
    evidence_ids: Sequence[str]
    observation_type: ObservationType
    algorithm_identity: AlgorithmIdentity
    role: CryptographicRole
    parameters: AlgorithmParameters
    primary_location: EvidenceLocation
    confidence: ConfidenceLevel
    disposition: DispositionStatus = DispositionStatus.UNREVIEWED
    interpretation_basis: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError("Finding must reference at least one evidence_id")
        
        frozen_ev_ids = FrozenIdTuple(self.evidence_ids)
        object.__setattr__(self, "evidence_ids", frozen_ev_ids)

        if not self.finding_id:
            # Deterministic finding ID derived from canonical evidence IDs
            derived_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:finding:{','.join(sorted(frozen_ev_ids))}"))
            object.__setattr__(self, "finding_id", derived_id)

        if not isinstance(self.observation_type, ObservationType):
            object.__setattr__(self, "observation_type", ObservationType.from_str(str(self.observation_type)))
        if not isinstance(self.role, CryptographicRole):
            object.__setattr__(self, "role", CryptographicRole.from_str(str(self.role)))
        if not isinstance(self.confidence, ConfidenceLevel):
            object.__setattr__(self, "confidence", ConfidenceLevel.from_str(str(self.confidence)))
        if not isinstance(self.disposition, DispositionStatus):
            object.__setattr__(self, "disposition", DispositionStatus.from_str(str(self.disposition)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "evidence_ids": list(self.evidence_ids),
            "observation_type": self.observation_type.value,
            "algorithm_identity": self.algorithm_identity.to_dict(),
            "role": self.role.value,
            "parameters": self.parameters.to_dict(),
            "primary_location": self.primary_location.to_dict(),
            "confidence": self.confidence.value,
            "disposition": self.disposition.value,
            "interpretation_basis": self.interpretation_basis,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            finding_id=data.get("finding_id", ""),
            evidence_ids=tuple(data.get("evidence_ids", [])),
            observation_type=ObservationType.from_str(data.get("observation_type")),
            algorithm_identity=AlgorithmIdentity.from_dict(data["algorithm_identity"]),
            role=CryptographicRole.from_str(data.get("role")),
            parameters=AlgorithmParameters.from_dict(data.get("parameters")),
            primary_location=EvidenceLocation.from_dict(data["primary_location"]),
            confidence=ConfidenceLevel.from_str(data.get("confidence")),
            disposition=DispositionStatus.from_str(data.get("disposition")),
            interpretation_basis=data.get("interpretation_basis", ""),
        )
