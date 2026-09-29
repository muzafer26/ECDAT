"""
ECDAT Provenance Tracking Model.

Tracks the unbroken audit chain:
CryptoAsset -> Finding(s) -> EvidenceRecord(s) -> Raw Discovery Output
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .evidence import EvidenceRecord


@dataclass(frozen=True)
class ScannerMetadata:
    """Metadata regarding the external scanner tool and execution instance."""
    scanner_name: str
    scanner_version: str
    scan_id: str
    raw_output_ref: str
    timestamp: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scan_id": self.scan_id,
            "raw_output_ref": self.raw_output_ref,
            "timestamp": self.timestamp,
        }


@dataclass
class ProvenanceChain:
    """
    Maintains complete traceability from high-level canonical entities
    back to immutable evidence records and source raw outputs.
    """
    asset_id: str
    finding_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    raw_output_refs: List[str] = field(default_factory=list)

    @classmethod
    def from_evidence(cls, asset_id: str, finding_id: str, evidence: List[EvidenceRecord]) -> "ProvenanceChain":
        evidence_ids = [e.evidence_id for e in evidence]
        raw_refs = sorted(list({e.raw_output_ref for e in evidence if e.raw_output_ref}))
        return cls(
            asset_id=asset_id,
            finding_ids=[finding_id],
            evidence_ids=evidence_ids,
            raw_output_refs=raw_refs,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "finding_ids": list(self.finding_ids),
            "evidence_ids": list(self.evidence_ids),
            "raw_output_refs": list(self.raw_output_refs),
        }
