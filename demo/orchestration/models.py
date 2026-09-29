"""
ECDAT Demo Presentation-Safe Result Models.

Establishes the anti-corruption boundary between the internal frozen ECDAT core
domain objects and external presentation/UI layers.
Preserves full evidence provenance, context, risk, and migration scheduling details.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DemoExecutionStatus(str, Enum):
    """Execution status distinguishing successful analysis from partial or failure states."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class ProvenanceSourceType(str, Enum):
    """
    Authoritative Provenance Classification (Phase D5 Section 4):
    - DIRECT_CORE_OUTPUT: Produced directly by frozen ECDAT core.
    - CONTROLLED_SCENARIO_CONTEXT: Intentionally supplied by demo scenario configuration.
    - BENCHMARK_GROUND_TRUTH: Facts known from fixture, not established by scanner AST evidence.
    - FUTURE_ARCHITECTURE: Planned future capabilities not executed in current demo.
    - DETERMINISTIC_TRANSFORMATION: Backward-compatible alias for presentation projection.
    - CONTROLLED_DEMO_REPRESENTATION: Backward-compatible alias for demo representations.
    """
    DIRECT_CORE_OUTPUT = "DIRECT_CORE_OUTPUT"
    CONTROLLED_SCENARIO_CONTEXT = "CONTROLLED_SCENARIO_CONTEXT"
    CONTROLLED_DEMONSTRATION_CONTEXT = "CONTROLLED_DEMONSTRATION_CONTEXT"
    BENCHMARK_GROUND_TRUTH = "BENCHMARK_GROUND_TRUTH"
    FUTURE_ARCHITECTURE = "FUTURE_ARCHITECTURE"
    DETERMINISTIC_TRANSFORMATION = "DETERMINISTIC_TRANSFORMATION"
    CONTROLLED_DEMO_REPRESENTATION = "CONTROLLED_DEMO_REPRESENTATION"


@dataclass(frozen=True)
class ProvenanceNode:
    """Represents a discrete step in the intellectual trace from scanner to schedule."""
    step: str             # e.g., "scanner", "raw_evidence", "finding", "crypto_asset", "risk", "migration", "schedule"
    entity_id: str
    label: str
    source_type: str      # ProvenanceSourceType value
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "entity_id": self.entity_id,
            "label": self.label,
            "source_type": self.source_type,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class DemoEvidenceSummary:
    """Presentation-safe summary of an immutable empirical evidence record."""
    evidence_id: str
    scanner_name: str
    scanner_version: str
    detection_method: str
    location_type: str
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    matched_text: str
    code_snippet: str
    scanner_category: str
    scanner_confidence: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "detection_method": self.detection_method,
            "location_type": self.location_type,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "matched_text": self.matched_text,
            "code_snippet": self.code_snippet,
            "scanner_category": self.scanner_category,
            "scanner_confidence": self.scanner_confidence,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class DemoFindingSummary:
    """Presentation-safe summary of an ECDAT finding."""
    finding_id: str
    evidence_ids: List[str]
    observation_type: str
    family: str
    algorithm: str
    role: str
    confidence: str
    disposition: str
    location_display: str
    interpretation_basis: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "evidence_ids": list(self.evidence_ids),
            "observation_type": self.observation_type,
            "family": self.family,
            "algorithm": self.algorithm,
            "role": self.role,
            "confidence": self.confidence,
            "disposition": self.disposition,
            "location_display": self.location_display,
            "interpretation_basis": self.interpretation_basis,
        }


@dataclass(frozen=True)
class DemoAssetSummary:
    """Presentation-safe summary of a canonical Cryptographic Asset with full risk and migration context."""
    asset_id: str
    asset_type: str
    family: str
    algorithm: str
    role: str
    key_size_bits: Optional[int]
    curve_name: Optional[str]
    confidence: str
    location_display: str
    correlation_basis: str
    finding_ids: List[str]
    evidence_ids: List[str]
    priority_tier: Optional[str]
    risk_category: Optional[str]
    primary_risk_cause: Optional[str]
    classical_status: Optional[str]
    quantum_exposure_class: Optional[str]
    uncertainty_level: Optional[str]
    remediation_summary: Optional[str]
    observed_facts: List[str] = field(default_factory=list)
    triggered_rules: List[Dict[str, str]] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    missing_facts: List[str] = field(default_factory=list)
    pqc_mapping_status: Optional[str] = None
    candidate_targets: List[str] = field(default_factory=list)
    target_details: List[Dict[str, Any]] = field(default_factory=list)
    mapping_rationale: Optional[str] = None
    standards_references: List[str] = field(default_factory=list)
    agility_level: Optional[str] = None
    agility_factors: List[str] = field(default_factory=list)
    requires_human_review: bool = False
    review_reasons: List[str] = field(default_factory=list)
    organization: Optional[str] = None
    system: Optional[str] = None
    component: Optional[str] = None
    business_criticality: Optional[str] = None
    data_sensitivity: Optional[str] = None
    data_lifetime: Optional[str] = None
    network_exposure: Optional[str] = None
    environment: Optional[str] = None
    hybrid_candidates: List[Dict[str, Any]] = field(default_factory=list)
    context_provenance: str = "CONTROLLED_SCENARIO_CONTEXT"
    benchmark_ground_truth: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "family": self.family,
            "algorithm": self.algorithm,
            "role": self.role,
            "key_size_bits": self.key_size_bits,
            "curve_name": self.curve_name,
            "confidence": self.confidence,
            "location_display": self.location_display,
            "correlation_basis": self.correlation_basis,
            "finding_ids": list(self.finding_ids),
            "evidence_ids": list(self.evidence_ids),
            "priority_tier": self.priority_tier,
            "risk_category": self.risk_category,
            "primary_risk_cause": self.primary_risk_cause,
            "classical_status": self.classical_status,
            "quantum_exposure_class": self.quantum_exposure_class,
            "uncertainty_level": self.uncertainty_level,
            "remediation_summary": self.remediation_summary,
            "observed_facts": list(self.observed_facts),
            "triggered_rules": [dict(r) for r in self.triggered_rules],
            "assumptions": list(self.assumptions),
            "missing_facts": list(self.missing_facts),
            "pqc_mapping_status": self.pqc_mapping_status,
            "candidate_targets": list(self.candidate_targets),
            "target_details": [dict(t) for t in self.target_details],
            "mapping_rationale": self.mapping_rationale,
            "standards_references": list(self.standards_references),
            "agility_level": self.agility_level,
            "agility_factors": list(self.agility_factors),
            "requires_human_review": self.requires_human_review,
            "review_reasons": list(self.review_reasons),
            "organization": self.organization,
            "system": self.system,
            "component": self.component,
            "business_criticality": self.business_criticality,
            "data_sensitivity": self.data_sensitivity,
            "data_lifetime": self.data_lifetime,
            "network_exposure": self.network_exposure,
            "environment": self.environment,
            "hybrid_candidates": [dict(h) for h in self.hybrid_candidates],
            "context_provenance": self.context_provenance,
            "benchmark_ground_truth": dict(self.benchmark_ground_truth) if self.benchmark_ground_truth else None,
        }


@dataclass(frozen=True)
class DemoRiskSummary:
    """Presentation-safe summary of risk and quantum exposure."""
    total_assets_evaluated: int
    critical_priority_count: int
    high_priority_count: int
    medium_priority_count: int
    low_priority_count: int
    informational_priority_count: int
    mandatory_review_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_assets_evaluated": self.total_assets_evaluated,
            "critical_priority_count": self.critical_priority_count,
            "high_priority_count": self.high_priority_count,
            "medium_priority_count": self.medium_priority_count,
            "low_priority_count": self.low_priority_count,
            "informational_priority_count": self.informational_priority_count,
            "mandatory_review_count": self.mandatory_review_count,
        }


@dataclass(frozen=True)
class DemoMigrationSummary:
    """Presentation-safe summary of Phase 4 PQC migration intelligence and scheduling."""
    phase_4_status: str
    pqc_recommended_count: int
    out_of_scope_count: int
    needs_review_count: int
    total_milestones: int
    blocking_gates_count: int
    schedule_status: str
    advisory_notice: str
    candidate_target_summary: List[Dict[str, Any]] = field(default_factory=list)
    milestones: List[Dict[str, Any]] = field(default_factory=list)
    review_gates: List[Dict[str, Any]] = field(default_factory=list)
    blocked_assets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase_4_status": self.phase_4_status,
            "pqc_recommended_count": self.pqc_recommended_count,
            "out_of_scope_count": self.out_of_scope_count,
            "needs_review_count": self.needs_review_count,
            "total_milestones": self.total_milestones,
            "blocking_gates_count": self.blocking_gates_count,
            "schedule_status": self.schedule_status,
            "advisory_notice": self.advisory_notice,
            "candidate_target_summary": [dict(c) for c in self.candidate_target_summary],
            "milestones": [dict(m) for m in self.milestones],
            "review_gates": [dict(g) for g in self.review_gates],
            "blocked_assets": list(self.blocked_assets),
        }


@dataclass(frozen=True)
class DemoRunResult:
    """
    Top-level presentation-safe demo run result.
    Maintains complete isolation between UI and internal dataclasses.
    """
    run_id: str
    scenario_id: str
    status: DemoExecutionStatus
    classification: str
    raw_input_ref: str
    scanner_name: str
    scanner_version: str
    execution_time_ms: float
    assets: List[DemoAssetSummary]
    evidence_records: List[DemoEvidenceSummary]
    findings: List[DemoFindingSummary]
    risk_summary: DemoRiskSummary
    migration_summary: DemoMigrationSummary
    cbom_summary: Dict[str, Any]
    provenance_chain: List[List[ProvenanceNode]]
    known_limitations: List[str]
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "status": self.status.value,
            "classification": self.classification,
            "raw_input_ref": self.raw_input_ref,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "execution_time_ms": self.execution_time_ms,
            "assets_count": len(self.assets),
            "evidence_count": len(self.evidence_records),
            "findings_count": len(self.findings),
            "assets": [a.to_dict() for a in self.assets],
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "findings": [f.to_dict() for f in self.findings],
            "risk_summary": self.risk_summary.to_dict(),
            "migration_summary": self.migration_summary.to_dict(),
            "cbom_summary": dict(self.cbom_summary),
            "provenance_chain": [[node.to_dict() for node in chain] for chain in self.provenance_chain],
            "known_limitations": list(self.known_limitations),
            "error_message": self.error_message,
            "error": self.error_message,
        }
