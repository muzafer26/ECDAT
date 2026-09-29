"""
ECDAT Canonical Models for Risk, Priority, Context, and Explainability.

Phase 3C-B: Immutable dataclasses strictly decoupling context,
technical risk, priority derivation, and explainability.
Enforces deep immutability via tuple containers and MappingProxyType.
"""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .enums import (
    ClassicalSecurityStatus,
    ContextAuthority,
    DeploymentEnvironment,
    MigrationComplexity,
    NetworkExposure,
    PrimaryRiskCause,
    PriorityTier,
    QuantumExposureClass,
    RiskCategory,
    UncertaintyLevel,
)


@dataclass(frozen=True)
class AssetContext:
    """
    Operational deployment context for a cryptographic asset.
    """
    environment: DeploymentEnvironment = DeploymentEnvironment.UNKNOWN
    network_exposure: NetworkExposure = NetworkExposure.UNKNOWN
    authority: ContextAuthority = ContextAuthority.UNASSESSED_DEFAULT
    complexity: MigrationComplexity = MigrationComplexity.UNKNOWN
    system_criticality: Optional[str] = None
    data_sensitivity: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.environment, DeploymentEnvironment):
            object.__setattr__(self, "environment", DeploymentEnvironment.from_str(str(self.environment)))
        if not isinstance(self.network_exposure, NetworkExposure):
            object.__setattr__(self, "network_exposure", NetworkExposure.from_str(str(self.network_exposure)))
        if not isinstance(self.authority, ContextAuthority):
            object.__setattr__(self, "authority", ContextAuthority.from_str(str(self.authority)))
        if not isinstance(self.complexity, MigrationComplexity):
            object.__setattr__(self, "complexity", MigrationComplexity.from_str(str(self.complexity)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment": self.environment.value,
            "network_exposure": self.network_exposure.value,
            "authority": self.authority.value,
            "complexity": self.complexity.value,
            "system_criticality": self.system_criticality,
            "data_sensitivity": self.data_sensitivity,
        }


@dataclass(frozen=True)
class RiskAssessment:
    """
    Authoritative, deterministic technical risk assessment for an asset.
    Strictly independent of migration priority and enterprise overrides.
    """
    asset_id: str
    risk_category: RiskCategory
    primary_cause: PrimaryRiskCause
    uncertainty_level: UncertaintyLevel
    classical_status: ClassicalSecurityStatus
    quantum_exposure: QuantumExposureClass
    rules_applied: Tuple[str, ...] = field(default_factory=tuple)
    mandatory_review_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "risk_category": self.risk_category.value,
            "primary_cause": self.primary_cause.value,
            "uncertainty_level": self.uncertainty_level.value,
            "classical_status": self.classical_status.value,
            "quantum_exposure": self.quantum_exposure.value,
            "rules_applied": list(self.rules_applied),
            "mandatory_review_required": self.mandatory_review_required,
        }


@dataclass(frozen=True)
class RiskExplanation:
    """
    Complete, seven-part auditable explanation accompanying every assessment.
    Conforms strictly to PHASE_3C_EXPLAINABILITY_MODEL.md §3:
    <OBSERVED_FACTS, DERIVED_CLASSIFICATIONS, CONTEXT, RULES, ASSUMPTIONS, UNCERTAINTY, RESULT>
    Deeply immutable: nested sequences are frozen as tuples, mappings as MappingProxyType.
    """
    asset_id: str

    # 1. Observed Facts
    observed_facts: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    code_locations: Tuple[str, ...]

    # 2. Derived Classifications
    algorithm_identity: str
    classical_status: str
    quantum_exposure_class: str

    # 3. Context & Provenance
    context_summary: Mapping[str, str]
    context_authority: str

    # 4. Rules Triggered (Structured audit records)
    triggered_rules: Tuple[Mapping[str, str], ...]

    # 5. Explicit Assumptions
    assumptions: Tuple[str, ...]

    # 6. Uncertainty & Missing Gaps
    uncertainty_level: str
    missing_facts_and_questions: Tuple[str, ...]

    # 7. Final Result
    risk_category: str
    final_priority_tier: str
    actionable_remediation_summary: str

    def __post_init__(self) -> None:
        # Enforce deep immutability against caller modification
        object.__setattr__(self, "observed_facts", tuple(self.observed_facts))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "code_locations", tuple(self.code_locations))
        object.__setattr__(self, "assumptions", tuple(self.assumptions))
        object.__setattr__(self, "missing_facts_and_questions", tuple(self.missing_facts_and_questions))

        # Deeply freeze context_summary
        object.__setattr__(
            self,
            "context_summary",
            MappingProxyType(dict(self.context_summary)),
        )

        # Deeply freeze structured triggered_rules
        frozen_rules = tuple(
            MappingProxyType(dict(r)) for r in self.triggered_rules
        )
        object.__setattr__(self, "triggered_rules", frozen_rules)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "observed_facts": list(self.observed_facts),
            "evidence_ids": list(self.evidence_ids),
            "code_locations": list(self.code_locations),
            "algorithm_identity": self.algorithm_identity,
            "classical_status": self.classical_status,
            "quantum_exposure_class": self.quantum_exposure_class,
            "context_summary": dict(self.context_summary),
            "context_authority": self.context_authority,
            "triggered_rules": [dict(r) for r in self.triggered_rules],
            "assumptions": list(self.assumptions),
            "uncertainty_level": self.uncertainty_level,
            "missing_facts_and_questions": list(self.missing_facts_and_questions),
            "risk_category": self.risk_category,
            "final_priority_tier": self.final_priority_tier,
            "actionable_remediation_summary": self.actionable_remediation_summary,
        }


@dataclass(frozen=True)
class MigrationPriorityRecord:
    """
    Actionable migration priority record.
    Preserves default technical priority, underlying technical risk category,
    and the complete 7-part explanation.
    """
    asset_id: str
    default_priority: PriorityTier
    effective_priority: PriorityTier
    risk_category: RiskCategory
    primary_cause: PrimaryRiskCause
    explanation: RiskExplanation
    mandatory_review_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "default_priority": self.default_priority.value,
            "effective_priority": self.effective_priority.value,
            "risk_category": self.risk_category.value,
            "primary_cause": self.primary_cause.value,
            "explanation": self.explanation.to_dict(),
            "mandatory_review_required": self.mandatory_review_required,
        }
