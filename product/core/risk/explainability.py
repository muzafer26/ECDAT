"""
ECDAT Explainability Builder.

Phase 3C-B: Implements the authoritative seven-part explainability contract conforming
strictly to PHASE_3C_EXPLAINABILITY_MODEL.md §3:
<OBSERVED_FACTS, DERIVED_CLASSIFICATIONS, CONTEXT, RULES, ASSUMPTIONS, UNCERTAINTY, RESULT>
"""

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from product.core.domain.asset import CryptoAsset
from .enums import (
    ClassicalSecurityStatus,
    NetworkExposure,
    PrimaryRiskCause,
    PriorityTier,
    QuantumExposureClass,
    RiskCategory,
    UncertaintyLevel,
)
from .models import AssetContext, RiskExplanation

# Structured Rule Authority Registry
RULE_REGISTRY: Dict[str, Dict[str, str]] = {
    "R-RISK-01": {
        "rule_id": "R-RISK-01",
        "authority": "NIST SP 800-131A Rev 2",
        "section": "Section 2 & Table 1 / Section 5.1.2 & Table 2 / Section 8 & Table 8",
        "citation_url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
        "statement": "Disallowed for cryptographic uses in US Federal executive branch systems under FISMA/FIPS; widely adopted commercial baseline.",
    },
    "R-POSTURE-RSA": {
        "rule_id": "R-POSTURE-RSA",
        "authority": "NIST SP 800-131A Rev 2",
        "section": "Section 5.1.2 & Table 2",
        "citation_url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
        "statement": "RSA modulus < 2048 bits is disallowed for key generation, signature generation, and key transport (< 112 bits security strength).",
    },
    "R-POSTURE-SHA1": {
        "rule_id": "R-POSTURE-SHA1",
        "authority": "NIST SP 800-131A Rev 2",
        "section": "Section 8 & Table 8",
        "citation_url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
        "statement": "SHA-1 is disallowed for digital signature generation; deprecated for general hashing; acceptable for HMAC if key length >= 112 bits.",
    },
    "R-RISK-05A": {
        "rule_id": "R-RISK-05A",
        "authority": "ECDAT Deterministic Risk Model",
        "section": "PHASE_3C_RISK_MODEL.md §5",
        "citation_url": "internal://docs/PHASE_3C_RISK_MODEL.md",
        "statement": "Classical disallowed or acceptable cryptography in verified isolated non-production environment is mitigated to LOW risk.",
    },
    "R-RISK-06": {
        "rule_id": "R-RISK-06",
        "authority": "ECDAT Uncertainty Policy",
        "section": "PHASE_3C_UNKNOWN_AND_UNCERTAINTY_POLICY.md §2",
        "citation_url": "internal://docs/PHASE_3C_UNKNOWN_AND_UNCERTAINTY_POLICY.md",
        "statement": "Missing cryptographic facts, unannotated parameters, or unverified context prevent safe risk determination; routes to human triage.",
    },
    "R-RISK-POLICY-DECISION-REQUIRED": {
        "rule_id": "R-RISK-POLICY-DECISION-REQUIRED",
        "authority": "ECDAT Risk Model Governance",
        "section": "PHASE_3C_RISK_MODEL.md §1 & §5",
        "citation_url": "internal://docs/PHASE_3C_RISK_MODEL.md",
        "statement": "Phase 3C-A does not define an approved synthesis rule or PrimaryRiskCause for acceptable production ciphers without operational instantiation analysis (mode, IV, key management); requires project owner policy decision.",
    },
    "R-PRIORITY-P0-CLASSICAL-MANDATORY": {
        "rule_id": "R-PRIORITY-P0-CLASSICAL-MANDATORY",
        "authority": "ECDAT Contextual Prioritization Model",
        "section": "PHASE_3C_PRIORITY_MODEL.md §3",
        "citation_url": "internal://docs/PHASE_3C_PRIORITY_MODEL.md",
        "statement": "Confirmed classical disallowed cipher in production demands immediate P0 remediation regardless of migration runway.",
    },
    "R-PRIORITY-P4-DEFERRED-MONITORING": {
        "rule_id": "R-PRIORITY-P4-DEFERRED-MONITORING",
        "authority": "ECDAT Contextual Prioritization Model",
        "section": "PHASE_3C_PRIORITY_MODEL.md §3",
        "citation_url": "internal://docs/PHASE_3C_PRIORITY_MODEL.md",
        "statement": "Mitigated non-production risk maps to P4 deferred monitoring and annual review.",
    },
    "R-PRIORITY-P-REVIEW-REQUIRED": {
        "rule_id": "R-PRIORITY-P-REVIEW-REQUIRED",
        "authority": "ECDAT Contextual Prioritization Model",
        "section": "PHASE_3C_PRIORITY_MODEL.md §3",
        "citation_url": "internal://docs/PHASE_3C_PRIORITY_MODEL.md",
        "statement": "Unresolved uncertainty routes to P_REVIEW_REQUIRED for immediate human triage.",
    },
}


def build_explanation(
    asset: CryptoAsset,
    context: AssetContext,
    normalized_algo_name: str,
    classical_status: ClassicalSecurityStatus,
    quantum_exposure: QuantumExposureClass,
    uncertainty_level: UncertaintyLevel,
    risk_category: RiskCategory,
    primary_cause: PrimaryRiskCause,
    priority: PriorityTier,
    rules_applied: Sequence[str],
    standards_citation: str,
    mandatory_review: bool,
) -> RiskExplanation:
    """
    Constructs a deeply immutable, structured 7-part RiskExplanation.
    """
    algo_id = asset.algorithm_identity
    params = asset.parameters
    loc = asset.primary_location

    # 1. Observed Facts (Code/Manifest ground truth)
    observed_facts: Tuple[str, ...] = (
        f"raw_token={algo_id.algorithm}",
        f"asset_type={asset.asset_type.value}",
        f"algorithm_family={algo_id.family.value}",
        f"key_size_bits={params.key_size_bits if params else None}",
        f"cipher_mode={params.cipher_mode if params else None}",
        f"role={asset.role.value}",
        f"confidence={asset.confidence.value}",
    )
    evidence_ids: Tuple[str, ...] = tuple(asset.finding_ids)
    code_locations: Tuple[str, ...] = (
        f"{loc.file_path or 'unknown'}:L{loc.line_start or 0}-{loc.line_end or 0}",
    )

    # 2. Derived Classifications
    algorithm_identity_str = normalized_algo_name
    classical_status_str = classical_status.value
    quantum_exposure_class_str = quantum_exposure.value

    # 3. Context & Provenance
    context_summary: Dict[str, str] = {
        "deployment_environment": context.environment.value,
        "network_exposure": context.network_exposure.value,
        "migration_complexity": context.complexity.value,
        "context_authority": context.authority.value,
    }
    context_authority_str = context.authority.value

    # 4. Rules Triggered (Structured Records)
    triggered_rules: List[Dict[str, str]] = []
    for r_id in rules_applied:
        if r_id in RULE_REGISTRY:
            triggered_rules.append(dict(RULE_REGISTRY[r_id]))
        else:
            triggered_rules.append({
                "rule_id": r_id,
                "authority": "ECDAT Internal Policy",
                "section": "Unspecified",
                "citation_url": "",
                "statement": "Internal deterministic policy rule triggered.",
            })

    # 5. Explicit Assumptions (including explicit disclosure of deferred features)
    assumptions_list: List[str] = [
        standards_citation,
        "DEFERRED_ANALYSIS: Multi-dimensional HNDL matrix evaluation is deferred to Phase 3C-B Increment 3.",
        "DEFERRED_ANALYSIS: Mosca planning horizon heuristic (X+Y>Z) is deferred to Phase 3C-B Increment 4.",
        "DEFERRED_ANALYSIS: Enterprise signed policy override verification is deferred to Phase 3C-B Increment 5.",
    ]

    # 6. Uncertainty & Missing Gaps
    missing_gaps: List[str] = []
    if params is None or params.key_size_bits is None:
        if "AES" in normalized_algo_name:
            missing_gaps.append(
                "Missing key_size_bits: AES requires explicit key size (128, 192, 256) to verify security margin."
            )
    if context.environment == context.environment.UNKNOWN:
        missing_gaps.append("Deployment environment is UNKNOWN; production containment assumed.")
    if context.network_exposure == NetworkExposure.UNKNOWN:
        missing_gaps.append("Network exposure is UNKNOWN; isolation cannot be verified.")
    if "R-RISK-POLICY-DECISION-REQUIRED" in rules_applied:
        missing_gaps.append(
            "UNRESOLVED_POLICY_DECISION: Phase 3C-A rules R-01..R-06 define risk for vulnerabilities, non-production mitigations, and uncertainty, but do not define an approved synthesis rule or PrimaryRiskCause for acceptable production ciphers without operational instantiation analysis (mode, IV, key management)."
        )
    if not missing_gaps and mandatory_review:
        missing_gaps.append("Mandatory human review required due to contextual or parameter uncertainty.")

    # 7. Final Result
    risk_category_str = risk_category.value
    final_priority_tier_str = priority.value

    if priority == PriorityTier.P0_IMMEDIATE_ACTION:
        actionable_summary = (
            "IMMEDIATE ACTION REQUIRED: Confirmed classical disallowed cryptographic primitive in production; "
            "schedule replacement in current sprint."
        )
    elif priority == PriorityTier.P4_DEFERRED_MONITORING:
        actionable_summary = (
            "DEFERRED MONITORING: Cryptographic asset is mitigated in verified isolated non-production environment; "
            "retain for annual audit."
        )
    else:
        actionable_summary = (
            "HUMAN TRIAGE REQUIRED: Unresolved parameters, missing isolation evidence, or policy decisions require "
            "analyst review before scheduling migration."
        )

    return RiskExplanation(
        asset_id=asset.asset_id,
        observed_facts=observed_facts,
        evidence_ids=evidence_ids,
        code_locations=code_locations,
        algorithm_identity=algorithm_identity_str,
        classical_status=classical_status_str,
        quantum_exposure_class=quantum_exposure_class_str,
        context_summary=context_summary,
        context_authority=context_authority_str,
        triggered_rules=tuple(triggered_rules),
        assumptions=tuple(assumptions_list),
        uncertainty_level=uncertainty_level.value,
        missing_facts_and_questions=tuple(missing_gaps),
        risk_category=risk_category_str,
        final_priority_tier=final_priority_tier_str,
        actionable_remediation_summary=actionable_summary,
    )
