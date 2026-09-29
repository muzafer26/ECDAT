"""
ECDAT Deterministic Risk Synthesis Rules.

Phase 3C-B: Implements deterministic synthesis rules (R-RISK-01, R-RISK-05A, R-RISK-06)
with strict boundary validation:
- Confirmed classical breaks in production unconditionally retain CRITICAL risk.
- Non-production mitigation (R-05A) requires verified isolation evidence (NetworkExposure).
- Missing parameters (e.g. unannotated AES key size) route to NEEDS_REVIEW (R-06).
- Acceptable production ciphers without instantiation analysis (mode, IV) are NOT falsely
  labeled NON_PROD_MITIGATED or silently assumed LOW; they disclose an unresolved policy decision.
"""

from typing import Tuple

from product.core.domain.asset import CryptoAsset
from .enums import (
    ClassicalSecurityStatus,
    DeploymentEnvironment,
    NetworkExposure,
    PrimaryRiskCause,
    QuantumExposureClass,
    RiskCategory,
    UncertaintyLevel,
)
from .models import AssetContext, RiskAssessment


def evaluate_risk_rules(
    asset: CryptoAsset,
    context: AssetContext,
    classical_status: ClassicalSecurityStatus,
    quantum_exposure: QuantumExposureClass,
    posture_uncertainty: UncertaintyLevel,
) -> RiskAssessment:
    """
    Synthesizes technical risk category, primary cause, and uncertainty.
    """
    env = context.environment
    exposure = context.network_exposure
    is_prod = env in (DeploymentEnvironment.PRODUCTION, DeploymentEnvironment.UNVERIFIED_ENVIRONMENT)
    is_non_prod = env in (DeploymentEnvironment.DEVELOPMENT, DeploymentEnvironment.TEST_FIXTURE)
    is_verified_isolated = exposure in (NetworkExposure.ISOLATED_AIRGAPPED, NetworkExposure.INTERNAL_VPC)

    has_uncertainty = (
        posture_uncertainty in (UncertaintyLevel.HIGH_UNCERTAINTY, UncertaintyLevel.NEEDS_REVIEW)
        or env in (DeploymentEnvironment.UNKNOWN, DeploymentEnvironment.UNVERIFIED_ENVIRONMENT)
        or exposure in (NetworkExposure.UNKNOWN, NetworkExposure.UNVERIFIED_EXPOSURE)
    )

    # 1. R-RISK-01: Classical disallowed cipher in production / unverified environment
    if classical_status == ClassicalSecurityStatus.DISALLOWED and is_prod:
        return RiskAssessment(
            asset_id=asset.asset_id,
            risk_category=RiskCategory.CRITICAL,
            primary_cause=PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD,
            uncertainty_level=UncertaintyLevel.NEEDS_REVIEW if has_uncertainty else UncertaintyLevel.CONFIRMED,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            rules_applied=("R-RISK-01",),
            mandatory_review_required=has_uncertainty,
        )

    # 2. R-RISK-05A: Classical disallowed in verified isolated non-production (test/dev)
    if classical_status == ClassicalSecurityStatus.DISALLOWED and is_non_prod:
        if is_verified_isolated:
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_category=RiskCategory.LOW,
                primary_cause=PrimaryRiskCause.NON_PROD_MITIGATED,
                uncertainty_level=UncertaintyLevel.CONFIRMED,
                classical_status=classical_status,
                quantum_exposure=quantum_exposure,
                rules_applied=("R-RISK-05A",),
                mandatory_review_required=False,
            )
        else:
            # Non-production without verified isolation cannot be assumed mitigated
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_category=RiskCategory.NEEDS_REVIEW,
                primary_cause=PrimaryRiskCause.UNRESOLVED_UNCERTAINTY,
                uncertainty_level=UncertaintyLevel.NEEDS_REVIEW,
                classical_status=classical_status,
                quantum_exposure=quantum_exposure,
                rules_applied=("R-RISK-06",),
                mandatory_review_required=True,
            )

    # 3. R-RISK-06: Indeterminate posture, missing parameters, or unknown environment
    if (
        classical_status == ClassicalSecurityStatus.INDETERMINATE
        or quantum_exposure == QuantumExposureClass.UNCLASSIFIED_QUANTUM_POSTURE
        or posture_uncertainty in (UncertaintyLevel.HIGH_UNCERTAINTY, UncertaintyLevel.NEEDS_REVIEW)
        or env == DeploymentEnvironment.UNKNOWN
    ):
        synthesized_uncertainty = (
            UncertaintyLevel.NEEDS_REVIEW
            if (classical_status == ClassicalSecurityStatus.INDETERMINATE or env == DeploymentEnvironment.UNKNOWN)
            else posture_uncertainty
        )
        return RiskAssessment(
            asset_id=asset.asset_id,
            risk_category=RiskCategory.NEEDS_REVIEW,
            primary_cause=PrimaryRiskCause.UNRESOLVED_UNCERTAINTY,
            uncertainty_level=synthesized_uncertainty,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            rules_applied=("R-RISK-06",),
            mandatory_review_required=True,
        )

    # 4. Classical acceptable in production: Posture is acceptable, but overall risk is an
    # unresolved specification decision in Phase 3C-A (which has no R-07 or production LOW cause).
    # Must NOT be labeled NON_PROD_MITIGATED or silently certified as LOW without operational checks.
    if classical_status == ClassicalSecurityStatus.ACCEPTABLE and is_prod:
        return RiskAssessment(
            asset_id=asset.asset_id,
            risk_category=RiskCategory.NEEDS_REVIEW,
            primary_cause=PrimaryRiskCause.UNRESOLVED_UNCERTAINTY,
            uncertainty_level=UncertaintyLevel.NEEDS_REVIEW,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            rules_applied=("R-RISK-POLICY-DECISION-REQUIRED",),
            mandatory_review_required=True,
        )

    # 5. Classical acceptable in verified isolated non-production
    if classical_status == ClassicalSecurityStatus.ACCEPTABLE and is_non_prod and is_verified_isolated:
        return RiskAssessment(
            asset_id=asset.asset_id,
            risk_category=RiskCategory.LOW,
            primary_cause=PrimaryRiskCause.NON_PROD_MITIGATED,
            uncertainty_level=UncertaintyLevel.CONFIRMED,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            rules_applied=("R-RISK-05A",),
            mandatory_review_required=False,
        )

    # Fallback for unmapped state (fails closed)
    return RiskAssessment(
        asset_id=asset.asset_id,
        risk_category=RiskCategory.NEEDS_REVIEW,
        primary_cause=PrimaryRiskCause.UNRESOLVED_UNCERTAINTY,
        uncertainty_level=UncertaintyLevel.NEEDS_REVIEW,
        classical_status=classical_status,
        quantum_exposure=quantum_exposure,
        rules_applied=("R-RISK-06",),
        mandatory_review_required=True,
    )
