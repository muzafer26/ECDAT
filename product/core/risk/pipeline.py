"""
ECDAT Risk Analysis Pipeline Orchestrator.

Phase 3C-B: Executes the deterministic decoupled pipeline:
Facts & Context -> Technical Risk -> Default Technical Priority -> Structured Explanation
"""

from typing import Optional

from product.core.domain.asset import CryptoAsset
from .enums import (
    ContextAuthority,
    DeploymentEnvironment,
    MigrationComplexity,
    PrimaryRiskCause,
    PriorityTier,
    RiskCategory,
    UncertaintyLevel,
)
from .explainability import build_explanation
from .models import AssetContext, MigrationPriorityRecord, RiskAssessment
from .posture import evaluate_crypto_posture
from .priority import derive_default_priority
from .rules import evaluate_risk_rules


class RiskAnalysisEngine:
    """
    Deterministic risk and priority evaluation engine for cryptographic assets.
    """

    def evaluate(
        self,
        asset: CryptoAsset,
        context: Optional[AssetContext] = None,
    ) -> MigrationPriorityRecord:
        """
        Evaluates a CryptoAsset under the specified AssetContext.

        Returns:
            MigrationPriorityRecord containing deterministic priority, technical risk,
            and complete 7-part explanation.
        """
        if context is None:
            context = AssetContext()

        # Step 1: Classical & quantum posture evaluation with normalized taxonomy
        classical_status, quantum_exposure, posture_uncertainty, citation, normalized_algo_name = (
            evaluate_crypto_posture(asset)
        )

        # Step 2: Deterministic risk synthesis
        assessment: RiskAssessment = evaluate_risk_rules(
            asset=asset,
            context=context,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            posture_uncertainty=posture_uncertainty,
        )

        # Step 3: Default technical priority derivation
        default_prio, prio_rule_id, prio_review = derive_default_priority(
            risk_category=assessment.risk_category,
            primary_cause=assessment.primary_cause,
            complexity=context.complexity,
        )

        combined_rules = list(assessment.rules_applied) + [prio_rule_id]
        combined_review = assessment.mandatory_review_required or prio_review

        # Step 4: Structured 7-part explanation
        explanation = build_explanation(
            asset=asset,
            context=context,
            normalized_algo_name=normalized_algo_name,
            classical_status=classical_status,
            quantum_exposure=quantum_exposure,
            uncertainty_level=assessment.uncertainty_level,
            risk_category=assessment.risk_category,
            primary_cause=assessment.primary_cause,
            priority=default_prio,
            rules_applied=combined_rules,
            standards_citation=citation,
            mandatory_review=combined_review,
        )

        # Step 5: Final actionable record
        return MigrationPriorityRecord(
            asset_id=asset.asset_id,
            default_priority=default_prio,
            effective_priority=default_prio,  # Overrides deferred to subsequent increments
            risk_category=assessment.risk_category,
            primary_cause=assessment.primary_cause,
            explanation=explanation,
            mandatory_review_required=combined_review,
        )
