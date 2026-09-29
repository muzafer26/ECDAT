"""
ECDAT Priority Derivation Layer.

Phase 3C-B First Slice: Maps technical risk category and cause to deterministic
default technical priority. Enterprise overrides are explicitly deferred to
subsequent increments per specification instructions.
"""

from typing import Tuple

from .enums import (
    MigrationComplexity,
    PrimaryRiskCause,
    PriorityTier,
    RiskCategory,
)


class InvalidRiskStateError(ValueError):
    """Raised when an unmapped or mathematically invalid risk state reaches priority derivation."""
    pass


def derive_default_priority(
    risk_category: RiskCategory,
    primary_cause: PrimaryRiskCause,
    complexity: MigrationComplexity = MigrationComplexity.UNKNOWN,
) -> Tuple[PriorityTier, str, bool]:
    """
    Derives the deterministic default technical priority.

    Returns:
        Tuple of:
        - PriorityTier (default technical priority)
        - priority_rule_id (audit identifier)
        - mandatory_review_required (boolean flag)
    """
    # 1. Critical classical production violation: unconditional P0 precedence
    if (
        risk_category == RiskCategory.CRITICAL
        and primary_cause == PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD
    ):
        return (
            PriorityTier.P0_IMMEDIATE_ACTION,
            "R-PRIORITY-P0-CLASSICAL-MANDATORY",
            False,
        )

    # 2. Mitigated non-production / low risk
    if (
        risk_category == RiskCategory.LOW
        and primary_cause == PrimaryRiskCause.NON_PROD_MITIGATED
    ):
        return (
            PriorityTier.P4_DEFERRED_MONITORING,
            "R-PRIORITY-P4-DEFERRED-MONITORING",
            False,
        )

    # 3. Unresolved uncertainty / Needs review
    if (
        risk_category == RiskCategory.NEEDS_REVIEW
        and primary_cause == PrimaryRiskCause.UNRESOLVED_UNCERTAINTY
    ):
        return (
            PriorityTier.P_REVIEW_REQUIRED,
            "R-PRIORITY-P-REVIEW-REQUIRED",
            True,
        )

    # Invalid / unmapped pair fails closed
    raise InvalidRiskStateError(
        f"Invalid or unreachable risk state pair: ({risk_category.value}, {primary_cause.value})"
    )
