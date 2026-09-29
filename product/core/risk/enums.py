"""
ECDAT Categorical Enums for Risk and Priority Analysis.

Phase 3C-B: Canonical string enumerations for risk categories,
causes, priorities, security status, environment attributes, and network exposure.
"""

from enum import Enum
from typing import Optional


class RiskCategory(str, Enum):
    """Overall contextual risk category."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEEDS_REVIEW = "NEEDS_REVIEW"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "RiskCategory":
        if not value:
            return cls.NEEDS_REVIEW
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NEEDS_REVIEW


class PrimaryRiskCause(str, Enum):
    """Root driver of the synthesized risk category."""
    CLASSICAL_DISALLOWED_PROD = "CLASSICAL_DISALLOWED_PROD"
    QUANTUM_HNDL_CRITICAL = "QUANTUM_HNDL_CRITICAL"
    QUANTUM_SHOR_CORE = "QUANTUM_SHOR_CORE"
    QUANTUM_GROVER_PERSISTENT = "QUANTUM_GROVER_PERSISTENT"
    NON_PROD_MITIGATED = "NON_PROD_MITIGATED"
    UNRESOLVED_UNCERTAINTY = "UNRESOLVED_UNCERTAINTY"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "PrimaryRiskCause":
        if not value:
            return cls.UNRESOLVED_UNCERTAINTY
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNRESOLVED_UNCERTAINTY


class PriorityTier(str, Enum):
    """Default technical and actionable priority tiers."""
    P0_IMMEDIATE_ACTION = "P0_IMMEDIATE_ACTION"
    P1_NEAR_TERM_MIGRATION = "P1_NEAR_TERM_MIGRATION"
    P2_PLANNED_TRANSITION = "P2_PLANNED_TRANSITION"
    P3_OPPORTUNISTIC_QUICK_WIN = "P3_OPPORTUNISTIC_QUICK_WIN"
    P4_DEFERRED_MONITORING = "P4_DEFERRED_MONITORING"
    P_REVIEW_REQUIRED = "P_REVIEW_REQUIRED"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "PriorityTier":
        if not value:
            return cls.P_REVIEW_REQUIRED
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.P_REVIEW_REQUIRED


class UncertaintyLevel(str, Enum):
    """Confidence and uncertainty quantification."""
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    HIGH_UNCERTAINTY = "HIGH_UNCERTAINTY"
    NEEDS_REVIEW = "NEEDS_REVIEW"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "UncertaintyLevel":
        if not value:
            return cls.NEEDS_REVIEW
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NEEDS_REVIEW


class ClassicalSecurityStatus(str, Enum):
    """Classical cryptographic algorithm standing under authoritative standards."""
    DISALLOWED = "DISALLOWED"
    DEPRECATED = "DEPRECATED"
    ACCEPTABLE = "ACCEPTABLE"
    INDETERMINATE = "INDETERMINATE"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ClassicalSecurityStatus":
        if not value:
            return cls.INDETERMINATE
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.INDETERMINATE


class QuantumExposureClass(str, Enum):
    """Theoretical quantum exposure taxonomy."""
    SHOR_VULNERABLE_ASYMMETRIC = "SHOR_VULNERABLE_ASYMMETRIC"
    GROVER_REDUCED_SYMMETRIC_LOW = "GROVER_REDUCED_SYMMETRIC_LOW"
    GROVER_RESILIENT_SYMMETRIC_HIGH = "GROVER_RESILIENT_SYMMETRIC_HIGH"
    GROVER_AFFECTED_HASH = "GROVER_AFFECTED_HASH"
    PQC_STANDARDIZED = "PQC_STANDARDIZED"
    UNCLASSIFIED_QUANTUM_POSTURE = "UNCLASSIFIED_QUANTUM_POSTURE"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "QuantumExposureClass":
        if not value:
            return cls.UNCLASSIFIED_QUANTUM_POSTURE
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNCLASSIFIED_QUANTUM_POSTURE


class DeploymentEnvironment(str, Enum):
    """Operational deployment context."""
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TEST_FIXTURE = "TEST_FIXTURE"
    UNVERIFIED_ENVIRONMENT = "UNVERIFIED_ENVIRONMENT"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "DeploymentEnvironment":
        if not value:
            return cls.UNKNOWN
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNKNOWN


class NetworkExposure(str, Enum):
    """Network accessibility of the host infrastructure."""
    INTERNET_FACING_PUBLIC = "INTERNET_FACING_PUBLIC"
    PARTNER_DMZ = "PARTNER_DMZ"
    INTERNAL_VPC = "INTERNAL_VPC"
    ISOLATED_AIRGAPPED = "ISOLATED_AIRGAPPED"
    UNVERIFIED_EXPOSURE = "UNVERIFIED_EXPOSURE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "NetworkExposure":
        if not value:
            return cls.UNKNOWN
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNKNOWN


class MigrationComplexity(str, Enum):
    """Implementation complexity of transitioning away from this asset."""
    TRIVIAL_QUICK_WIN = "TRIVIAL_QUICK_WIN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "MigrationComplexity":
        if not value:
            return cls.UNKNOWN
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNKNOWN


class ContextAuthority(str, Enum):
    """Provenance and trustworthiness of contextual claims."""
    ENTERPRISE_POLICY_SIGNED = "ENTERPRISE_POLICY_SIGNED"
    CI_DEPLOYMENT_METADATA = "CI_DEPLOYMENT_METADATA"
    LOCAL_REPO_CONFIG = "LOCAL_REPO_CONFIG"
    UNASSESSED_DEFAULT = "UNASSESSED_DEFAULT"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ContextAuthority":
        if not value:
            return cls.UNASSESSED_DEFAULT
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNASSESSED_DEFAULT
