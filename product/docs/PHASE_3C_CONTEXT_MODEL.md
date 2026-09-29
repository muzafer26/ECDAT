# PHASE 3C — CONTEXT MODEL SPECIFICATION (REVISED)

---

## 1. Contextual Dimensions and Classification Audit

Every contextual dimension serves a distinct operational purpose and carries explicit provenance:

| Context Dimension | Operational Purpose | Classification | Provenance Requirement |
|:---|:---|:---|:---|
| **Data Sensitivity** | Classification of data protected (Secret, Confidential, Financial, PII, Public, Unknown) | **KEEP** | Explicit source and author tracking. |
| **Data Lifetime ($X$)** | Retention duration requiring ongoing confidentiality/integrity (Maps to canonical Mosca $x$ / ECDAT $X$) | **KEEP** | Value with units (years/months/persistent/unknown). |
| **System Criticality** | Enterprise operational criticality of the hosting system | **KEEP** | Tier classification (Tier 1 Core, Tier 2 Business, Tier 3 Peripheral, Unknown). |
| **Network Exposure** | Exposure of the endpoint (Public Internet, Partner DMZ, Internal VPC, Airgapped, Unknown) | **KEEP** | Infrastructure/deployment configuration lineage. |
| **Regulatory Scope** | Governing standards (FIPS 140-3, PCI-DSS, HIPAA, CNSA 2.0, DPDP Act) | **KEEP** | Enterprise compliance profile mapping. |
| **Migration Difficulty ($Y$)** | Implementation complexity, dependency entanglement, crypto-agility (Maps to canonical Mosca $y$ / ECDAT $Y$) | **KEEP** | Engineering assessment (Trivial, Low, Medium, High, Very High, Unknown). |
| **Operational Constraints**| Specialized deployment constraints (Low Latency, Bandwidth Constrained, Embedded) | **MODIFY** | Explicit operational tag list. |
| **Dependency Blast Radius**| Blast radius of library providers | **MODIFY** | Derived strictly from evidence-backed provides graph (`dependency.provides`). |
| **Ownership** | Responsible team or code owner | **VERIFY LATER**| Deferred to enterprise directory integration (Phase 5). |
| **Environment** | Production, Staging, Development, Test Fixture | **KEEP** | Infrastructure deployment tag. |

---

## 2. Canonical Context Domain Model

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence


class DataSensitivity(str, Enum):
    """Classification of data protected by the asset."""
    CRITICAL_SECRET = "critical_secret"
    RESTRICTED_CONFIDENTIAL = "restricted_confidential"
    PII_FINANCIAL = "pii_financial"
    INTERNAL_OPERATIONAL = "internal_operational"
    PUBLIC = "public"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "DataSensitivity":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class DataLifetime(str, Enum):
    """
    Retention duration requiring ongoing cryptographic protection.
    Maps to parameter 'X' in Mosca inequality (Shelf-life / Secrecy duration).
    """
    TRANSIENT_UNDER_1Y = "transient_under_1y"
    MEDIUM_1_TO_5Y = "medium_1_to_5y"
    LONG_5_TO_10Y = "long_5_to_10y"
    PERSISTENT_OVER_10Y = "persistent_over_10y"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "DataLifetime":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class SystemCriticality(str, Enum):
    """Enterprise criticality of the hosting system."""
    TIER1_MISSION_CRITICAL = "tier1_mission_critical"
    TIER2_BUSINESS_OPERATIONAL = "tier2_business_operational"
    TIER3_PERIPHERAL = "tier3_peripheral"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "SystemCriticality":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class NetworkExposure(str, Enum):
    """Network accessibility of the component."""
    INTERNET_FACING_PUBLIC = "internet_facing_public"
    PARTNER_DMZ = "partner_dmz"
    INTERNAL_VPC = "internal_vpc"
    ISOLATED_AIRGAPPED = "isolated_airgapped"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "NetworkExposure":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class DeploymentEnvironment(str, Enum):
    """Operational environment."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST_FIXTURE = "test_fixture"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "DeploymentEnvironment":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class MigrationComplexity(str, Enum):
    """Estimated migration complexity (Maps to parameter 'Y' in Mosca heuristic - Migration Time)."""
    TRIVIAL_QUICK_WIN = "trivial_quick_win"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "MigrationComplexity":
        if not val:
            return cls.UNKNOWN
        v = val.strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        return cls.UNKNOWN


class ContextAuthority(str, Enum):
    """Source authority for contextual declarations."""
    ENTERPRISE_POLICY_SIGNED = "enterprise_policy_signed"
    CI_DEPLOYMENT_METADATA = "ci_deployment_metadata"
    LOCAL_REPO_CONFIG = "local_repo_config"
    UNASSESSED_DEFAULT = "unassessed_default"


@dataclass(frozen=True)
class ContextProvenance:
    """Audit trail verifying the origin of contextual metadata."""
    authority: ContextAuthority
    author: str
    timestamp: str  # ISO-8601 UTC
    policy_ref: Optional[str] = None


@dataclass(frozen=True)
class EnterprisePolicyThresholds:
    """
    Configurable enterprise risk policy thresholds with explicit provenance.
    Eliminates hardcoded universal assumptions.
    
    CRITICAL POLICY DISTINCTION:
    - 5 years is an ECDAT policy/demo default and is not a universal scientific
      or standards-mandated threshold.
    - STANDARDS_GUIDANCE provenance can ONLY be used if a specific cited standard
      mandates a numeric retention/transition horizon for that specific context.
    """
    hndl_data_lifetime_threshold_years: float = 5.0
    mosca_default_planning_horizon_years: float = 10.0
    policy_name: str = "ECDAT_DEMO_DEFAULT_POLICY"
    authority: str = "ECDAT Demonstration Baseline (5 years is an ECDAT policy/demo default and is not a universal scientific or standards-mandated threshold)"
    provenance: Optional[ContextProvenance] = None


@dataclass(frozen=True)
class AssetContext:
    """
    Immutable contextual envelope for a Cryptographic Asset.
    """
    asset_id: str
    sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    data_lifetime: DataLifetime = DataLifetime.UNKNOWN
    criticality: SystemCriticality = SystemCriticality.UNKNOWN
    exposure: NetworkExposure = NetworkExposure.UNKNOWN
    environment: DeploymentEnvironment = DeploymentEnvironment.UNKNOWN
    migration_complexity: MigrationComplexity = MigrationComplexity.UNKNOWN
    regulatory_scopes: Sequence[str] = ()
    operational_constraints: Sequence[str] = ()
    provenance: Optional[ContextProvenance] = None
```

---

## 3. Policy on Incomplete Context and Uncertainty

1. **Zero Favorable Inference:**
   - Missing exposure is **never** assumed internal.
   - Missing data lifetime is **never** assumed transient.
   - Missing sensitivity is **never** assumed public.
   - Missing environment is **never** assumed non-production.
2. **Provenance Attributability:**
   - Every contextual attribute must be attributable to its `ContextAuthority`.
   - Untrusted repository configuration (`LOCAL_REPO_CONFIG`) cannot downgrade classical broken ciphers.
