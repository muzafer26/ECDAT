"""
ECDAT Migration Decision Support Models — Phase 4A & Phase 4B.

Defines immutable, typed models for:
- NIST FIPS 203/204/205 target mapping (Phase 4A)
- NIST SP 800-57 classical security-strength classification (Phase 4A)
- Cryptographic agility assessment (Phase 4A)
- Standards-grounded Hybrid & Composite transition schemes (Phase 4B)
- Dependency-aware, explainable migration scheduling and review gating (Phase 4B)

CRITICAL ARCHITECTURAL BOUNDARIES:
1. Classical Security Strength (in bits) per NIST SP 800-57 Pt 1 Rev 5 Table 2:
   - Measures resistance to classical cryptanalysis on conventional hardware (112, 128, 192, 256 bits).
2. NIST PQC Security Category per NIST FIPS 203/204/205:
   - Measures computational attack complexity of post-quantum algorithms relative to AES key search
     and SHA collision search (Categories 1 through 5).
3. Candidate Targets & Hybrid Schemes:
   - Explicitly advisory proposals for decision support; NEVER approved targets or drop-in guarantees.
4. Hybrid Security Semantics:
   - Rejects universal "Security >= max(classical, PQC)" claims. Security properties are construction-specific,
     combiner-dependent, and conditional upon protocol, negotiation, and implementation assumptions.
5. Migration Scheduling:
   - True DAG-based sequencing preserving observed prerequisites, blockers, review gates, and cycles.
   - Advisory milestone groupings; never fabricates operational dates or compliance deadlines.
"""

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


class TargetMappingStatus(str, Enum):
    """
    Categorical status of the cryptographic target mapping.
    """
    MAPPED = "MAPPED"
    CONDITIONAL = "CONDITIONAL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNSUPPORTED = "UNSUPPORTED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "TargetMappingStatus":
        if not value:
            return cls.NEEDS_REVIEW
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NEEDS_REVIEW


class ClassicalSecurityStrength(str, Enum):
    """
    Classical security strength classification strictly aligned with:
    - NIST SP 800-57 Part 1 Rev. 5, Section 5.6.1, Table 2 ("Comparable security strengths")
    - NIST SP 800-131A Rev. 2, Table 2 & Table 8 ("Transitioning the Use of Cryptographic Algorithms")

    This measures classical bits of security against conventional cryptanalysis.
    It does NOT represent post-quantum security or NIST PQC categories.
    """
    BITS_128 = "BITS_128"                      # 128 bits classical strength (e.g. RSA-3072, P-256, Ed25519, AES-128)
    BITS_192 = "BITS_192"                      # 192 bits classical strength (e.g. RSA-7680, P-384, AES-192)
    BITS_256 = "BITS_256"                      # 256 bits classical strength (e.g. RSA-15360, P-521, AES-256)
    LEGACY_112 = "LEGACY_112"                  # 112 bits classical strength (e.g. RSA-2048, P-224) - legacy acceptable through 2030
    DISALLOWED_SUB_112 = "DISALLOWED_SUB_112"  # < 112 bits classical strength (e.g. RSA-1024, DES, SHA-1 signatures) - disallowed
    INDETERMINATE = "INDETERMINATE"            # Key length or curve missing/unverified; strength cannot be established
    OUT_OF_SCOPE = "OUT_OF_SCOPE"              # Non-algorithm entity (e.g. software package manifest)

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ClassicalSecurityStrength":
        if not value:
            return cls.INDETERMINATE
        val = value.strip().upper()
        # Aliases for backward compatibility
        if val in ("CATEGORY_1", "CAT_1"):
            return cls.BITS_128
        if val in ("CATEGORY_3", "CAT_3"):
            return cls.BITS_192
        if val in ("CATEGORY_5", "CAT_5"):
            return cls.BITS_256
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.INDETERMINATE


class PqcSecurityCategory(str, Enum):
    """
    NIST Post-Quantum Cryptography Security Categories as defined in:
    - NIST FIPS 203 Section 1 & Table 1 (ML-KEM)
    - NIST FIPS 204 Section 1 & Table 1 (ML-DSA)
    - NIST FIPS 205 Section 1 & Table 1 (SLH-DSA)
    - NIST PQC Standardization Call for Proposals (2016), Section 4.A.5

    These categories measure attack resources relative to AES key search and SHA collision search.
    They apply ONLY to candidate post-quantum algorithms or target equivalence requirements.
    """
    CATEGORY_1 = "CATEGORY_1"          # Computational attack resources >= AES-128 key search (e.g. ML-KEM-512, SLH-DSA-128s)
    CATEGORY_2 = "CATEGORY_2"          # Computational attack resources >= SHA-256 collision search (e.g. ML-DSA-44)
    CATEGORY_3 = "CATEGORY_3"          # Computational attack resources >= AES-192 key search (e.g. ML-KEM-768, ML-DSA-65)
    CATEGORY_4 = "CATEGORY_4"          # Computational attack resources >= SHA-384 collision search
    CATEGORY_5 = "CATEGORY_5"          # Computational attack resources >= AES-256 key search (e.g. ML-KEM-1024, ML-DSA-87)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Not a standardized PQC parameter set

    @classmethod
    def from_str(cls, value: Optional[str]) -> "PqcSecurityCategory":
        if not value:
            return cls.NOT_APPLICABLE
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NOT_APPLICABLE


class NistSecurityCategory(str, Enum):
    """
    Transitional compatibility enum providing access to both classical and PQC categories.
    Retained for backward compatibility with earlier Phase 4A callers.
    """
    CATEGORY_1 = "CATEGORY_1"
    CATEGORY_2 = "CATEGORY_2"
    CATEGORY_3 = "CATEGORY_3"
    CATEGORY_4 = "CATEGORY_4"
    CATEGORY_5 = "CATEGORY_5"
    LEGACY_112 = "LEGACY_112"
    DISALLOWED_SUB_112 = "DISALLOWED_SUB_112"
    BITS_128 = "BITS_128"
    BITS_192 = "BITS_192"
    BITS_256 = "BITS_256"
    INDETERMINATE = "INDETERMINATE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "NistSecurityCategory":
        if not value:
            return cls.INDETERMINATE
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.INDETERMINATE


class PqcTargetFamily(str, Enum):
    """
    Standardized Post-Quantum Cryptographic (PQC) and transition target families.
    """
    ML_KEM = "ML_KEM"                  # NIST FIPS 203 (Module-Lattice Key Encapsulation)
    ML_DSA = "ML_DSA"                  # NIST FIPS 204 (Module-Lattice Digital Signatures)
    SLH_DSA = "SLH_DSA"                # NIST FIPS 205 (Stateless Hash-Based Digital Signatures)
    AES_256_EXPANSION = "AES_256_EXPANSION"  # Symmetric key expansion for Grover mitigation (not PQC replacement)
    SHA2_OR_SHA3 = "SHA2_OR_SHA3"      # Secure hash function replacement (SHA-256/384/512 or SHA-3)
    NONE = "NONE"                      # No applicable target family

    @classmethod
    def from_str(cls, value: Optional[str]) -> "PqcTargetFamily":
        if not value:
            return cls.NONE
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NONE


class AgilityLevel(str, Enum):
    """
    Categorical cryptographic agility assessment based strictly on observable evidence.
    """
    HARDCODED = "HARDCODED"            # Algorithm string/parameters hardcoded in invocation statement
    CONFIGURABLE = "CONFIGURABLE"      # Algorithm/parameters loaded from environment, property, or configuration
    MODULAR_PROVIDER = "MODULAR_PROVIDER"  # Invocation routed through factory, helper, or provider abstraction
    UNEVALUATED = "UNEVALUATED"        # Insufficient source or AST evidence to determine agility

    @classmethod
    def from_str(cls, value: Optional[str]) -> "AgilityLevel":
        if not value:
            return cls.UNEVALUATED
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNEVALUATED


# =============================================================================
# Phase 4B: Hybrid Transition & Scheduling Models
# =============================================================================

class StandardsStatus(str, Enum):
    """
    Authoritative standards standing for a proposed cryptographic transition construction.
    Distinguishes ratified standards from work-in-progress drafts and deployment patterns.
    """
    STANDARDIZED = "STANDARDIZED"                  # Formally published standard (RFC, NIST FIPS, ISO)
    DRAFT = "DRAFT"                                # Active Internet-Draft or draft standard (e.g. IETF draft)
    PROFILE_DEPLOYMENT_PATTERN = "PROFILE_DEPLOYMENT_PATTERN"  # Architectural pattern (e.g. Dual-Certificate PKI)
    ILLUSTRATIVE = "ILLUSTRATIVE"                  # Informational / non-standard proposal
    UNVERIFIED = "UNVERIFIED"                      # Insufficient evidence to establish standards pedigree

    @classmethod
    def from_str(cls, value: Optional[str]) -> "StandardsStatus":
        if not value:
            return cls.UNVERIFIED
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNVERIFIED


class HybridConstructionType(str, Enum):
    """
    Structural taxonomy of hybrid cryptographic transitions.
    Enforces that distinct architectural constructions are not conflated:
    1. Protocol-Level Hybrid Key Exchange / KEM Combiner
    2. Composite Signature Schemes (Unified OID with dual-verification)
    3. Two Independent Signatures / Signature Validation Paths (Parallel signatures)
    4. Dual Certificates (PKI deployment pattern bound via RFC 9763)
    5. Protocol-Level Authentication Arrangements (Handshake negotiation)
    6. Application-Layer Envelope Dual Key Wrapping
    7. Inapplicable (None)
    """
    PROTOCOL_LEVEL_KEM = "PROTOCOL_LEVEL_KEM"          # Protocol-level hybrid key exchange (e.g. TLS 1.3, IKEv2 RFC 9370)
    COMPOSITE_SIGNATURE = "COMPOSITE_SIGNATURE"        # Dual-verification composite signature (e.g. IETF LAMPS)
    DUAL_SIGNATURE = "DUAL_SIGNATURE"                  # Two independent signatures / dual validation paths (e.g. CMS dual SignerInfo)
    DUAL_CERTIFICATE = "DUAL_CERTIFICATE"              # Parallel PKI / dual X.509 certificates for same entity (RFC 9763)
    PROTOCOL_AUTHENTICATION = "PROTOCOL_AUTHENTICATION"# Protocol-level handshake authentication arrangement
    APPLICATION_ENVELOPE = "APPLICATION_ENVELOPE"      # Application-layer dual key wrapping / envelope encryption
    NONE = "NONE"                                      # Inapplicable (e.g. symmetric ciphers, standalone hashes)

    @classmethod
    def from_str(cls, value: Optional[str]) -> "HybridConstructionType":
        if not value:
            return cls.NONE
        val = value.strip().upper()
        # Aliases for flexibility
        aliases = {
            "PROTOCOL_HYBRID_KEM": cls.PROTOCOL_LEVEL_KEM,
            "PROTOCOL_LEVEL_KEY_EXCHANGE": cls.PROTOCOL_LEVEL_KEM,
            "COMPOSITE": cls.COMPOSITE_SIGNATURE,
            "DUAL_CERT": cls.DUAL_CERTIFICATE,
            "INDEPENDENT_SIGNATURES": cls.DUAL_SIGNATURE,
            "PARALLEL_SIGNATURES": cls.DUAL_SIGNATURE,
        }
        if val in aliases:
            return aliases[val]
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.NONE


@dataclass(frozen=True)
class HybridSchemeCandidate:
    """
    A specific standardized or draft hybrid/composite transition scheme candidate.

    CRITICAL INVARIANTS:
    - Never encoded as an unconditional universal security guarantee.
    - security_property explicitly articulates combiner assumptions, protocol boundaries,
      and failure conditions.
    - standards_status clearly labels Drafts vs Standards.
    """
    scheme_name: str                               # e.g. "X25519MLKEM768", "MLDSA65-ECDSA-P256"
    classical_component: str                       # e.g. "X25519", "ECDSA P-256", "RSA-3072"
    pqc_component: str                             # e.g. "ML-KEM-768", "ML-DSA-65"
    construction_type: HybridConstructionType
    standards_reference: str                       # e.g. "IETF draft-ietf-tls-hybrid-design", "RFC 9370"
    standards_status: StandardsStatus
    applicability: str                             # e.g. "TLS 1.3 Key Exchange", "X.509 PKIX Signatures"
    security_property: str                         # Construction-specific conditional security description
    compatibility_assumptions: Tuple[str, ...]     # Peer protocol support, client verification, MTU constraints
    overhead_bytes: Optional[int] = None           # Combined wire size expansion in bytes (if evidenced)
    evidence_basis: str = ""                       # Discovered AST facts supporting applicability
    confidence_status: str = "CANDIDATE_EVALUATION"

    def __post_init__(self) -> None:
        if not isinstance(self.construction_type, HybridConstructionType):
            object.__setattr__(self, "construction_type", HybridConstructionType.from_str(str(self.construction_type)))
        if not isinstance(self.standards_status, StandardsStatus):
            object.__setattr__(self, "standards_status", StandardsStatus.from_str(str(self.standards_status)))
        object.__setattr__(self, "compatibility_assumptions", tuple(self.compatibility_assumptions))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme_name": self.scheme_name,
            "classical_component": self.classical_component,
            "pqc_component": self.pqc_component,
            "construction_type": self.construction_type.value,
            "standards_reference": self.standards_reference,
            "standards_status": self.standards_status.value,
            "applicability": self.applicability,
            "security_property": self.security_property,
            "compatibility_assumptions": list(self.compatibility_assumptions),
            "overhead_bytes": self.overhead_bytes,
            "evidence_basis": self.evidence_basis,
            "confidence_status": self.confidence_status,
        }


@dataclass(frozen=True)
class CandidateTarget:
    """
    A specific standardized PQC candidate algorithm parameter set.
    """
    family: PqcTargetFamily
    parameter_set: str                 # e.g. "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s"
    pqc_security_category: PqcSecurityCategory
    standard: str                      # e.g. "NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"
    primary_use_case: str              # e.g. "Key Encapsulation / Transport", "Digital Signatures / Authentication"
    public_key_bytes: Optional[int] = None
    ciphertext_or_signature_bytes: Optional[int] = None
    rationale: str = ""
    nist_category: Optional[Any] = None  # Backward compatibility alias

    def __post_init__(self) -> None:
        if not isinstance(self.family, PqcTargetFamily):
            object.__setattr__(self, "family", PqcTargetFamily.from_str(str(self.family)))
        if not isinstance(self.pqc_security_category, PqcSecurityCategory):
            object.__setattr__(self, "pqc_security_category", PqcSecurityCategory.from_str(str(self.pqc_security_category)))
        # Mirror pqc_security_category into nist_category for backward compatibility
        if self.nist_category is None:
            object.__setattr__(self, "nist_category", self.pqc_security_category)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family.value,
            "parameter_set": self.parameter_set,
            "pqc_security_category": self.pqc_security_category.value,
            "nist_category": self.pqc_security_category.value,
            "standard": self.standard,
            "primary_use_case": self.primary_use_case,
            "public_key_bytes": self.public_key_bytes,
            "ciphertext_or_signature_bytes": self.ciphertext_or_signature_bytes,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class AgilityAssessment:
    """
    Empirical cryptographic agility assessment derived strictly from observed facts.
    """
    level: AgilityLevel
    evidenced_factors: Tuple[str, ...] = field(default_factory=tuple)
    limitations_and_unknowns: Tuple[str, ...] = field(default_factory=tuple)
    protocol_context: str = "unknown"

    def __post_init__(self) -> None:
        if not isinstance(self.level, AgilityLevel):
            object.__setattr__(self, "level", AgilityLevel.from_str(str(self.level)))
        object.__setattr__(self, "evidenced_factors", tuple(self.evidenced_factors))
        object.__setattr__(self, "limitations_and_unknowns", tuple(self.limitations_and_unknowns))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "evidenced_factors": list(self.evidenced_factors),
            "limitations_and_unknowns": list(self.limitations_and_unknowns),
            "protocol_context": self.protocol_context,
        }


@dataclass(frozen=True)
class PqcTargetMapping:
    """
    Authoritative, immutable migration target mapping decision record.
    Provides complete audit traceability from discovered legacy asset to candidate PQC & hybrid standards.

    ENFORCES EXPLICIT SEPARATION BETWEEN:
    - classical_security_strength: Bits of classical security (NIST SP 800-57 Table 2)
    - classical_bits: Integer bits of security (e.g. 112, 128, 192, 256)
    - target_equivalence_category: Minimum PQC Category needed for parity (FIPS 203/204/205)
    - candidate_targets: Specific standardized parameter sets proposed for evaluation
    - hybrid_candidates: Candidate hybrid transition schemes with standards status and conditional security
    - selection_basis: Why these candidates were chosen and what tradeoffs exist
    """
    source_asset_id: str
    source_algorithm: str
    source_family: str
    source_role: str
    observed_parameters: Mapping[str, Any]
    classical_security_strength: ClassicalSecurityStrength
    mapping_status: TargetMappingStatus
    candidate_targets: Tuple[CandidateTarget, ...]
    mapping_rationale: str
    standards_references: Tuple[str, ...]
    assumptions_and_questions: Tuple[str, ...]
    compatibility_considerations: Tuple[str, ...]
    agility_assessment: AgilityAssessment
    required_human_review: bool
    classical_bits: Optional[int] = None
    target_equivalence_category: Optional[PqcSecurityCategory] = None
    selection_basis: str = ""
    hybrid_candidates: Tuple[HybridSchemeCandidate, ...] = field(default_factory=tuple)
    unmapped_reasons: Tuple[str, ...] = field(default_factory=tuple)
    security_strength: Optional[Any] = None  # Backward compatibility alias

    def __post_init__(self) -> None:
        # Coerce classical_security_strength
        if not isinstance(self.classical_security_strength, ClassicalSecurityStrength):
            raw_val = self.security_strength if self.classical_security_strength is None else self.classical_security_strength
            object.__setattr__(self, "classical_security_strength", ClassicalSecurityStrength.from_str(str(raw_val)))

        # Mirror to security_strength for backward compatibility
        object.__setattr__(self, "security_strength", self.classical_security_strength)

        if not isinstance(self.mapping_status, TargetMappingStatus):
            object.__setattr__(self, "mapping_status", TargetMappingStatus.from_str(str(self.mapping_status)))

        if self.target_equivalence_category is not None and not isinstance(self.target_equivalence_category, PqcSecurityCategory):
            object.__setattr__(self, "target_equivalence_category", PqcSecurityCategory.from_str(str(self.target_equivalence_category)))

        object.__setattr__(self, "observed_parameters", MappingProxyType(dict(self.observed_parameters)))
        object.__setattr__(self, "candidate_targets", tuple(self.candidate_targets))
        object.__setattr__(self, "hybrid_candidates", tuple(self.hybrid_candidates))
        object.__setattr__(self, "standards_references", tuple(self.standards_references))
        object.__setattr__(self, "assumptions_and_questions", tuple(self.assumptions_and_questions))
        object.__setattr__(self, "compatibility_considerations", tuple(self.compatibility_considerations))
        object.__setattr__(self, "unmapped_reasons", tuple(self.unmapped_reasons))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_asset_id": self.source_asset_id,
            "source_algorithm": self.source_algorithm,
            "source_family": self.source_family,
            "source_role": self.source_role,
            "observed_parameters": dict(self.observed_parameters),
            "classical_security_strength": self.classical_security_strength.value,
            "classical_bits": self.classical_bits,
            "target_equivalence_category": self.target_equivalence_category.value if self.target_equivalence_category else None,
            "selection_basis": self.selection_basis,
            "security_strength": self.classical_security_strength.value,  # backward compatibility
            "mapping_status": self.mapping_status.value,
            "candidate_targets": [t.to_dict() for t in self.candidate_targets],
            "hybrid_candidates": [h.to_dict() for h in self.hybrid_candidates],
            "mapping_rationale": self.mapping_rationale,
            "standards_references": list(self.standards_references),
            "assumptions_and_questions": list(self.assumptions_and_questions),
            "compatibility_considerations": list(self.compatibility_considerations),
            "agility_assessment": self.agility_assessment.to_dict(),
            "required_human_review": self.required_human_review,
            "unmapped_reasons": list(self.unmapped_reasons),
        }


# =============================================================================
# Migration Scheduling & Governance Models (Phase 4B)
# =============================================================================

class MigrationPhase(str, Enum):
    """
    Advisory migration milestone phase groupings.
    These are logical, evidence-driven categorization buckets, NOT universal mandatory sequential steps.
    """
    PREPARATION = "PREPARATION"                              # Dependencies, providers, library upgrades
    KEY_EXCHANGE_HNDL = "KEY_EXCHANGE_HNDL"                  # Session keys, data-in-transit, HNDL-exposed keys
    AUTHENTICATION_SIGNATURES = "AUTHENTICATION_SIGNATURES"  # Certificates, PKI, digital signatures
    DATA_AT_REST = "DATA_AT_REST"                            # Symmetric storage keys, envelope encryption
    PURE_PQC = "PURE_PQC"                                    # Deprecation of classical components; pure PQC

    @classmethod
    def from_str(cls, value: Optional[str]) -> "MigrationPhase":
        if not value:
            return cls.PREPARATION
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.PREPARATION


@dataclass(frozen=True)
class ReviewGate:
    """
    Formal human-review gate for uncertain, ambiguous, or hardcoded assets.
    Prevents unverified assumptions from silently progressing into automated schedules.
    """
    gate_id: str
    asset_id: str
    reason: str
    evidence_summary: str
    missing_information: str
    consequence_if_unresolved: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "asset_id": self.asset_id,
            "reason": self.reason,
            "evidence_summary": self.evidence_summary,
            "missing_information": self.missing_information,
            "consequence_if_unresolved": self.consequence_if_unresolved,
        }


@dataclass(frozen=True)
class MigrationMilestone:
    """
    An advisory milestone grouping in the migration schedule.
    Contains target assets, explicit prerequisite IDs, blockers, and review gates.
    """
    milestone_id: str
    phase: MigrationPhase
    title: str
    target_asset_ids: Tuple[str, ...]
    prerequisites: Tuple[str, ...]
    review_gates: Tuple[ReviewGate, ...]
    blockers: Tuple[str, ...]
    rationale: str
    unresolved_items: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.phase, MigrationPhase):
            object.__setattr__(self, "phase", MigrationPhase.from_str(str(self.phase)))
        object.__setattr__(self, "target_asset_ids", tuple(self.target_asset_ids))
        object.__setattr__(self, "prerequisites", tuple(self.prerequisites))
        object.__setattr__(self, "review_gates", tuple(self.review_gates))
        object.__setattr__(self, "blockers", tuple(self.blockers))
        object.__setattr__(self, "unresolved_items", tuple(self.unresolved_items))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "milestone_id": self.milestone_id,
            "phase": self.phase.value,
            "title": self.title,
            "target_asset_ids": list(self.target_asset_ids),
            "prerequisites": list(self.prerequisites),
            "review_gates": [g.to_dict() for g in self.review_gates],
            "blockers": list(self.blockers),
            "rationale": self.rationale,
            "unresolved_items": list(self.unresolved_items),
        }


@dataclass(frozen=True)
class MigrationSchedule:
    """
    Authoritative, immutable migration schedule decision-support record.
    Constructed strictly from observed asset dependencies, HNDL risk, and agility facts.
    """
    milestones: Tuple[MigrationMilestone, ...]
    dependency_graph: Mapping[str, Tuple[str, ...]]  # asset_id -> prerequisites
    review_gates: Tuple[ReviewGate, ...]
    blocked_assets: Tuple[str, ...]
    dependency_cycles: Tuple[Tuple[str, ...], ...]
    hndl_prioritized_assets: Tuple[str, ...]
    summary: str
    assumptions: Tuple[str, ...]
    schedule_status: str  # "ACTIONABLE", "ADVISORY_PENDING_REVIEW", "BLOCKED_DEPENDENCY_CYCLE"

    def __post_init__(self) -> None:
        object.__setattr__(self, "milestones", tuple(self.milestones))
        object.__setattr__(self, "review_gates", tuple(self.review_gates))
        object.__setattr__(self, "blocked_assets", tuple(self.blocked_assets))
        object.__setattr__(self, "dependency_cycles", tuple(self.dependency_cycles))
        object.__setattr__(self, "hndl_prioritized_assets", tuple(self.hndl_prioritized_assets))
        object.__setattr__(self, "assumptions", tuple(self.assumptions))

        frozen_graph = {k: tuple(v) for k, v in self.dependency_graph.items()}
        object.__setattr__(self, "dependency_graph", MappingProxyType(frozen_graph))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "milestones": [m.to_dict() for m in self.milestones],
            "dependency_graph": {k: list(v) for k, v in self.dependency_graph.items()},
            "review_gates": [g.to_dict() for g in self.review_gates],
            "blocked_assets": list(self.blocked_assets),
            "dependency_cycles": [list(c) for c in self.dependency_cycles],
            "hndl_prioritized_assets": list(self.hndl_prioritized_assets),
            "summary": self.summary,
            "assumptions": list(self.assumptions),
            "schedule_status": self.schedule_status,
        }
