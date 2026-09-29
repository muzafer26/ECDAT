"""
ECDAT PQC Target Mapping Engine — Phase 4A & Phase 4B.

Deterministically maps discovered cryptographic assets to candidate Post-Quantum
Cryptographic (PQC) algorithm families and candidate hybrid transition schemes under official standards:
- NIST FIPS 203 (ML-KEM — Module-Lattice Key Encapsulation Mechanism)
- NIST FIPS 204 (ML-DSA — Module-Lattice Digital Signature Algorithm)
- NIST FIPS 205 (SLH-DSA — Stateless Hash-Based Digital Signature Algorithm)
- NIST SP 800-57 Part 1 Rev. 5 (Security Strength Recommendations)
- IETF draft-ietf-tls-hybrid-design (TLS 1.3 Hybrid Key Exchange)
- IETF RFC 9370 (Multiple Key Exchanges in IKEv2)
- IETF draft-ietf-lamps-pq-composite-sigs (Composite Dual-Verification Signatures)

CRITICAL ARCHITECTURAL INVARIANTS:
1. Strict Boundary Separation:
   - Classical Security Strength (bits of security under SP 800-57) is kept distinct from
     NIST PQC Security Categories (Categories 1-5 under FIPS 203/204/205).
   - Candidate targets and hybrid schemes are decision-support proposals, NOT approved targets.
2. Role-Aware: ML-KEM is mapped strictly to key establishment/transport; ML-DSA/SLH-DSA strictly to signatures.
3. Hybrid Scheme Grounding: Evaluates candidate hybrid options with explicit standards status and conditional security.
4. Symmetric ciphers (AES, DES) and hashes (SHA-1) are classified as OUT_OF_SCOPE for public-key PQC mapping.
5. Unknown algorithms, bare Rijndael, and ambiguous dynamic calls evaluate to NEEDS_REVIEW.
6. Never mutates input assets; produces immutable PqcTargetMapping decision records.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.role import CryptographicRole
from .agility import assess_cryptographic_agility
from .hybrid import evaluate_hybrid_options
from .models import (
    AgilityAssessment,
    CandidateTarget,
    ClassicalSecurityStrength,
    HybridSchemeCandidate,
    PqcSecurityCategory,
    PqcTargetFamily,
    PqcTargetMapping,
    TargetMappingStatus,
)
from .strength import classify_classical_security_strength


class PqcTargetMapper:
    """
    Deterministic decision-support engine mapping legacy cryptographic assets
    to standardized NIST FIPS 203/204/205 candidate targets and hybrid transition schemes.
    """

    def map_asset(self, asset: CryptoAsset) -> PqcTargetMapping:
        """
        Evaluates a single CryptoAsset and produces an auditable PqcTargetMapping record.
        """
        if not isinstance(asset, CryptoAsset):
            raise TypeError(f"Expected CryptoAsset instance, got {type(asset).__name__}")

        # 1. Agility & Classical Security Strength Classifications
        agility = assess_cryptographic_agility(asset)
        classical_strength, classical_bits, strength_rationale, strength_citations = classify_classical_security_strength(asset)
        hybrid_candidates = evaluate_hybrid_options(asset)

        algo_id = asset.algorithm_identity
        family = algo_id.family
        raw_name = algo_id.algorithm or ""
        norm_name = raw_name.strip().upper()
        role = asset.role
        params = asset.parameters
        observed_params = params.to_dict() if params else {}

        # 2. Library Packages (Out of scope for algorithm replacement)
        if asset.asset_type == AssetType.LIBRARY_DEPENDENCY:
            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name,
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=ClassicalSecurityStrength.OUT_OF_SCOPE,
                classical_bits=None,
                target_equivalence_category=None,
                selection_basis="Package dependency manifests are outside the scope of direct algorithm replacement.",
                mapping_status=TargetMappingStatus.OUT_OF_SCOPE,
                candidate_targets=(),
                hybrid_candidates=(),
                mapping_rationale="Library dependency manifests represent software package presence, not active cryptographic algorithm invocations. Target mapping applies to algorithm usage sites.",
                standards_references=("ADR-012 (Library Component Representation)",),
                assumptions_and_questions=(
                    f"Does application source code invoke cryptographic algorithms provided by package '{raw_name}'?",
                ),
                compatibility_considerations=(
                    "Dependency upgrade to a PQC-enabled provider (e.g. Bouncy Castle >= 1.78, OpenSSL >= 3.2) required.",
                ),
                agility_assessment=agility,
                required_human_review=False,
                unmapped_reasons=("Package dependency presence is outside the scope of direct algorithm replacement.",),
            )

        # 3. Unknown, Ambiguous, Decoy, or Low-Confidence Assets
        if (
            asset.asset_type == AssetType.UNKNOWN
            or family == AlgorithmFamily.UNKNOWN
            or "RIJNDAEL" in norm_name
            or asset.confidence == ConfidenceLevel.NEEDS_REVIEW
        ):
            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name if raw_name else "UNKNOWN",
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=classical_strength,
                classical_bits=classical_bits,
                target_equivalence_category=None,
                selection_basis="Automated target mapping blocked due to unverified algorithm identity or parameters.",
                mapping_status=TargetMappingStatus.NEEDS_REVIEW,
                candidate_targets=(),
                hybrid_candidates=(),
                mapping_rationale=f"Algorithm '{raw_name}' is unknown, ambiguous, or unconfirmed. Automated PQC target selection is unsafe without human architectural review.",
                standards_references=strength_citations,
                assumptions_and_questions=(
                    "What specific cryptographic primitive and parameter set is executed at runtime?",
                    "Can static AST analysis be supplemented with configuration or dependency analysis?",
                ),
                compatibility_considerations=(
                    "Target selection is blocked until algorithm identity and operational role are verified.",
                ),
                agility_assessment=agility,
                required_human_review=True,
                unmapped_reasons=("Algorithm identity or parameters are insufficiently evidenced for automated mapping.",),
            )

        # 4. Symmetric Cryptography (AES, DES) — Out of public-key PQC scope
        if family in (AlgorithmFamily.AES, AlgorithmFamily.DES) or any(k in norm_name for k in ("AES", "DES")):
            candidate_targets: List[CandidateTarget] = []
            reasons = [
                "Symmetric ciphers are unaffected by Shor's polynomial-time factoring/DLP attacks. Grover's quantum search reduces effective key strength by half (k/2 bits). Public-key KEMs (FIPS 203) cannot replace symmetric ciphers."
            ]

            if family == AlgorithmFamily.AES:
                key_size = params.key_size_bits if params else None
                if key_size == 128:
                    candidate_targets.append(
                        CandidateTarget(
                            family=PqcTargetFamily.AES_256_EXPANSION,
                            parameter_set="AES-256",
                            pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                            standard="NIST FIPS 197 / NSA CNSA 2.0",
                            primary_use_case="Symmetric Data Encryption (Grover-Resilient)",
                            public_key_bytes=None,
                            ciphertext_or_signature_bytes=None,
                            rationale="Key expansion from 128 to 256 bits restores a 128-bit quantum security margin against unconstrained Grover search.",
                        )
                    )
            elif family == AlgorithmFamily.DES:
                candidate_targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.AES_256_EXPANSION,
                        parameter_set="AES-256",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                        standard="NIST FIPS 197 / NIST SP 800-131A Rev. 2",
                        primary_use_case="Symmetric Data Encryption (Classical & Quantum Approved)",
                        public_key_bytes=None,
                        ciphertext_or_signature_bytes=None,
                        rationale="DES/3DES is disallowed under classical standards (< 112 bits). Immediate migration to AES-256 is required.",
                    )
                )

            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name,
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=classical_strength,
                classical_bits=classical_bits,
                target_equivalence_category=None,
                selection_basis="Symmetric block cipher: PQC public-key categories do not apply. Symmetric Grover mitigation applies.",
                mapping_status=TargetMappingStatus.OUT_OF_SCOPE,
                candidate_targets=tuple(candidate_targets),
                hybrid_candidates=(),
                mapping_rationale="Symmetric block ciphers are outside the scope of NIST FIPS 203/204/205 public-key PQC replacements.",
                standards_references=("NIST FIPS 197", "NIST SP 800-57 Part 1 Rev. 5", "NISTIR 8105"),
                assumptions_and_questions=(
                    "Can storage schemas and protocol fields support 256-bit symmetric keys?",
                ),
                compatibility_considerations=(
                    "Symmetric key length transition does not incur public-key ciphertext expansion.",
                ),
                agility_assessment=agility,
                required_human_review=False,
                unmapped_reasons=tuple(reasons),
            )

        # 5. Cryptographic Hash Functions (SHA-1, SHA-2, SHA-3) — Out of public-key PQC scope
        if family == AlgorithmFamily.SHA1 or any(k in norm_name for k in ("SHA1", "SHA_1", "SHA2", "SHA3")):
            candidate_targets: List[CandidateTarget] = []
            if family == AlgorithmFamily.SHA1 or "SHA1" in norm_name:
                candidate_targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.SHA2_OR_SHA3,
                        parameter_set="SHA-256 / SHA-384 / SHA3-256",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_1,
                        standard="NIST FIPS 180-4 / NIST FIPS 202",
                        primary_use_case="Cryptographic Hashing / Collision Resistance",
                        public_key_bytes=None,
                        ciphertext_or_signature_bytes=None,
                        rationale="SHA-1 collision resistance is broken (< 80 bits). Migration to SHA-256 or SHA3-256 restores classical and quantum collision security.",
                    )
                )

            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name,
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=classical_strength,
                classical_bits=classical_bits,
                target_equivalence_category=None,
                selection_basis="Hash function: public-key PQC algorithms are inapplicable. Classical collision resistance restoration applies.",
                mapping_status=TargetMappingStatus.OUT_OF_SCOPE,
                candidate_targets=tuple(candidate_targets),
                hybrid_candidates=(),
                mapping_rationale="Cryptographic hash functions are outside the scope of NIST FIPS 203/204/205 public-key PQC replacements.",
                standards_references=("NIST FIPS 180-4", "NIST FIPS 202", "NIST SP 800-131A Rev. 2 Table 8"),
                assumptions_and_questions=(
                    "Is the hash function used for digital signatures (collision-sensitive) or HMAC (PRF-sensitive)?",
                ),
                compatibility_considerations=(
                    "Digest output expansion: SHA-1 (20 bytes) to SHA-256 (32 bytes) requires database/protocol field adjustments.",
                ),
                agility_assessment=agility,
                required_human_review=False,
                unmapped_reasons=("Hash functions are not public-key asymmetric primitives.",),
            )

        # 6. Key Establishment / Key Encapsulation (FIPS 203 — ML-KEM)
        # Includes RSA encryption/transport, Diffie-Hellman, and ECDH
        is_kem_role = role in (
            CryptographicRole.KEY_AGREEMENT,
            CryptographicRole.ENCRYPTION_DECRYPTION,
            CryptographicRole.KEY_GENERATION,
            CryptographicRole.UNKNOWN,
        )

        is_asymmetric_kem_family = (
            family in (AlgorithmFamily.RSA, AlgorithmFamily.DH, AlgorithmFamily.EC)
            or any(k in norm_name for k in ("RSA", "DH", "ECDH", "DIFFIE", "CURVE25519", "X25519", "X448"))
        )

        if is_asymmetric_kem_family and is_kem_role and role != CryptographicRole.DIGITAL_SIGNATURE:
            targets: List[CandidateTarget] = []
            compat: List[str] = []
            assumptions: List[str] = []
            unmapped_reasons: List[str] = []
            equiv_category: Optional[PqcSecurityCategory] = None
            selection_basis: str = ""

            # Determine parameter level recommendations based on classical security strength
            if classical_strength in (
                ClassicalSecurityStrength.LEGACY_112,
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                ClassicalSecurityStrength.BITS_128,
            ):
                equiv_category = PqcSecurityCategory.CATEGORY_1
                selection_basis = (
                    "Source asset provides 112-128 bits classical security (NIST SP 800-57 Table 2). "
                    "Category 1 is the minimum target category for classical strength parity. "
                    "ML-KEM-768 (Category 3) is proposed as the primary general-purpose baseline (NIST FIPS 203 recommendation) "
                    "to provide a conservative security margin; ML-KEM-512 (Category 1) is proposed for compact resource-constrained environments."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-768",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 203",
                        primary_use_case="General-Purpose Key Encapsulation (NIST Default Recommendation)",
                        public_key_bytes=1184,
                        ciphertext_or_signature_bytes=1088,
                        rationale="NIST FIPS 203 recommended baseline for general-purpose key establishment; provides Category 3 security exceeding legacy 112/128-bit baseline.",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-512",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_1,
                        standard="NIST FIPS 203",
                        primary_use_case="Compact Key Encapsulation (Category 1 Parity)",
                        public_key_bytes=800,
                        ciphertext_or_signature_bytes=768,
                        rationale="Category 1 equivalent for resource-constrained environments where 128-bit security margin is acceptable.",
                    )
                )
            elif classical_strength == ClassicalSecurityStrength.BITS_192:
                equiv_category = PqcSecurityCategory.CATEGORY_3
                selection_basis = (
                    "Source asset provides 192 bits classical security (NIST SP 800-57 Table 2). "
                    "Parity requires at least Category 3. ML-KEM-768 (Category 3) provides direct equivalent security; "
                    "ML-KEM-1024 (Category 5) provides a high-security option."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-768",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 203",
                        primary_use_case="Category 3 Key Encapsulation",
                        public_key_bytes=1184,
                        ciphertext_or_signature_bytes=1088,
                        rationale="Direct Category 3 equivalence for legacy 192-bit strength primitives (e.g. RSA-7680, P-384).",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-1024",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                        standard="NIST FIPS 203",
                        primary_use_case="High-Security Key Encapsulation (CNSA 2.0)",
                        public_key_bytes=1568,
                        ciphertext_or_signature_bytes=1568,
                        rationale="High-security option satisfying NSA CNSA 2.0 requirements.",
                    )
                )
            elif classical_strength == ClassicalSecurityStrength.BITS_256:
                equiv_category = PqcSecurityCategory.CATEGORY_5
                selection_basis = (
                    "Source asset provides 256 bits classical security (NIST SP 800-57 Table 2). "
                    "Parity requires Category 5. ML-KEM-1024 (Category 5) is proposed as direct equivalent (mandated by NSA CNSA 2.0)."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-1024",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                        standard="NIST FIPS 203",
                        primary_use_case="High-Security Key Encapsulation (CNSA 2.0 Mandated)",
                        public_key_bytes=1568,
                        ciphertext_or_signature_bytes=1568,
                        rationale="Direct Category 5 equivalence for legacy 256-bit strength primitives (e.g. P-521, RSA-15360); mandated by CNSA 2.0.",
                    )
                )
            else:
                # INDETERMINATE classical security strength (missing key size or curve)
                equiv_category = None
                selection_basis = (
                    "Source key size / curve unevidenced in static AST. "
                    "ML-KEM-768 proposed provisionally as default general-purpose baseline subject to parameter verification."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_KEM,
                        parameter_set="ML-KEM-768",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 203",
                        primary_use_case="General-Purpose Key Encapsulation (Provisional Default)",
                        public_key_bytes=1184,
                        ciphertext_or_signature_bytes=1088,
                        rationale="Provisional Category 3 baseline proposed subject to runtime modulus / curve verification.",
                    )
                )
                assumptions.append("Source key size / curve unevidenced in static AST; recommendation assumes general-purpose migration.")
                unmapped_reasons.append("Source cryptographic parameters are unannotated; target is conditional on parameter verification.")

            # Compatibility considerations for KEM migration
            compat.extend([
                "Mechanism change: ML-KEM encapsulates a random 32-byte shared secret. It cannot directly encrypt arbitrary application payload bytes.",
                "Applications using RSA public-key encryption for data payloads must transition to a hybrid KEM + AEAD envelope encryption construction.",
                "Public key size expansion: ML-KEM-768 public key (1,184 bytes) is ~4.6x larger than RSA-2048 (256 bytes) and ~37x larger than Curve25519 (32 bytes).",
                "Ciphertext expansion: ML-KEM-768 ciphertext (1,088 bytes) requires protocol buffer and network MTU validation.",
            ])

            mapping_status = (
                TargetMappingStatus.CONDITIONAL
                if classical_strength == ClassicalSecurityStrength.INDETERMINATE or role == CryptographicRole.UNKNOWN
                else TargetMappingStatus.MAPPED
            )

            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name,
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=classical_strength,
                classical_bits=classical_bits,
                target_equivalence_category=equiv_category,
                selection_basis=selection_basis,
                mapping_status=mapping_status,
                candidate_targets=tuple(targets),
                hybrid_candidates=hybrid_candidates,
                mapping_rationale=f"Asymmetric key establishment primitive '{raw_name}' ({role.value}) is vulnerable to Shor's algorithm. Mapped to candidate NIST FIPS 203 (ML-KEM) key encapsulation mechanism.",
                standards_references=("NIST FIPS 203, Section 1 & Table 2", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
                assumptions_and_questions=tuple(assumptions),
                compatibility_considerations=tuple(compat),
                agility_assessment=agility,
                required_human_review=(mapping_status == TargetMappingStatus.CONDITIONAL),
                unmapped_reasons=tuple(unmapped_reasons),
            )

        # 7. Digital Signatures (FIPS 204 — ML-DSA, FIPS 205 — SLH-DSA)
        # Includes RSA signatures, ECDSA, Ed25519
        is_signature_role = role in (CryptographicRole.DIGITAL_SIGNATURE, CryptographicRole.CERTIFICATE_OPERATIONS)
        is_signature_family = (
            family in (AlgorithmFamily.RSA, AlgorithmFamily.EC, AlgorithmFamily.EDWARDS)
            or any(k in norm_name for k in ("RSA", "ECDSA", "ED25519", "ED448"))
        )

        if is_signature_family and is_signature_role:
            targets: List[CandidateTarget] = []
            compat: List[str] = []
            assumptions: List[str] = []
            unmapped_reasons: List[str] = []
            equiv_category: Optional[PqcSecurityCategory] = None
            selection_basis: str = ""

            # Parameter selection based on classical security strength
            if classical_strength in (
                ClassicalSecurityStrength.LEGACY_112,
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                ClassicalSecurityStrength.BITS_128,
            ):
                equiv_category = PqcSecurityCategory.CATEGORY_1
                selection_basis = (
                    "Source asset provides 112-128 bits classical security (NIST SP 800-57 Table 2). "
                    "Category 1 is the minimum target category for classical strength parity. "
                    "ML-DSA-65 (Category 3) is proposed as the primary general-purpose lattice signature baseline; "
                    "ML-DSA-44 (Category 2) is proposed for compact signature budgets; "
                    "SLH-DSA-SHA2-128s (Category 1) is proposed as a stateless hash-based hedge."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_DSA,
                        parameter_set="ML-DSA-65",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 204",
                        primary_use_case="General-Purpose Digital Signatures (NIST Primary Recommendation)",
                        public_key_bytes=1952,
                        ciphertext_or_signature_bytes=3309,
                        rationale="NIST FIPS 204 primary general-purpose digital signature recommendation; provides Category 3 security.",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_DSA,
                        parameter_set="ML-DSA-44",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_2,
                        standard="NIST FIPS 204",
                        primary_use_case="Compact Lattice Digital Signatures (Category 1/2 Parity)",
                        public_key_bytes=1312,
                        ciphertext_or_signature_bytes=2420,
                        rationale="Compact lattice option for resource-constrained signature applications.",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.SLH_DSA,
                        parameter_set="SLH-DSA-SHA2-128s",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_1,
                        standard="NIST FIPS 205",
                        primary_use_case="Stateless Hash-Based Signatures (Smallest Hash-Based Size / Lattice Hedge)",
                        public_key_bytes=32,
                        ciphertext_or_signature_bytes=7856,
                        rationale="Stateless hash-based alternative relying solely on hash collision/preimage security; provides a mathematical hedge against lattice cryptanalysis.",
                    )
                )
            elif classical_strength == ClassicalSecurityStrength.BITS_192:
                equiv_category = PqcSecurityCategory.CATEGORY_3
                selection_basis = (
                    "Source asset provides 192 bits classical security (NIST SP 800-57 Table 2). "
                    "Parity requires Category 3. ML-DSA-65 (Category 3) and SLH-DSA-SHA2-192s (Category 3) proposed."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_DSA,
                        parameter_set="ML-DSA-65",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 204",
                        primary_use_case="Category 3 Digital Signatures",
                        public_key_bytes=1952,
                        ciphertext_or_signature_bytes=3309,
                        rationale="Direct Category 3 equivalence for legacy 192-bit strength primitives (e.g. P-384, RSA-7680).",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.SLH_DSA,
                        parameter_set="SLH-DSA-SHA2-192s",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 205",
                        primary_use_case="Category 3 Stateless Hash-Based Signatures",
                        public_key_bytes=48,
                        ciphertext_or_signature_bytes=16224,
                        rationale="Category 3 stateless hash-based hedge.",
                    )
                )
            elif classical_strength == ClassicalSecurityStrength.BITS_256:
                equiv_category = PqcSecurityCategory.CATEGORY_5
                selection_basis = (
                    "Source asset provides 256 bits classical security (NIST SP 800-57 Table 2). "
                    "Parity requires Category 5. ML-DSA-87 (Category 5; CNSA 2.0 mandated) and SLH-DSA-SHA2-256s (Category 5) proposed."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_DSA,
                        parameter_set="ML-DSA-87",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                        standard="NIST FIPS 204",
                        primary_use_case="High-Security Digital Signatures (CNSA 2.0 Mandated)",
                        public_key_bytes=2592,
                        ciphertext_or_signature_bytes=4627,
                        rationale="Category 5 digital signature algorithm mandated by NSA CNSA 2.0.",
                    )
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.SLH_DSA,
                        parameter_set="SLH-DSA-SHA2-256s",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_5,
                        standard="NIST FIPS 205",
                        primary_use_case="Category 5 Stateless Hash-Based Signatures",
                        public_key_bytes=64,
                        ciphertext_or_signature_bytes=29792,
                        rationale="Category 5 stateless hash-based hedge.",
                    )
                )
            else:
                # INDETERMINATE classical security strength
                equiv_category = None
                selection_basis = (
                    "Source key size / curve unevidenced in static AST. "
                    "ML-DSA-65 proposed provisionally as default general-purpose baseline subject to parameter verification."
                )
                targets.append(
                    CandidateTarget(
                        family=PqcTargetFamily.ML_DSA,
                        parameter_set="ML-DSA-65",
                        pqc_security_category=PqcSecurityCategory.CATEGORY_3,
                        standard="NIST FIPS 204",
                        primary_use_case="General-Purpose Digital Signatures (Provisional Default)",
                        public_key_bytes=1952,
                        ciphertext_or_signature_bytes=3309,
                        rationale="Provisional Category 3 baseline proposed subject to runtime modulus / curve verification.",
                    )
                )
                assumptions.append("Source key size / curve unevidenced in static AST; recommendation assumes general-purpose migration.")
                unmapped_reasons.append("Source cryptographic parameters are unannotated; target is conditional on parameter verification.")

            compat.extend([
                "Signature size expansion: Ed25519 signature (64 bytes) to ML-DSA-65 (3,309 bytes) represents ~51x expansion; SLH-DSA-SHA2-128s (7,856 bytes) represents ~122x expansion.",
                "Public key size expansion: Ed25519 public key (32 bytes) to ML-DSA-65 (1,952 bytes) represents ~61x expansion.",
                "X.509 certificate and TLS handshake packet fragmentation: Multi-kilobyte signatures and keys may exceed UDP datagram limits and TLS buffer allocations.",
                "Library & HSM availability: Ensure crypto provider and cryptographic hardware (PKCS#11 / HSM) support FIPS 204/205 signature operations.",
            ])

            mapping_status = (
                TargetMappingStatus.CONDITIONAL
                if classical_strength == ClassicalSecurityStrength.INDETERMINATE
                else TargetMappingStatus.MAPPED
            )

            return PqcTargetMapping(
                source_asset_id=asset.asset_id,
                source_algorithm=raw_name,
                source_family=family.value,
                source_role=role.value,
                observed_parameters=observed_params,
                classical_security_strength=classical_strength,
                classical_bits=classical_bits,
                target_equivalence_category=equiv_category,
                selection_basis=selection_basis,
                mapping_status=mapping_status,
                candidate_targets=tuple(targets),
                hybrid_candidates=hybrid_candidates,
                mapping_rationale=f"Digital signature primitive '{raw_name}' ({role.value}) is vulnerable to Shor's algorithm. Mapped to candidate NIST FIPS 204 (ML-DSA) and NIST FIPS 205 (SLH-DSA) signature schemes.",
                standards_references=(
                    "NIST FIPS 204, Section 1 & Table 1",
                    "NIST FIPS 205, Section 1 & Table 1",
                    "NIST SP 800-57 Part 1 Rev. 5, Table 2",
                ),
                assumptions_and_questions=tuple(assumptions),
                compatibility_considerations=tuple(compat),
                agility_assessment=agility,
                required_human_review=(mapping_status == TargetMappingStatus.CONDITIONAL),
                unmapped_reasons=tuple(unmapped_reasons),
            )

        # 8. Unsupported Role / Algorithm Combinations
        return PqcTargetMapping(
            source_asset_id=asset.asset_id,
            source_algorithm=raw_name,
            source_family=family.value,
            source_role=role.value,
            observed_parameters=observed_params,
            classical_security_strength=classical_strength,
            classical_bits=classical_bits,
            target_equivalence_category=None,
            selection_basis="Operational role / family combination has no standardized PQC mapping.",
            mapping_status=TargetMappingStatus.UNSUPPORTED,
            candidate_targets=(),
            hybrid_candidates=(),
            mapping_rationale=f"Algorithm '{raw_name}' with operational role '{role.value}' does not have a recognized NIST PQC replacement standard.",
            standards_references=("NIST SP 800-57 Part 1 Rev. 5",),
            assumptions_and_questions=(
                f"Is the operational role '{role.value}' accurately classified from AST evidence?",
            ),
            compatibility_considerations=(
                "Custom protocol construction or proprietary usage requiring protocol re-architecture.",
            ),
            agility_assessment=agility,
            required_human_review=True,
            unmapped_reasons=(f"Unsupported operational role '{role.value}' for algorithm family '{family.value}'.",),
        )

    def map_assets(self, assets: Sequence[CryptoAsset]) -> Tuple[PqcTargetMapping, ...]:
        """
        Batch maps a sequence of CryptoAsset instances, returning an immutable tuple of PqcTargetMapping records.
        Preserves deterministic ordering by source asset ID.
        """
        if not isinstance(assets, (list, tuple)):
            raise TypeError(f"Expected Sequence[CryptoAsset], got {type(assets).__name__}")

        records = [self.map_asset(a) for a in assets]
        records.sort(key=lambda r: r.source_asset_id)
        return tuple(records)
