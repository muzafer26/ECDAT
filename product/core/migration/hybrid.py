"""
ECDAT Hybrid Transition Schemes Evaluation Engine — Phase 4B.

Deterministically evaluates candidate hybrid and composite cryptographic transition options
for discovered cryptographic assets under authoritative standards and developing specifications:
- IETF draft-ietf-tls-hybrid-design (X25519MLKEM768, SecP256r1MLKEM768)
- IETF RFC 9370 (Multiple Key Exchanges in IKEv2)
- IETF draft-ietf-lamps-pq-composite-sigs (Composite Signatures for PKIX & CMS)
- IETF RFC 9763 (Related Certificates for Use in Multiple Authentications within a Protocol)
- NIST SP 800-227 (Recommendations for Key-Encapsulation Mechanisms, Final Sept 2025)

CRITICAL INVARIANTS:
1. Strict Standards Status Labeling:
   - Ratified RFCs (RFC 9370, RFC 7748) are labeled STANDARDIZED.
   - Active IETF working group drafts are labeled DRAFT.
   - Architectural deployment architectures (Dual-Cert PKI) are labeled PROFILE_DEPLOYMENT_PATTERN.
2. Conditional Security Semantics:
   - Rejects universal "Security >= max(classical, PQC)" claims.
   - Every candidate scheme specifies an exact, construction-specific security_property
     explaining combiner assumptions, protocol limitations, and failure conditions.
3. Role-Aware & Architecture-Aware:
   - Protocol-level KEMs apply strictly to key establishment / exchange.
   - Composite signatures and dual-cert apply strictly to signatures and PKI.
   - Symmetric ciphers (AES) and hashes evaluate to NONE; bulk data encryption is decoupled
     from public-key hybrid schemes.
4. Fail-Closed on Uncertainty:
   - Ambiguous algorithms, dynamic calls, and unknown roles return zero candidates.
"""

from typing import List, Optional, Sequence, Tuple

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.role import CryptographicRole
from .models import (
    ClassicalSecurityStrength,
    HybridConstructionType,
    HybridSchemeCandidate,
    PqcTargetMapping,
    StandardsStatus,
    TargetMappingStatus,
)


def evaluate_hybrid_options(
    asset: CryptoAsset,
    target_mapping: Optional[PqcTargetMapping] = None,
) -> Tuple[HybridSchemeCandidate, ...]:
    """
    Evaluates candidate hybrid/composite transition options for a discovered CryptoAsset.

    Args:
        asset: The canonical CryptoAsset to evaluate.
        target_mapping: Optional pre-computed Phase 4A PqcTargetMapping record.

    Returns:
        Immutable tuple of HybridSchemeCandidate records (empty if inapplicable or ambiguous).
    """
    if not isinstance(asset, CryptoAsset):
        raise TypeError(f"Expected CryptoAsset instance, got {type(asset).__name__}")

    # 1. Non-cryptographic or package dependency assets
    if asset.asset_type == AssetType.LIBRARY_DEPENDENCY:
        return ()

    # 2. Unknown, ambiguous, or low-confidence assets fail closed
    algo_id = asset.algorithm_identity
    family = algo_id.family
    raw_name = algo_id.algorithm or ""
    norm_name = raw_name.strip().upper()
    role = asset.role
    params = asset.parameters
    curve_name = params.curve_name.lower().strip() if (params and params.curve_name) else ""

    if (
        asset.asset_type == AssetType.UNKNOWN
        or family == AlgorithmFamily.UNKNOWN
        or "RIJNDAEL" in norm_name
        or asset.confidence == ConfidenceLevel.NEEDS_REVIEW
        or role == CryptographicRole.UNKNOWN
    ):
        return ()

    # 3. Symmetric Ciphers (AES, DES) — No public-key hybrid candidates
    if family in (AlgorithmFamily.AES, AlgorithmFamily.DES) or any(k in norm_name for k in ("AES", "DES")):
        # Symmetric data encryption does not use public-key hybrid schemes.
        # Key wrapping / management is evaluated separately if public-key evidence exists.
        return ()

    # 4. Hash Functions (SHA-1, SHA-2, SHA-3) — Inapplicable
    if family == AlgorithmFamily.SHA1 or any(k in norm_name for k in ("SHA1", "SHA_1", "SHA2", "SHA3")):
        return ()

    candidates: List[HybridSchemeCandidate] = []

    # 5. Key Agreement & Key Exchange (Protocol-Level Hybrid KEM & Envelope)
    is_kem_role = role in (
        CryptographicRole.KEY_AGREEMENT,
        CryptographicRole.ENCRYPTION_DECRYPTION,
        CryptographicRole.KEY_GENERATION,
    )

    if is_kem_role and role != CryptographicRole.DIGITAL_SIGNATURE:
        # 5A. Elliptic Curve Key Agreement (X25519, NIST P-256)
        is_ec = (
            family in (AlgorithmFamily.EC, AlgorithmFamily.EDWARDS)
            or any(k in norm_name for k in ("ECDH", "EC", "CURVE25519", "X25519"))
        )

        if is_ec:
            is_x25519 = (
                "25519" in norm_name
                or "25519" in curve_name
                or family == AlgorithmFamily.EDWARDS
            )

            if is_x25519:
                candidates.append(
                    HybridSchemeCandidate(
                        scheme_name="X25519MLKEM768",
                        classical_component="X25519 (RFC 7748)",
                        pqc_component="ML-KEM-768 (NIST FIPS 203)",
                        construction_type=HybridConstructionType.PROTOCOL_LEVEL_KEM,
                        standards_reference="IETF draft-ietf-tls-hybrid-design (codepoint 0x11ec)",
                        standards_status=StandardsStatus.DRAFT,
                        applicability="TLS 1.3 Key Exchange (draft-ietf-tls-hybrid-design)",
                        security_property=(
                            "Under the dual-PRF assumption of the TLS 1.3 key schedule combiner, secrecy of the negotiated "
                            "shared secret is preserved against passive retroactive cryptanalysis (HNDL) if either X25519 ECDH or "
                            "ML-KEM-768 remains unbroken under CDH/IND-CCA2. Does NOT provide active quantum security during the "
                            "handshake if peer authentication uses classical signatures. Downgrade prevention requires TLS 1.3 "
                            "transcript integrity and server enforcement of hybrid groups."
                        ),
                        compatibility_assumptions=(
                            "TLS 1.3 client and server must both support draft-ietf-tls-hybrid-design named group 0x11ec.",
                            "Additional ~1,184 bytes client public key share in ClientHello; network MTU fragmentation must be accommodated.",
                        ),
                        overhead_bytes=1184 + 1088,  # Client share (1184) + Server ciphertext (1088)
                        evidence_basis="Discovered X25519 / Curve25519 key agreement primitive.",
                        confidence_status="CANDIDATE_EVALUATION",
                    )
                )

            # P-256 / secp256r1 hybrid option
            is_p256 = (
                "256" in curve_name
                or "secp256r1" in curve_name
                or "prime256v1" in curve_name
                or (not is_x25519 and family == AlgorithmFamily.EC)
            )

            if is_p256:
                candidates.append(
                    HybridSchemeCandidate(
                        scheme_name="SecP256r1MLKEM768",
                        classical_component="NIST P-256 / secp256r1 (FIPS 186-5)",
                        pqc_component="ML-KEM-768 (NIST FIPS 203)",
                        construction_type=HybridConstructionType.PROTOCOL_LEVEL_KEM,
                        standards_reference="IETF draft-ietf-tls-hybrid-design (codepoint 0x11ed)",
                        standards_status=StandardsStatus.DRAFT,
                        applicability="TLS 1.3 Key Exchange for FIPS 140 compliance profiles",
                        security_property=(
                            "Under the dual-PRF assumption of the TLS 1.3 key schedule combiner, secrecy is maintained against "
                            "passive eavesdropping if at least one component key exchange remains secure. FIPS 140 validated "
                            "classical primitive paired with FIPS 203 PQC mechanism. Does NOT protect against active quantum "
                            "man-in-the-middle attacks if handshake authentication is classical. Downgrade protection relies on "
                            "TLS 1.3 transcript hash integrity."
                        ),
                        compatibility_assumptions=(
                            "Peer support for named group 0x11ed in TLS 1.3.",
                            "ClientHello packet buffer must support ~1,248 bytes combined public key share (64 bytes P-256 + 1,184 bytes ML-KEM).",
                        ),
                        overhead_bytes=1184 + 1088,
                        evidence_basis="Discovered NIST P-256 / secp256r1 key agreement primitive.",
                        confidence_status="CANDIDATE_EVALUATION",
                    )
                )

            # IKEv2 Multiple Key Exchanges option
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="IKEV2_MULTIPLE_KE_MLKEM768",
                    classical_component="Classical DH / ECDH Group (RFC 7296)",
                    pqc_component="ML-KEM-768 (NIST FIPS 203)",
                    construction_type=HybridConstructionType.PROTOCOL_LEVEL_KEM,
                    standards_reference="IETF RFC 9370 (Multiple Key Exchanges in IKEv2)",
                    standards_status=StandardsStatus.STANDARDIZED,
                    applicability="IKEv2 / IPsec VPN session key establishment",
                    security_property=(
                        "RFC 9370 standardizes intermediate key exchanges (IKE_INTERMEDIATE); derived keys incorporate entropy "
                        "from both classical and additional PQC key exchanges into SKEYSEED. Confidentiality against retro-decryption "
                        "(HNDL) holds if ML-KEM-768 is uncompromised. Does NOT provide active quantum resistance if IKEv2 peer "
                        "authentication remains classical."
                    ),
                    compatibility_assumptions=(
                        "VPN gateway and client support for RFC 9370 extensions.",
                        "Support for IKE_INTERMEDIATE message exchange packets.",
                    ),
                    overhead_bytes=1184 + 1088,
                    evidence_basis="Discovered key agreement asset evaluated for network VPN transition.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

        # 5B. RSA Key Establishment (RSA OAEP / Key Transport)
        if family == AlgorithmFamily.RSA or "RSA" in norm_name:
            # RSA does NOT map to X25519MLKEM768 as a drop-in.
            # In TLS 1.3, RSA key exchange was deprecated/removed entirely.
            # In application-layer envelope encryption, dual-wrapping applies.
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="RSA_OAEP_MLKEM768_DUAL_WRAP",
                    classical_component="RSA-OAEP 2048/3072/4096 (RFC 8017)",
                    pqc_component="ML-KEM-768 (NIST FIPS 203)",
                    construction_type=HybridConstructionType.APPLICATION_ENVELOPE,
                    standards_reference="NIST SP 800-56B Rev. 2 / NIST SP 800-227 (Final Sept 2025)",
                    standards_status=StandardsStatus.PROFILE_DEPLOYMENT_PATTERN,
                    applicability="Application-layer envelope encryption & storage key wrapping",
                    security_property=(
                        "Dual key-wrapping combiner per NIST SP 800-227 Section 6 and SP 800-56B: a symmetric data encryption key (DEK) "
                        "is encapsulated using both RSA-OAEP and ML-KEM-768, with DEK derived via KDF(K_rsa || K_kem). Confidentiality "
                        "against classical and quantum cryptanalysis holds if either wrapping mechanism remains intact and the KDF "
                        "enforces strict domain separation. Both encapsulations must be securely validated upon unwrapping."
                    ),
                    compatibility_assumptions=(
                        "Application storage schema must accommodate both RSA ciphertext (256-512 bytes) and ML-KEM ciphertext (1,088 bytes).",
                        "Cryptographic library must support concurrent execution of RSA-OAEP and FIPS 203 ML-KEM.",
                    ),
                    overhead_bytes=256 + 1088,
                    evidence_basis="Discovered RSA encryption / key transport primitive.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

    # 6. Digital Signatures (Composite Signatures & Dual Certificates)
    is_sig_role = role in (CryptographicRole.DIGITAL_SIGNATURE, CryptographicRole.CERTIFICATE_OPERATIONS)

    if is_sig_role:
        # 6A. ECDSA / Ed25519 Signatures
        if family in (AlgorithmFamily.EC, AlgorithmFamily.EDWARDS) or any(k in norm_name for k in ("ECDSA", "ED25519")):
            # Composite Signature per draft-ietf-lamps-pq-composite-sigs
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="MLDSA65-ECDSA-P256-SHA512",
                    classical_component="ECDSA P-256 (FIPS 186-5)",
                    pqc_component="ML-DSA-65 (NIST FIPS 204)",
                    construction_type=HybridConstructionType.COMPOSITE_SIGNATURE,
                    standards_reference="IETF draft-ietf-lamps-pq-composite-sigs",
                    standards_status=StandardsStatus.DRAFT,
                    applicability="X.509 PKIX certificates, S/MIME, and CMS digital signatures",
                    security_property=(
                        "Dual-verification semantics under draft-ietf-lamps-pq-composite-sigs: verification succeeds if and only if "
                        "both the ECDSA signature and the ML-DSA-65 signature verify against their respective public keys. Existential "
                        "unforgeability under chosen message attack holds if at least one component scheme is secure. However, key "
                        "compromise of either private key or protocol implementation bugs can undermine the system, signature failure "
                        "of either component causes rejection, and verifiers must support composite ASN.1 OIDs (legacy verifiers reject)."
                    ),
                    compatibility_assumptions=(
                        "Relying party PKIX library must support composite signature OID and dual-verification logic.",
                        "Certificate size increases by ~2,016 bytes; signature size increases by ~3,373 bytes.",
                        "TLS handshake buffer and certificate chain limits must accommodate multi-kilobyte certificates.",
                    ),
                    overhead_bytes=1952 + 3309 + 64 + 64,
                    evidence_basis="Discovered ECDSA digital signature primitive.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

            # Dual Certificate Parallel PKI Deployment Pattern
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="DUAL_CERT_ECDSA_MLDSA65",
                    classical_component="ECDSA P-256 X.509 Certificate",
                    pqc_component="ML-DSA-65 X.509 Certificate (FIPS 204)",
                    construction_type=HybridConstructionType.DUAL_CERTIFICATE,
                    standards_reference="IETF RFC 9763 (Related Certificates for Multiple Authentications) / NIST SP 800-57 Pt 1",
                    standards_status=StandardsStatus.PROFILE_DEPLOYMENT_PATTERN,
                    applicability="Web server TLS server certificates and enterprise PKI issuance",
                    security_property=(
                        "Parallel dual-certificate PKI deployment using RFC 9763 RelatedCertificate bindings: entity maintains distinct "
                        "classical and PQC certificates. Security is strictly partitioned: clients negotiating the classical certificate "
                        "receive zero post-quantum authentication protection. Post-quantum authentication is achieved only when client "
                        "and server both negotiate and validate the PQC certificate."
                    ),
                    compatibility_assumptions=(
                        "Web server software must support dual certificate binding (e.g. Apache/Nginx dual cert configuration).",
                        "Requires parallel PKI certificate authorities or dual issuance pipelines.",
                    ),
                    overhead_bytes=None,
                    evidence_basis="Discovered digital signature / certificate operation asset.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

            # Stateless Hash-Based Hedge Composite
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="SLHDSA128s-ECDSA-P256",
                    classical_component="ECDSA P-256 (FIPS 186-5)",
                    pqc_component="SLH-DSA-SHA2-128s (NIST FIPS 205)",
                    construction_type=HybridConstructionType.COMPOSITE_SIGNATURE,
                    standards_reference="IETF draft-ietf-lamps-pq-composite-sigs",
                    standards_status=StandardsStatus.DRAFT,
                    applicability="High-assurance long-term code signing and firmware authentication",
                    security_property=(
                        "Dual-verification composite combining classical elliptic curve with stateless hash-based signature. "
                        "Provides a mathematical hedge against potential future cryptanalytic breakthroughs in structured lattice problems."
                    ),
                    compatibility_assumptions=(
                        "Signer and verifier must support ~7.9 KB signature size.",
                        "Firmware ROM buffer limits must support multi-kilobyte signature payloads.",
                    ),
                    overhead_bytes=32 + 7856 + 64 + 64,
                    evidence_basis="Discovered digital signature asset evaluated for high-assurance code signing.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

        # 6B. RSA Signatures
        if family == AlgorithmFamily.RSA or "RSA" in norm_name:
            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="MLDSA65-RSA3072-PKCS15",
                    classical_component="RSA-3072 PKCS#1 v1.5 / PSS (RFC 8017)",
                    pqc_component="ML-DSA-65 (NIST FIPS 204)",
                    construction_type=HybridConstructionType.COMPOSITE_SIGNATURE,
                    standards_reference="IETF draft-ietf-lamps-pq-composite-sigs",
                    standards_status=StandardsStatus.DRAFT,
                    applicability="Enterprise PKIX certificates and document signing",
                    security_property=(
                        "Dual-verification semantics under draft-ietf-lamps-pq-composite-sigs requiring both RSA-3072 and ML-DSA-65 "
                        "verification. Protects against classical forgery via RSA and quantum forgery via ML-DSA. Rejection occurs if "
                        "either signature fails. Requires verifier support for composite OIDs; does not provide backward compatibility "
                        "with legacy single-algorithm verifiers."
                    ),
                    compatibility_assumptions=(
                        "Relying parties must parse composite ASN.1 structure.",
                        "Total signature size is ~3,693 bytes (~10x larger than RSA-3072 alone).",
                    ),
                    overhead_bytes=384 + 1952 + 384 + 3309,
                    evidence_basis="Discovered RSA digital signature primitive.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

            candidates.append(
                HybridSchemeCandidate(
                    scheme_name="DUAL_CERT_RSA_MLDSA65",
                    classical_component="RSA-3072 X.509 Certificate",
                    pqc_component="ML-DSA-65 X.509 Certificate (FIPS 204)",
                    construction_type=HybridConstructionType.DUAL_CERTIFICATE,
                    standards_reference="IETF RFC 9763 (Related Certificates for Multiple Authentications) / NIST SP 800-57 Pt 1",
                    standards_status=StandardsStatus.PROFILE_DEPLOYMENT_PATTERN,
                    applicability="Enterprise web server TLS and legacy client authentication",
                    security_property=(
                        "Parallel dual-certificate pattern using RFC 9763 RelatedCertificate bindings allowing legacy RSA clients "
                        "to connect without disruption while offering ML-DSA-65 authentication to upgraded clients. Security is "
                        "strictly partitioned: connections negotiating classical RSA receive zero quantum protection."
                    ),
                    compatibility_assumptions=(
                        "Dual certificate configuration supported on TLS termination endpoint.",
                        "Certificate authority infrastructure supporting dual issuance.",
                    ),
                    overhead_bytes=None,
                    evidence_basis="Discovered RSA certificate / signature primitive.",
                    confidence_status="CANDIDATE_EVALUATION",
                )
            )

    return tuple(candidates)
