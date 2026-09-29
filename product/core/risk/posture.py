"""
ECDAT Cryptographic Posture Evaluation.

Phase 3C-B: Parameter- and operation-aware evaluation of classical
security standing and theoretical quantum exposure based on verified standards.
Uses explicit, deterministic taxonomies and whitelisted aliases; strictly rejects
unsafe substring matching (e.g., CAESAR != AES, DESIGN_TOKEN != DES).
"""

import re
from typing import Optional, Set, Tuple

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import CryptoAsset
from product.core.domain.role import CryptographicRole
from .enums import (
    ClassicalSecurityStatus,
    QuantumExposureClass,
    UncertaintyLevel,
)

# Explicitly approved canonical alias taxonomies
DES_APPROVED_ALIASES: Set[str] = {
    "DES",
    "3DES",
    "TRIPLEDES",
    "TRIPLE_DES",
    "TDES",
    "DES_EDE3",
    "DESEDE",
    "DES3",
}

AES_APPROVED_ALIASES: Set[str] = {
    "AES",
    "AES_128",
    "AES_192",
    "AES_256",
}

RSA_APPROVED_ALIASES: Set[str] = {
    "RSA",
    "RSA_ENCRYPTION",
    "RIVEST_SHAMIR_ADLEMAN",
    "RSA512",
    "RSA_512",
    "RSA1024",
    "RSA_1024",
    "RSA2048",
    "RSA_2048",
    "RSA3072",
    "RSA_3072",
    "RSA4096",
    "RSA_4096",
}

SHA1_APPROVED_ALIASES: Set[str] = {
    "SHA1",
    "SHA_1",
    "SHA_160",
    "SHA160",
    "HMAC_SHA1",
    "HMAC_SHA_1",
    "HMAC_SHA160",
    "HMAC_SHA_160",
}


def _normalize_token(token: Optional[str]) -> str:
    """Normalizes an algorithm token without broad substring matching."""
    if not token:
        return ""
    # Uppercase, strip, replace non-alphanumeric separators with underscores, collapse underscores
    cleaned = re.sub(r"[^A-Z0-9]+", "_", token.strip().upper())
    return cleaned.strip("_")


def evaluate_crypto_posture(
    asset: CryptoAsset,
) -> Tuple[ClassicalSecurityStatus, QuantumExposureClass, UncertaintyLevel, str, str]:
    """
    Evaluates classical status and quantum exposure for a cryptographic asset.

    Returns:
        Tuple of:
        - ClassicalSecurityStatus
        - QuantumExposureClass
        - UncertaintyLevel
        - Standards citation / rationale
        - Normalized algorithm identity name
    """
    algo_id = asset.algorithm_identity
    family = algo_id.family
    raw_algo_name = algo_id.algorithm or ""
    normalized_token = _normalize_token(raw_algo_name)
    params = asset.parameters

    # 1. DES / 3DES evaluation (Normative mandate: NIST SP 800-131A Rev 2)
    # Exact token match or recognized family with generic/empty name
    is_des_token = normalized_token in DES_APPROVED_ALIASES
    is_des_family_generic = family == AlgorithmFamily.DES and normalized_token in ("", "UNKNOWN", "DES", "3DES")

    if is_des_token or is_des_family_generic:
        normalized_name = "3DES" if ("3" in normalized_token or "TRIPLE" in normalized_token) else "DES"
        return (
            ClassicalSecurityStatus.DISALLOWED,
            QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW,
            UncertaintyLevel.CONFIRMED,
            "NIST SP 800-131A Rev 2 (Section 2 & Table 1): Disallowed for all cryptographic uses.",
            normalized_name,
        )

    # 2. AES evaluation (FIPS 197 / NIST SP 800-57 Pt 1 Rev 5 / NISTIR 8105)
    is_aes_token = normalized_token in AES_APPROVED_ALIASES
    is_aes_family_generic = family == AlgorithmFamily.AES and normalized_token in ("", "UNKNOWN", "AES")

    if is_aes_token or is_aes_family_generic:
        # Determine effective key size from parameters or explicit token
        key_size = params.key_size_bits if params else None
        if key_size is None:
            if "256" in normalized_token:
                key_size = 256
            elif "192" in normalized_token:
                key_size = 192
            elif "128" in normalized_token:
                key_size = 128

        if key_size == 256:
            return (
                ClassicalSecurityStatus.ACCEPTABLE,
                QuantumExposureClass.GROVER_RESILIENT_SYMMETRIC_HIGH,
                UncertaintyLevel.CONFIRMED,
                "FIPS 197 / NIST SP 800-57 Pt 1 Rev 5: Approved Federal standard; 128-bit quantum security margin.",
                "AES-256",
            )
        elif key_size in (128, 192):
            return (
                ClassicalSecurityStatus.ACCEPTABLE,
                QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW,
                UncertaintyLevel.CONFIRMED,
                f"FIPS 197 / NIST SP 800-57 Pt 1 Rev 5: Approved Federal standard; {key_size // 2}-bit unconstrained Grover margin.",
                f"AES-{key_size}",
            )
        elif key_size is None:
            return (
                ClassicalSecurityStatus.ACCEPTABLE,
                QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW,
                UncertaintyLevel.HIGH_UNCERTAINTY,
                "FIPS 197: Key size unannotated; evaluated conservatively with HIGH_UNCERTAINTY under ECDAT policy.",
                "AES",
            )
        else:
            # Non-standard key size for AES
            return (
                ClassicalSecurityStatus.DISALLOWED,
                QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW,
                UncertaintyLevel.CONFIRMED,
                f"FIPS 197: Non-standard AES key size {key_size} bits is not approved.",
                f"AES-{key_size}",
            )

    # 3. RSA evaluation (NIST SP 800-131A Rev 2 / NIST SP 800-57 Pt 1 Rev 5)
    is_rsa_token = normalized_token in RSA_APPROVED_ALIASES
    is_rsa_family = family == AlgorithmFamily.RSA

    if is_rsa_token or is_rsa_family:
        key_size = params.key_size_bits if params else None

        # Check for conflicting evidence (e.g. token specifies key size differing from parameters)
        token_key_size = None
        for sz in (512, 1024, 2048, 3072, 4096):
            if str(sz) in normalized_token:
                token_key_size = sz
                break
        if token_key_size is not None and key_size is not None and token_key_size != key_size:
            return (
                ClassicalSecurityStatus.INDETERMINATE,
                QuantumExposureClass.SHOR_VULNERABLE_ASYMMETRIC,
                UncertaintyLevel.HIGH_UNCERTAINTY,
                f"Conflicting RSA modulus evidence detected: token indicates {token_key_size} bits but parameter indicates {key_size} bits.",
                "RSA",
            )

        effective_key = key_size if key_size is not None else token_key_size
        role = asset.role

        if effective_key is None:
            return (
                ClassicalSecurityStatus.INDETERMINATE,
                QuantumExposureClass.SHOR_VULNERABLE_ASYMMETRIC,
                UncertaintyLevel.HIGH_UNCERTAINTY,
                "NIST SP 800-131A Rev 2 Section 5.1: Key length missing from static evidence; compliance cannot be established.",
                "RSA",
            )
        elif effective_key < 2048:
            if role == CryptographicRole.KEY_GENERATION:
                return (
                    ClassicalSecurityStatus.DISALLOWED,
                    QuantumExposureClass.SHOR_VULNERABLE_ASYMMETRIC,
                    UncertaintyLevel.CONFIRMED,
                    f"NIST SP 800-131A Rev 2 Section 5.1.2 Table 2: RSA key generation with modulus {effective_key} bits (< 2048 bits) is disallowed (< 112 bits strength).",
                    f"RSA-{effective_key}",
                )
            else:
                # DIGITAL_SIGNATURE, ENCRYPTION_DECRYPTION, or UNKNOWN: fail-safe DISALLOWED with review required
                return (
                    ClassicalSecurityStatus.DISALLOWED,
                    QuantumExposureClass.SHOR_VULNERABLE_ASYMMETRIC,
                    UncertaintyLevel.NEEDS_REVIEW,
                    f"NIST SP 800-131A Rev 2 Section 5.1.2 Table 2: RSA modulus {effective_key} bits (< 2048 bits) is disallowed for signature generation and key transport. Operational direction unevidenced in static AST.",
                    f"RSA-{effective_key}",
                )
        else:
            # effective_key >= 2048
            return (
                ClassicalSecurityStatus.ACCEPTABLE,
                QuantumExposureClass.SHOR_VULNERABLE_ASYMMETRIC,
                UncertaintyLevel.CONFIRMED,
                f"NIST SP 800-131A Rev 2 Table 2 / NIST SP 800-57 Pt 1 Rev 5: RSA modulus {effective_key} bits acceptable for classical security (>= 112 bits strength); Shor-vulnerable.",
                f"RSA-{effective_key}",
            )

    # 4. SHA-1 evaluation (NIST SP 800-131A Rev 2 Section 8 & Table 8)
    is_sha1_token = normalized_token in SHA1_APPROVED_ALIASES
    is_sha1_family = family == AlgorithmFamily.SHA1

    if is_sha1_token or is_sha1_family:
        role = asset.role

        if role == CryptographicRole.DIGITAL_SIGNATURE:
            return (
                ClassicalSecurityStatus.DISALLOWED,
                QuantumExposureClass.GROVER_AFFECTED_HASH,
                UncertaintyLevel.NEEDS_REVIEW,
                "NIST SP 800-131A Rev 2 Section 8 & Table 8: SHA-1 disallowed for digital signature generation due to practical collision attacks. Operational direction unevidenced in static AST.",
                "SHA-1",
            )
        elif role == CryptographicRole.CERTIFICATE_OPERATIONS:
            return (
                ClassicalSecurityStatus.DEPRECATED,
                QuantumExposureClass.GROVER_AFFECTED_HASH,
                UncertaintyLevel.NEEDS_REVIEW,
                "NIST SP 800-131A Rev 2 Section 8 & Table 8: SHA-1 digital signature verification / certificate handling is legacy use.",
                "SHA-1",
            )
        elif role == CryptographicRole.MESSAGE_DIGEST:
            return (
                ClassicalSecurityStatus.DEPRECATED,
                QuantumExposureClass.GROVER_AFFECTED_HASH,
                UncertaintyLevel.NEEDS_REVIEW,
                "NIST SP 800-131A Rev 2 Table 8: SHA-1 deprecated for general hashing; collision resistance is broken, but preimage resistance remains intact (> 150 bits). Requires operational review.",
                "SHA-1",
            )
        elif role == CryptographicRole.MAC:
            hmac_key_size = params.key_size_bits if params else None
            if hmac_key_size is not None and hmac_key_size < 112:
                return (
                    ClassicalSecurityStatus.DISALLOWED,
                    QuantumExposureClass.GROVER_AFFECTED_HASH,
                    UncertaintyLevel.CONFIRMED,
                    f"NIST SP 800-131A Rev 2 Table 8: HMAC key {hmac_key_size} bits (< 112 bits) is disallowed for message authentication.",
                    "HMAC-SHA-1",
                )
            elif hmac_key_size is None:
                return (
                    ClassicalSecurityStatus.ACCEPTABLE,
                    QuantumExposureClass.GROVER_AFFECTED_HASH,
                    UncertaintyLevel.NEEDS_REVIEW,
                    "NIST SP 800-131A Rev 2 Table 8: HMAC-SHA-1 acceptable where key >= 112 bits; HMAC relies on PRF properties. Key size unverified in static code.",
                    "HMAC-SHA-1",
                )
            else:
                return (
                    ClassicalSecurityStatus.ACCEPTABLE,
                    QuantumExposureClass.GROVER_AFFECTED_HASH,
                    UncertaintyLevel.CONFIRMED,
                    f"NIST SP 800-131A Rev 2 Table 8: HMAC-SHA-1 acceptable with key size {hmac_key_size} bits (>= 112 bits).",
                    "HMAC-SHA-1",
                )
        else:
            # role == UNKNOWN or undifferentiated
            return (
                ClassicalSecurityStatus.INDETERMINATE,
                QuantumExposureClass.GROVER_AFFECTED_HASH,
                UncertaintyLevel.HIGH_UNCERTAINTY,
                "Operational role unevidenced; cannot determine if SHA-1 is utilized in a collision-sensitive context.",
                "SHA-1",
            )

    # 5. Unknown, unevidenced, or unsupported primitive (e.g. CAESAR, DESIGN_TOKEN, etc.)
    return (
        ClassicalSecurityStatus.INDETERMINATE,
        QuantumExposureClass.UNCLASSIFIED_QUANTUM_POSTURE,
        UncertaintyLevel.NEEDS_REVIEW,
        f"Primitive '{raw_algo_name}' is unrecognized or insufficiently evidenced; requires human review.",
        raw_algo_name if raw_algo_name else "UNKNOWN",
    )
