"""
ECDAT Classical Security Strength Classifier — Phase 4A.

Classifies discovered cryptographic assets into formal Classical Security Strength levels
(ClassicalSecurityStrength) and classical bits strictly according to:
- NIST SP 800-57 Part 1 Rev. 5, Section 5.6.1, Table 2 ("Comparable security strengths")
- NIST SP 800-131A Rev. 2, Table 2 & Table 8 ("Transitioning the Use of Cryptographic Algorithms")
- NIST FIPS 197 (AES)
- NIST FIPS 186-5 (Digital Signature Standard)

CRITICAL INVARIANTS:
1. Evaluates CLASSICAL bits of security only. Never assigns a NIST PQC Security Category to an RSA or ECC asset.
2. Never infers security strength from a bare algorithm name when required parameters are missing.
3. Unknown algorithms, bare Rijndael, or unparameterized primitives evaluate to INDETERMINATE.
4. Classical disallowance (< 112 bits) is kept distinct from quantum exposure.
"""

import re
from typing import Optional, Set, Tuple

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import CryptoAsset
from product.core.domain.role import CryptographicRole
from .models import ClassicalSecurityStrength, NistSecurityCategory


# Standardized curve mapping based on NIST SP 800-186 and SP 800-57 Pt 1 Rev 5 Table 2
NIST_P256_NAMES: Set[str] = {
    "secp256r1", "p-256", "p256", "prime256v1", "nistp256", "1.2.840.10045.3.1.7"
}
NIST_P384_NAMES: Set[str] = {
    "secp384r1", "p-384", "p384", "nistp384", "1.3.132.0.34"
}
NIST_P521_NAMES: Set[str] = {
    "secp521r1", "p-521", "p521", "nistp521", "1.3.132.0.35"
}
NIST_P224_NAMES: Set[str] = {
    "secp224r1", "p-224", "p224", "nistp224", "1.3.132.0.33"
}
CURVE25519_NAMES: Set[str] = {
    "curve25519", "x25519", "ed25519", "25519", "1.3.101.110", "1.3.101.112"
}
CURVE448_NAMES: Set[str] = {
    "curve448", "x448", "ed448", "448", "1.3.101.111", "1.3.101.113"
}


def _clean_token(token: Optional[str]) -> str:
    if not token:
        return ""
    cleaned = re.sub(r"[^A-Z0-9]+", "_", token.strip().upper())
    return cleaned.strip("_")


def classify_classical_security_strength(
    asset: CryptoAsset,
) -> Tuple[ClassicalSecurityStrength, Optional[int], str, Tuple[str, ...]]:
    """
    Evaluates the classical security strength of a CryptoAsset under authoritative NIST standards.

    Returns:
        Tuple of:
        - ClassicalSecurityStrength (BITS_128, BITS_192, BITS_256, LEGACY_112, DISALLOWED_SUB_112, INDETERMINATE, OUT_OF_SCOPE)
        - Optional[int]: integer classical bits of security (e.g. 112, 128, 192, 256, or None)
        - Scientific rationale explaining the standard and parameter evaluation
        - Tuple of authoritative standards citations
    """
    algo_id = asset.algorithm_identity
    family = algo_id.family
    raw_name = algo_id.algorithm or ""
    norm_token = _clean_token(raw_name)
    params = asset.parameters
    key_size = params.key_size_bits if params else None
    curve = params.curve_name.lower().strip() if (params and params.curve_name) else ""
    variant = algo_id.variant.lower().strip() if algo_id.variant else ""

    effective_curve = curve or variant

    # 1. Unknown / Unverified family or bare Rijndael
    if family == AlgorithmFamily.UNKNOWN or "RIJNDAEL" in norm_token:
        return (
            ClassicalSecurityStrength.INDETERMINATE,
            None,
            f"Algorithm '{raw_name}' is unrecognized or insufficiently evidenced; classical security strength cannot be established.",
            ("NIST SP 800-57 Part 1 Rev. 5, Section 5.6.1",),
        )

    # 2. RSA (NIST SP 800-57 Pt 1 Rev 5 Table 2 & SP 800-131A Rev 2 Table 2)
    if family == AlgorithmFamily.RSA or "RSA" in norm_token:
        effective_key = key_size
        if effective_key is None:
            # Check if token explicitly embeds modulus (e.g. RSA2048, RSA_4096)
            for sz in (512, 1024, 2048, 3072, 4096, 7680, 15360):
                if str(sz) in norm_token:
                    effective_key = sz
                    break

        if effective_key is None:
            return (
                ClassicalSecurityStrength.INDETERMINATE,
                None,
                "RSA modulus length missing from static evidence; classical security strength cannot be determined without verified key size.",
                ("NIST SP 800-131A Rev. 2, Section 5.1", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
            )
        elif effective_key < 2048:
            return (
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                80 if effective_key >= 1024 else 0,
                f"RSA modulus {effective_key} bits provides < 112 bits of classical security strength; disallowed for all cryptographic operations.",
                ("NIST SP 800-131A Rev. 2, Section 5.1.2 Table 2", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
            )
        elif effective_key < 3072:
            return (
                ClassicalSecurityStrength.LEGACY_112,
                112,
                f"RSA modulus {effective_key} bits provides 112 bits of classical security strength (legacy acceptable; disallowed after 2030).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-131A Rev. 2, Section 5.1.2"),
            )
        elif effective_key < 7680:
            bits_val = 128 if effective_key == 3072 else 140
            return (
                ClassicalSecurityStrength.BITS_128,
                bits_val,
                f"RSA modulus {effective_key} bits provides >= 128 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )
        elif effective_key < 15360:
            return (
                ClassicalSecurityStrength.BITS_192,
                192,
                f"RSA modulus {effective_key} bits provides >= 192 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )
        else:
            return (
                ClassicalSecurityStrength.BITS_256,
                256,
                f"RSA modulus {effective_key} bits provides >= 256 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )

    # 3. Elliptic Curve & Edwards (NIST SP 800-57 Pt 1 Rev 5 Table 2, SP 800-186, FIPS 186-5)
    if family in (AlgorithmFamily.EC, AlgorithmFamily.EDWARDS) or any(
        k in norm_token for k in ("EC", "ECDSA", "ECDH", "ED25519", "X25519", "ED448", "X448")
    ):
        # Check by curve name first
        if effective_curve in NIST_P256_NAMES or effective_curve in CURVE25519_NAMES:
            return (
                ClassicalSecurityStrength.BITS_128,
                128,
                f"Curve '{effective_curve}' provides 128 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-186, Section 3.2"),
            )
        elif effective_curve in NIST_P384_NAMES or effective_curve in CURVE448_NAMES:
            return (
                ClassicalSecurityStrength.BITS_192,
                192,
                f"Curve '{effective_curve}' provides 192 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-186, Section 3.2"),
            )
        elif effective_curve in NIST_P521_NAMES:
            return (
                ClassicalSecurityStrength.BITS_256,
                256,
                f"Curve '{effective_curve}' provides 256 bits of classical security strength (NIST SP 800-57 Table 2).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-186, Section 3.2"),
            )
        elif effective_curve in NIST_P224_NAMES:
            return (
                ClassicalSecurityStrength.LEGACY_112,
                112,
                f"Curve '{effective_curve}' provides 112 bits of classical security strength (legacy acceptable; disallowed after 2030).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-131A Rev. 2, Section 5.1.2"),
            )

        # Check by key size / field size bits if curve name was omitted or custom
        if key_size is not None:
            if key_size < 224:
                return (
                    ClassicalSecurityStrength.DISALLOWED_SUB_112,
                    80,
                    f"EC field size {key_size} bits provides < 112 bits classical security strength; disallowed.",
                    ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "NIST SP 800-131A Rev. 2, Section 5.1.2"),
                )
            elif key_size < 256:
                return (
                    ClassicalSecurityStrength.LEGACY_112,
                    112,
                    f"EC field size {key_size} bits provides 112 bits classical security strength (legacy acceptable).",
                    ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
                )
            elif key_size < 384:
                return (
                    ClassicalSecurityStrength.BITS_128,
                    128,
                    f"EC field size {key_size} bits provides >= 128 bits classical security strength.",
                    ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
                )
            elif key_size < 512:
                return (
                    ClassicalSecurityStrength.BITS_192,
                    192,
                    f"EC field size {key_size} bits provides >= 192 bits classical security strength.",
                    ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
                )
            else:
                return (
                    ClassicalSecurityStrength.BITS_256,
                    256,
                    f"EC field size {key_size} bits provides >= 256 bits classical security strength.",
                    ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
                )

        # Check for Ed25519 token
        if "ED25519" in norm_token or "X25519" in norm_token:
            return (
                ClassicalSecurityStrength.BITS_128,
                128,
                "Curve25519 / Ed25519 provides 128 bits of classical security strength.",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2", "RFC 8032 / RFC 7748"),
            )

        return (
            ClassicalSecurityStrength.INDETERMINATE,
            None,
            "Elliptic curve parameters (curve name or field size) missing; classical security strength cannot be determined.",
            ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
        )

    # 4. Finite Field Diffie-Hellman (DH)
    if family == AlgorithmFamily.DH or any(k in norm_token for k in ("DH", "DIFFIE")):
        if key_size is None:
            return (
                ClassicalSecurityStrength.INDETERMINATE,
                None,
                "Diffie-Hellman prime modulus length missing; classical strength indeterminate.",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )
        elif key_size < 2048:
            return (
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                80,
                f"Diffie-Hellman prime {key_size} bits provides < 112 bits security; disallowed.",
                ("NIST SP 800-131A Rev. 2, Table 2",),
            )
        elif key_size < 3072:
            return (
                ClassicalSecurityStrength.LEGACY_112,
                112,
                f"Diffie-Hellman prime {key_size} bits provides 112 bits classical security (legacy acceptable through 2030).",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )
        elif key_size < 7680:
            return (
                ClassicalSecurityStrength.BITS_128,
                128,
                f"Diffie-Hellman prime {key_size} bits provides >= 128 bits classical security.",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )
        else:
            return (
                ClassicalSecurityStrength.BITS_256,
                256,
                f"Diffie-Hellman prime {key_size} bits provides >= 256 bits classical security.",
                ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
            )

    # 5. Symmetric Ciphers (AES, DES, 3DES)
    if family in (AlgorithmFamily.AES, AlgorithmFamily.DES) or any(k in norm_token for k in ("AES", "DES")):
        if family == AlgorithmFamily.DES or "DES" in norm_token:
            if "3DES" in norm_token or "TRIPLE" in norm_token or "TDES" in norm_token:
                return (
                    ClassicalSecurityStrength.LEGACY_112,
                    112,
                    "3-key Triple-DES provides 112 bits classical security (legacy; disallowed for new systems after 2023).",
                    ("NIST SP 800-131A Rev. 2, Table 1", "NIST SP 800-67 Rev. 2"),
                )
            return (
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                56,
                "Single DES provides 56 bits security; disallowed under NIST standards.",
                ("NIST SP 800-131A Rev. 2, Table 1",),
            )

        if family == AlgorithmFamily.AES or "AES" in norm_token:
            effective_key = key_size
            if effective_key is None:
                for sz in (128, 192, 256):
                    if str(sz) in norm_token:
                        effective_key = sz
                        break

            if effective_key == 128:
                return (
                    ClassicalSecurityStrength.BITS_128,
                    128,
                    "AES-128 provides 128 bits classical security strength (NIST FIPS 197 / SP 800-57 Table 2). Note: Quantum exposure reduces key search margin to 64 bits under Grover.",
                    ("NIST FIPS 197", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
                )
            elif effective_key == 192:
                return (
                    ClassicalSecurityStrength.BITS_192,
                    192,
                    "AES-192 provides 192 bits classical security strength.",
                    ("NIST FIPS 197", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
                )
            elif effective_key == 256:
                return (
                    ClassicalSecurityStrength.BITS_256,
                    256,
                    "AES-256 provides 256 bits classical security strength (128-bit quantum security margin under Grover).",
                    ("NIST FIPS 197", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
                )
            else:
                return (
                    ClassicalSecurityStrength.INDETERMINATE,
                    None,
                    "AES key length missing from static evidence; classical strength indeterminate.",
                    ("NIST FIPS 197",),
                )

    # 6. Cryptographic Hashes (SHA-1, SHA-2, SHA-3)
    if family == AlgorithmFamily.SHA1 or "SHA" in norm_token:
        if family == AlgorithmFamily.SHA1 or "SHA1" in norm_token or "SHA_1" in norm_token:
            return (
                ClassicalSecurityStrength.DISALLOWED_SUB_112,
                0,
                "SHA-1 collision resistance is broken (< 80 bits security); disallowed for digital signatures.",
                ("NIST SP 800-131A Rev. 2, Table 8",),
            )
        if "256" in norm_token:
            return (
                ClassicalSecurityStrength.BITS_128,
                128,
                "SHA-256 provides 128 bits collision resistance and 256 bits preimage resistance.",
                ("NIST FIPS 180-4", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
            )
        if "384" in norm_token:
            return (
                ClassicalSecurityStrength.BITS_192,
                192,
                "SHA-384 provides 192 bits collision resistance.",
                ("NIST FIPS 180-4", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
            )
        if "512" in norm_token:
            return (
                ClassicalSecurityStrength.BITS_256,
                256,
                "SHA-512 provides 256 bits collision resistance.",
                ("NIST FIPS 180-4", "NIST SP 800-57 Part 1 Rev. 5, Table 2"),
            )

    return (
        ClassicalSecurityStrength.INDETERMINATE,
        None,
        f"Primitive '{raw_name}' does not map to a recognized classical security strength rule.",
        ("NIST SP 800-57 Part 1 Rev. 5, Table 2",),
    )


def classify_nist_security_strength(
    asset: CryptoAsset,
) -> Tuple[ClassicalSecurityStrength, str, Tuple[str, ...]]:
    """
    Backward-compatible adapter returning (ClassicalSecurityStrength, rationale, standards_citations).
    """
    strength, bits, rationale, citations = classify_classical_security_strength(asset)
    return strength, rationale, citations
