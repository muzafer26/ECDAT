"""
ECDAT Normalization Engine.

Converts heterogeneous, untrusted EvidenceRecord instances into canonical Finding instances.
Strictly preserves immutable evidence, enforces the specificity invariant, distinguishes
scanner category from domain interpretation, and maintains uncertainty without false certainty.
"""

import re
from typing import List, Optional
import uuid

from product.core.evidence.evidence import EvidenceRecord, DetectionMethod, LocationType
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.role import CryptographicRole
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.confidence import ConfidenceLevel, DispositionStatus
from product.core.domain.observation import ObservationType
from product.core.domain.finding import Finding
from .taxonomy import resolve_algorithm_family, infer_role_from_api, extract_parameters


# Regex patterns for detecting non-executable or decoy contexts
_COMMENT_LINE_PATTERN = re.compile(r"^\s*(?://|/\*|\*|#|--|\"\"\"|\'\'\')")
_DECOY_STRING_PATTERN = re.compile(
    r"(?:logger|log|System\.out|print)\s*\.\s*(?:info|debug|warn|error|println|print)\s*\(|String\s+[a-zA-Z0-9_]*(?:dummy|fake|sample|test|log|msg|name)\s*=",
    re.IGNORECASE,
)
_DYNAMIC_CALL_PATTERN = re.compile(
    r"Cipher\.getInstance\s*\(\s*(?![\"\'])|System\.(?:getenv|getProperty)\s*\(",
    re.IGNORECASE,
)
_DEPENDENCY_FILE_PATTERN = re.compile(r"(?:pom\.xml|build\.gradle|requirements\.txt|package\.json|go\.mod|Cargo\.toml)$", re.IGNORECASE)


class NormalizationEngine:
    """
    Deterministic, conservative normalization engine.
    
    Invariants:
    1. Evidence is NEVER deleted, mutated, or suppressed.
    2. Evidence Specificity >= Interpretation Specificity.
       - ECC evidence alone != ECDH interpretation.
       - Generic ECC without specific evidence remains family=EC, algorithm=UNKNOWN.
    3. Raw scanner_category in EvidenceRecord is never overwritten.
    4. Decoys and comments are observations, not cryptographic roles.
    5. Dynamic ciphers remain UNKNOWN with NEEDS_REVIEW confidence.
    6. Dependency declarations do not infer algorithm usage.
    """

    def normalize(self, evidence: EvidenceRecord) -> Finding:
        """Transforms a single EvidenceRecord into a canonical Finding."""
        code_text = evidence.location.code_snippet or evidence.location.matched_text or ""
        file_path = evidence.location.file_path or ""
        finding_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:finding:{evidence.evidence_id}"))

        # 1. Check for Manifest / Dependency declarations
        if (
            evidence.detection_method == DetectionMethod.LOCKFILE_PARSE
            or evidence.location.location_type == LocationType.DEPENDENCY
            or (file_path and _DEPENDENCY_FILE_PATTERN.search(file_path))
        ):
            return Finding(
                finding_id=finding_id,
                evidence_ids=[evidence.evidence_id],
                observation_type=ObservationType.LIBRARY_DEPENDENCY,
                algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
                role=CryptographicRole.UNKNOWN,
                parameters=AlgorithmParameters(),
                primary_location=evidence.location,
                confidence=ConfidenceLevel.CONFIRMED,
                disposition=DispositionStatus.UNREVIEWED,
                interpretation_basis="Cryptographic library package declaration in manifest; no active code invocation proven",
            )

        # 2. Check for Comment-Only observations
        matched_stripped = (evidence.location.matched_text or "").strip()
        code_stripped = code_text.strip()
        is_comment = (
            evidence.detection_method == DetectionMethod.COMMENT_MATCH
            or (_COMMENT_LINE_PATTERN.match(matched_stripped) if matched_stripped else False)
            or (_COMMENT_LINE_PATTERN.match(code_stripped) if code_stripped else False)
        )
        if is_comment:
            return Finding(
                finding_id=finding_id,
                evidence_ids=[evidence.evidence_id],
                observation_type=ObservationType.COMMENT_ONLY,
                algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
                role=CryptographicRole.UNKNOWN,
                parameters=AlgorithmParameters(),
                primary_location=evidence.location,
                confidence=ConfidenceLevel.NEEDS_REVIEW,
                disposition=DispositionStatus.FALSE_POSITIVE,
                interpretation_basis="Non-functional comment text; zero active cryptographic execution",
            )

        # 3. Check for Dynamic / Ambiguous cipher construction
        if _DYNAMIC_CALL_PATTERN.search(code_text) or _DYNAMIC_CALL_PATTERN.search(evidence.location.matched_text or ""):
            return Finding(
                finding_id=finding_id,
                evidence_ids=[evidence.evidence_id],
                observation_type=ObservationType.AMBIGUOUS_CALL,
                algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
                role=CryptographicRole.ENCRYPTION_DECRYPTION,
                parameters=AlgorithmParameters(),
                primary_location=evidence.location,
                confidence=ConfidenceLevel.NEEDS_REVIEW,
                disposition=DispositionStatus.NEEDS_REVIEW,
                interpretation_basis="Dynamic cipher initialization with variable transformation; algorithm cannot be statically proven",
            )

        # 4. Check for Non-Cryptographic Decoy (logging strings, decoy variable assignments without crypto API)
        has_crypto_api = bool(re.search(r"(?:getInstance|hashlib\.|SecretKeySpec|KeyAgreement|Signature|MessageDigest)", code_text))
        is_decoy = not has_crypto_api and bool(_DECOY_STRING_PATTERN.search(code_text))
        if is_decoy:
            return Finding(
                finding_id=finding_id,
                evidence_ids=[evidence.evidence_id],
                observation_type=ObservationType.NON_CRYPTOGRAPHIC_DECOY,
                algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
                role=CryptographicRole.UNKNOWN,
                parameters=AlgorithmParameters(),
                primary_location=evidence.location,
                confidence=ConfidenceLevel.NEEDS_REVIEW,
                disposition=DispositionStatus.FALSE_POSITIVE,
                interpretation_basis="Non-cryptographic decoy string or variable naming; zero active cryptographic execution",
            )

        # 5. Standard Cryptographic Normalization
        # Determine algorithm family and specific algorithm based strictly on evidence
        family, algorithm, variant, role, confidence, basis = self._resolve_cryptographic_identity(evidence, code_text)

        parameters = extract_parameters(code_text, algorithm)

        return Finding(
            finding_id=finding_id,
            evidence_ids=[evidence.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=AlgorithmIdentity(family=family, algorithm=algorithm, variant=variant),
            role=role,
            parameters=parameters,
            primary_location=evidence.location,
            confidence=confidence,
            disposition=DispositionStatus.UNREVIEWED,
            interpretation_basis=basis,
        )

    def normalize_batch(self, evidence_list: List[EvidenceRecord]) -> List[Finding]:
        """Normalizes a batch of EvidenceRecords, preserving all evidence without omissions."""
        return [self.normalize(e) for e in evidence_list]

    def _resolve_cryptographic_identity(
        self, evidence: EvidenceRecord, code_text: str
    ) -> tuple[AlgorithmFamily, str, Optional[str], CryptographicRole, ConfidenceLevel, str]:
        """
        Resolves (family, algorithm, variant, role, confidence, interpretation_basis).
        Enforces: Evidence Specificity >= Interpretation Specificity.
        """
        scanner_cat = evidence.scanner_category.upper()
        api_role = infer_role_from_api(code_text)

        # --- A. EDWARDS CURVE / ED25519 ---
        if re.search(r"\bEd25519\b", code_text, re.IGNORECASE) or "ED25519" in scanner_cat:
            role = api_role if api_role != CryptographicRole.UNKNOWN else CryptographicRole.DIGITAL_SIGNATURE
            return (
                AlgorithmFamily.EDWARDS,
                "Ed25519",
                None,
                role,
                ConfidenceLevel.CONFIRMED,
                "Explicit Ed25519 token in code evidence",
            )

        # --- B. EXPLICIT ECDSA ---
        if re.search(r"\bECDSA\b|SHA\d+withECDSA", code_text, re.IGNORECASE) or "ECDSA" in scanner_cat:
            variant_match = re.search(r"(secp256r1|P-256)", code_text, re.IGNORECASE)
            variant = "secp256r1" if variant_match else None
            role = CryptographicRole.DIGITAL_SIGNATURE if api_role in (CryptographicRole.DIGITAL_SIGNATURE, CryptographicRole.UNKNOWN) else api_role
            return (
                AlgorithmFamily.EC,
                "ECDSA",
                variant,
                role,
                ConfidenceLevel.CONFIRMED,
                "Explicit ECDSA digital signature evidenced by API or token",
            )

        # --- C. DIFFIE-HELLMAN (Explicit in code) ---
        # Specificity Invariant: Explicit DH in code must NEVER be overridden by generic ECC scanner category
        has_explicit_dh = (
            re.search(r"getInstance\s*\(\s*[\"']DH[\"']\s*\)|\bDiffieHellman\b", code_text, re.IGNORECASE) is not None
            or (re.search(r"\bDH\b", code_text) and ("KeyAgreement" in code_text or api_role == CryptographicRole.KEY_AGREEMENT))
        )
        if has_explicit_dh:
            return (
                AlgorithmFamily.DH,
                "DH",
                None,
                CryptographicRole.KEY_AGREEMENT,
                ConfidenceLevel.CONFIRMED,
                "Explicit Diffie-Hellman key agreement evidenced in code",
            )

        # --- D. EXPLICIT ECDH (KeyAgreement) ---
        # Critical invariant: EVIDENCE >= INTERPRETATION.
        # Generic scanner category "ECC" or "EC" alone MUST NEVER manufacture "ECDH"!
        # ECDH requires explicit ECDH token in code or explicit curve agreement parameter.
        has_explicit_ecdh = (
            re.search(r"getInstance\s*\(\s*[\"']ECDH[\"']\s*\)|\bECDH\b", code_text, re.IGNORECASE) is not None
        )
        if has_explicit_ecdh:
            variant_match = re.search(r"(secp256r1|prime256v1|P-256)", code_text, re.IGNORECASE)
            variant = "secp256r1" if variant_match else None
            return (
                AlgorithmFamily.EC,
                "ECDH",
                variant,
                CryptographicRole.KEY_AGREEMENT,
                ConfidenceLevel.CONFIRMED,
                "Explicit ECDH key agreement evidenced by code token or API parameter",
            )

        # --- E. GENERIC KEYAGREEMENT (No specific algorithm token in code) ---
        # Generic KeyAgreement without specific algorithm evidence must NOT manufacture ECDH,
        # even if scanner category is ECC/EC.
        has_key_agreement_api = "KeyAgreement.getInstance" in code_text or api_role == CryptographicRole.KEY_AGREEMENT
        if has_key_agreement_api:
            has_ec_context = bool(re.search(r"(?:ECGenParameterSpec|ECParameterSpec|secp256r1|P-256)", code_text, re.IGNORECASE))
            family = AlgorithmFamily.EC if has_ec_context else AlgorithmFamily.UNKNOWN
            variant = "secp256r1" if re.search(r"(?:secp256r1|P-256)", code_text, re.IGNORECASE) else None
            return (
                family,
                "UNKNOWN",
                variant,
                CryptographicRole.KEY_AGREEMENT,
                ConfidenceLevel.NEEDS_REVIEW,
                "KeyAgreement operation without explicit algorithm evidence; algorithm preserved as UNKNOWN",
            )

        # --- F. GENERIC EC / ECC (KeyGen or unspecified) ---
        if "EC" in scanner_cat or "ECC" in scanner_cat or re.search(r"\bEC\b|KeyPairGenerator.*\"EC\"", code_text):
            variant_match = re.search(r"(secp256r1|prime256v1|P-256)", code_text, re.IGNORECASE)
            variant = "secp256r1" if variant_match else None
            # Generic EC KeyPairGenerator does not prove role (could be signature or agreement later)
            role = api_role if api_role != CryptographicRole.UNKNOWN else CryptographicRole.KEY_GENERATION
            return (
                AlgorithmFamily.EC,
                "UNKNOWN",  # Specificity Invariant: Do NOT manufacture ECDSA or ECDH from generic ECC!
                variant,
                role,
                ConfidenceLevel.CONFIRMED,
                "Generic Elliptic Curve primitive without specific algorithm evidence; algorithm preserved as UNKNOWN",
            )

        # --- G. RSA ---
        if "RSA" in scanner_cat or re.search(r"\bRSA\b", code_text, re.IGNORECASE):
            role = api_role if api_role != CryptographicRole.UNKNOWN else CryptographicRole.KEY_GENERATION
            return (
                AlgorithmFamily.RSA,
                "RSA",
                None,
                role,
                ConfidenceLevel.CONFIRMED,
                "Explicit RSA algorithm evidence",
            )

        # --- H. AES ---
        if "AES" in scanner_cat or re.search(r"\bAES\b", code_text, re.IGNORECASE):
            return (
                AlgorithmFamily.AES,
                "AES",
                None,
                CryptographicRole.ENCRYPTION_DECRYPTION,
                ConfidenceLevel.CONFIRMED,
                "Explicit AES block cipher evidence",
            )

        # --- I. DES / 3DES (Direct or Wrapper) ---
        if "DES" in scanner_cat or re.search(r"\bDES\b|\bDESede\b", code_text, re.IGNORECASE):
            algo_name = "3DES" if "DESede" in code_text or "3DES" in scanner_cat else "DES"
            return (
                AlgorithmFamily.DES,
                algo_name,
                None,
                CryptographicRole.ENCRYPTION_DECRYPTION,
                ConfidenceLevel.CONFIRMED,
                "Legacy DES cipher usage evidenced directly or in wrapper class",
            )

        # --- J. SHA-1 ---
        if "SHA1" in scanner_cat or "SHA-1" in scanner_cat or re.search(r"\bsha1\b|SHA-1|MessageDigest.*\"SHA-1\"", code_text, re.IGNORECASE):
            return (
                AlgorithmFamily.SHA1,
                "SHA-1",
                None,
                CryptographicRole.MESSAGE_DIGEST,
                ConfidenceLevel.CONFIRMED,
                "SHA-1 cryptographic hash digest function",
            )

        # --- K. DIFFIE-HELLMAN (Scanner-evidenced fallback) ---
        if "DH" in scanner_cat or "DIFFIE" in scanner_cat:
            return (
                AlgorithmFamily.DH,
                "DH",
                None,
                CryptographicRole.KEY_AGREEMENT,
                ConfidenceLevel.LIKELY,
                "Diffie-Hellman key agreement evidenced by scanner category",
            )

        # --- L. UNKNOWN / CONSERVATIVE FALLBACK ---
        return (
            AlgorithmFamily.UNKNOWN,
            "UNKNOWN",
            None,
            api_role,
            ConfidenceLevel.NEEDS_REVIEW,
            "Unrecognized cryptographic token; preserved as UNKNOWN to prevent false certainty",
        )
