"""
ECDAT CBOM Projection Engine.

Implements the non-inferential translation of ECDAT canonical domain models
into CycloneDX 1.7 CBOM component, metadata, and evidence dictionaries.

Invariant:
EVIDENCE -> CANONICAL INTERPRETATION -> CYCLONEDX FIELD
NOT: ROLE -> ASSUMED CYCLONEDX SEMANTIC
"""

import re
from typing import Any, Dict, List, Optional, Sequence

from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import EvidenceLocation, EvidenceRecord

from .constants import (
    ALGORITHM_FAMILIES,
    ASSET_TYPES,
    CRYPTO_FUNCTIONS,
    ECDAT_PROPERTY_PREFIX,
    MODES,
    PADDINGS,
    PRIMITIVES,
)


# Explicit, auditable mapping table from ECDAT AssetType to official CycloneDX 1.7 assetType enum.
# Prevents accidental string equality and enforces exact schema alignment.
#
# LIBRARY_DEPENDENCY is intentionally EXCLUDED:
#   Libraries (e.g. BouncyCastle) are NOT cryptographic algorithms.
#   Setting assetType="algorithm" on a library would falsely communicate
#   "this algorithm is being used" — violating the benchmark invariant:
#   dependency/provider presence ≠ algorithm usage.
#   Library components are projected as type="library" with PURL, evidence,
#   ECDAT properties, and dependency.provides graph. No cryptoProperties.
#
# UNKNOWN is intentionally EXCLUDED:
#   In canonical ECDAT semantics and evidence contract, AssetType.UNKNOWN means:
#   "A cryptographic usage was observed, but the actual asset type is unknown."
#   (It could be an algorithm, key, certificate, protocol, library, or configuration).
#   CycloneDX 1.7 has NO assetType="unknown" (allowed values: algorithm, certificate,
#   protocol, related-crypto-material). Emitting cryptoProperties.assetType="algorithm"
#   would falsely assert that the asset is known to be an algorithm.
#   Therefore, the incompatible CycloneDX crypto representation is omitted,
#   and ECDAT UNKNOWN semantics are preserved through ecdat: properties/provenance.
ECDAT_TO_CYCLONEDX_ASSET_TYPE: Dict[AssetType, str] = {
    AssetType.ALGORITHM: "algorithm",
    AssetType.PROTOCOL: "protocol",
    AssetType.CERTIFICATE: "certificate",
    AssetType.CRYPTO_KEY: "related-crypto-material",
}


class CBOMProjector:
    """
    Translates ECDAT canonical assets into CycloneDX 1.7 compliant dictionaries
    under strict non-inference and zero silent semantic loss invariants.
    """

    @classmethod
    def project_asset_type(cls, asset_type: AssetType) -> Optional[str]:
        """
        Explicitly maps an ECDAT canonical AssetType to an official CycloneDX 1.7
        cryptoProperties.assetType enum value.
        
        CRITICAL RULES:
        - Never relies on accidental string equality.
        - AssetType.CRYPTO_KEY maps to official 'related-crypto-material'.
        - Protocol and certificate map 1-to-1 to official schema enums.
        - LIBRARY_DEPENDENCY and UNKNOWN are intentionally NOT mapped: neither receives
          cryptoProperties.
          * LIBRARY_DEPENDENCY: library presence ≠ algorithm usage (ADR-012).
          * UNKNOWN: actual asset type is unknown; projecting as 'algorithm' would falsely
            assert algorithm identity.
        - Inverse boundary: CycloneDX enums must never be inferred back to a narrower
          ECDAT asset type without evidence.
        
        Returns None for unmapped or non-crypto asset types.
        """
        target = ECDAT_TO_CYCLONEDX_ASSET_TYPE.get(asset_type)
        if not target or target not in ASSET_TYPES:
            return None
        return target

    @staticmethod
    def project_algorithm_family(
        algorithm_identity: AlgorithmIdentity,
        parameters: Optional[AlgorithmParameters] = None,
    ) -> Optional[str]:
        """
        Maps an AlgorithmIdentity to an official CycloneDX algorithmFamily enum value.
        
        CRITICAL RULE:
        An operational role alone MUST NOT determine a narrower CycloneDX family.
        Maps ONLY when the specific scheme/algorithm is explicitly established by evidence.
        If generic/unresolved (bare RSA, bare EC, bare DH, bare Edwards, UNKNOWN),
        returns None so the field is omitted from standard output and preserved in ecdat: properties.
        """
        family = algorithm_identity.family
        algo_upper = (algorithm_identity.algorithm or "").strip().upper()
        variant_upper = (algorithm_identity.variant or "").strip().upper()
        padding_upper = (parameters.padding_scheme if parameters and parameters.padding_scheme else "").strip().upper()

        if family == AlgorithmFamily.AES:
            return "AES"

        if family == AlgorithmFamily.DES:
            if "3DES" in algo_upper or "DESEDE" in algo_upper or "3DES" in variant_upper:
                return "3DES"
            return "DES"

        if family == AlgorithmFamily.SHA1:
            return "SHA-1"

        if family == AlgorithmFamily.SHA2:
            return "SHA-2"

        if "SHA3" in algo_upper or "SHA-3" in algo_upper:
            return "SHA-3"

        if family == AlgorithmFamily.RSA:
            # Scheme must be explicitly established by algorithm name or padding
            if "PSS" in algo_upper or padding_upper == "PSS":
                return "RSASSA-PSS"
            if "OAEP" in algo_upper or padding_upper == "OAEP":
                return "RSAES-OAEP"
            if "SHA" in algo_upper and "RSA" in algo_upper:
                return "RSASSA-PKCS1"
            if "PKCS1" in algo_upper or padding_upper in ("PKCS1", "PKCS1V15"):
                # Distinguish encryption vs signature if scheme is explicit
                if "SIGN" in algo_upper or "SSA" in algo_upper:
                    return "RSASSA-PKCS1"
                if "ENC" in algo_upper or "ES" in algo_upper:
                    return "RSAES-PKCS1"
            # Generic RSA without explicit scheme: DO NOT GUESS
            return None

        if family == AlgorithmFamily.EC:
            # Scheme must be explicitly named in algorithm or API
            if "ECDSA" in algo_upper:
                return "ECDSA"
            if "ECDH" in algo_upper:
                return "ECDH"
            if "ECIES" in algo_upper:
                return "ECIES"
            # Generic EC key generation or curve only: DO NOT GUESS
            return None

        if family == AlgorithmFamily.DH:
            if "FFDH" in algo_upper:
                return "FFDH"
            if "ECDH" in algo_upper:
                return "ECDH"
            # Generic DH without parameters: DO NOT GUESS
            return None

        if family == AlgorithmFamily.EDWARDS:
            if algo_upper in ("ED25519", "ED448", "EDDSA") or "ED25519" in algo_upper:
                return "EdDSA"
            if algo_upper in ("X25519", "X448") or "X25519" in algo_upper:
                return "ECDH"  # Montgomery curve for Diffie-Hellman key agreement
            # Generic Edwards: DO NOT GUESS
            return None

        # Direct check for other official families
        for official_family in ALGORITHM_FAMILIES:
            if official_family.upper() == algo_upper or official_family.upper() == family.value.upper():
                return official_family

        return None

    @staticmethod
    def project_primitive(
        asset: CryptoAsset,
        evidence_records: Sequence[EvidenceRecord] = (),
    ) -> Optional[str]:
        """
        Maps an asset to an official CycloneDX algorithmProperties.primitive enum value.
        
        CRITICAL RULE:
        primitive is mapped strictly from the evidenced mathematical construction,
        NEVER from high-level role alone.
        
        - Authenticated Encryption ("ae") requires explicit AEAD / GCM / CCM evidence.
        - Block Cipher ("block-cipher") requires block mode / block cipher evidence.
        - Stream Cipher ("stream-cipher") requires stream cipher evidence.
        - Public-key Encryption ("pke") requires asymmetric encryption evidence.
        - Digital Signature ("signature") requires signature scheme evidence.
        - Key Agreement ("key-agree") requires key agreement protocol evidence.
        - Hash ("hash") requires digest evidence.
        - MAC ("mac") requires MAC evidence.
        - KDF ("kdf") requires KDF evidence.
        - If construction is generic or unevidenced, returns None (omitted).
        """
        algo_upper = (asset.algorithm_identity.algorithm or "").strip().upper()
        mode_upper = (asset.parameters.cipher_mode or "").strip().upper()
        family = asset.algorithm_identity.family

        # 1. Authenticated Encryption
        if mode_upper in ("GCM", "CCM") or "GCM" in algo_upper or "CHACHA20-POLY1305" in algo_upper:
            return "ae"

        # 2. Block Cipher
        if mode_upper in ("CBC", "ECB", "CTR", "CFB", "OFB") or (
            family in (AlgorithmFamily.AES, AlgorithmFamily.DES)
            and mode_upper
        ):
            return "block-cipher"

        # 3. Stream Cipher
        if algo_upper in ("SALSA20", "CHACHA20", "RC4") or (
            "CHACHA20" in algo_upper and "POLY1305" not in algo_upper
        ):
            return "stream-cipher"

        # 4. Public-Key Encryption
        if "RSAES" in algo_upper or (
            family == AlgorithmFamily.RSA and asset.parameters.padding_scheme in ("OAEP", "oaep")
        ):
            return "pke"

        # 5. Digital Signature
        if (
            "ECDSA" in algo_upper
            or "ED25519" in algo_upper
            or "ED448" in algo_upper
            or "EDDSA" in algo_upper
            or "RSASSA" in algo_upper
            or "DSA" in algo_upper
            or "WITHRSA" in algo_upper
            or "WITHECDSA" in algo_upper
        ):
            return "signature"

        # 6. Key Agreement
        if (
            "ECDH" in algo_upper
            or "FFDH" in algo_upper
            or "X25519" in algo_upper
            or "X448" in algo_upper
            or (family == AlgorithmFamily.DH and "KEYAGREEMENT" in asset.primary_location.matched_text.upper())
        ):
            return "key-agree"

        # 7. Hash
        if family in (AlgorithmFamily.SHA1, AlgorithmFamily.SHA2) or "SHA3" in algo_upper or "SHA-3" in algo_upper or (
            algo_upper in ("MD5", "SHA-256", "SHA-512", "SHA-1", "SHA-384", "SHA-224", "RIPEMD")
        ):
            return "hash"

        # 8. Extended Output Function
        if "SHAKE128" in algo_upper or "SHAKE256" in algo_upper:
            return "xof"

        # 9. Message Authentication Code
        if "HMAC" in algo_upper or "CMAC" in algo_upper or "POLY1305" in algo_upper:
            return "mac"

        # 10. Key Derivation Function
        if "PBKDF2" in algo_upper or "HKDF" in algo_upper or "ARGON2" in algo_upper or "SCRYPT" in algo_upper:
            return "kdf"

        # 11. Key Encapsulation Mechanism
        if "ML-KEM" in algo_upper or "KEM" in algo_upper:
            return "kem"

        # 12. Dynamic Unknown
        if algo_upper == "UNKNOWN" or family == AlgorithmFamily.UNKNOWN:
            return "unknown"

        # If construction cannot be established without inference, omit it
        return None

    @staticmethod
    def project_crypto_functions(
        asset: CryptoAsset,
        evidence_records: Sequence[EvidenceRecord] = (),
    ) -> Optional[List[str]]:
        """
        Maps an asset to an array of official CycloneDX cryptoFunctions enums.
        
        CRITICAL RULE:
        Functions MUST NOT be synthesized from role alone (e.g. KEY_AGREEMENT never
        emits ["keyderive", "other"], ENCRYPTION never emits ["encrypt", "decrypt"]).
        Populated ONLY when the specific operation is empirically evidenced at the call site.
        If unevidenced, returns None (omitted).
        "other" is NEVER used as a placeholder.
        """
        combined_text = asset.primary_location.matched_text.lower() + " " + asset.primary_location.code_snippet.lower()
        for ev in evidence_records:
            if ev.location:
                combined_text += " " + ev.location.matched_text.lower() + " " + ev.location.code_snippet.lower()

        functions: List[str] = []

        if "encrypt_mode" in combined_text or re.search(r"\bencrypt\b", combined_text):
            functions.append("encrypt")
        if "decrypt_mode" in combined_text or re.search(r"\bdecrypt\b", combined_text):
            functions.append("decrypt")
        if "generatekey" in combined_text or "getinstance" in combined_text and "keypairgenerator" in combined_text:
            functions.append("keygen")
        if "generatesecret" in combined_text:
            functions.append("keyderive")
        if re.search(r"\.sign\s*\(", combined_text):
            functions.append("sign")
        if re.search(r"\.verify\s*\(", combined_text):
            functions.append("verify")
        if re.search(r"\.digest\s*\(", combined_text):
            functions.append("digest")
        if re.search(r"\.dofinal\s*\(", combined_text) and "mac" in combined_text:
            functions.append("tag")
        if "encapsulate" in combined_text:
            functions.append("encapsulate")
        if "decapsulate" in combined_text:
            functions.append("decapsulate")

        if functions:
            return sorted(list(set(functions)))

        return None

    @staticmethod
    def project_parameter_set_identifier(asset: CryptoAsset) -> Optional[str]:
        """
        Maps recognized formal cryptographic parameter set identifiers.
        
        CRITICAL RULE:
        Curve, mode, padding, and general asymmetric key sizes (e.g. RSA 2048)
        MUST NOT be dumped into parameterSetIdentifier.
        Populated ONLY when the value represents a recognized formal parameter set.
        """
        algo_upper = (asset.algorithm_identity.algorithm or "").strip().upper()
        variant = (asset.algorithm_identity.variant or "").strip()
        family = asset.algorithm_identity.family

        # Symmetric formal parameter sets (populated ONLY when explicitly evidenced as variant or formal name)
        # Raw key_size_bits is preserved in ecdat:key_size_bits and must NOT merely bleed into parameterSetIdentifier.
        if family == AlgorithmFamily.AES:
            if variant in ("128", "192", "256"):
                return variant
            for size in ("128", "192", "256"):
                # Formal naming pattern: e.g. "AES-128", "AES-256-GCM" where size is an explicit token in the algorithm name
                if f"AES-{size}" in algo_upper or f"AES_{size}" in algo_upper:
                    return size

        # Hash digest length parameter sets (e.g. SHA-256 -> "256", SHA3-512 -> "512")
        if family == AlgorithmFamily.SHA2 or "SHA3" in algo_upper or "SHA-3" in algo_upper:
            if variant in ("224", "256", "384", "512"):
                return variant
            for size in ("224", "256", "384", "512"):
                if f"-{size}" in algo_upper or f"_{size}" in algo_upper or algo_upper.endswith(size):
                    return size

        # Formal PQC parameter set identifiers (e.g. ML-KEM-768 -> "768")
        if "SLH-DSA" in algo_upper or "ML-KEM" in algo_upper or "ML-DSA" in algo_upper:
            if variant:
                return variant

        return None

    @staticmethod
    def project_properties(
        asset: CryptoAsset,
        evidence_records: Sequence[EvidenceRecord] = (),
    ) -> List[Dict[str, str]]:
        """
        Builds the standardized ecdat:* property extension array preserving
        all authoritative analytical and provenance metadata without silent semantic loss.
        """
        props: List[Dict[str, str]] = [
            {"name": f"{ECDAT_PROPERTY_PREFIX}asset_id", "value": asset.asset_id},
            {"name": f"{ECDAT_PROPERTY_PREFIX}asset_type", "value": asset.asset_type.value},
            {"name": f"{ECDAT_PROPERTY_PREFIX}role", "value": asset.role.value},
            {"name": f"{ECDAT_PROPERTY_PREFIX}algorithm_family", "value": asset.algorithm_identity.family.value},
            {"name": f"{ECDAT_PROPERTY_PREFIX}confidence", "value": asset.confidence.value},
            {"name": f"{ECDAT_PROPERTY_PREFIX}disposition", "value": "UNREVIEWED"},
            {"name": f"{ECDAT_PROPERTY_PREFIX}correlation_basis", "value": asset.correlation_basis},
            {"name": f"{ECDAT_PROPERTY_PREFIX}finding_ids", "value": ",".join(asset.finding_ids)},
        ]

        # Key size segregation
        if asset.parameters.key_size_bits:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}key_size_bits", "value": str(asset.parameters.key_size_bits)})
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}key_size", "value": str(asset.parameters.key_size_bits)})

        # Curve segregation
        if asset.parameters.curve_name:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}curve", "value": asset.parameters.curve_name})

        # Mode segregation
        if asset.parameters.cipher_mode:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}mode", "value": asset.parameters.cipher_mode.lower()})

        # Padding segregation
        if asset.parameters.padding_scheme:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}padding", "value": asset.parameters.padding_scheme.lower()})

        # Digest algorithm
        if asset.parameters.digest_algorithm:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}digest_algorithm", "value": asset.parameters.digest_algorithm})

        # Informal scanner variant
        if asset.algorithm_identity.variant:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}algorithm_variant", "value": asset.algorithm_identity.variant})

        # Location end coordinates for multi-line spans
        loc = asset.primary_location
        if loc.line_end is not None and loc.line_start is not None and loc.line_end > loc.line_start:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}line_end", "value": str(loc.line_end)})
        if loc.column_end is not None:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}column_end", "value": str(loc.column_end)})
        if loc.matched_text:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}matched_text", "value": loc.matched_text[:200]})

        # Multi-scanner provenance
        scanners = sorted(list({f"{e.scanner_name}:{e.scanner_version}" for e in evidence_records if e.scanner_name}))
        if scanners:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}scanners", "value": ",".join(scanners)})

        evidence_ids = sorted(list({e.evidence_id for e in evidence_records if e.evidence_id}))
        if evidence_ids:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}evidence_ids", "value": ",".join(evidence_ids)})

        raw_refs = sorted(list({e.raw_output_ref for e in evidence_records if e.raw_output_ref}))
        if raw_refs:
            props.append({"name": f"{ECDAT_PROPERTY_PREFIX}raw_output_ref", "value": raw_refs[0]})

        return props

    @classmethod
    def project_component(
        cls,
        asset: CryptoAsset,
        evidence_records: Sequence[EvidenceRecord] = (),
    ) -> Dict[str, Any]:
        """
        Projects a canonical CryptoAsset into a CycloneDX 1.7 component dictionary.

        LIBRARY_DEPENDENCY and UNKNOWN assets do NOT receive cryptoProperties:
        - LIBRARY_DEPENDENCY is projected as type="library" because a library provider
          IS NOT a cryptographic algorithm (dependency presence ≠ algorithm usage).
        - UNKNOWN is projected as type="cryptographic-asset" without cryptoProperties
          because CycloneDX lacks an 'unknown' assetType; emitting 'algorithm' would
          falsely assert algorithm identity.
        
        algorithmProperties is emitted ONLY when cryptoProperties.assetType == 'algorithm'.
        Non-algorithm crypto assets receive strictly their respective property objects:
        - CRYPTO_KEY -> relatedCryptoMaterialProperties only
        - CERTIFICATE -> certificateProperties only
        - PROTOCOL -> protocolProperties only
        """
        bom_ref = f"ecdat:asset:{asset.asset_id}"
        comp_type = "cryptographic-asset" if asset.asset_type != AssetType.LIBRARY_DEPENDENCY else "library"

        component: Dict[str, Any] = {
            "type": comp_type,
            "name": asset.algorithm_identity.algorithm or "UNKNOWN",
            "bom-ref": bom_ref,
        }

        # Package coordinates for libraries
        if asset.asset_type == AssetType.LIBRARY_DEPENDENCY and asset.primary_location.package_coordinate:
            component["purl"] = asset.primary_location.package_coordinate

        # Cryptographic Properties:
        # Emitted ONLY when the asset has an authentic CycloneDX cryptoProperties representation.
        cdx_asset_type = cls.project_asset_type(asset.asset_type)
        if cdx_asset_type:
            crypto_props: Dict[str, Any] = {
                "assetType": cdx_asset_type
            }

            if asset.asset_type == AssetType.ALGORITHM:
                algo_props: Dict[str, Any] = {}

                # 1. Algorithm Family (Non-inference)
                family = cls.project_algorithm_family(asset.algorithm_identity, asset.parameters)
                if family:
                    algo_props["algorithmFamily"] = family

                # 2. Primitive (Non-inference)
                primitive = cls.project_primitive(asset, evidence_records)
                if primitive:
                    algo_props["primitive"] = primitive

                # 3. Cryptographic Functions (Evidence-driven)
                crypto_funcs = cls.project_crypto_functions(asset, evidence_records)
                if crypto_funcs:
                    algo_props["cryptoFunctions"] = crypto_funcs

                # 4. Parameter Set Identifier
                param_set = cls.project_parameter_set_identifier(asset)
                if param_set:
                    algo_props["parameterSetIdentifier"] = param_set

                # 5. Curve
                if asset.parameters.curve_name:
                    algo_props["curve"] = asset.parameters.curve_name

                # 6. Mode
                if asset.parameters.cipher_mode and asset.parameters.cipher_mode.lower() in MODES:
                    algo_props["mode"] = asset.parameters.cipher_mode.lower()

                # 7. Padding
                if asset.parameters.padding_scheme:
                    pad_lower = asset.parameters.padding_scheme.lower()
                    if "pkcs5" in pad_lower:
                        algo_props["padding"] = "pkcs5"
                    elif "pkcs7" in pad_lower:
                        algo_props["padding"] = "pkcs7"
                    elif "oaep" in pad_lower:
                        algo_props["padding"] = "oaep"
                    elif "pkcs1" in pad_lower:
                        algo_props["padding"] = "pkcs1v15"
                    elif "raw" in pad_lower or "nopadding" in pad_lower:
                        algo_props["padding"] = "raw"
                    elif pad_lower in PADDINGS:
                        algo_props["padding"] = pad_lower

                # algorithmProperties emitted ONLY for algorithm assets
                crypto_props["algorithmProperties"] = algo_props

            elif asset.asset_type == AssetType.CRYPTO_KEY:
                mat_props: Dict[str, Any] = {"type": "key"}
                if asset.parameters.key_size_bits:
                    mat_props["size"] = int(asset.parameters.key_size_bits)
                crypto_props["relatedCryptoMaterialProperties"] = mat_props

            elif asset.asset_type == AssetType.CERTIFICATE:
                cert_props: Dict[str, Any] = {}
                crypto_props["certificateProperties"] = cert_props

            elif asset.asset_type == AssetType.PROTOCOL:
                proto_props: Dict[str, Any] = {}
                algo_name_lower = (asset.algorithm_identity.algorithm or "").strip().lower()
                for p_enum in ("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "dtls", "quic"):
                    if p_enum in algo_name_lower:
                        proto_props["type"] = p_enum
                        break
                crypto_props["protocolProperties"] = proto_props

            component["cryptoProperties"] = crypto_props

        # Evidence occurrences
        loc = asset.primary_location
        occurrence: Dict[str, Any] = {
            "location": loc.file_path or "unknown",
            "line": int(loc.line_start or 0),
        }
        if loc.column_start is not None:
            occurrence["offset"] = int(loc.column_start)
        if loc.code_snippet:
            occurrence["additionalContext"] = loc.code_snippet

        component["evidence"] = {
            "occurrences": [occurrence]
        }

        # Extension properties
        component["properties"] = cls.project_properties(asset, evidence_records)

        return component
