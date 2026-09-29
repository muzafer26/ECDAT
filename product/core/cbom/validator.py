"""
ECDAT Two-Tier CBOM Validator.

Provides zero-external-dependency validation of CycloneDX 1.7 CBOM documents:
- Tier 1: Structural & Schema Validation (compliant with CycloneDX 1.7 schema & cryptography registry).
- Tier 2: Semantic Non-Inference Validation (verifies preservation of non-inference invariants).
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Sequence, Set

from product.core.domain.asset import AssetType, CryptoAsset

from .constants import (
    ALGORITHM_FAMILIES,
    ASSET_TYPES,
    CRYPTO_FUNCTIONS,
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    ECDAT_PROPERTY_PREFIX,
    MODES,
    PADDINGS,
    PRIMITIVES,
)

URN_UUID_REGEX = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
ISO8601_UTC_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of CBOM validation."""
    is_valid: bool
    tier: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class CBOMValidator:
    """
    Two-tier CBOM validator implementing offline structural schema checks
    and semantic non-inference invariants.
    """

    @classmethod
    def validate_tier1_structure(cls, bom_data: Dict[str, Any]) -> ValidationResult:
        """
        Tier 1: Structural and Schema Validation.
        Verifies all required fields, regex patterns, and official schema enum memberships.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Root fields
        if bom_data.get("bomFormat") != CYCLONEDX_BOM_FORMAT:
            errors.append(f"Invalid bomFormat: expected '{CYCLONEDX_BOM_FORMAT}', got '{bom_data.get('bomFormat')}'")

        if bom_data.get("specVersion") != CYCLONEDX_SPEC_VERSION:
            errors.append(f"Invalid specVersion: expected '{CYCLONEDX_SPEC_VERSION}', got '{bom_data.get('specVersion')}'")

        serial = bom_data.get("serialNumber", "")
        if not URN_UUID_REGEX.match(serial):
            errors.append(f"Invalid serialNumber format: '{serial}' does not match RFC 4122 urn:uuid regex")

        if not isinstance(bom_data.get("version"), int) or bom_data.get("version", 0) < 1:
            errors.append(f"Invalid version: must be integer >= 1, got '{bom_data.get('version')}'")

        # 2. Metadata
        metadata = bom_data.get("metadata")
        if not isinstance(metadata, dict):
            errors.append("Missing or invalid 'metadata' object")
        else:
            ts = metadata.get("timestamp", "")
            if not ISO8601_UTC_REGEX.match(ts):
                errors.append(f"Invalid metadata timestamp format: '{ts}'")

            meta_comp = metadata.get("component")
            if not isinstance(meta_comp, dict):
                errors.append("Missing metadata 'component' object")
            elif not meta_comp.get("name"):
                errors.append("Metadata component must have a non-empty 'name'")

            tools = metadata.get("tools")
            if not isinstance(tools, dict) or not isinstance(tools.get("components"), list):
                errors.append("Missing or invalid metadata.tools.components list")

        # 3. Components
        components = bom_data.get("components", [])
        if not isinstance(components, list):
            errors.append("'components' must be a list")
            return ValidationResult(is_valid=False, tier="Tier 1 (Structural)", errors=errors)

        seen_refs: Set[str] = set()

        for idx, comp in enumerate(components):
            if not isinstance(comp, dict):
                errors.append(f"Component at index {idx} is not an object")
                continue

            ref = comp.get("bom-ref")
            if not ref or not isinstance(ref, str):
                errors.append(f"Component at index {idx} missing valid 'bom-ref'")
            elif ref in seen_refs:
                errors.append(f"Duplicate bom-ref detected: '{ref}'")
            else:
                seen_refs.add(ref)

            if not comp.get("name"):
                errors.append(f"Component '{ref}' missing required 'name'")

            comp_type = comp.get("type")
            if not comp_type or not isinstance(comp_type, str):
                errors.append(f"Component '{ref}' missing required 'type'")

            # Cryptographic properties validation
            crypto_props = comp.get("cryptoProperties")
            if crypto_props is not None:
                if comp_type != "cryptographic-asset":
                    errors.append(
                        f"Component '{ref}' has type '{comp_type}' but possesses 'cryptoProperties'; "
                        f"'cryptoProperties' is permitted ONLY on 'cryptographic-asset' components"
                    )

                if not isinstance(crypto_props, dict):
                    errors.append(f"Component '{ref}' has invalid 'cryptoProperties'")
                    continue

                asset_type = crypto_props.get("assetType")
                if asset_type not in ASSET_TYPES:
                    errors.append(f"Component '{ref}' has invalid assetType '{asset_type}'; must be one of {sorted(list(ASSET_TYPES))}")

                algo_props = crypto_props.get("algorithmProperties")
                if algo_props is not None:
                    if asset_type != "algorithm":
                        errors.append(
                            f"Component '{ref}' has 'algorithmProperties' but assetType is '{asset_type}'; "
                            f"'algorithmProperties' is permitted ONLY when assetType is 'algorithm'"
                        )
                    if not isinstance(algo_props, dict):
                        errors.append(f"Component '{ref}' has invalid 'algorithmProperties'")
                        continue

                    # Validate algorithmFamily against 93 official registry enums
                    family = algo_props.get("algorithmFamily")
                    if family is not None:
                        if family not in ALGORITHM_FAMILIES:
                            errors.append(f"Component '{ref}' algorithmFamily '{family}' is NOT in official CycloneDX 1.7 registry")

                    # Validate primitive
                    primitive = algo_props.get("primitive")
                    if primitive is not None:
                        if primitive not in PRIMITIVES:
                            errors.append(f"Component '{ref}' primitive '{primitive}' is NOT in official CycloneDX 1.7 primitive enum")

                    # Validate cryptoFunctions
                    crypto_funcs = algo_props.get("cryptoFunctions")
                    if crypto_funcs is not None:
                        if not isinstance(crypto_funcs, list):
                            errors.append(f"Component '{ref}' cryptoFunctions must be a list")
                        else:
                            for fn in crypto_funcs:
                                if fn not in CRYPTO_FUNCTIONS:
                                    errors.append(f"Component '{ref}' cryptoFunctions contains invalid enum '{fn}'")

                    # Validate mode
                    mode = algo_props.get("mode")
                    if mode is not None and mode not in MODES:
                        errors.append(f"Component '{ref}' mode '{mode}' is NOT in official CycloneDX mode enum")

                    # Validate padding
                    padding = algo_props.get("padding")
                    if padding is not None and padding not in PADDINGS:
                        errors.append(f"Component '{ref}' padding '{padding}' is NOT in official CycloneDX padding enum")

                # Validate relatedCryptoMaterialProperties exclusivity
                mat_props = crypto_props.get("relatedCryptoMaterialProperties")
                if mat_props is not None:
                    if asset_type != "related-crypto-material":
                        errors.append(
                            f"Component '{ref}' has 'relatedCryptoMaterialProperties' but assetType is '{asset_type}'; "
                            f"'relatedCryptoMaterialProperties' is permitted ONLY when assetType is 'related-crypto-material'"
                        )
                    if not isinstance(mat_props, dict):
                        errors.append(f"Component '{ref}' has invalid 'relatedCryptoMaterialProperties'")

                # Validate certificateProperties exclusivity
                cert_props = crypto_props.get("certificateProperties")
                if cert_props is not None:
                    if asset_type != "certificate":
                        errors.append(
                            f"Component '{ref}' has 'certificateProperties' but assetType is '{asset_type}'; "
                            f"'certificateProperties' is permitted ONLY when assetType is 'certificate'"
                        )
                    if not isinstance(cert_props, dict):
                        errors.append(f"Component '{ref}' has invalid 'certificateProperties'")

                # Validate protocolProperties exclusivity
                proto_props = crypto_props.get("protocolProperties")
                if proto_props is not None:
                    if asset_type != "protocol":
                        errors.append(
                            f"Component '{ref}' has 'protocolProperties' but assetType is '{asset_type}'; "
                            f"'protocolProperties' is permitted ONLY when assetType is 'protocol'"
                        )
                    if not isinstance(proto_props, dict):
                        errors.append(f"Component '{ref}' has invalid 'protocolProperties'")

        # 4. Dependencies
        dependencies = bom_data.get("dependencies", [])
        if isinstance(dependencies, list):
            for dep in dependencies:
                if isinstance(dep, dict):
                    ref = dep.get("ref")
                    if ref and ref not in seen_refs:
                        errors.append(f"Dependency references non-existent bom-ref: '{ref}'")
                    for d_ref in dep.get("dependsOn", []):
                        if d_ref not in seen_refs:
                            errors.append(f"Dependency dependsOn references non-existent bom-ref: '{d_ref}'")
                    for p_ref in dep.get("provides", []):
                        if p_ref not in seen_refs:
                            errors.append(f"Dependency provides references non-existent bom-ref: '{p_ref}'")

        return ValidationResult(
            is_valid=len(errors) == 0,
            tier="Tier 1 (Structural)",
            errors=errors,
            warnings=warnings,
        )

    @classmethod
    def validate_tier2_semantics(
        cls,
        bom_data: Dict[str, Any],
        source_assets: Sequence[CryptoAsset],
    ) -> ValidationResult:
        """
        Tier 2: Semantic Non-Inference Validation.
        Verifies that no inferential leaps occurred, parameter sets were not conflated,
        and all canonical information is preserved without silent loss.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # Index components by asset_id from property
        comp_by_asset_id: Dict[str, Dict[str, Any]] = {}
        for comp in bom_data.get("components", []):
            for prop in comp.get("properties", []):
                if prop.get("name") == f"{ECDAT_PROPERTY_PREFIX}asset_id":
                    comp_by_asset_id[prop.get("value")] = comp

        for asset in source_assets:
            comp = comp_by_asset_id.get(asset.asset_id)
            if not comp:
                errors.append(f"Canonical asset '{asset.asset_id}' missing from CBOM components")
                continue

            crypto_props = comp.get("cryptoProperties", {})
            algo_props = crypto_props.get("algorithmProperties", {})

            # 1. Non-inference check: role alone must not infer "ae"
            primitive = algo_props.get("primitive")
            mode = (asset.parameters.cipher_mode or "").lower()
            algo_name = (asset.algorithm_identity.algorithm or "").lower()

            if primitive == "ae":
                if mode not in ("gcm", "ccm") and "gcm" not in algo_name and "poly1305" not in algo_name:
                    errors.append(
                        f"Asset '{asset.asset_id}': primitive='ae' emitted without authenticated encryption evidence (mode='{mode}', algo='{algo_name}')"
                    )

            # 2. Non-inference check: cryptoFunctions must not contain fabricated "other"
            crypto_funcs = algo_props.get("cryptoFunctions", [])
            if "other" in crypto_funcs:
                errors.append(
                    f"Asset '{asset.asset_id}': cryptoFunctions contains forbidden placeholder 'other'"
                )

            # 3. Non-inference check: cryptoFunctions must not be synthesized from role alone
            if asset.role.value == "KEY_AGREEMENT" and crypto_funcs == ["keyderive", "other"]:
                errors.append(
                    f"Asset '{asset.asset_id}': cryptoFunctions synthesized as ['keyderive', 'other'] from role alone"
                )

            # 4. Parameter set segregation check
            param_set = algo_props.get("parameterSetIdentifier")
            if param_set:
                # Must not be a curve name
                if param_set.lower() in ("secp256r1", "secp384r1", "curve25519", "ed25519"):
                    errors.append(f"Asset '{asset.asset_id}': curve '{param_set}' erroneously placed in parameterSetIdentifier")
                # Must not be a cipher mode
                if param_set.lower() in ("gcm", "cbc", "ecb", "ctr"):
                    errors.append(f"Asset '{asset.asset_id}': mode '{param_set}' erroneously placed in parameterSetIdentifier")
                # Must not be an RSA key size unless formal parameter set
                if asset.algorithm_identity.family.value == "RSA" and param_set in ("2048", "4096", "1024"):
                    errors.append(f"Asset '{asset.asset_id}': RSA key size '{param_set}' erroneously placed in parameterSetIdentifier")

            # 5. Algorithm family non-narrowing check
            fam = algo_props.get("algorithmFamily")
            if asset.algorithm_identity.family.value == "RSA" and fam in ("RSASSA-PKCS1", "RSASSA-PSS", "RSAES-OAEP"):
                # Verify scheme is actually evidenced in source
                if "rsa" == algo_name and not asset.parameters.padding_scheme:
                    errors.append(f"Asset '{asset.asset_id}': generic RSA narrowed to '{fam}' without scheme evidence")

            if asset.algorithm_identity.family.value == "EC" and fam in ("ECDSA", "ECDH", "ECIES"):
                if "ec" == algo_name and "ecdh" not in algo_name and "ecdsa" not in algo_name:
                    errors.append(f"Asset '{asset.asset_id}': generic EC narrowed to '{fam}' without scheme evidence")

            # 6. Unknown preservation check
            if asset.algorithm_identity.algorithm == "UNKNOWN":
                if comp.get("name") != "UNKNOWN":
                    errors.append(f"Asset '{asset.asset_id}': UNKNOWN algorithm replaced with guessed '{comp.get('name')}'")

        return ValidationResult(
            is_valid=len(errors) == 0,
            tier="Tier 2 (Semantic)",
            errors=errors,
            warnings=warnings,
        )

    @classmethod
    def validate(
        cls,
        bom_data: Dict[str, Any],
        source_assets: Optional[Sequence[CryptoAsset]] = None,
    ) -> ValidationResult:
        """
        Runs complete two-tier validation.
        """
        t1 = cls.validate_tier1_structure(bom_data)
        if not t1.is_valid:
            return t1

        if source_assets:
            t2 = cls.validate_tier2_semantics(bom_data, source_assets)
            if not t2.is_valid:
                return t2

        return ValidationResult(is_valid=True, tier="Two-Tier Validation Passed")
