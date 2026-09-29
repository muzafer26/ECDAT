"""
ECDAT / SIH26164 — Phase 3B Adversarial & Boundary Test Suite
Validates all Section 19 adversarial scenarios, non-inference invariants,
parameter segregation, unsupported scheme prevention, and error safety.
"""

import copy
import json
import os
import unittest
from typing import Any, Dict, List, Optional

from product.core.cbom.constants import (
    ALGORITHM_FAMILIES,
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    ECDAT_PROPERTY_PREFIX,
    MODES,
    PADDINGS,
    PRIMITIVES,
)
from product.core.cbom.projection import CBOMProjector
from product.core.cbom.serializer import CBOMSerializer
from product.core.cbom.validator import CBOMValidator
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceLocation,
    EvidenceRecord,
    LocationType,
    SourceLocation,
)


class TestCBOMAdversarial(unittest.TestCase):
    """
    Adversarial and boundary test suite for CycloneDX 1.7 CBOM serialization.
    Enforces strict non-inference, parameter segregation, and malformed input safety.
    """

    def setUp(self) -> None:
        self.serializer = CBOMSerializer()
        self.validator = CBOMValidator()

    def _create_mock_asset(
        self,
        asset_id: str,
        algo_name: str,
        family: AlgorithmFamily,
        role: CryptographicRole,
        parameters: Optional[AlgorithmParameters] = None,
        confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
        finding_ids: Optional[List[str]] = None,
    ) -> CryptoAsset:
        return CryptoAsset(
            asset_id=asset_id,
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=AlgorithmIdentity(family=family, algorithm=algo_name),
            role=role,
            parameters=parameters or AlgorithmParameters(),
            finding_ids=finding_ids or ["f-adv-01"],
            primary_location=SourceLocation("src/SecurityTest.java", 10, 12),
            confidence=confidence,
            correlation_basis="adversarial_test_fixture",
        )

    # 1. Role says SIGNATURE but only key generation is evidenced
    def test_adv_01_role_signature_keygen_only_no_signature_inference(self) -> None:
        """
        Adversarial: Asset role is DIGITAL_SIGNATURE, but algorithm is generic RSA and
        evidence is strictly key generation (KeyPairGenerator).
        Non-inference invariant:
        - primitive MUST NOT be 'signature'
        - cryptoFunctions MUST NOT synthesize ['sign', 'verify']
        - algorithmFamily MUST NOT become 'RSASSA-PKCS1'
        """
        ev_keygen = EvidenceRecord(
            evidence_id="ev-adv-01",
            location=SourceLocation("src/Keys.java", 20, 22, code_snippet="KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");"),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="KEYGEN",
        )
        asset = self._create_mock_asset(
            asset_id="adv-rsa-keygen",
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.DIGITAL_SIGNATURE,  # Mislabeled or unevidenced role
        )
        comp = CBOMProjector.project_component(asset, evidence_records=[ev_keygen])
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        # Invariant: primitive must be omitted or unknown, NOT "signature"
        self.assertNotEqual(algo_props.get("primitive"), "signature")
        # Invariant: cryptoFunctions must be ["keygen"], NOT ["sign", "verify"]
        self.assertEqual(algo_props.get("cryptoFunctions"), ["keygen"])
        # Invariant: algorithmFamily must not be narrowed to RSASSA
        self.assertIsNone(algo_props.get("algorithmFamily"))

        # Validator verifies absence of illegal inference
        bom = self.serializer.serialize_to_dict([asset], evidence_records=[ev_keygen])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

    # 2. Role says ENCRYPTION but mode is unknown -> no "ae" upgrade
    def test_adv_02_role_encryption_unknown_mode_no_ae_upgrade(self) -> None:
        """
        Adversarial: Asset has role ENCRYPTION_DECRYPTION with generic AES and unknown mode.
        Must NOT be upgraded to authenticated encryption ('ae').
        """
        asset = self._create_mock_asset(
            asset_id="adv-aes-generic",
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode=None),
        )
        comp = CBOMProjector.project_component(asset)
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        self.assertNotEqual(algo_props.get("primitive"), "ae")
        # Invariant: Generic AES without mode has primitive omitted (None) or block-cipher/unknown
        self.assertIn(algo_props.get("primitive"), (None, "block-cipher", "unknown"))

    # 3. AES-CBC incorrectly attempting to become "ae" -> rejected by validator
    def test_adv_03_aes_cbc_attempting_ae_rejected_by_validator(self) -> None:
        """
        Adversarial: If a malformed CBOM projects AES-CBC as primitive 'ae',
        Tier 2 validator MUST detect and reject it.
        """
        asset = self._create_mock_asset(
            asset_id="adv-aes-cbc",
            algo_name="AES-CBC",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="CBC"),
        )
        bom = self.serializer.serialize_to_dict([asset])
        # Tamper component to simulate an illegal AE upgrade
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "ae"

        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject AES-CBC labeled as primitive 'ae'")
        self.assertTrue(any("without authenticated encryption evidence" in e for e in val.errors))

    # 4. RSA key generation incorrectly becoming signature -> rejected by validator
    def test_adv_04_rsa_keygen_attempting_signature_family_rejected(self) -> None:
        """
        Adversarial: Generic RSA key generation must not narrow to RSASSA without scheme evidence.
        """
        asset = self._create_mock_asset(
            asset_id="adv-rsa-gen",
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_GENERATION,
        )
        bom = self.serializer.serialize_to_dict([asset])
        # Tamper component to simulate illegal narrowing
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] = "RSASSA-PKCS1"

        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject generic RSA narrowed to RSASSA-PKCS1")
        self.assertTrue(any("generic RSA narrowed to 'RSASSA-PKCS1'" in e for e in val.errors))

    # 5. EC key generation incorrectly becoming ECDSA -> rejected by validator
    def test_adv_05_ec_keygen_attempting_ecdsa_rejected(self) -> None:
        """
        Adversarial: Generic EC key generation must not narrow to ECDSA without scheme evidence.
        """
        asset = self._create_mock_asset(
            asset_id="adv-ec-gen",
            algo_name="EC",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(curve_name="secp256r1"),
        )
        bom = self.serializer.serialize_to_dict([asset])
        # Tamper component to simulate illegal narrowing
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] = "ECDSA"

        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject generic EC narrowed to ECDSA")
        self.assertTrue(any("generic EC narrowed to 'ECDSA'" in e for e in val.errors))

    # 6. Generic DH incorrectly becoming FFDH -> rejected by validator
    def test_adv_06_generic_dh_non_inference(self) -> None:
        """
        Adversarial: Generic DH without parameterization must not claim FFDH in standard CycloneDX field.
        """
        asset = self._create_mock_asset(
            asset_id="adv-dh-generic",
            algo_name="DH",
            family=AlgorithmFamily.DH,
            role=CryptographicRole.KEY_AGREEMENT,
        )
        comp = CBOMProjector.project_component(asset)
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        self.assertIsNone(algo_props.get("algorithmFamily"))
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(props["ecdat:algorithm_family"], "DH")

    # 7. Dynamic Cipher.getInstance(variable) -> UNKNOWN preserved
    def test_adv_07_dynamic_cipher_unknown_preserved(self) -> None:
        """
        Adversarial: Dynamic cipher where algorithm name is UNKNOWN.
        Must NOT guess an algorithm, must preserve name="UNKNOWN" and primitive="unknown".
        """
        asset = self._create_mock_asset(
            asset_id="adv-dynamic",
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        comp = CBOMProjector.project_component(asset)
        self.assertEqual(comp["name"], "UNKNOWN")
        self.assertEqual(comp["cryptoProperties"]["algorithmProperties"]["primitive"], "unknown")
        self.assertIsNone(comp["cryptoProperties"]["algorithmProperties"].get("algorithmFamily"))

        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

    # 8. cryptoFunctions attempting to add "other" -> rejected by validator
    def test_adv_08_cryptofunctions_placeholder_other_forbidden(self) -> None:
        """
        Adversarial: 'other' is strictly forbidden as an uncertainty placeholder in cryptoFunctions.
        """
        asset = self._create_mock_asset(
            asset_id="adv-other-func",
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
        )
        bom = self.serializer.serialize_to_dict([asset])
        # Inject "other" into cryptoFunctions
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"] = ["encrypt", "other"]

        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject 'other' in cryptoFunctions")
        self.assertTrue(any("forbidden placeholder 'other'" in e for e in val.errors))

    # 9. Parameter set segregation: Key size entering parameterSetIdentifier
    def test_adv_09_rsa_key_size_segregation_from_parameterset(self) -> None:
        """
        Adversarial: RSA-2048 key size must NOT enter parameterSetIdentifier.
        Must be preserved under ecdat:key_size_bits.
        """
        asset = self._create_mock_asset(
            asset_id="adv-rsa-2048",
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(key_size_bits=2048),
        )
        comp = CBOMProjector.project_component(asset)
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        self.assertIsNone(algo_props.get("parameterSetIdentifier"))
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(props["ecdat:key_size_bits"], "2048")

        # Validator check if tampered
        bom = self.serializer.serialize_to_dict([asset])
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = "2048"
        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject RSA key size in parameterSetIdentifier")

    # 10. Parameter set segregation: Curve name entering parameterSetIdentifier
    def test_adv_10_curve_segregation_from_parameterset(self) -> None:
        """
        Adversarial: Curve name 'secp256r1' must NOT enter parameterSetIdentifier.
        Must enter algorithmProperties.curve and ecdat:curve.
        """
        asset = self._create_mock_asset(
            asset_id="adv-ec-curve",
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            parameters=AlgorithmParameters(curve_name="secp256r1"),
        )
        comp = CBOMProjector.project_component(asset)
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        self.assertEqual(algo_props.get("curve"), "secp256r1")
        self.assertIsNone(algo_props.get("parameterSetIdentifier"))

        # Validator check if tampered
        bom = self.serializer.serialize_to_dict([asset])
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = "secp256r1"
        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject curve name in parameterSetIdentifier")

    # 11. Parameter set segregation: Mode and Padding entering parameterSetIdentifier
    def test_adv_11_mode_and_padding_segregation_from_parameterset(self) -> None:
        """
        Adversarial: Mode 'GCM' and padding 'PKCS5Padding' must NOT enter parameterSetIdentifier.
        """
        asset = self._create_mock_asset(
            asset_id="adv-aes-gcm",
            algo_name="AES-GCM",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM", padding_scheme="PKCS5Padding"),
        )
        comp = CBOMProjector.project_component(asset)
        algo_props = comp["cryptoProperties"]["algorithmProperties"]

        self.assertEqual(algo_props.get("mode"), "gcm")
        self.assertEqual(algo_props.get("padding"), "pkcs5")
        self.assertNotEqual(algo_props.get("parameterSetIdentifier"), "GCM")
        self.assertNotEqual(algo_props.get("parameterSetIdentifier"), "PKCS5Padding")

        # Validator check if tampered
        bom = self.serializer.serialize_to_dict([asset])
        bom["components"][0]["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = "gcm"
        val = self.validator.validate(bom, [asset])
        self.assertFalse(val.is_valid, "Validator must reject mode in parameterSetIdentifier")

    # 12. Duplicate and Conflicting Scanner Observations -> Preserved without merge
    def test_adv_12_conflicting_scanner_observations_preserved(self) -> None:
        """
        Adversarial: Two scanners report conflicting algorithms at the same location.
        System must preserve separate assets and separate provenance without forced merge.
        """
        ev1 = EvidenceRecord(
            evidence_id="ev-scanner-a",
            location=SourceLocation("src/Cipher.java", 15, 15),
            scanner_name="ScannerA",
            scanner_version="1.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
        )
        ev2 = EvidenceRecord(
            evidence_id="ev-scanner-b",
            location=SourceLocation("src/Cipher.java", 15, 15),
            scanner_name="ScannerB",
            scanner_version="2.0",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="DES",
        )
        asset1 = self._create_mock_asset("asset-aes", "AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION, finding_ids=["f-aes"])
        asset2 = self._create_mock_asset("asset-des", "DES", AlgorithmFamily.DES, CryptographicRole.ENCRYPTION_DECRYPTION, finding_ids=["f-des"])

        bom = self.serializer.serialize_to_dict([asset1, asset2], evidence_records=[ev1, ev2])
        val = self.validator.validate(bom, [asset1, asset2])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        self.assertEqual(len(bom["components"]), 2)
        c_names = {c["name"] for c in bom["components"]}
        self.assertEqual(c_names, {"AES", "DES"})

    # 13. Missing native IDs -> fallback fingerprint preserved
    def test_adv_13_missing_native_ids_fallback_fingerprint(self) -> None:
        """
        Adversarial: Evidence record with zero native attributes/IDs.
        Projection safely creates a location fingerprint and preserves provenance.
        """
        ev_no_native = EvidenceRecord(
            evidence_id="ev-bare",
            location=SourceLocation("src/KeyHelper.java", 42, 42),
            scanner_name="SimpleScan",
            scanner_version="0.1.0",
            detection_method=DetectionMethod.LOCKFILE_PARSE,
            scanner_category="CRYPTO",
        )
        asset = self._create_mock_asset("asset-bare", "AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION, finding_ids=["f-bare"])
        comp = CBOMProjector.project_component(asset, evidence_records=[ev_no_native])

        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertIn("ecdat:scanners", props)
        self.assertIn("SimpleScan:0.1.0", props["ecdat:scanners"])

    # 14. Unknown Confidence preserved
    def test_adv_14_unknown_confidence_preserved(self) -> None:
        """
        Adversarial: Confidence level is UNKNOWN / NEEDS_REVIEW.
        Preserved as property without fabricating CONFIRMED or omitting it.
        """
        asset = self._create_mock_asset(
            "asset-unknown-conf",
            "AES",
            AlgorithmFamily.AES,
            CryptographicRole.ENCRYPTION_DECRYPTION,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        comp = CBOMProjector.project_component(asset)
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(props["ecdat:confidence"], "NEEDS_REVIEW")

    # 15. Malformed types fail Tier 1 structural validation
    def test_adv_15_malformed_types_fail_tier1(self) -> None:
        """
        Adversarial: Malformed CBOM structures (wrong types, missing required fields).
        Tier 1 validator must fail cleanly with descriptive errors.
        """
        # Missing bomFormat
        val1 = self.validator.validate_tier1_structure({"specVersion": "1.7", "components": []})
        self.assertFalse(val1.is_valid)
        self.assertTrue(any("bomFormat" in e for e in val1.errors))

        # components is not a list
        val2 = self.validator.validate_tier1_structure({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": "not-a-list"})
        self.assertFalse(val2.is_valid)
        self.assertTrue(any("must be a list" in e for e in val2.errors))

        # cryptoProperties is not an object
        val3 = self.validator.validate_tier1_structure({
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [{"bom-ref": "c1", "type": "cryptographic-asset", "name": "AES", "cryptoProperties": "bad-type"}]
        })
        self.assertFalse(val3.is_valid)
        self.assertTrue(any("invalid 'cryptoProperties'" in e for e in val3.errors))

    # 16. Unsupported CycloneDX registry value fails Tier 1
    def test_adv_16_unsupported_registry_value_fails_tier1(self) -> None:
        """
        Adversarial: algorithmFamily set to an unapproved invented string.
        Must be rejected by Tier 1 validation against the 93-value cryptography registry.
        """
        malformed_comp = {
            "bom-ref": "c-unsupported",
            "type": "cryptographic-asset",
            "name": "SuperCrypto2000",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "algorithmFamily": "QuantumSuperShield",  # NOT in CycloneDX registry
                }
            }
        }
        bom = {
            "bomFormat": CYCLONEDX_BOM_FORMAT,
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "components": [malformed_comp],
        }
        val = self.validator.validate_tier1_structure(bom)
        self.assertFalse(val.is_valid, "Validator must reject unregistered algorithmFamily")
        self.assertTrue(any("QuantumSuperShield" in e for e in val.errors))

    # 17. Safe string serialization & no code execution
    def test_adv_17_safe_string_serialization_untrusted_input(self) -> None:
        """
        Security: Untrusted code snippets containing quotes, HTML, code tags, or escape sequences
        must be serialized cleanly as valid JSON without command execution or script injection.
        """
        malicious_snippet = 'Cipher c = Cipher.getInstance("AES"); </script><exec>$(rm -rf /)</exec>\n\t"quotes"'
        ev = EvidenceRecord(
            evidence_id="ev-malicious",
            location=SourceLocation("src/Attack.java", 1, 1, code_snippet=malicious_snippet),
            scanner_name="UntrustedScanner; DROP TABLE users;--",
            scanner_version="1.0.0",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="ATTACK",
        )
        asset = self._create_mock_asset(
            "asset-attack",
            "AES",
            AlgorithmFamily.AES,
            CryptographicRole.ENCRYPTION_DECRYPTION,
            finding_ids=["find-attack"],
        )
        json_str = self.serializer.serialize_to_json([asset], evidence_records=[ev])
        
        # Must parse cleanly back as JSON without syntax error
        parsed = json.loads(json_str)
        self.assertEqual(parsed["bomFormat"], CYCLONEDX_BOM_FORMAT)
        comp = parsed["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertIn("UntrustedScanner", props["ecdat:scanners"])

    def test_def03_multi_asset_evidence_isolation(self) -> None:
        """DEF-03: Verifies that distinct assets receive only their own evidence IDs when serialized with findings."""
        from product.core.domain.finding import Finding
        from product.core.domain.observation import ObservationType

        ev1 = EvidenceRecord(
            evidence_id="ev-scanner-a1",
            location=SourceLocation("src/AesService.java", 10, 10),
            scanner_name="ScannerA",
            scanner_version="1.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
        )
        ev2 = EvidenceRecord(
            evidence_id="ev-scanner-b2",
            location=SourceLocation("src/DesLegacy.java", 20, 20),
            scanner_name="ScannerB",
            scanner_version="2.0",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="DES",
        )

        f1 = Finding(
            finding_id="find-aes-01",
            evidence_ids=["ev-scanner-a1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.AES, algorithm="AES"),
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=256),
            primary_location=SourceLocation("src/AesService.java", 10, 10),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="find-des-02",
            evidence_ids=["ev-scanner-b2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.DES, algorithm="DES"),
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=56),
            primary_location=SourceLocation("src/DesLegacy.java", 20, 20),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        asset1 = self._create_mock_asset(
            "asset-aes", "AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION,
            finding_ids=["find-aes-01"]
        )
        asset2 = self._create_mock_asset(
            "asset-des", "DES", AlgorithmFamily.DES, CryptographicRole.ENCRYPTION_DECRYPTION,
            finding_ids=["find-des-02"]
        )

        bom = self.serializer.serialize_to_dict(
            assets=[asset1, asset2],
            evidence_records=[ev1, ev2],
            findings=[f1, f2],
        )

        comp_by_name = {c["name"]: c for c in bom["components"]}
        self.assertIn("AES", comp_by_name)
        self.assertIn("DES", comp_by_name)

        # Asset 1 (AES) must have ONLY ev1
        aes_props = {p["name"]: p["value"] for p in comp_by_name["AES"]["properties"]}
        self.assertEqual(aes_props.get("ecdat:evidence_ids"), "ev-scanner-a1")
        self.assertEqual(aes_props.get("ecdat:scanners"), "ScannerA:1.0")

        # Asset 2 (DES) must have ONLY ev2
        des_props = {p["name"]: p["value"] for p in comp_by_name["DES"]["properties"]}
        self.assertEqual(des_props.get("ecdat:evidence_ids"), "ev-scanner-b2")
        self.assertEqual(des_props.get("ecdat:scanners"), "ScannerB:2.0")

    def test_def07_validator_structural_property_exclusivity(self) -> None:
        """DEF-07: Verifies CBOMValidator catches illegal property placement and non-crypto components with cryptoProperties."""
        valid_bom = self.serializer.serialize_to_dict([])

        # 1. Component with type="library" but possessing cryptoProperties
        bad_library_bom = copy.deepcopy(valid_bom)
        bad_library_bom["components"] = [{
            "type": "library",
            "name": "bouncy-castle",
            "bom-ref": "ecdat:pkg:bcprov",
            "cryptoProperties": {"assetType": "algorithm"},
        }]
        res = self.validator.validate_tier1_structure(bad_library_bom)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("must NOT have 'cryptoProperties'" in err or "permitted ONLY on 'cryptographic-asset'" in err for err in res.errors))

        # 2. Component with assetType="algorithm" but possessing relatedCryptoMaterialProperties
        bad_algo_bom = copy.deepcopy(valid_bom)
        bad_algo_bom["components"] = [{
            "type": "cryptographic-asset",
            "name": "AES",
            "bom-ref": "ecdat:asset:aes-01",
            "cryptoProperties": {
                "assetType": "algorithm",
                "relatedCryptoMaterialProperties": {"type": "key", "size": 256},
            },
        }]
        res = self.validator.validate_tier1_structure(bad_algo_bom)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("relatedCryptoMaterialProperties" in err for err in res.errors))

        # 3. Component with assetType="certificate" but possessing protocolProperties
        bad_cert_bom = copy.deepcopy(valid_bom)
        bad_cert_bom["components"] = [{
            "type": "cryptographic-asset",
            "name": "Cert",
            "bom-ref": "ecdat:asset:cert-01",
            "cryptoProperties": {
                "assetType": "certificate",
                "protocolProperties": {"type": "tls"},
            },
        }]
        res = self.validator.validate_tier1_structure(bad_cert_bom)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("protocolProperties" in err for err in res.errors))


if __name__ == "__main__":
    unittest.main()

