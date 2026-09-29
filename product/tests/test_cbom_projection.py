"""
ECDAT Phase 3B CBOM Projection & Serialization Tests.

Validates the complete projection from canonical ECDAT domain entities into
CycloneDX 1.7 CBOM JSON documents across all 28 required test categories.
"""

import json
import os
from typing import Any, Dict, List, Optional, Sequence
import unittest
import uuid

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
from product.core.ingestion.adapters.cryptoscan import CryptoScanAdapter
from product.core.ingestion.adapters.syft import SyftAdapter
from product.core.normalization.correlation import AssetCorrelationEngine
from product.core.normalization.normalizer import NormalizationEngine


class TestCBOMProjection(unittest.TestCase):
    """Core CBOM projection, serialization, and validation tests."""

    def setUp(self) -> None:
        self.projector = CBOMProjector()
        self.serializer = CBOMSerializer(self.projector)
        self.validator = CBOMValidator()
        self.cryptoscan = CryptoScanAdapter()
        self.syft = SyftAdapter()
        self.normalizer = NormalizationEngine()
        self.correlator = AssetCorrelationEngine()

    def _create_simple_asset(
        self,
        algo_name: str,
        family: AlgorithmFamily,
        role: CryptographicRole,
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
        mode: Optional[str] = None,
        padding: Optional[str] = None,
        file_path: str = "src/main/Crypto.java",
        line_start: int = 42,
        matched_text: str = "",
        code_snippet: str = "",
        finding_id: str = "finding-001",
        confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
        variant: Optional[str] = None,
    ) -> CryptoAsset:
        loc = SourceLocation(
            file_path=file_path,
            line_start=line_start,
            line_end=line_start,
            matched_text=matched_text,
            code_snippet=code_snippet,
        )
        params = AlgorithmParameters(
            key_size_bits=key_size,
            curve_name=curve,
            cipher_mode=mode,
            padding_scheme=padding,
        )
        identity = AlgorithmIdentity(
            family=family,
            algorithm=algo_name,
            variant=variant,
        )
        return CryptoAsset(
            asset_id="",  # derived deterministically
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=identity,
            role=role,
            parameters=params,
            finding_ids=(finding_id,),
            primary_location=loc,
            confidence=confidence,
            correlation_basis="test_asset",
        )

    # 1. Basic Valid Projection (AES-256-GCM)
    def test_01_basic_valid_projection(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES-256-GCM",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
            mode="GCM",
            matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\")",
        )
        bom = self.serializer.serialize_to_dict([asset], run_id="run-01")
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        self.assertEqual(comp["type"], "cryptographic-asset")
        self.assertEqual(comp["name"], "AES-256-GCM")
        self.assertEqual(comp["cryptoProperties"]["algorithmProperties"]["algorithmFamily"], "AES")
        self.assertEqual(comp["cryptoProperties"]["algorithmProperties"]["primitive"], "ae")
        self.assertEqual(comp["cryptoProperties"]["algorithmProperties"]["mode"], "gcm")
        self.assertEqual(comp["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"], "256")

    # 2. RSA Key Generation (TC-01)
    def test_02_rsa_key_generation_tc01(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc01_direct_rsa", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc01-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)
        self.assertEqual(len(assets), 1)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        # Non-inference: generic RSA keygen MUST NOT guess RSASSA-PKCS1 or RSAES-OAEP
        self.assertNotIn("algorithmFamily", algo_props)
        # Non-inference: role key generation alone MUST NOT become signature or pke
        self.assertNotIn("primitive", algo_props)
        # Preserved in ecdat: properties
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["ecdat:algorithm_family"], "RSA")

    # 3. AES-GCM (TC-02)
    def test_03_aes_gcm_tc02(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc02_symmetric_aes", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc02-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        gcm_comps = [c for c in bom["components"] if c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("mode") == "gcm"]
        self.assertEqual(len(gcm_comps), 1)
        algo_props = gcm_comps[0]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["algorithmFamily"], "AES")
        self.assertEqual(algo_props["primitive"], "ae")
        self.assertEqual(algo_props["mode"], "gcm")

    # 4. AES-CBC
    def test_04_aes_cbc_primitive(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES/CBC/PKCS5Padding",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=128,
            mode="CBC",
            padding="PKCS7",
            matched_text="Cipher.getInstance(\"AES/CBC/PKCS5Padding\")",
        )
        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["algorithmFamily"], "AES")
        self.assertEqual(algo_props["primitive"], "block-cipher")
        self.assertEqual(algo_props["mode"], "cbc")

    # 5. Generic AES / Ambiguous Mode
    def test_05_generic_aes_ambiguous_mode(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            matched_text="Cipher.getInstance(\"AES\")",
        )
        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        self.assertEqual(algo_props["algorithmFamily"], "AES")
        # Without mode, primitive MUST NOT be guessed as "ae" or "block-cipher"
        self.assertNotIn("primitive", algo_props)
        self.assertNotIn("cryptoFunctions", algo_props)

    # 6. ECDSA (TC-04)
    def test_06_ecdsa_tc04(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc04_ecdsa", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc04-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        ecdsa_comps = [c for c in bom["components"] if c.get("name") == "ECDSA"]
        self.assertGreater(len(ecdsa_comps), 0)
        algo_props = ecdsa_comps[0]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["algorithmFamily"], "ECDSA")
        self.assertEqual(algo_props["primitive"], "signature")

    # 7. ECDH (TC-05)
    def test_07_ecdh_tc05(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc05_ecdh", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc05-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        ecdh_comps = [c for c in bom["components"] if c.get("name") == "ECDH"]
        self.assertGreater(len(ecdh_comps), 0)
        algo_props = ecdh_comps[0]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["algorithmFamily"], "ECDH")
        self.assertEqual(algo_props["primitive"], "key-agree")

    # 8. Ed25519 (TC-06)
    def test_08_ed25519_tc06(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc06_ed25519", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc06-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["algorithmFamily"], "EdDSA")
        self.assertEqual(algo_props["primitive"], "signature")

    # 9. SHA-1 & SHA-256 (TC-07)
    def test_09_sha1_and_sha256_tc07(self) -> None:
        loc_sha1 = SourceLocation(
            file_path="tc07_sha1_hash/sha1_hash.py",
            line_start=10,
            line_end=11,
            matched_text="hashlib.sha1(data)",
            code_snippet="h = hashlib.sha1()\nh.update(data)",
        )
        ev_sha1 = EvidenceRecord(
            evidence_id="tc07-ev1",
            location=loc_sha1,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="SHA1",
        )
        finding_sha1 = self.normalizer.normalize(ev_sha1)
        assets_sha1 = self.correlator.correlate([finding_sha1])
        bom_sha1 = self.serializer.serialize_to_dict(assets_sha1, evidence_records=[ev_sha1])
        val_sha1 = self.validator.validate(bom_sha1, assets_sha1)
        self.assertTrue(val_sha1.is_valid, f"Validation failed: {val_sha1.errors}")

        comp_sha1 = bom_sha1["components"][0]
        algo_props_sha1 = comp_sha1["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props_sha1["algorithmFamily"], "SHA-1")
        self.assertEqual(algo_props_sha1["primitive"], "hash")

        # Test SHA-256 asset
        loc_sha256 = SourceLocation(
            file_path="src/HashUtil.java",
            line_start=15,
            line_end=16,
            matched_text="MessageDigest.getInstance(\"SHA-256\");",
            code_snippet="MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nmd.digest();",
        )
        asset_sha256 = CryptoAsset(
            asset_id="sha256-asset",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.SHA2, algorithm="SHA-256"),
            role=CryptographicRole.MESSAGE_DIGEST,
            parameters=AlgorithmParameters(),
            finding_ids=["finding-sha256"],
            primary_location=loc_sha256,
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="Explicit SHA-256 test",
        )
        bom_sha256 = self.serializer.serialize_to_dict([asset_sha256])
        val_sha256 = self.validator.validate(bom_sha256, [asset_sha256])
        self.assertTrue(val_sha256.is_valid, f"Validation failed: {val_sha256.errors}")

        comp_sha256 = bom_sha256["components"][0]
        algo_props_sha256 = comp_sha256["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props_sha256["algorithmFamily"], "SHA-2")
        self.assertEqual(algo_props_sha256["primitive"], "hash")

    # 10. Generic EC Key Generation (TC-03)
    def test_10_generic_ec_tc03_non_inference(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc03_ecc_generic", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="tc03-scan")
        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        assets = self.correlator.correlate(findings)

        bom = self.serializer.serialize_to_dict(assets, evidence_records=res.evidence_records)
        val = self.validator.validate(bom, assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        # Non-inference: Generic EC keygen MUST NOT narrow to ECDSA or ECDH
        self.assertNotIn("algorithmFamily", algo_props)
        self.assertEqual(algo_props.get("primitive"), "unknown")
        # Curve is preserved
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["ecdat:algorithm_family"], "UNKNOWN")
        self.assertEqual(algo_props.get("curve"), "secp256r1")

    # 11. Generic DH Non-Inference
    def test_11_generic_dh_non_inference(self) -> None:
        asset = self._create_simple_asset(
            algo_name="DH",
            family=AlgorithmFamily.DH,
            role=CryptographicRole.KEY_AGREEMENT,
            matched_text="KeyAgreement.getInstance(\"DH\")",
        )
        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        # Non-inference: generic DH MUST NOT guess FFDH or ECDH
        self.assertNotIn("algorithmFamily", algo_props)
        self.assertEqual(algo_props.get("primitive"), "key-agree")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["ecdat:algorithm_family"], "DH")

    # 12. Dynamic Algorithm (TC-11)
    def test_12_dynamic_algorithm_unknown_preservation(self) -> None:
        asset = self._create_simple_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.UNKNOWN,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            matched_text="Cipher.getInstance(algoVariable)",
        )
        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        self.assertEqual(comp["name"], "UNKNOWN")
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        self.assertNotIn("algorithmFamily", algo_props)
        self.assertEqual(algo_props.get("primitive"), "unknown")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["ecdat:confidence"], "NEEDS_REVIEW")

    # 13. Parameter Segregation: Key size NOT in parameterSetIdentifier
    def test_13_parameter_segregation_rsa(self) -> None:
        asset = self._create_simple_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_GENERATION,
            key_size=2048,
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"].get("algorithmProperties", {})
        # RSA-2048 key size MUST NOT enter parameterSetIdentifier
        self.assertNotIn("parameterSetIdentifier", algo_props)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["ecdat:key_size_bits"], "2048")
        self.assertEqual(props["ecdat:key_size"], "2048")

    # 14. Parameter Segregation: Curve NOT in parameterSetIdentifier
    def test_14_parameter_segregation_curve(self) -> None:
        asset = self._create_simple_asset(
            algo_name="EC",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_GENERATION,
            curve="secp256r1",
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props.get("curve"), "secp256r1")
        self.assertNotIn("parameterSetIdentifier", algo_props)

    # 15. Parameter Segregation: Mode NOT in parameterSetIdentifier
    def test_15_parameter_segregation_mode(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            mode="GCM",
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props.get("mode"), "gcm")
        self.assertNotEqual(algo_props.get("parameterSetIdentifier"), "GCM")

    # 16. Parameter Segregation: Padding NOT in parameterSetIdentifier
    def test_16_parameter_segregation_padding(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            padding="PKCS7",
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props.get("padding"), "pkcs7")
        self.assertNotEqual(algo_props.get("parameterSetIdentifier"), "PKCS7")

    # 17. Formal Parameter Set Preservation (AES key length)
    def test_17_formal_parameter_set_aes(self) -> None:
        asset = self._create_simple_asset(
            algo_name="AES-128",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=128,
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props.get("parameterSetIdentifier"), "128")

    # 18. cryptoFunctions Evidence Rules: No synthesis from role alone
    def test_18_crypto_functions_no_role_synthesis(self) -> None:
        asset = self._create_simple_asset(
            algo_name="ECDH",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_AGREEMENT,
            matched_text="KeyAgreement ka;",  # declaration only
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        # Operation not evidenced -> cryptoFunctions must be omitted, never ["keyderive", "other"]
        self.assertNotIn("cryptoFunctions", algo_props)

    # 19. cryptoFunctions Evidence Rules: Call site invocation evidenced
    def test_19_crypto_functions_call_site_evidenced(self) -> None:
        asset = self._create_simple_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            matched_text="sig.initSign(key); byte[] s = sig.sign();",
        )
        bom = self.serializer.serialize_to_dict([asset])
        comp = bom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertIn("sign", algo_props.get("cryptoFunctions", []))
        self.assertNotIn("verify", algo_props.get("cryptoFunctions", []))
        self.assertNotIn("other", algo_props.get("cryptoFunctions", []))

    # 20. Multiple Scanner Provenance (CryptoScan + Syft)
    def test_20_multi_scanner_provenance_integration(self) -> None:
        ev1 = EvidenceRecord(
            evidence_id="cryptoscan:rule-01",
            location=SourceLocation("src/Crypto.java", 10, 10),
            scanner_name="cryptoscan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CIPHER",
            raw_output_ref="sha256:abc123def456",
        )
        ev2 = EvidenceRecord(
            evidence_id="syft:pkg-02",
            location=SourceLocation("src/Crypto.java", 10, 10),
            scanner_name="syft",
            scanner_version="1.51.1",
            detection_method=DetectionMethod.LOCKFILE_PARSE,
            scanner_category="PACKAGE",
            raw_output_ref="sha256:abc123def456",
        )
        asset = self._create_simple_asset(
            algo_name="AES-256-GCM",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
            mode="GCM",
            finding_id="finding-01",
        )
        bom = self.serializer.serialize_to_dict([asset], evidence_records=[ev1, ev2])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        comp = bom["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertIn("cryptoscan:1.4.0", props["ecdat:scanners"])
        self.assertIn("syft:1.51.1", props["ecdat:scanners"])
        self.assertEqual(props["ecdat:raw_output_ref"], "sha256:abc123def456")

    # 21. Identity Stability
    def test_21_identity_stability(self) -> None:
        asset1 = self._create_simple_asset("AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION)
        asset2 = self._create_simple_asset("AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION)
        self.assertEqual(asset1.asset_id, asset2.asset_id)

        bom1 = self.serializer.serialize_to_dict([asset1], run_id="run-a")
        bom2 = self.serializer.serialize_to_dict([asset2], run_id="run-b")
        # bom-ref must remain completely identical across independent runs
        self.assertEqual(bom1["components"][0]["bom-ref"], bom2["components"][0]["bom-ref"])

    # 22. Deterministic Serialization
    def test_22_deterministic_serialization(self) -> None:
        asset_a = self._create_simple_asset("AES-GCM", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION, line_start=10)
        asset_b = self._create_simple_asset("RSA", AlgorithmFamily.RSA, CryptographicRole.KEY_GENERATION, line_start=50)

        json1 = self.serializer.serialize_to_json([asset_b, asset_a], run_id="fixed-run-id", timestamp="2026-09-14T12:00:00Z")
        json2 = self.serializer.serialize_to_json([asset_a, asset_b], run_id="fixed-run-id", timestamp="2026-09-14T12:00:00Z")
        self.assertEqual(json1, json2, "CBOM serialization must be strictly deterministic regardless of input order")

    # 23. Dependency & Supply Chain Graph
    def test_23_dependency_supply_chain_graph(self) -> None:
        lib_asset = CryptoAsset(
            asset_id="lib-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "bcprov-jdk18on"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=("find-dep",),
            primary_location=EvidenceLocation(LocationType.DEPENDENCY, package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="syft_manifest",
        )
        crypto_asset = self._create_simple_asset("AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION)

        dep_graph = [
            {
                "ref": f"ecdat:asset:{lib_asset.asset_id}",
                "provides": [f"ecdat:asset:{crypto_asset.asset_id}"],
            }
        ]
        bom = self.serializer.serialize_to_dict([lib_asset, crypto_asset], dependencies=dep_graph)
        val = self.validator.validate(bom, [lib_asset, crypto_asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        self.assertEqual(len(bom["dependencies"]), 1)
        self.assertEqual(bom["dependencies"][0]["ref"], f"ecdat:asset:{lib_asset.asset_id}")
        self.assertIn(f"ecdat:asset:{crypto_asset.asset_id}", bom["dependencies"][0]["provides"])

    # 24. AssetType Mappings & Regression for CRYPTO_KEY / related-crypto-material
    def test_24_asset_type_mappings(self) -> None:
        """
        Regression test for Finding 1 & Secondary Asset-Type Mapping Audit:
        Ensures all mapped ECDAT AssetType enum members project to valid
        CycloneDX 1.7 cryptoProperties.assetType values, specifically verifying
        that AssetType.CRYPTO_KEY maps to 'related-crypto-material' with
        proper relatedCryptoMaterialProperties.

        LIBRARY_DEPENDENCY is intentionally EXCLUDED from cryptoProperties
        (libraries are NOT algorithms).
        """
        from product.core.cbom.projection import ECDAT_TO_CYCLONEDX_ASSET_TYPE
        from product.core.cbom.constants import ASSET_TYPES

        # Verify mapping table covers all mapped enum members
        for ecdat_type, cdx_val in ECDAT_TO_CYCLONEDX_ASSET_TYPE.items():
            self.assertIn(
                cdx_val,
                ASSET_TYPES,
                f"Projected value '{cdx_val}' for {ecdat_type} is not in CycloneDX ASSET_TYPES"
            )

        # LIBRARY_DEPENDENCY and UNKNOWN must NOT be in the mapping table
        self.assertNotIn(
            AssetType.LIBRARY_DEPENDENCY,
            ECDAT_TO_CYCLONEDX_ASSET_TYPE,
            "LIBRARY_DEPENDENCY must NOT be in ECDAT_TO_CYCLONEDX_ASSET_TYPE"
        )
        self.assertNotIn(
            AssetType.UNKNOWN,
            ECDAT_TO_CYCLONEDX_ASSET_TYPE,
            "UNKNOWN must NOT be in ECDAT_TO_CYCLONEDX_ASSET_TYPE (Semantic B)"
        )

        # 1. Test CRYPTO_KEY specifically — must NEVER emit "crypto_key"
        key_asset = CryptoAsset(
            asset_id="key-01",
            asset_type=AssetType.CRYPTO_KEY,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.AES, "AES-256-Key"),
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=256),
            finding_ids=("find-key",),
            primary_location=SourceLocation(file_path="src/keys.py", line_start=10, line_end=10),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_key = self.projector.project_component(key_asset)
        crypto_props = comp_key["cryptoProperties"]
        self.assertEqual(crypto_props["assetType"], "related-crypto-material")
        self.assertNotEqual(crypto_props["assetType"], "crypto_key",
                            "REGRESSION: CRYPTO_KEY must never emit 'crypto_key'")
        self.assertIn("relatedCryptoMaterialProperties", crypto_props)
        self.assertEqual(crypto_props["relatedCryptoMaterialProperties"]["type"], "key")
        self.assertEqual(crypto_props["relatedCryptoMaterialProperties"]["size"], 256)
        self.assertNotIn("algorithmProperties", crypto_props,
                         "CRYPTO_KEY must NOT receive algorithmProperties")

        # 2. Test PROTOCOL
        protocol_asset = CryptoAsset(
            asset_id="proto-01",
            asset_type=AssetType.PROTOCOL,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "TLS"),
            role=CryptographicRole.KEY_AGREEMENT,
            parameters=AlgorithmParameters(),
            finding_ids=("find-proto",),
            primary_location=SourceLocation(file_path="src/network.py", line_start=20, line_end=20),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_proto = self.projector.project_component(protocol_asset)
        self.assertEqual(comp_proto["cryptoProperties"]["assetType"], "protocol")
        self.assertIn("protocolProperties", comp_proto["cryptoProperties"])
        self.assertNotIn("algorithmProperties", comp_proto["cryptoProperties"],
                         "PROTOCOL must NOT receive algorithmProperties")

        # 3. Test CERTIFICATE
        cert_asset = CryptoAsset(
            asset_id="cert-01",
            asset_type=AssetType.CERTIFICATE,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.RSA, "X.509"),
            role=CryptographicRole.DIGITAL_SIGNATURE,
            parameters=AlgorithmParameters(key_size_bits=2048),
            finding_ids=("find-cert",),
            primary_location=SourceLocation(file_path="certs/server.pem", line_start=1, line_end=1),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_cert = self.projector.project_component(cert_asset)
        self.assertEqual(comp_cert["cryptoProperties"]["assetType"], "certificate")
        self.assertIn("certificateProperties", comp_cert["cryptoProperties"])
        self.assertNotIn("algorithmProperties", comp_cert["cryptoProperties"],
                         "CERTIFICATE must NOT receive algorithmProperties")

        # 4. Test LIBRARY_DEPENDENCY — must NOT have cryptoProperties at all
        lib_asset = CryptoAsset(
            asset_id="lib-02",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "cryptography"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=("find-lib",),
            primary_location=EvidenceLocation(LocationType.DEPENDENCY, package_coordinate="pkg:pypi/cryptography@41.0.0"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_lib = self.projector.project_component(lib_asset)
        self.assertEqual(comp_lib["type"], "library")
        self.assertNotIn("cryptoProperties", comp_lib,
                          "LIBRARY_DEPENDENCY must NOT have cryptoProperties "
                          "(dependency presence ≠ algorithm usage)")
        # PURL and ECDAT properties must be preserved
        self.assertEqual(comp_lib.get("purl"), "pkg:pypi/cryptography@41.0.0")
        ecdat_props = {p["name"]: p["value"] for p in comp_lib.get("properties", [])}
        self.assertEqual(ecdat_props.get("ecdat:algorithm_family"), "UNKNOWN")

        # 5. Test UNKNOWN — must NOT have cryptoProperties (Semantic B)
        unk_asset = CryptoAsset(
            asset_id="unk-01",
            asset_type=AssetType.UNKNOWN,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "UNKNOWN"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=("find-unk",),
            primary_location=SourceLocation(file_path="src/unclassified.py", line_start=1, line_end=1),
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            correlation_basis="test",
        )
        comp_unk = self.projector.project_component(unk_asset)
        self.assertEqual(comp_unk["type"], "cryptographic-asset")
        self.assertNotIn("cryptoProperties", comp_unk,
                         "UNKNOWN asset must NOT receive cryptoProperties (no 'unknown' assetType in CycloneDX)")
        ecdat_props_unk = {p["name"]: p["value"] for p in comp_unk.get("properties", [])}
        self.assertEqual(ecdat_props_unk.get("ecdat:asset_type"), "unknown")
        self.assertEqual(ecdat_props_unk.get("ecdat:confidence"), "NEEDS_REVIEW")

        # 6. Full CBOM serialization and validation with all distinct asset types
        crypto_assets = [key_asset, protocol_asset, cert_asset, unk_asset]
        bom = self.serializer.serialize_to_dict(crypto_assets)
        val = self.validator.validate(bom, crypto_assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

    # 25. Library Dependency ≠ Algorithm Usage (BouncyCastle Regression)
    def test_25_library_dependency_not_algorithm_usage(self) -> None:
        """
        Regression test proving that BouncyCastle/dependency evidence alone
        does NOT become algorithm usage. The library component must:
        1. Have type='library', not 'cryptographic-asset'
        2. NOT have cryptoProperties (no assetType='algorithm' assertion)
        3. Preserve PURL and ECDAT metadata
        4. Link capabilities only through dependency.provides graph
        5. Pass two-tier validation
        """
        lib_asset = CryptoAsset(
            asset_id="bc-lib-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "bcprov-jdk18on"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=("find-bc",),
            primary_location=EvidenceLocation(LocationType.DEPENDENCY, package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="syft_manifest",
        )
        algo_asset = self._create_simple_asset("AES", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION)

        dep_graph = [
            {
                "ref": f"ecdat:asset:{lib_asset.asset_id}",
                "provides": [f"ecdat:asset:{algo_asset.asset_id}"],
            }
        ]

        bom = self.serializer.serialize_to_dict([lib_asset, algo_asset], dependencies=dep_graph)
        val = self.validator.validate(bom, [lib_asset, algo_asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

        # Find the library component in the BOM
        lib_comp = None
        algo_comp = None
        for comp in bom["components"]:
            if comp["bom-ref"] == f"ecdat:asset:{lib_asset.asset_id}":
                lib_comp = comp
            elif comp["bom-ref"] == f"ecdat:asset:{algo_asset.asset_id}":
                algo_comp = comp

        self.assertIsNotNone(lib_comp, "Library component must be in BOM")
        self.assertIsNotNone(algo_comp, "Algorithm component must be in BOM")

        # Library MUST NOT claim to be a cryptographic algorithm
        self.assertEqual(lib_comp["type"], "library")
        self.assertNotIn("cryptoProperties", lib_comp,
                          "Library dependency must NOT have cryptoProperties")
        self.assertEqual(lib_comp.get("purl"), "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1")

        # The actual algorithm component DOES have cryptoProperties
        self.assertIn("cryptoProperties", algo_comp)
        self.assertEqual(algo_comp["cryptoProperties"]["assetType"], "algorithm")

        # Dependency graph correctly links library → provides → algorithm
        self.assertEqual(len(bom["dependencies"]), 1)
        self.assertEqual(bom["dependencies"][0]["ref"], f"ecdat:asset:{lib_asset.asset_id}")
        self.assertIn(f"ecdat:asset:{algo_asset.asset_id}", bom["dependencies"][0]["provides"])

    # 26. UNKNOWN Preserves Unknown State
    def test_26_unknown_preserves_unknown_state(self) -> None:
        """
        Proves that UNKNOWN does NOT become a known algorithm, specific primitive,
        specific operation, or parameter set.

        CycloneDX has no assetType='unknown'. The mapping to 'algorithm' is a
        DOCUMENTED SEMANTIC APPROXIMATION. All other fields must maximally
        signal uncertainty.
        """
        asset = self._create_simple_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.UNKNOWN,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            matched_text="Cipher.getInstance(algoVariable)",
        )
        comp = self.projector.project_component(asset)
        crypto_props = comp["cryptoProperties"]
        algo_props = crypto_props.get("algorithmProperties", {})

        # UNKNOWN must NOT become a specific algorithm
        self.assertEqual(comp["name"], "UNKNOWN")

        # assetType is 'algorithm' (CycloneDX has no 'unknown' assetType)
        # This is a documented semantic approximation, NOT a claim of specific algorithm knowledge
        self.assertEqual(crypto_props["assetType"], "algorithm")

        # primitive MUST be 'unknown' (not a specific construction)
        self.assertEqual(algo_props.get("primitive"), "unknown")

        # algorithmFamily must NOT be set (UNKNOWN family → None)
        self.assertNotIn("algorithmFamily", algo_props)

        # cryptoFunctions must NOT be synthesized
        self.assertNotIn("cryptoFunctions", algo_props)

        # parameterSetIdentifier must NOT exist
        self.assertNotIn("parameterSetIdentifier", algo_props)

        # mode, padding must NOT exist
        self.assertNotIn("mode", algo_props)
        self.assertNotIn("padding", algo_props)

        # curve must NOT exist
        self.assertNotIn("curve", algo_props)

        # ECDAT properties must preserve NEEDS_REVIEW
        ecdat_props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(ecdat_props.get("ecdat:confidence"), "NEEDS_REVIEW")
        self.assertEqual(ecdat_props.get("ecdat:role"), "unknown")
        self.assertEqual(ecdat_props.get("ecdat:algorithm_family"), "UNKNOWN")

        # Full serialization + validation
        bom = self.serializer.serialize_to_dict([asset])
        val = self.validator.validate(bom, [asset])
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

    # 27. Negative Semantic Validation Tests
    def test_27_negative_semantic_validations(self) -> None:
        """
        Negative tests verifying that invalid semantic projections are
        correctly rejected or prevented.
        """
        from product.core.cbom.constants import ASSET_TYPES

        # A. "crypto_key" is NOT a valid CycloneDX assetType
        self.assertNotIn("crypto_key", ASSET_TYPES,
                          "'crypto_key' must not be in ASSET_TYPES")

        # B. "related-crypto-material" IS a valid CycloneDX assetType
        self.assertIn("related-crypto-material", ASSET_TYPES)

        # C. Generic EC must remain generic (no narrowing to ECDSA/ECDH)
        ec_asset = self._create_simple_asset(
            algo_name="EC",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_GENERATION,
            curve="secp256r1",
        )
        ec_comp = self.projector.project_component(ec_asset)
        ec_algo = ec_comp["cryptoProperties"]["algorithmProperties"]
        self.assertNotIn("algorithmFamily", ec_algo,
                          "Generic EC must NOT be narrowed to ECDSA/ECDH/ECIES")

        # D. Generic DH must remain generic
        dh_asset = self._create_simple_asset(
            algo_name="DH",
            family=AlgorithmFamily.DH,
            role=CryptographicRole.KEY_AGREEMENT,
        )
        dh_comp = self.projector.project_component(dh_asset)
        dh_algo = dh_comp["cryptoProperties"]["algorithmProperties"]
        self.assertNotIn("algorithmFamily", dh_algo,
                          "Generic DH must NOT be narrowed to ECDH/FFDH")

        # E. Generic RSA must NOT be narrowed
        rsa_asset = self._create_simple_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_GENERATION,
            key_size=2048,
        )
        rsa_comp = self.projector.project_component(rsa_asset)
        rsa_algo = rsa_comp["cryptoProperties"]["algorithmProperties"]
        self.assertNotIn("algorithmFamily", rsa_algo,
                          "Generic RSA must NOT be narrowed to specific scheme")

        # F. Role alone must NOT produce primitive
        role_asset = self._create_simple_asset(
            algo_name="ECDH",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_AGREEMENT,
            matched_text="KeyAgreement ka;",  # declaration only, no call
        )
        role_comp = self.projector.project_component(role_asset)
        role_algo = role_comp["cryptoProperties"]["algorithmProperties"]
        # cryptoFunctions must NOT be synthesized from role
        self.assertNotIn("cryptoFunctions", role_algo,
                          "Role alone must NOT produce cryptoFunctions")

        # G. Key size must NOT become parameterSetIdentifier for RSA
        self.assertNotIn("parameterSetIdentifier", rsa_algo,
                          "RSA key size must NOT become parameterSetIdentifier")

        # H. Ambiguous evidence must remain ambiguous
        ambig_asset = self._create_simple_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.UNKNOWN,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            matched_text="Cipher.getInstance(var)",
        )
        ambig_comp = self.projector.project_component(ambig_asset)
        ambig_props = {p["name"]: p["value"] for p in ambig_comp.get("properties", [])}
        self.assertEqual(ambig_props["ecdat:confidence"], "NEEDS_REVIEW",
                          "Ambiguous evidence must remain marked NEEDS_REVIEW")

    # 28. Non-Inference Audit Integration Test
    def test_28_non_inference_audit(self) -> None:
        """
        Integration test explicitly verifying that the projection layer
        does NOT perform any of the forbidden inference patterns:
        - role → primitive
        - role → cryptoFunctions
        - key size → parameterSetIdentifier
        - family → specific algorithm without evidence
        - dependency → algorithm usage
        - UNKNOWN → known algorithm
        - CycloneDX representation → ECDAT ground truth
        """
        # 1. KEY_AGREEMENT role must NOT produce primitive='key-agree' for unknown algo
        ka_asset = self._create_simple_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.KEY_AGREEMENT,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        ka_comp = self.projector.project_component(ka_asset)
        ka_algo = ka_comp["cryptoProperties"]["algorithmProperties"]
        # primitive should be 'unknown' (from UNKNOWN family), NOT 'key-agree' (from role)
        self.assertEqual(ka_algo.get("primitive"), "unknown")
        self.assertNotIn("cryptoFunctions", ka_algo)

        # 2. ENCRYPTION role must NOT produce cryptoFunctions=['encrypt', 'decrypt']
        enc_asset = self._create_simple_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        enc_comp = self.projector.project_component(enc_asset)
        enc_algo = enc_comp["cryptoProperties"]["algorithmProperties"]
        self.assertNotIn("cryptoFunctions", enc_algo,
                          "ENCRYPTION role alone must NOT produce cryptoFunctions")

        # 3. AES-256 key_size_bits=256 must go to ecdat:key_size_bits, NOT parameterSetIdentifier
        # (unless "AES-256" appears in the algorithm name)
        aes_key_asset = self._create_simple_asset(
            algo_name="AES",  # bare AES, not "AES-256"
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
        )
        aes_comp = self.projector.project_component(aes_key_asset)
        aes_algo = aes_comp["cryptoProperties"]["algorithmProperties"]
        # Bare "AES" with key_size_bits=256 should NOT get parameterSetIdentifier
        # because "AES-256" is not in the algorithm name
        self.assertNotIn("parameterSetIdentifier", aes_algo,
                          "Bare 'AES' with key_size=256 must NOT produce parameterSetIdentifier")
        aes_props = {p["name"]: p["value"] for p in aes_comp.get("properties", [])}
        self.assertEqual(aes_props.get("ecdat:key_size_bits"), "256")

        # 4. Full pipeline validation
        all_assets = [ka_asset, enc_asset, aes_key_asset]
        bom = self.serializer.serialize_to_dict(all_assets)
        val = self.validator.validate(bom, all_assets)
        self.assertTrue(val.is_valid, f"Validation failed: {val.errors}")

    # 29. Non-Algorithm Crypto Assets Do Not Receive algorithmProperties
    def test_29_non_algorithm_crypto_assets_no_empty_algorithm_properties(self) -> None:
        """
        Regression test proving that algorithmProperties is emitted ONLY when
        cryptoProperties.assetType == 'algorithm'.
        
        Non-algorithm crypto assets must NOT receive algorithmProperties: {} or
        any algorithmProperties field:
        - CRYPTO_KEY -> relatedCryptoMaterialProperties only
        - CERTIFICATE -> certificateProperties only
        - PROTOCOL -> protocolProperties only
        - LIBRARY_DEPENDENCY -> no cryptoProperties
        - UNKNOWN -> no cryptoProperties
        - ALGORITHM -> algorithmProperties as justified by evidence
        
        Also verifies that Tier 1 structural validation rejects components
        where algorithmProperties is attached to non-algorithm assetTypes.
        """
        import copy

        # A. CRYPTO_KEY
        key_asset = CryptoAsset(
            asset_id="key-reg-01",
            asset_type=AssetType.CRYPTO_KEY,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.AES, "AES-128-Key"),
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=128),
            finding_ids=("find-k",),
            primary_location=SourceLocation(file_path="src/key.py", line_start=1, line_end=1),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_key = self.projector.project_component(key_asset)
        self.assertIn("cryptoProperties", comp_key)
        self.assertEqual(comp_key["cryptoProperties"]["assetType"], "related-crypto-material")
        self.assertIn("relatedCryptoMaterialProperties", comp_key["cryptoProperties"])
        self.assertNotIn("algorithmProperties", comp_key["cryptoProperties"],
                         "CRYPTO_KEY must NOT have algorithmProperties")

        # B. CERTIFICATE
        cert_asset = CryptoAsset(
            asset_id="cert-reg-01",
            asset_type=AssetType.CERTIFICATE,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.RSA, "X509-Cert"),
            role=CryptographicRole.DIGITAL_SIGNATURE,
            parameters=AlgorithmParameters(key_size_bits=4096),
            finding_ids=("find-c",),
            primary_location=SourceLocation(file_path="src/cert.pem", line_start=1, line_end=1),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_cert = self.projector.project_component(cert_asset)
        self.assertIn("cryptoProperties", comp_cert)
        self.assertEqual(comp_cert["cryptoProperties"]["assetType"], "certificate")
        self.assertIn("certificateProperties", comp_cert["cryptoProperties"])
        self.assertNotIn("algorithmProperties", comp_cert["cryptoProperties"],
                         "CERTIFICATE must NOT have algorithmProperties")

        # C. PROTOCOL
        proto_asset = CryptoAsset(
            asset_id="proto-reg-01",
            asset_type=AssetType.PROTOCOL,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "TLSv1.3"),
            role=CryptographicRole.KEY_AGREEMENT,
            parameters=AlgorithmParameters(),
            finding_ids=("find-p",),
            primary_location=SourceLocation(file_path="src/tls.py", line_start=1, line_end=1),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        comp_proto = self.projector.project_component(proto_asset)
        self.assertIn("cryptoProperties", comp_proto)
        self.assertEqual(comp_proto["cryptoProperties"]["assetType"], "protocol")
        self.assertIn("protocolProperties", comp_proto["cryptoProperties"])
        self.assertEqual(comp_proto["cryptoProperties"]["protocolProperties"].get("type"), "tls")
        self.assertNotIn("algorithmProperties", comp_proto["cryptoProperties"],
                         "PROTOCOL must NOT have algorithmProperties")

        # D. ALGORITHM (must have algorithmProperties)
        algo_asset = self._create_simple_asset("AES-GCM", AlgorithmFamily.AES, CryptographicRole.ENCRYPTION_DECRYPTION)
        comp_algo = self.projector.project_component(algo_asset)
        self.assertIn("cryptoProperties", comp_algo)
        self.assertEqual(comp_algo["cryptoProperties"]["assetType"], "algorithm")
        self.assertIn("algorithmProperties", comp_algo["cryptoProperties"],
                         "ALGORITHM must have algorithmProperties")

        # E. Validation tier rejection: injecting algorithmProperties on non-algorithm asset must fail
        bom = self.serializer.serialize_to_dict([key_asset, cert_asset, proto_asset, algo_asset])
        val_pass = self.validator.validate(bom, [key_asset, cert_asset, proto_asset, algo_asset])
        self.assertTrue(val_pass.is_valid, f"Validation should pass: {val_pass.errors}")

        # Inject invalid algorithmProperties into key component
        bad_bom = copy.deepcopy(bom)
        for comp in bad_bom["components"]:
            if comp.get("cryptoProperties", {}).get("assetType") == "related-crypto-material":
                comp["cryptoProperties"]["algorithmProperties"] = {}
                break

        val_fail = self.validator.validate_tier1_structure(bad_bom)
        self.assertFalse(val_fail.is_valid, "Validator must reject algorithmProperties on non-algorithm asset")
        self.assertTrue(any("algorithmProperties" in err for err in val_fail.errors))

    # 30. UNKNOWN Asset Type Semantics (Semantic B Regression)
    def test_30_unknown_asset_type_semantics(self) -> None:
        """
        Regression test proving that AssetType.UNKNOWN represents Semantic B:
        'A cryptographic usage was observed, but the actual asset type is unknown.'
        
        Therefore:
        1. cryptoProperties.assetType 'algorithm' is NOT emitted.
        2. Incompatible CycloneDX crypto representation is omitted entirely.
        3. Component type is 'cryptographic-asset'.
        4. ECDAT UNKNOWN semantics are preserved through ecdat: properties/provenance.
        5. Full serialization and two-tier validation pass cleanly.
        """
        unknown_asset = CryptoAsset(
            asset_id="unknown-asset-42",
            asset_type=AssetType.UNKNOWN,
            algorithm_identity=AlgorithmIdentity(AlgorithmFamily.UNKNOWN, "UNKNOWN"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=("find-unknown-obs",),
            primary_location=SourceLocation(file_path="src/opaque_crypto.py", line_start=42, line_end=42),
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            correlation_basis="opaque_heuristic_match",
        )

        comp = self.projector.project_component(unknown_asset)

        # 1. Must be a cryptographic-asset component
        self.assertEqual(comp["type"], "cryptographic-asset")
        self.assertEqual(comp["name"], "UNKNOWN")

        # 2. Must NOT emit cryptoProperties (CycloneDX has no assetType='unknown')
        self.assertNotIn(
            "cryptoProperties",
            comp,
            "AssetType.UNKNOWN must NOT emit cryptoProperties.assetType='algorithm'"
        )

        # 3. ECDAT properties preserve full provenance and semantic uncertainty
        ecdat_props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(ecdat_props.get("ecdat:asset_type"), "unknown")
        self.assertEqual(ecdat_props.get("ecdat:confidence"), "NEEDS_REVIEW")
        self.assertEqual(ecdat_props.get("ecdat:role"), "unknown")
        self.assertEqual(ecdat_props.get("ecdat:algorithm_family"), "UNKNOWN")
        self.assertEqual(ecdat_props.get("ecdat:correlation_basis"), "opaque_heuristic_match")

        # 4. Full CBOM serialization & two-tier validation
        bom = self.serializer.serialize_to_dict([unknown_asset])
        val = self.validator.validate(bom, [unknown_asset])
        self.assertTrue(val.is_valid, f"Validation failed for UNKNOWN asset: {val.errors}")

        # In BOM components, verify component exists without cryptoProperties
        bom_comp = bom["components"][0]
        self.assertEqual(bom_comp["bom-ref"], f"ecdat:asset:{unknown_asset.asset_id}")
        self.assertNotIn("cryptoProperties", bom_comp)

    # 31. Unsupported Future AssetType Does Not Silently Fall Back
    def test_31_unsupported_future_asset_type_no_silent_fallback(self) -> None:
        """
        Forward-compatibility regression test proving that any future, unmapped,
        or unsupported AssetType cannot silently fall through to 'algorithm'
        or use a raw .value string as a CycloneDX assetType.
        
        Requirements verified:
        1. project_asset_type returns None for any unmapped asset type.
        2. No '.value' fallback is used as a CycloneDX assetType.
        3. An unknown/new AssetType does NOT automatically become 'algorithm'.
        4. project_component omits cryptoProperties entirely when unmapped.
        5. Canonical domain asset_type value is faithfully preserved in ecdat:asset_type.
        """
        from enum import Enum
        from unittest.mock import MagicMock

        # Define an artificial future asset type outside the supported enum
        FutureAssetType = Enum("FutureAssetType", {
            "QUANTUM_CIRCUIT": "quantum_circuit",
            "HARDWARE_SECURITY_MODULE": "hardware_security_module",
        })

        # 1. Direct mapping check: must return None, NOT 'algorithm' or 'quantum_circuit'
        cdx_type = self.projector.project_asset_type(FutureAssetType.QUANTUM_CIRCUIT)
        self.assertIsNone(
            cdx_type,
            "FutureAssetType.QUANTUM_CIRCUIT must return None (no silent fallback to 'algorithm')"
        )

        cdx_hsm = self.projector.project_asset_type(FutureAssetType.HARDWARE_SECURITY_MODULE)
        self.assertIsNone(
            cdx_hsm,
            "FutureAssetType.HARDWARE_SECURITY_MODULE must return None"
        )

        # 2. String fallback prevention: passing raw unmapped string must return None
        self.assertIsNone(self.projector.project_asset_type("unmapped_type"))

        # 3. Component projection check: mock asset with future asset type
        mock_future_asset = MagicMock()
        mock_future_asset.asset_id = "future-asset-99"
        mock_future_asset.asset_type = FutureAssetType.QUANTUM_CIRCUIT
        mock_future_asset.algorithm_identity.algorithm = "Shor-Algorithm-Circuit"
        mock_future_asset.algorithm_identity.family.value = "QUANTUM"
        mock_future_asset.role.value = "UNKNOWN"
        mock_future_asset.confidence.value = "NEEDS_REVIEW"
        mock_future_asset.correlation_basis = "future_quantum_scanner"
        mock_future_asset.finding_ids = ("find-q99",)
        mock_future_asset.parameters.key_size_bits = None
        mock_future_asset.parameters.curve_name = None
        mock_future_asset.parameters.cipher_mode = None
        mock_future_asset.parameters.padding_scheme = None
        mock_future_asset.parameters.digest_algorithm = None
        mock_future_asset.algorithm_identity.variant = None
        mock_future_asset.primary_location.file_path = "src/quantum.py"
        mock_future_asset.primary_location.line_start = 10
        mock_future_asset.primary_location.line_end = 10
        mock_future_asset.primary_location.column_start = None
        mock_future_asset.primary_location.column_end = None
        mock_future_asset.primary_location.matched_text = ""
        mock_future_asset.primary_location.code_snippet = ""
        mock_future_asset.primary_location.package_coordinate = None

        comp = self.projector.project_component(mock_future_asset)

        # Must NOT emit cryptoProperties
        self.assertNotIn(
            "cryptoProperties",
            comp,
            "Component with unsupported AssetType must NOT emit cryptoProperties (no silent fallback)"
        )

        # Must project as general cryptographic-asset component
        self.assertEqual(comp["type"], "cryptographic-asset")
        self.assertEqual(comp["name"], "Shor-Algorithm-Circuit")

        # Must preserve exact canonical asset_type in ecdat: properties
        ecdat_props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        self.assertEqual(ecdat_props.get("ecdat:asset_type"), "quantum_circuit")


if __name__ == "__main__":
    unittest.main()
