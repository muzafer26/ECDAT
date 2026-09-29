"""
ECDAT CryptoScan Adapter Unit & End-to-End Test Suite.

Tests CryptoScanAdapter against real Phase 1C-B benchmark raw output fixtures
and synthetic hostile inputs, asserting verbatim category preservation,
native ID collision handling, defensive path handling, UNKNOWN detection method,
and end-to-end integration through Phase 1D Normalization and Asset Correlation.
"""

from pathlib import Path
import unittest

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import AssetType, CanonicalAssetKey
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.observation import ObservationType
from product.core.evidence.evidence import DetectionMethod, EvidenceRecord, LocationType
from product.core.ingestion.adapter import IngestionStatus, RawScannerOutput
from product.core.ingestion.adapters.cryptoscan import CryptoScanAdapter, normalize_source_path
from product.core.ingestion.orchestrator import IngestionOrchestrator
from product.core.ingestion.registry import AdapterRegistry
from product.core.normalization.correlation import AssetCorrelationEngine
from product.core.normalization.normalizer import NormalizationEngine


class TestCryptoScanAdapter(unittest.TestCase):
    """Unit and end-to-end tests for CryptoScan v1.4.0 adapter."""

    def setUp(self) -> None:
        self.adapter = CryptoScanAdapter()
        self.raw_dir = Path("product/benchmark/tools/raw_outputs/cryptoscan")

    def test_tc01_direct_rsa_raw_output_ingestion(self) -> None:
        """TC-01: Verifies CryptoScan raw output ingestion produces valid RSA evidence."""
        raw_file = self.raw_dir / "tc01_direct_rsa" / "run1_output.json"
        res = self.adapter.ingest_from_file(str(raw_file))

        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 1)

        ev = res.evidence_records[0]
        # 1. Native ID namespacing
        self.assertEqual(ev.evidence_id, "cryptoscan:RSA-001-16-64")
        self.assertEqual(ev.scanner_name, "CryptoScan")
        self.assertEqual(ev.scanner_version, "1.4.0")

        # 2. Strict UNKNOWN detection method (no manufactured AST_ANALYSIS)
        self.assertEqual(ev.detection_method, DetectionMethod.UNKNOWN)

        # 3. Verbatim category preservation
        self.assertEqual(ev.scanner_category, "Asymmetric Encryption")

        # 4. Location and path sanitization
        self.assertEqual(ev.location.location_type, LocationType.SOURCE)
        self.assertIn("DirectRSAKeyGen.java", ev.location.file_path)
        self.assertEqual(ev.location.line_start, 16)
        self.assertEqual(ev.location.column_start, 65)

        # 5. Raw attributes preserved
        self.assertEqual(ev.raw_attributes["native_finding_id"], "RSA-001-16-64")
        self.assertEqual(ev.raw_attributes["native_algorithm"], "RSA")
        self.assertEqual(ev.raw_attributes["native_primitive"], "pke")
        self.assertFalse(ev.raw_attributes["native_id_collision"])

    def test_scanner_category_does_not_determine_interpretation(self) -> None:
        """
        Critical invariant: scanner_category is raw empirical evidence only.
        It must not automatically determine the algorithm family, specific algorithm, or role.
        """
        raw_payload = b'''{
            "findings": [
                {
                    "id": "MISC-001",
                    "category": "RandomCustomCategory",
                    "file": "src/App.java",
                    "line": 10,
                    "match": "KeyPairGenerator.getInstance(\\"RSA\\");",
                    "context": "KeyPairGenerator.getInstance(\\"RSA\\");"
                }
            ]
        }'''
        raw_out = RawScannerOutput.from_bytes(raw_payload, "cryptoscan", "CryptoScan", "1.4.0")
        res = self.adapter.ingest_raw_output(raw_out)
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        ev = res.evidence_records[0]

        # Raw category is preserved verbatim
        self.assertEqual(ev.scanner_category, "RandomCustomCategory")

        # Downstream Phase 1D normalizer inspects matched code evidence to determine RSA, NOT the category
        normalizer = NormalizationEngine()
        finding = normalizer.normalize(ev)
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.RSA)
        self.assertEqual(finding.algorithm_identity.algorithm, "RSA")

    def test_duplicate_native_id_collision_handling(self) -> None:
        """
        Validates that duplicate native IDs in a CryptoScan output:
        - preserve all observations
        - preserve the original native ID in raw_attributes['native_finding_id']
        - assign distinct collision disambiguators ({adapter}:{id}:collision:{idx})
        - record native_id_collision = True
        - emit observable collision warning
        """
        raw_payload = b'''{
            "findings": [
                {
                    "id": "DUP-ID-01",
                    "category": "Asymmetric Encryption",
                    "file": "src/KeyA.java",
                    "line": 10,
                    "match": "RSA"
                },
                {
                    "id": "DUP-ID-01",
                    "category": "Asymmetric Encryption",
                    "file": "src/KeyB.java",
                    "line": 20,
                    "match": "RSA"
                }
            ]
        }'''
        raw_out = RawScannerOutput.from_bytes(raw_payload, "cryptoscan", "CryptoScan", "1.4.0")
        res = self.adapter.ingest_raw_output(raw_out)

        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 2)
        ev1, ev2 = res.evidence_records

        # 1. Distinct collision IDs
        self.assertEqual(ev1.evidence_id, "cryptoscan:DUP-ID-01:collision:0")
        self.assertEqual(ev2.evidence_id, "cryptoscan:DUP-ID-01:collision:1")

        # 2. Original raw ID preserved
        self.assertEqual(ev1.raw_attributes["native_finding_id"], "DUP-ID-01")
        self.assertEqual(ev2.raw_attributes["native_finding_id"], "DUP-ID-01")

        # 3. Collision flag set
        self.assertTrue(ev1.raw_attributes["native_id_collision"])
        self.assertTrue(ev2.raw_attributes["native_id_collision"])

        # 4. Observable warning recorded
        self.assertTrue(any("Duplicate native finding ID" in w for w in res.warnings))

    def test_missing_native_id_fallback_fingerprint(self) -> None:
        """
        Validates that findings lacking an ID receive a deterministic UUIDv5
        derived from full source coordinates, category, matched text, and occurrence_index.
        """
        raw_payload = b'''{
            "findings": [
                {
                    "category": "ECC",
                    "file": "src/Curve.java",
                    "line": 45,
                    "match": "secp256r1"
                },
                {
                    "category": "ECC",
                    "file": "src/Curve.java",
                    "line": 45,
                    "match": "secp256r1"
                }
            ]
        }'''
        raw_out = RawScannerOutput.from_bytes(raw_payload, "cryptoscan", "CryptoScan", "1.4.0")
        res = self.adapter.ingest_raw_output(raw_out)

        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 2)
        ev1, ev2 = res.evidence_records

        self.assertNotEqual(ev1.evidence_id, ev2.evidence_id)
        self.assertEqual(ev1.raw_attributes["native_finding_id"], "")
        self.assertFalse(ev1.raw_attributes["native_id_collision"])

    def test_path_sanitization_and_traversal_rejection(self) -> None:
        """Verifies path normalization rejects directory traversal attempts."""
        # Traversal attempts
        with self.assertRaises(Exception):
            normalize_source_path("../../etc/passwd")
        with self.assertRaises(Exception):
            normalize_source_path("..\\..\\windows\\system32\\cmd.exe")

        # Valid relative paths
        self.assertEqual(normalize_source_path("src/main/Crypto.java"), "src/main/Crypto.java")
        self.assertEqual(normalize_source_path(".\\src\\Key.java"), "src/Key.java")

    def test_mandatory_end_to_end_pipeline(self) -> None:
        """
        MANDATORY END-TO-END PIPELINE TEST:
        CryptoScan raw JSON
        -> CryptoScanAdapter
        -> EvidenceRecord
        -> NormalizationEngine (Phase 1D)
        -> Finding (Phase 1D)
        -> AssetCorrelationEngine (Phase 1D)
        -> CryptoAsset (Phase 1D)

        Verifies:
        - Unbroken provenance
        - Raw category preservation
        - Specificity preservation
        - Asset ID independence from finding/evidence IDs
        """
        reg = AdapterRegistry()
        reg.register(self.adapter)
        orch = IngestionOrchestrator(registry=reg)

        raw_file = self.raw_dir / "tc01_direct_rsa" / "run1_output.json"
        with open(raw_file, "rb") as f:
            raw_output = RawScannerOutput.from_bytes(
                f.read(),
                adapter_id="cryptoscan",
                scanner_name="CryptoScan",
                scanner_version="1.4.0",
                storage_ref=f"file://{raw_file}",
            )

        ing_res, findings, assets = orch.run_pipeline("cryptoscan", raw_output)

        # 1. Ingestion check
        self.assertEqual(ing_res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(ing_res.evidence_records), 1)
        ev = ing_res.evidence_records[0]
        self.assertEqual(ev.scanner_category, "Asymmetric Encryption")
        self.assertEqual(ev.detection_method, DetectionMethod.UNKNOWN)

        # 2. Normalization check
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.RSA)
        self.assertEqual(finding.algorithm_identity.algorithm, "RSA")
        self.assertIn(ev.evidence_id, finding.evidence_ids)

        # 3. Correlation check
        self.assertEqual(len(assets), 1)
        asset = assets[0]
        self.assertEqual(asset.algorithm_identity.family, AlgorithmFamily.RSA)
        self.assertEqual(asset.algorithm_identity.algorithm, "RSA")
        self.assertIn(finding.finding_id, asset.finding_ids)

        # 4. Asset ID independence from finding and evidence IDs
        self.assertIsNotNone(asset.asset_key)
        self.assertEqual(asset.asset_id, asset.asset_key.derive_asset_id())
        expected_key = CanonicalAssetKey.build(
            asset.asset_type,
            finding.primary_location,
            finding.algorithm_identity,
            finding.role,
            finding.parameters,
        )
        self.assertEqual(asset.asset_id, expected_key.derive_asset_id())

        # 5. Provenance audit trail
        self.assertEqual(asset.primary_location.file_path, ev.location.file_path)
        self.assertEqual(ev.raw_output_ref, f"file://{raw_file}")


if __name__ == "__main__":
    unittest.main()
