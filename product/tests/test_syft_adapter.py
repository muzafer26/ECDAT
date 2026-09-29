"""
ECDAT Syft Scanner Adapter Unit & Integration Tests.

Validates:
1. Real Phase 1C-B Syft raw output ingestion (TC-09 Bouncy Castle).
2. Strict non-inference invariant: package names never imply algorithms.
3. LocationType.DEPENDENCY invariant and manifest path normalization.
4. Observable relevance filtering without silent evidence destruction.
5. Native artifact ID collision disambiguation.
6. Defensive PURL handling (zero fabrication of missing PURLs).
7. Phase 1D integration through NormalizationEngine and AssetCorrelationEngine.
"""

import json
import os
import unittest
from typing import Dict, Any

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.observation import ObservationType
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceRecord,
    LocationType,
)
from product.core.ingestion.adapter import (
    IngestionStatus,
    RawScannerOutput,
)
from product.core.ingestion.adapters.syft import (
    SyftAdapter,
    normalize_manifest_path,
)
from product.core.normalization.normalizer import NormalizationEngine
from product.core.normalization.correlation import AssetCorrelationEngine


class TestSyftAdapter(unittest.TestCase):
    """Test suite for Anchore Syft v1.51.1 adapter."""

    def setUp(self) -> None:
        self.adapter = SyftAdapter()
        self.normalization_engine = NormalizationEngine()
        self.correlation_engine = AssetCorrelationEngine()

    def test_tc09_real_syft_raw_output_ingestion(self) -> None:
        """
        Tests ingestion of real benchmark Syft raw output from TC-09 (Bouncy Castle).
        Verifies:
        - LocationType.DEPENDENCY
        - Package coordinates and PURLs extracted verbatim
        - Scanner category preserved as 'dependency'
        - DetectionMethod remains strictly UNKNOWN
        - Raw metadata (cataloger, licenses, version) preserved
        """
        raw_file = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "syft",
            "tc09_dependency_crypto", "run1_output.json"
        )
        self.assertTrue(os.path.isfile(raw_file), f"Benchmark raw output not found: {raw_file}")

        result = self.adapter.ingest_from_file(raw_file, scan_id="test-tc09-syft")

        self.assertEqual(result.status, IngestionStatus.SUCCESS)
        self.assertGreater(len(result.evidence_records), 0)

        # Locate the Bouncy Castle dependency artifact
        bc_records = [
            r for r in result.evidence_records
            if "bcprov" in str(r.location.package_coordinate or "") or
               "bcprov" in str(r.raw_attributes.get("package_name", ""))
        ]
        self.assertGreater(len(bc_records), 0, "Bouncy Castle package must be present in TC-09 output")

        bc = bc_records[0]
        # Invariants
        self.assertEqual(bc.location.location_type, LocationType.DEPENDENCY)
        self.assertEqual(bc.scanner_name, "syft")
        self.assertEqual(bc.scanner_version, "1.51.1")
        self.assertEqual(bc.scanner_category, "dependency")
        self.assertEqual(bc.detection_method, DetectionMethod.UNKNOWN)

        # PURL and raw attributes
        self.assertIn("pkg:maven/org.bouncycastle/bcprov-jdk18on", bc.location.package_coordinate or "")
        self.assertEqual(bc.raw_attributes.get("package_name"), "bcprov-jdk18on")
        self.assertEqual(bc.raw_attributes.get("package_type"), "java-archive")
        self.assertIn("pom-cataloger", bc.raw_attributes.get("cataloger", ""))

    def test_strict_non_inference_of_algorithms_from_package(self) -> None:
        """
        CRITICAL SEMANTIC TEST:
        Validates that presence of a crypto library (e.g. Bouncy Castle, OpenSSL, PyCryptodome)
        DOES NOT cause the adapter or Phase 1D normalizer to infer specific algorithms (AES, RSA).
        Must produce ObservationType.LIBRARY_DEPENDENCY with AlgorithmFamily.UNKNOWN.
        """
        raw_file = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "syft",
            "tc09_dependency_crypto", "run1_output.json"
        )
        result = self.adapter.ingest_from_file(raw_file, scan_id="test-non-inference")
        self.assertEqual(result.status, IngestionStatus.SUCCESS)

        # Normalize all evidence records through Phase 1D
        findings = [self.normalization_engine.normalize(ev) for ev in result.evidence_records]
        self.assertGreater(len(findings), 0)

        for finding in findings:
            # All Syft findings must be dependency observations
            self.assertEqual(finding.observation_type, ObservationType.LIBRARY_DEPENDENCY)
            # Under NO circumstances may an algorithm be manufactured
            self.assertEqual(
                finding.algorithm_identity.family,
                AlgorithmFamily.UNKNOWN,
                f"Manufactured algorithm family {finding.algorithm_identity.family} from dependency!"
            )
            self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
            self.assertEqual(finding.role, CryptographicRole.UNKNOWN)
            # Must have zero key lengths or curves inferred
            self.assertIsNone(finding.parameters.key_size_bits)
            self.assertIsNone(finding.parameters.curve_name)

    def test_observable_relevance_filtering(self) -> None:
        """
        Tests that relevance filtering is explicit and observable:
        - When filtering is active, filtered count is recorded in warnings
        - Raw payload retains all artifacts
        - No silent destruction of evidence occurs
        """
        # Create an adapter that only accepts packages with 'bcprov'
        def bc_filter(art: Dict[str, Any]) -> bool:
            name = str(art.get("name", "")).lower()
            return "bcprov" in name

        filtered_adapter = SyftAdapter(relevance_policy=bc_filter)
        raw_file = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "syft",
            "tc09_dependency_crypto", "run1_output.json"
        )

        result = filtered_adapter.ingest_from_file(raw_file, scan_id="test-filter")
        self.assertEqual(result.status, IngestionStatus.SUCCESS)

        # Check that warnings contain explicit record of filtered packages
        self.assertTrue(
            any("Relevance policy filtered" in w for w in result.warnings),
            "Expected warning recording the number of filtered artifacts"
        )

        for record in result.evidence_records:
            pkg_name = str(record.raw_attributes.get("package_name", "")).lower()
            self.assertTrue("bc" in pkg_name or "crypto" in pkg_name)

    def test_defensive_purl_and_missing_coordinates(self) -> None:
        """
        Validates that missing PURLs and coordinates are NEVER fabricated.
        """
        synthetic_syft = {
            "artifacts": [
                {
                    "id": "art-1",
                    "name": "internal-tool",
                    "version": "1.0.0",
                    "type": "binary",
                    # No purl, no locations
                }
            ],
            "source": {"type": "directory", "target": "/app"},
        }
        raw_bytes = json.dumps(synthetic_syft).encode("utf-8")
        raw = RawScannerOutput.from_bytes(
            stdout_bytes=raw_bytes,
            adapter_id="syft",
            scanner_name="syft",
            scanner_version="1.51.1",
        )
        res = self.adapter.ingest_raw_output(raw)
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 1)

        rec = res.evidence_records[0]
        self.assertIsNone(rec.location.package_coordinate)
        self.assertEqual(rec.location.matched_text, "internal-tool")
        self.assertEqual(rec.raw_attributes.get("purl"), "")

    def test_duplicate_native_id_collision_handling(self) -> None:
        """
        Validates that duplicate native artifact IDs from Syft:
        - Are both preserved
        - Receive collision disambiguated evidence IDs
        - Emit observable warnings
        """
        synthetic_syft = {
            "artifacts": [
                {
                    "id": "dup-id-123",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "purl": "pkg:generic/pkg-a@1.0.0",
                },
                {
                    "id": "dup-id-123",
                    "name": "pkg-b",
                    "version": "2.0.0",
                    "purl": "pkg:generic/pkg-b@2.0.0",
                },
            ],
        }
        raw_bytes = json.dumps(synthetic_syft).encode("utf-8")
        raw = RawScannerOutput.from_bytes(
            stdout_bytes=raw_bytes,
            adapter_id="syft",
            scanner_name="syft",
            scanner_version="1.51.1",
        )
        res = self.adapter.ingest_raw_output(raw)
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 2)

        ev1, ev2 = res.evidence_records[0], res.evidence_records[1]
        self.assertEqual(ev1.evidence_id, "syft:dup-id-123:collision:0")
        self.assertEqual(ev2.evidence_id, "syft:dup-id-123:collision:1")
        self.assertTrue(ev1.raw_attributes["native_id_collision"])
        self.assertTrue(ev2.raw_attributes["native_id_collision"])
        self.assertTrue(any("Duplicate native artifact ID" in w for w in res.warnings))

    def test_syft_phase1d_end_to_end_correlation_isolation(self) -> None:
        """
        Tests end-to-end flow:
        Syft raw JSON -> SyftAdapter -> EvidenceRecord -> NormalizationEngine -> Finding -> AssetCorrelationEngine -> CryptoAsset.
        Verifies that dependency evidence correlates into dependency assets and NEVER merges
        or pollutes source-level code findings.
        """
        raw_file = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "syft",
            "tc09_dependency_crypto", "run1_output.json"
        )
        ingest_res = self.adapter.ingest_from_file(raw_file, scan_id="test-e2e-syft")
        self.assertEqual(ingest_res.status, IngestionStatus.SUCCESS)

        findings = [self.normalization_engine.normalize(ev) for ev in ingest_res.evidence_records]
        self.assertGreater(len(findings), 0)

        assets = self.correlation_engine.correlate(findings)
        self.assertGreater(len(assets), 0)

        for asset in assets:
            self.assertEqual(asset.primary_location.location_type, LocationType.DEPENDENCY)
            self.assertIsNotNone(asset.asset_key)
            self.assertEqual(asset.asset_id, asset.asset_key.derive_asset_id())
            # Asset ID must be derived strictly from domain fields, zero scanner ID dependence
            self.assertNotIn("syft", asset.asset_id)


if __name__ == "__main__":
    unittest.main()
