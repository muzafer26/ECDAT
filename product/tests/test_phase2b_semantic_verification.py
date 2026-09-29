"""
ECDAT Phase 2B Semantic Verification Tests (TC-01 through TC-11).

Validates the complete pipeline:
Raw Scanner Output -> ScannerAdapter -> EvidenceRecord -> NormalizationEngine -> Finding -> AssetCorrelationEngine -> CryptoAsset

Strictly enforces:
- TC-01: RSA remains RSA evidence.
- TC-02: AES remains AES evidence.
- TC-03: Generic EC remains family=UNKNOWN/EC, curve preserved if evidenced, role=unknown, never promoted to ECDSA.
- TC-04: ECDSA remains ECDSA where scanner evidence supports it.
- TC-05: ECDH / key-establishment remains ECDH evidence where supported.
- TC-06: Ed25519 remains Ed25519; never collapsed into generic ECC.
- TC-07: SHA-1 remains SHA-1 / deprecated hash evidence.
- TC-08: Wrapper blindness: zero evidence synthesized; status=NO_FINDINGS.
- TC-09: Bouncy Castle dependency remains dependency evidence; no algorithm inference.
- TC-10: Misleading comments classified as non_cryptographic_decoy; zero crypto assets created.
- TC-11: Dynamic cipher construction: zero evidence synthesized; status=NO_FINDINGS.
"""

import os
import unittest

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.observation import ObservationType
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import DetectionMethod, LocationType
from product.core.ingestion.adapter import IngestionStatus
from product.core.ingestion.adapters.cryptoscan import CryptoScanAdapter
from product.core.ingestion.adapters.syft import SyftAdapter
from product.core.normalization.normalizer import NormalizationEngine
from product.core.normalization.correlation import AssetCorrelationEngine


class TestPhase2BSemanticVerification(unittest.TestCase):
    """Semantic test suite validating all benchmark test cases across the Phase 2B boundary."""

    def setUp(self) -> None:
        self.cryptoscan = CryptoScanAdapter()
        self.syft = SyftAdapter()
        self.normalizer = NormalizationEngine()
        self.correlator = AssetCorrelationEngine()

    def test_tc01_rsa_preservation(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc01_direct_rsa", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc01")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 1)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].algorithm_identity.family, AlgorithmFamily.RSA)
        self.assertEqual(findings[0].algorithm_identity.algorithm, "RSA")

        assets = self.correlator.correlate(findings)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].algorithm_identity.family, AlgorithmFamily.RSA)

    def test_tc02_aes_preservation(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc02_symmetric_aes", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc02")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 2)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        for f in findings:
            self.assertEqual(f.algorithm_identity.family, AlgorithmFamily.AES)
            self.assertEqual(f.algorithm_identity.algorithm, "AES")

    def test_tc03_generic_ecc_no_premature_ecdsa_inference(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc03_ecc_generic", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc03")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # Invariant: Must NOT be inferred as ECDSA
        self.assertNotEqual(f.algorithm_identity.algorithm, "ECDSA")
        self.assertEqual(f.role, CryptographicRole.UNKNOWN)

    def test_tc04_ecdsa_preserved_where_evidenced(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc04_ecdsa", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc04")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        ecdsa_findings = [f for f in findings if f.algorithm_identity.algorithm == "ECDSA"]
        self.assertGreater(len(ecdsa_findings), 0)
        self.assertEqual(ecdsa_findings[0].role, CryptographicRole.DIGITAL_SIGNATURE)

    def test_tc05_ecdh_preserved_where_evidenced(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc05_ecdh", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc05")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        ecdh_findings = [f for f in findings if f.algorithm_identity.algorithm == "ECDH"]
        self.assertGreater(len(ecdh_findings), 0)
        self.assertEqual(ecdh_findings[0].role, CryptographicRole.KEY_AGREEMENT)

    def test_tc06_ed25519_preserved_not_collapsed_to_generic_ecc(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc06_ed25519", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc06")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.algorithm_identity.family, AlgorithmFamily.EDWARDS)
        self.assertEqual(f.algorithm_identity.algorithm, "Ed25519")

    def test_tc07_sha1_preservation(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc07_sha1_hash", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc07")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(res.evidence_records), 3)
        for ev in res.evidence_records:
            self.assertEqual(ev.scanner_category, "Deprecated Hash")
            self.assertEqual(ev.raw_attributes.get("native_algorithm"), "SHA-1")

    def test_tc08_wrapper_blindness_zero_fabricated_evidence(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc08_crypto_wrapper", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc08")
        # Invariant: zero evidence synthesized when scanner misses wrapper
        self.assertEqual(res.status, IngestionStatus.NO_FINDINGS)
        self.assertEqual(len(res.evidence_records), 0)

    def test_tc09_dependency_non_inference(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "syft",
            "tc09_dependency_crypto", "run1_output.json"
        )
        res = self.syft.ingest_from_file(raw_path, scan_id="test-tc09")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        for f in findings:
            self.assertEqual(f.observation_type, ObservationType.LIBRARY_DEPENDENCY)
            self.assertEqual(f.algorithm_identity.family, AlgorithmFamily.UNKNOWN)
            self.assertEqual(f.algorithm_identity.algorithm, "UNKNOWN")

    def test_tc10_misleading_comments_not_crypto_usage(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc10_misleading_comments", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc10")
        self.assertEqual(res.status, IngestionStatus.SUCCESS)

        findings = [self.normalizer.normalize(ev) for ev in res.evidence_records]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # Invariant: Must be recognized as decoy / comment, NOT operational cryptographic usage
        self.assertEqual(f.observation_type, ObservationType.NON_CRYPTOGRAPHIC_DECOY)
        assets = self.correlator.correlate(findings)
        # Decoys never produce Cryptographic Assets
        self.assertEqual(len(assets), 0)

    def test_tc11_ambiguous_dynamic_zero_fabricated_evidence(self) -> None:
        raw_path = os.path.join(
            "product", "benchmark", "tools", "raw_outputs", "cryptoscan",
            "tc11_ambiguous_dynamic", "run1_output.json"
        )
        res = self.cryptoscan.ingest_from_file(raw_path, scan_id="test-tc11")
        # Invariant: silent scanner failure on dynamic cipher construction must NOT be papered over
        self.assertEqual(res.status, IngestionStatus.NO_FINDINGS)
        self.assertEqual(len(res.evidence_records), 0)


if __name__ == "__main__":
    unittest.main()
