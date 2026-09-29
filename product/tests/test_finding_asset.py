"""
Tests for Finding, CryptoAsset, and Conservative Correlation Semantics.
"""

import unittest

from product.core.evidence.evidence import EvidenceRecord, SourceLocation, DetectionMethod
from product.core.domain.confidence import ConfidenceLevel, DispositionStatus
from product.core.domain.observation import ObservationType
from product.core.domain.role import CryptographicRole
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.finding import Finding
from product.core.domain.asset import CryptoAsset, AssetType, CanonicalAssetKey
from product.core.normalization.correlation import AssetCorrelationEngine, CorrelationDecision


class TestFindingAssetModel(unittest.TestCase):

    def setUp(self) -> None:
        self.loc1 = SourceLocation(
            file_path="src/CryptoService.java",
            line_start=15,
            line_end=15,
            matched_text="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
        )
        self.loc2 = SourceLocation(
            file_path="src/CryptoService.java",
            line_start=18,
            line_end=18,
            matched_text="cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);",
        )
        self.loc_other_file = SourceLocation(
            file_path="src/OtherService.java",
            line_start=15,
            line_end=15,
            matched_text="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
        )
        self.algo_aes = AlgorithmIdentity(family=AlgorithmFamily.AES, algorithm="AES")
        self.params_aes = AlgorithmParameters(key_size_bits=256, cipher_mode="GCM")

    def test_finding_can_reference_multiple_evidence_records(self) -> None:
        """Verifies finding can associate multiple evidence records."""
        finding = Finding(
            finding_id="find-001",
            evidence_ids=["ev-1", "ev-2", "ev-3"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        self.assertEqual(len(finding.evidence_ids), 3)
        self.assertIn("ev-2", finding.evidence_ids)

    def test_asset_can_reference_multiple_findings(self) -> None:
        """Verifies CryptoAsset can correlate multiple findings with explicit basis."""
        asset = CryptoAsset(
            asset_id="asset-001",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            finding_ids=["find-001", "find-002"],
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="conservative_correlation_same_file_same_statement",
        )
        self.assertEqual(len(asset.finding_ids), 2)
        self.assertEqual(asset.correlation_basis, "conservative_correlation_same_file_same_statement")

    def test_conservative_correlation_keeps_different_lines_separate(self) -> None:
        """Verifies findings on different lines remain separate in Phase 1D."""
        f1 = Finding(
            finding_id="f-1",
            evidence_ids=["e-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,  # Line 15
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-2",
            evidence_ids=["e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc2,  # Line 18
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f1, f2])

        # In Phase 1D, different lines are NOT merged
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-1"])
        self.assertEqual(assets[1].finding_ids, ["f-2"])

    def test_conservative_correlation_keeps_different_files_separate(self) -> None:
        """Verifies findings in different files are NEVER merged."""
        f1 = Finding(
            finding_id="f-1",
            evidence_ids=["e-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,  # src/CryptoService.java
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-2",
            evidence_ids=["e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc_other_file,  # src/OtherService.java
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f1, f2])

        # Must NOT be merged into one asset
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-1"])
        self.assertEqual(assets[1].finding_ids, ["f-2"])

    def test_conservative_correlation_keeps_different_algorithms_separate(self) -> None:
        """Verifies findings with different algorithms in the same file are NOT merged."""
        f1 = Finding(
            finding_id="f-1",
            evidence_ids=["e-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-2",
            evidence_ids=["e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.RSA, algorithm="RSA"),
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(key_size_bits=2048),
            primary_location=self.loc2,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f1, f2])
        self.assertEqual(len(assets), 2)

    def test_finding_and_asset_serialization_round_trip(self) -> None:
        """Verifies Finding and CryptoAsset serialize to dict and restore losslessly."""
        f = Finding(
            finding_id="f-serial-1",
            evidence_ids=["e-1", "e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
            disposition=DispositionStatus.UNREVIEWED,
            interpretation_basis="Test basis string",
        )
        f_dict = f.to_dict()
        f_restored = Finding.from_dict(f_dict)
        self.assertEqual(f_restored.finding_id, f.finding_id)
        self.assertEqual(f_restored.evidence_ids, f.evidence_ids)
        self.assertEqual(f_restored.algorithm_identity.algorithm, "AES")
        self.assertEqual(f_restored.role, CryptographicRole.ENCRYPTION_DECRYPTION)
        self.assertEqual(f_restored.interpretation_basis, "Test basis string")

        asset = CryptoAsset(
            asset_id="a-serial-1",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            finding_ids=["f-serial-1"],
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="single_finding_direct_instantiation",
        )
        a_dict = asset.to_dict()
        a_restored = CryptoAsset.from_dict(a_dict)
        self.assertEqual(a_restored.asset_id, asset.asset_id)
        self.assertEqual(a_restored.asset_type, AssetType.ALGORITHM)
        self.assertEqual(a_restored.finding_ids, ["f-serial-1"])
        self.assertEqual(a_restored.correlation_basis, "single_finding_direct_instantiation")

    def test_h01_two_independent_aes_operations_within_20_lines_not_merged(self) -> None:
        """H-01: Independent AES operations nearby with different variables MUST NOT merge."""
        f_a = Finding(
            finding_id="f-aes-a",
            evidence_ids=["e-a"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=10,
                line_end=10,
                matched_text="Cipher cipherA = Cipher.getInstance(\"AES/GCM/NoPadding\");",
                code_snippet="Cipher cipherA = Cipher.getInstance(\"AES/GCM/NoPadding\");\ncipherA.init(1, keyA);",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_b = Finding(
            finding_id="f-aes-b",
            evidence_ids=["e-b"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=14,
                line_end=14,
                matched_text="Cipher cipherB = Cipher.getInstance(\"AES/GCM/NoPadding\");",
                code_snippet="Cipher cipherB = Cipher.getInstance(\"AES/GCM/NoPadding\");\ncipherB.init(1, keyB);",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f_a, f_b])

        # MUST remain separate assets
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-aes-a"])
        self.assertEqual(assets[1].finding_ids, ["f-aes-b"])

    def test_h01_same_operation_multiple_observations_exact_location_merged(self) -> None:
        """H-01: Multiple observations of the exact same source location correlate into one asset."""
        f1 = Finding(
            finding_id="f-obs-1",
            evidence_ids=["e-obs-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=15,
                line_end=15,
                matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-obs-2",
            evidence_ids=["e-obs-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=15,
                line_end=15,
                matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f1, f2])

        self.assertEqual(len(assets), 1)
        self.assertEqual(len(assets[0].finding_ids), 2)
        self.assertIn("same_statement_deduplication", assets[0].correlation_basis)

    def test_h01_same_variable_distant_lines_remain_separate(self) -> None:
        """H-01 / Case E: Operations sharing variable name on distant lines MUST NOT correlate in Phase 1D."""
        f_init = Finding(
            finding_id="f-init",
            evidence_ids=["e-init"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/LongMethod.java",
                line_start=10,
                line_end=10,
                matched_text="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
                code_snippet="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_final = Finding(
            finding_id="f-final",
            evidence_ids=["e-final"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/LongMethod.java",
                line_start=55,
                line_end=55,
                matched_text="cipher.doFinal(plaintext);",
                code_snippet="byte[] ciphertext = cipher.doFinal(plaintext);",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f_init, f_final])

        # Phase 1D: Distinct statements on different lines MUST NOT correlate.
        # Dataflow/lifecycle correlation across distant lines is deferred to Phase 4.
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-init"])
        self.assertEqual(assets[1].finding_ids, ["f-final"])

    def test_h01_ambiguous_correlation_without_variable_keeps_separate_assets(self) -> None:
        """H-01: Ambiguous calls without shared variable or exact location remain separate."""
        f1 = Finding(
            finding_id="f-ambig-1",
            evidence_ids=["e-ambig-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/AnonCrypto.java",
                line_start=10,
                line_end=10,
                matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-ambig-2",
            evidence_ids=["e-ambig-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=SourceLocation(
                file_path="src/AnonCrypto.java",
                line_start=16,
                line_end=16,
                matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets = engine.correlate([f1, f2])

        # Conservative non-correlation: ambiguous findings remain separate
        self.assertEqual(len(assets), 2)

    def test_m01_deterministic_asset_id(self) -> None:
        """M-01: Asset ID is deterministic for identical canonical inputs."""
        f1 = Finding(
            finding_id="f-det-1",
            evidence_ids=["e-det-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-det-2",
            evidence_ids=["e-det-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,  # Same statement, multi-scanner
            confidence=ConfidenceLevel.CONFIRMED,
        )

        engine = AssetCorrelationEngine()
        assets_run1 = engine.correlate([f1, f2])
        # Pass in reverse order
        assets_run2 = engine.correlate([f2, f1])

        self.assertEqual(len(assets_run1), 1)
        self.assertEqual(len(assets_run2), 1)
        self.assertEqual(assets_run1[0].asset_id, assets_run2[0].asset_id)

    def test_m03_frozen_domain_object_immutability(self) -> None:
        """M-03: Verifies Finding and CryptoAsset reject in-place attribute assignment and ID mutation."""
        f = Finding(
            finding_id="f-frozen",
            evidence_ids=["e-1", "e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        # Cannot assign attribute
        with self.assertRaises((Exception, AttributeError)):
            f.role = CryptographicRole.KEY_GENERATION  # type: ignore

        # Cannot append to evidence_ids (FrozenIdTuple rejects append)
        with self.assertRaises(AttributeError):
            f.evidence_ids.append("e-3")  # type: ignore

        asset = CryptoAsset(
            asset_id="a-frozen",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.params_aes,
            finding_ids=["f-frozen"],
            primary_location=self.loc1,
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        with self.assertRaises((Exception, AttributeError)):
            asset.asset_id = "new-id"  # type: ignore

        with self.assertRaises(AttributeError):
            asset.finding_ids.append("f-extra")  # type: ignore


class TestPhase1DCorrelationAndIdentityRedesign(unittest.TestCase):
    """
    Focused verification tests for the Phase 1D correlation and identity redesign.
    Validates all 20 requirements from Prompt Section 12 plus provenance reconstruction.
    """

    def setUp(self) -> None:
        self.engine = AssetCorrelationEngine()
        self.algo_aes = AlgorithmIdentity(family=AlgorithmFamily.AES, algorithm="AES")
        self.algo_rsa = AlgorithmIdentity(family=AlgorithmFamily.RSA, algorithm="RSA")
        self.algo_dh = AlgorithmIdentity(family=AlgorithmFamily.DH, algorithm="DH")
        self.algo_ecdh = AlgorithmIdentity(family=AlgorithmFamily.EC, algorithm="ECDH")
        self.default_params = AlgorithmParameters()

    def test_case_01_same_statement_different_scanner_finding_ids(self) -> None:
        """1. Multiple scanner findings on the exact same statement correlate into one asset preserving all finding IDs."""
        loc = SourceLocation(
            file_path="src/App.java",
            line_start=21,
            line_end=21,
            matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
        )
        f_cs = Finding(
            finding_id="find-cryptoscan-001",
            evidence_ids=["ev-cs-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM", key_size_bits=256),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_sn = Finding(
            finding_id="find-sonar-002",
            evidence_ids=["ev-sn-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM", key_size_bits=256),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_cs, f_sn])

        self.assertEqual(len(assets), 1)
        self.assertEqual(set(assets[0].finding_ids), {"find-cryptoscan-001", "find-sonar-002"})
        self.assertIn("same_statement_deduplication", assets[0].correlation_basis)

    def test_case_02_same_statement_different_scanner_names(self) -> None:
        """2. Same statement detected by different scanners merges into a single asset."""
        loc = SourceLocation(file_path="src/Crypto.java", line_start=15, line_end=15, matched_text="Cipher.getInstance(\"AES\");")
        ev1 = EvidenceRecord(
            evidence_id="ev-scanner-a",
            location=loc,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
        )
        ev2 = EvidenceRecord(
            evidence_id="ev-scanner-b",
            location=loc,
            scanner_name="SonarQube",
            scanner_version="10.2",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="AES",
        )
        f1 = Finding(
            finding_id="f-a",
            evidence_ids=[ev1.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-b",
            evidence_ids=[ev2.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f1, f2])
        self.assertEqual(len(assets), 1)
        self.assertEqual(len(assets[0].finding_ids), 2)

    def test_case_03_independently_constructed_equivalent_observations(self) -> None:
        """3. Cross-scan requirement: Independently constructed equivalent observations produce identical asset_id."""
        # Run 1: new EvidenceRecord -> new Finding -> correlate -> Asset A
        loc1 = SourceLocation(file_path="src/Service.java", line_start=40, line_end=40, matched_text="Cipher.getInstance(\"AES/CBC\");")
        ev1 = EvidenceRecord(
            evidence_id="run1-ev-123",
            location=loc1,
            scanner_name="Scanner1",
            scanner_version="1.0",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="AES",
        )
        f1 = Finding(
            finding_id="run1-finding-abc",
            evidence_ids=[ev1.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="CBC"),
            primary_location=loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        assets_run1 = self.engine.correlate([f1])

        # Run 2: Completely independent construction (different IDs, different instances)
        loc2 = SourceLocation(file_path="src/Service.java", line_start=40, line_end=40, matched_text="Cipher.getInstance(\"AES/CBC\");")
        ev2 = EvidenceRecord(
            evidence_id="run2-ev-999",
            location=loc2,
            scanner_name="Scanner2",
            scanner_version="2.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
        )
        f2 = Finding(
            finding_id="run2-finding-xyz",
            evidence_ids=[ev2.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="CBC"),
            primary_location=loc2,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        assets_run2 = self.engine.correlate([f2])

        self.assertEqual(len(assets_run1), 1)
        self.assertEqual(len(assets_run2), 1)
        # Identical canonical identity produces identical asset_id
        self.assertEqual(assets_run1[0].asset_id, assets_run2[0].asset_id)

    def test_case_04_reordered_findings(self) -> None:
        """4. Finding input order does not affect asset clustering or asset IDs."""
        loc_aes = SourceLocation(file_path="src/Crypto.java", line_start=15, line_end=15, matched_text="Cipher.getInstance(\"AES\");")
        loc_rsa = SourceLocation(file_path="src/Crypto.java", line_start=30, line_end=30, matched_text="KeyPairGenerator.getInstance(\"RSA\");")

        f_aes1 = Finding(
            finding_id="f-aes-1",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc_aes,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_aes2 = Finding(
            finding_id="f-aes-2",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc_aes,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_rsa = Finding(
            finding_id="f-rsa-1",
            evidence_ids=["e3"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_rsa,
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(key_size_bits=2048),
            primary_location=loc_rsa,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        res1 = self.engine.correlate([f_aes1, f_aes2, f_rsa])
        res2 = self.engine.correlate([f_rsa, f_aes2, f_aes1])
        res3 = self.engine.correlate([f_aes2, f_rsa, f_aes1])

        self.assertEqual(len(res1), 2)
        self.assertEqual(len(res2), 2)
        self.assertEqual(len(res3), 2)

        ids1 = {a.asset_id for a in res1}
        ids2 = {a.asset_id for a in res2}
        ids3 = {a.asset_id for a in res3}
        self.assertEqual(ids1, ids2)
        self.assertEqual(ids1, ids3)

    def test_case_05_two_aes_operations_different_variables(self) -> None:
        """5. Two AES operations with different variables remain separate."""
        f_a = Finding(
            finding_id="f-aes-a",
            evidence_ids=["e-a"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM", key_size_bits=256),
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=10,
                line_end=10,
                matched_text="Cipher cipherA = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_b = Finding(
            finding_id="f-aes-b",
            evidence_ids=["e-b"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM", key_size_bits=256),
            primary_location=SourceLocation(
                file_path="src/CryptoService.java",
                line_start=14,
                line_end=14,
                matched_text="Cipher cipherB = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_a, f_b])
        self.assertEqual(len(assets), 2)
        self.assertNotEqual(assets[0].asset_id, assets[1].asset_id)

    def test_case_06_same_variable_gcm_then_cbc(self) -> None:
        """6. Case B: Reassigned variable (AES/GCM then AES/CBC) MUST remain separate assets."""
        f_gcm = Finding(
            finding_id="f-gcm",
            evidence_ids=["e-gcm"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM"),
            primary_location=SourceLocation(
                file_path="src/CipherReuse.java",
                line_start=10,
                line_end=10,
                matched_text="cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_cbc = Finding(
            finding_id="f-cbc",
            evidence_ids=["e-cbc"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="CBC"),
            primary_location=SourceLocation(
                file_path="src/CipherReuse.java",
                line_start=20,
                line_end=20,
                matched_text="cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_gcm, f_cbc])
        self.assertEqual(len(assets), 2)
        self.assertNotEqual(assets[0].asset_id, assets[1].asset_id)

    def test_case_07_same_variable_separate_gcm_instantiations(self) -> None:
        """7. Case C: Separate instantiations with same variable and algorithm remain separate."""
        f1 = Finding(
            finding_id="f-gcm-1",
            evidence_ids=["e-1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM"),
            primary_location=SourceLocation(
                file_path="src/Reinstantiation.java",
                line_start=10,
                line_end=10,
                matched_text="cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-gcm-2",
            evidence_ids=["e-2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM"),
            primary_location=SourceLocation(
                file_path="src/Reinstantiation.java",
                line_start=30,
                line_end=30,
                matched_text="cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f1, f2])
        self.assertEqual(len(assets), 2)
        self.assertNotEqual(assets[0].asset_id, assets[1].asset_id)

    def test_case_08_same_variable_across_methods(self) -> None:
        """8. Case D: Same variable name across different methods MUST remain separate."""
        f_method_a = Finding(
            finding_id="f-method-a",
            evidence_ids=["e-a"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM"),
            primary_location=SourceLocation(
                file_path="src/Methods.java",
                line_start=12,
                line_end=12,
                matched_text="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_method_b = Finding(
            finding_id="f-method-b",
            evidence_ids=["e-b"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(cipher_mode="GCM"),
            primary_location=SourceLocation(
                file_path="src/Methods.java",
                line_start=45,
                line_end=45,
                matched_text="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_method_a, f_method_b])
        self.assertEqual(len(assets), 2)
        self.assertNotEqual(assets[0].asset_id, assets[1].asset_id)

    def test_case_09_same_line_distinct_statements(self) -> None:
        """9. Distinct statements on the exact same line (e.g. c1 = ...; c2 = ...;) remain separate."""
        loc1 = SourceLocation(
            file_path="src/SameLine.java",
            line_start=15,
            line_end=15,
            matched_text="Cipher c1 = Cipher.getInstance(\"AES\");",
        )
        loc2 = SourceLocation(
            file_path="src/SameLine.java",
            line_start=15,
            line_end=15,
            matched_text="Cipher c2 = Cipher.getInstance(\"AES\");",
        )
        f1 = Finding(
            finding_id="f-c1",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-c2",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc2,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f1, f2])
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-c1"])
        self.assertEqual(assets[1].finding_ids, ["f-c2"])

    def test_case_10_column_disambiguated_same_line_statements(self) -> None:
        """10. Same line statements with non-overlapping column ranges remain separate."""
        loc1 = SourceLocation(
            file_path="src/DenseLine.java",
            line_start=20,
            line_end=20,
            column_start=5,
            column_end=35,
            matched_text="Cipher.getInstance(\"AES\");",
        )
        loc2 = SourceLocation(
            file_path="src/DenseLine.java",
            line_start=20,
            line_end=20,
            column_start=45,
            column_end=75,
            matched_text="Cipher.getInstance(\"AES\");",
        )
        f1 = Finding(
            finding_id="f-col-1",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc1,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f2 = Finding(
            finding_id="f-col-2",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc2,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f1, f2])
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0].finding_ids, ["f-col-1"])
        self.assertEqual(assets[1].finding_ids, ["f-col-2"])

    def test_case_11_same_algorithm_different_roles(self) -> None:
        """11. Same algorithm with incompatible roles (e.g. ENCRYPTION vs KEY_GENERATION) remain separate."""
        loc = SourceLocation(file_path="src/App.java", line_start=15, line_end=15, matched_text="AES")
        f_enc = Finding(
            finding_id="f-enc",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_gen = Finding(
            finding_id="f-gen",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.KEY_GENERATION,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_enc, f_gen])
        self.assertEqual(len(assets), 2)

    def test_case_12_rsa_2048_vs_rsa_3072(self) -> None:
        """12. Conflicting key sizes (RSA-2048 vs RSA-3072) MUST reject correlation."""
        loc = SourceLocation(file_path="src/Keys.java", line_start=10, line_end=10, matched_text="KeyPairGenerator.getInstance(\"RSA\");")
        f_2048 = Finding(
            finding_id="f-2048",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_rsa,
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(key_size_bits=2048),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_3072 = Finding(
            finding_id="f-3072",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_rsa,
            role=CryptographicRole.KEY_GENERATION,
            parameters=AlgorithmParameters(key_size_bits=3072),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        decision, reason, _ = self.engine.evaluate_correlation(f_2048, f_3072)
        self.assertEqual(decision, CorrelationDecision.NOT_CORRELATED)
        self.assertIn("conflicting_key_sizes", reason)

        assets = self.engine.correlate([f_2048, f_3072])
        self.assertEqual(len(assets), 2)

    def test_case_13_dh_vs_ecdh(self) -> None:
        """13. DH vs ECDH: Conflicting algorithm families MUST reject correlation."""
        loc = SourceLocation(file_path="src/Agreement.java", line_start=12, line_end=12, matched_text="KeyAgreement.getInstance(...)")
        f_dh = Finding(
            finding_id="f-dh",
            evidence_ids=["e-dh"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_dh,
            role=CryptographicRole.KEY_AGREEMENT,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_ecdh = Finding(
            finding_id="f-ecdh",
            evidence_ids=["e-ecdh"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_ecdh,
            role=CryptographicRole.KEY_AGREEMENT,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        decision, reason, _ = self.engine.evaluate_correlation(f_dh, f_ecdh)
        self.assertEqual(decision, CorrelationDecision.NOT_CORRELATED)
        self.assertIn("conflicting_families", reason)

        assets = self.engine.correlate([f_dh, f_ecdh])
        self.assertEqual(len(assets), 2)

    def test_case_14_unknown_parameter_vs_known_parameter(self) -> None:
        """14. Unknown/omitted parameters correlate with known parameters (unknown does not overwrite known)."""
        loc = SourceLocation(
            file_path="src/CryptoService.java",
            line_start=15,
            line_end=15,
            matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
        )
        # Scanner 1 saw key_size=256, but mode=None
        f1 = Finding(
            finding_id="f-partial-1",
            evidence_ids=["e1"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=256, cipher_mode=None),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        # Scanner 2 saw mode=GCM, but key_size=None
        f2 = Finding(
            finding_id="f-partial-2",
            evidence_ids=["e2"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=None, cipher_mode="GCM"),
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f1, f2])
        self.assertEqual(len(assets), 1)
        # Merged parameters retain both known values
        self.assertEqual(assets[0].parameters.key_size_bits, 256)
        self.assertEqual(assets[0].parameters.cipher_mode, "GCM")

    def test_case_15_dynamic_algorithm(self) -> None:
        """15. Dynamic algorithm calls remain UNKNOWN and do not blindly merge with specific algorithms."""
        loc_dyn = SourceLocation(file_path="src/Dynamic.java", line_start=10, line_end=10, matched_text="Cipher.getInstance(algorithmVar);")
        loc_aes = SourceLocation(file_path="src/Dynamic.java", line_start=25, line_end=25, matched_text="Cipher.getInstance(\"AES\");")

        f_dyn = Finding(
            finding_id="f-dyn",
            evidence_ids=["e-dyn"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc_dyn,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        f_aes = Finding(
            finding_id="f-aes",
            evidence_ids=["e-aes"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc_aes,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_dyn, f_aes])
        self.assertEqual(len(assets), 2)
        self.assertNotEqual(assets[0].asset_id, assets[1].asset_id)

    def test_case_16_dependency_vs_source_usage(self) -> None:
        """16. Dependency declaration and source-level cryptographic usage produce separate distinct assets."""
        f_dep = Finding(
            finding_id="f-dep",
            evidence_ids=["e-dep"],
            observation_type=ObservationType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="UNKNOWN"),
            role=CryptographicRole.UNKNOWN,
            parameters=self.default_params,
            primary_location=SourceLocation(file_path="build.gradle", line_start=18, line_end=18, matched_text="bcprov-jdk18on"),
            confidence=ConfidenceLevel.CONFIRMED,
        )
        f_src = Finding(
            finding_id="f-src",
            evidence_ids=["e-src"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=SourceLocation(file_path="src/Main.java", line_start=15, line_end=15, matched_text="AES"),
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f_dep, f_src])
        self.assertEqual(len(assets), 2)
        types = {a.asset_type for a in assets}
        self.assertIn(AssetType.LIBRARY_DEPENDENCY, types)
        self.assertIn(AssetType.ALGORITHM, types)

    def test_case_17_comment_or_decoy_vs_real_usage(self) -> None:
        """17. Comment-only or decoy findings with FALSE_POSITIVE disposition do NOT merge with real cryptographic usage."""
        loc = SourceLocation(file_path="src/RealCrypto.java", line_start=15, line_end=15, matched_text="// TODO: use AES encryption")
        f_decoy = Finding(
            finding_id="f-decoy",
            evidence_ids=["e-decoy"],
            observation_type=ObservationType.COMMENT_ONLY,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.UNKNOWN,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.UNKNOWN,
            disposition=DispositionStatus.FALSE_POSITIVE,
        )
        f_real = Finding(
            finding_id="f-real",
            evidence_ids=["e-real"],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=SourceLocation(file_path="src/RealCrypto.java", line_start=20, line_end=20, matched_text="Cipher.getInstance(\"AES\");"),
            confidence=ConfidenceLevel.CONFIRMED,
            disposition=DispositionStatus.UNREVIEWED,
        )

        assets = self.engine.correlate([f_decoy, f_real])
        # Only the genuine cryptographic usage produces an active CryptoAsset
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].finding_ids, ["f-real"])

    def test_case_18_deterministic_asset_ids(self) -> None:
        """18. CanonicalAssetKey derives 100% deterministic UUID5 asset ID with zero reliance on finding_ids."""
        loc = SourceLocation(file_path="src/Crypto.java", line_start=10, line_end=10)
        key1 = CanonicalAssetKey.build(
            asset_type=AssetType.ALGORITHM,
            location=loc,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=256, cipher_mode="GCM"),
        )
        key2 = CanonicalAssetKey.build(
            asset_type=AssetType.ALGORITHM,
            location=loc,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=AlgorithmParameters(key_size_bits=256, cipher_mode="GCM"),
        )

        id1 = key1.derive_asset_id()
        id2 = key2.derive_asset_id()
        self.assertEqual(id1, id2)
        # Verify key string contains no finding or evidence references
        self.assertNotIn("finding", key1.canonical_string())
        self.assertNotIn("evidence", key1.canonical_string())

    def test_case_19_different_location_different_asset_id(self) -> None:
        """19. Different source locations produce distinct canonical keys and distinct asset IDs."""
        loc1 = SourceLocation(file_path="src/Crypto.java", line_start=10, line_end=10)
        loc2 = SourceLocation(file_path="src/Crypto.java", line_start=20, line_end=20)
        loc3 = SourceLocation(file_path="src/Other.java", line_start=10, line_end=10)

        f1 = Finding(finding_id="f1", evidence_ids=["e1"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_aes, role=CryptographicRole.ENCRYPTION_DECRYPTION, parameters=self.default_params, primary_location=loc1, confidence=ConfidenceLevel.CONFIRMED)
        f2 = Finding(finding_id="f2", evidence_ids=["e2"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_aes, role=CryptographicRole.ENCRYPTION_DECRYPTION, parameters=self.default_params, primary_location=loc2, confidence=ConfidenceLevel.CONFIRMED)
        f3 = Finding(finding_id="f3", evidence_ids=["e3"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_aes, role=CryptographicRole.ENCRYPTION_DECRYPTION, parameters=self.default_params, primary_location=loc3, confidence=ConfidenceLevel.CONFIRMED)

        assets = self.engine.correlate([f1, f2, f3])
        self.assertEqual(len(assets), 3)
        ids = [a.asset_id for a in assets]
        self.assertEqual(len(set(ids)), 3)

    def test_case_20_finding_order_does_not_affect_asset_id(self) -> None:
        """20. Finding input permutation does not change generated asset IDs or grouping."""
        loc1 = SourceLocation(file_path="src/A.java", line_start=10, line_end=10, matched_text="AES")
        loc2 = SourceLocation(file_path="src/B.java", line_start=20, line_end=20, matched_text="RSA")

        f1 = Finding(finding_id="f1", evidence_ids=["e1"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_aes, role=CryptographicRole.ENCRYPTION_DECRYPTION, parameters=self.default_params, primary_location=loc1, confidence=ConfidenceLevel.CONFIRMED)
        f2 = Finding(finding_id="f2", evidence_ids=["e2"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_aes, role=CryptographicRole.ENCRYPTION_DECRYPTION, parameters=self.default_params, primary_location=loc1, confidence=ConfidenceLevel.CONFIRMED)
        f3 = Finding(finding_id="f3", evidence_ids=["e3"], observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
                     algorithm_identity=self.algo_rsa, role=CryptographicRole.KEY_GENERATION, parameters=self.default_params, primary_location=loc2, confidence=ConfidenceLevel.CONFIRMED)

        run1 = self.engine.correlate([f1, f2, f3])
        run2 = self.engine.correlate([f3, f2, f1])
        run3 = self.engine.correlate([f2, f3, f1])

        self.assertEqual([a.asset_id for a in run1], [a.asset_id for a in run2])
        self.assertEqual([a.asset_id for a in run1], [a.asset_id for a in run3])

    def test_provenance_reconstructability_from_asset(self) -> None:
        """Verifies Asset -> Finding IDs -> Evidence IDs -> Raw provenance is fully reconstructable."""
        loc = SourceLocation(file_path="src/App.java", line_start=15, line_end=15, matched_text="AES")
        ev = EvidenceRecord(
            evidence_id="ev-prov-1",
            location=loc,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
            raw_attributes={"raw_rule_id": "CS-AES-01"},
        )
        evidence_store = {ev.evidence_id: ev}
        f = Finding(
            finding_id="f-prov-1",
            evidence_ids=[ev.evidence_id],
            observation_type=ObservationType.CRYPTOGRAPHIC_USAGE,
            algorithm_identity=self.algo_aes,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            parameters=self.default_params,
            primary_location=loc,
            confidence=ConfidenceLevel.CONFIRMED,
        )

        assets = self.engine.correlate([f])
        self.assertEqual(len(assets), 1)
        asset = assets[0]

        # Asset holds finding_ids
        self.assertIn("f-prov-1", asset.finding_ids)
        # Finding holds evidence_ids
        self.assertIn("ev-prov-1", f.evidence_ids)
        # Trace back to raw evidence
        provenance_ev = evidence_store[f.evidence_ids[0]]
        self.assertEqual(provenance_ev.raw_attributes["raw_rule_id"], "CS-AES-01")
        self.assertEqual(provenance_ev.scanner_name, "CryptoScan")


if __name__ == "__main__":
    unittest.main()


