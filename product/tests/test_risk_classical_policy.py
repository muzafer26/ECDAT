"""
Unit Tests for ECDAT Phase 3C-C Classical Cryptographic Policy (RSA & SHA-1).

Validates:
1. RSA-512 in production -> DISALLOWED, SHOR_VULNERABLE, CRITICAL, P0_IMMEDIATE_ACTION (R-RISK-01).
2. RSA-1024 in production -> DISALLOWED, SHOR_VULNERABLE, CRITICAL, P0_IMMEDIATE_ACTION (R-RISK-01).
3. RSA-2048 in production -> ACCEPTABLE, SHOR_VULNERABLE, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-POLICY-DECISION-REQUIRED).
4. RSA-4096 in production -> ACCEPTABLE, SHOR_VULNERABLE, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-POLICY-DECISION-REQUIRED).
5. RSA missing key size -> INDETERMINATE, HIGH_UNCERTAINTY, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-06).
6. RSA conflicting key size evidence -> INDETERMINATE, HIGH_UNCERTAINTY, NEEDS_REVIEW, P_REVIEW_REQUIRED.
7. RSA-1024 in isolated air-gapped test fixture -> DISALLOWED, LOW, P4_DEFERRED_MONITORING (R-RISK-05A).
8. RSA-1024 in unverified dev exposure -> DISALLOWED, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-06).
9. RSA-1024 in public test exposure -> DISALLOWED, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-06).
10. SHA-1 digital signature in production -> DISALLOWED, GROVER_AFFECTED_HASH, CRITICAL, P0 (R-RISK-01, review required).
11. SHA-1 certificate operations -> DEPRECATED, GROVER_AFFECTED_HASH, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-06).
12. SHA-1 message digest -> DEPRECATED, GROVER_AFFECTED_HASH, NEEDS_REVIEW, P_REVIEW_REQUIRED (R-RISK-06).
13. SHA-1 HMAC with known key size >= 112 -> ACCEPTABLE, GROVER_AFFECTED_HASH, NEEDS_REVIEW, P_REVIEW_REQUIRED (Policy decision).
14. SHA-1 HMAC with missing key size -> ACCEPTABLE, GROVER_AFFECTED_HASH, NEEDS_REVIEW, P_REVIEW_REQUIRED (review required).
15. SHA-1 HMAC with short key (< 112 bits) -> DISALLOWED, GROVER_AFFECTED_HASH, CRITICAL, P0 (R-RISK-01).
16. SHA-1 unknown role -> INDETERMINATE, GROVER_AFFECTED_HASH, HIGH_UNCERTAINTY, NEEDS_REVIEW, P_REVIEW_REQUIRED.
17. Rejection of substring "ADVERSARY" as RSA.
18. Rejection of substring "PERSISTENT" as RSA.
19. SHA-1 token alone does not infer signature.
20. ECDH excluded from FFDH logic.
21. TC01 unannotated RSA key generator stability.
22. TC07 hashlib.sha1() stability.
"""

import unittest

from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import EvidenceLocation, LocationType

from product.core.risk import (
    AssetContext,
    ClassicalSecurityStatus,
    ContextAuthority,
    DeploymentEnvironment,
    MigrationComplexity,
    NetworkExposure,
    PrimaryRiskCause,
    PriorityTier,
    QuantumExposureClass,
    RiskAnalysisEngine,
    RiskCategory,
    UncertaintyLevel,
)
from product.core.risk.posture import evaluate_crypto_posture


class TestPhase3CClassicalPolicy(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = RiskAnalysisEngine()
        self.dummy_loc = EvidenceLocation(
            location_type=LocationType.SOURCE,
            file_path="src/crypto/service.py",
            line_start=10,
            line_end=15,
            matched_text="crypto_call()",
        )

    def _create_asset(
        self,
        family: AlgorithmFamily,
        algo_name: str,
        role: CryptographicRole = CryptographicRole.ENCRYPTION_DECRYPTION,
        key_size_bits: int | None = None,
    ) -> CryptoAsset:
        return CryptoAsset(
            asset_id=f"test-{family.value}-{algo_name}-{role.value}-{key_size_bits}",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=AlgorithmIdentity(family=family, algorithm=algo_name),
            role=role,
            parameters=AlgorithmParameters(key_size_bits=key_size_bits),
            confidence=ConfidenceLevel.CONFIRMED,
            finding_ids=["finding-001"],
            primary_location=self.dummy_loc,
            correlation_basis="test_fixture",
        )

    # 1. RSA-512 in production
    def test_rsa_512_prod_critical(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=512)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION, network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(rec.primary_cause, PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD)
        self.assertEqual(rec.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.explanation.quantum_exposure_class, "SHOR_VULNERABLE_ASYMMETRIC")
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-01", rule_ids)

    # 2. RSA-1024 in production
    def test_rsa_1024_prod_critical(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.DIGITAL_SIGNATURE, key_size_bits=1024)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(rec.primary_cause, PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD)
        self.assertEqual(rec.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        # Mandatory review required because operational direction is unevidenced in static AST
        self.assertTrue(rec.mandatory_review_required)

    # 3. RSA-2048 in production
    def test_rsa_2048_prod_acceptable_policy_req(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=2048)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "ACCEPTABLE")
        self.assertEqual(rec.explanation.quantum_exposure_class, "SHOR_VULNERABLE_ASYMMETRIC")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-POLICY-DECISION-REQUIRED", rule_ids)

    # 4. RSA-4096 in production
    def test_rsa_4096_prod_acceptable_policy_req(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=4096)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "ACCEPTABLE")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 5. RSA missing key size
    def test_rsa_missing_key_size_uncertainty(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=None)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)
        status, quantum, unc, citation, name = evaluate_crypto_posture(asset)

        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertEqual(unc, UncertaintyLevel.HIGH_UNCERTAINTY)
        self.assertEqual(rec.explanation.classical_status, "INDETERMINATE")
        self.assertEqual(rec.explanation.uncertainty_level, "NEEDS_REVIEW")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-06", rule_ids)

    # 6. RSA conflicting key size evidence
    def test_rsa_conflicting_key_size_uncertainty(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA_1024", CryptographicRole.KEY_GENERATION, key_size_bits=2048)
        status, quantum, unc, citation, name = evaluate_crypto_posture(asset)

        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertEqual(unc, UncertaintyLevel.HIGH_UNCERTAINTY)
        self.assertIn("Conflicting RSA modulus evidence", citation)

    # 7. RSA-1024 in isolated air-gapped test fixture
    def test_rsa_1024_isolated_airgap_mitigated(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=1024)
        ctx = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.ISOLATED_AIRGAPPED,
        )
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.risk_category, RiskCategory.LOW)
        self.assertEqual(rec.primary_cause, PrimaryRiskCause.NON_PROD_MITIGATED)
        self.assertEqual(rec.default_priority, PriorityTier.P4_DEFERRED_MONITORING)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-05A", rule_ids)

    # 8. RSA-1024 in unverified dev exposure
    def test_rsa_1024_unverified_exposure_needs_review(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=1024)
        ctx = AssetContext(
            environment=DeploymentEnvironment.DEVELOPMENT,
            network_exposure=NetworkExposure.UNVERIFIED_EXPOSURE,
        )
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-06", rule_ids)

    # 9. RSA-1024 in public test exposure
    def test_rsa_1024_public_test_needs_review(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=1024)
        ctx = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
        )
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 10. SHA-1 digital signature in production
    def test_sha1_digital_signature_prod_critical(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA-1", CryptographicRole.DIGITAL_SIGNATURE)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.explanation.quantum_exposure_class, "GROVER_AFFECTED_HASH")
        self.assertEqual(rec.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(rec.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        self.assertTrue(rec.mandatory_review_required)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-01", rule_ids)

    # 11. SHA-1 certificate operations
    def test_sha1_cert_operations_deprecated(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA-1", CryptographicRole.CERTIFICATE_OPERATIONS)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DEPRECATED")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-06", rule_ids)

    # 12. SHA-1 message digest
    def test_sha1_message_digest_deprecated(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA-1", CryptographicRole.MESSAGE_DIGEST)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DEPRECATED")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 13. SHA-1 HMAC with adequate key (>= 112 bits)
    def test_sha1_hmac_known_key_acceptable(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "HMAC-SHA1", CryptographicRole.MAC, key_size_bits=256)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "ACCEPTABLE")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 14. SHA-1 HMAC with unannotated key
    def test_sha1_hmac_unannotated_key_needs_review(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "HMAC-SHA1", CryptographicRole.MAC, key_size_bits=None)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "ACCEPTABLE")
        self.assertTrue(rec.mandatory_review_required)
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 15. SHA-1 HMAC with short key (< 112 bits)
    def test_sha1_hmac_short_key_disallowed(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "HMAC-SHA1", CryptographicRole.MAC, key_size_bits=64)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DISALLOWED")
        self.assertEqual(rec.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(rec.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        rule_ids = [r["rule_id"] for r in rec.explanation.triggered_rules]
        self.assertIn("R-RISK-01", rule_ids)

    # 16. SHA-1 unknown role
    def test_sha1_unknown_role_uncertainty(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA-1", CryptographicRole.UNKNOWN)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)
        status, quantum, unc, citation, name = evaluate_crypto_posture(asset)

        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertEqual(unc, UncertaintyLevel.HIGH_UNCERTAINTY)
        self.assertEqual(rec.explanation.classical_status, "INDETERMINATE")
        self.assertEqual(rec.explanation.uncertainty_level, "NEEDS_REVIEW")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 17. Rejection of substring "ADVERSARY" as RSA
    def test_adversary_token_rejected_as_rsa(self) -> None:
        asset = self._create_asset(AlgorithmFamily.UNKNOWN, "ADVERSARY")
        status, quantum, unc, cit, name = evaluate_crypto_posture(asset)
        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertNotEqual(name, "RSA")

    # 18. Rejection of substring "PERSISTENT" as RSA
    def test_persister_token_rejected_as_rsa(self) -> None:
        asset = self._create_asset(AlgorithmFamily.UNKNOWN, "PERSISTENT")
        status, quantum, unc, cit, name = evaluate_crypto_posture(asset)
        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertNotEqual(name, "RSA")

    # 19. SHA-1 token alone does not infer signature
    def test_sha1_token_alone_does_not_infer_signature(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA1", role=CryptographicRole.UNKNOWN)
        status, quantum, unc, cit, name = evaluate_crypto_posture(asset)
        # Must be INDETERMINATE because role is unknown; does not infer signature
        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)
        self.assertEqual(unc, UncertaintyLevel.HIGH_UNCERTAINTY)

    # 20. ECDH excluded from FFDH logic
    def test_ecdh_not_evaluated_as_ffdh(self) -> None:
        asset = self._create_asset(AlgorithmFamily.EC, "ECDH", role=CryptographicRole.KEY_AGREEMENT)
        status, quantum, unc, cit, name = evaluate_crypto_posture(asset)
        # FFDH is deferred; EC remains INDETERMINATE in classical status without crash
        self.assertEqual(status, ClassicalSecurityStatus.INDETERMINATE)

    # 21. TC01 unannotated RSA key generator stability
    def test_tc01_rsa_ast_output_stability(self) -> None:
        asset = self._create_asset(AlgorithmFamily.RSA, "RSA", CryptographicRole.KEY_GENERATION, key_size_bits=None)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "INDETERMINATE")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)

    # 22. TC07 hashlib.sha1() stability
    def test_tc07_sha1_ast_output_stability(self) -> None:
        asset = self._create_asset(AlgorithmFamily.SHA1, "SHA-1", CryptographicRole.MESSAGE_DIGEST)
        ctx = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        rec = self.engine.evaluate(asset, ctx)

        self.assertEqual(rec.explanation.classical_status, "DEPRECATED")
        self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)


if __name__ == "__main__":
    unittest.main()
