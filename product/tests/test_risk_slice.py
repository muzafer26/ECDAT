"""
Unit Tests for ECDAT Phase 3C-B Targeted Correction & Specification Reconciliation.

Validates:
1. DES in production -> CRITICAL risk, CLASSICAL_DISALLOWED_PROD, P0_IMMEDIATE_ACTION.
2. Non-production mitigation (R-05A) requires verified isolation evidence.
3. Non-production without verified isolation routes to NEEDS_REVIEW / P_REVIEW_REQUIRED.
4. False match prevention: CAESAR is NOT classified as AES.
5. False match prevention: DESIGN_TOKEN is NOT classified as DES.
6. Supported DES aliases and case normalization.
7. Supported AES aliases and case normalization.
8. Acceptable AES in production does NOT assign NON_PROD_MITIGATED; discloses policy decision gap.
9. Missing AES key size routes to NEEDS_REVIEW / P_REVIEW_REQUIRED, NOT silent LOW/P4.
10. Explainability contract completeness (PHASE_3C_EXPLAINABILITY_MODEL.md §3).
11. Deep immutability: MappingProxyType prevents nested mutation via returned and input containers.
12. Determinism: Repeated execution yields identical records.
13. Error handling: Invalid risk state fails closed with InvalidRiskStateError.
14. Critical precedence: Confirmed classical break retains CRITICAL/P0 even under context uncertainty.
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
    InvalidRiskStateError,
    MigrationComplexity,
    NetworkExposure,
    PrimaryRiskCause,
    PriorityTier,
    QuantumExposureClass,
    RiskAnalysisEngine,
    RiskCategory,
    UncertaintyLevel,
)
from product.core.risk.priority import derive_default_priority


class TestRiskFirstSliceReconciliation(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = RiskAnalysisEngine()
        self.dummy_location = EvidenceLocation(
            location_type=LocationType.SOURCE,
            file_path="src/crypto/service.py",
            line_start=42,
            line_end=45,
            matched_text="Cipher.getInstance('DES')",
        )

    def _create_asset(
        self,
        family: AlgorithmFamily,
        algo_name: str,
        key_size: int | None = None,
        role: CryptographicRole = CryptographicRole.ENCRYPTION_DECRYPTION,
        finding_id: str = "find-001",
    ) -> CryptoAsset:
        algo_id = AlgorithmIdentity(family=family, algorithm=algo_name)
        params = AlgorithmParameters(key_size_bits=key_size)
        return CryptoAsset(
            asset_id="",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=algo_id,
            role=role,
            parameters=params,
            finding_ids=(finding_id,),
            primary_location=self.dummy_location,
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test_fixture",
        )

    def test_case_01_des_in_production_critical_p0(self) -> None:
        """Verifies DES in production produces CRITICAL risk, CLASSICAL_DISALLOWED_PROD, and P0 priority."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(
            environment=DeploymentEnvironment.PRODUCTION,
            network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
            authority=ContextAuthority.CI_DEPLOYMENT_METADATA,
            complexity=MigrationComplexity.LOW,
        )

        record = self.engine.evaluate(des_asset, context)

        self.assertEqual(record.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(record.primary_cause, PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD)
        self.assertEqual(record.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        self.assertEqual(record.effective_priority, PriorityTier.P0_IMMEDIATE_ACTION)

        exp = record.explanation
        rule_ids = [r["rule_id"] for r in exp.triggered_rules]
        self.assertIn("R-RISK-01", rule_ids)
        self.assertIn("R-PRIORITY-P0-CLASSICAL-MANDATORY", rule_ids)
        self.assertEqual(exp.classical_status, ClassicalSecurityStatus.DISALLOWED.value)
        self.assertEqual(exp.quantum_exposure_class, QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW.value)
        self.assertEqual(exp.risk_category, RiskCategory.CRITICAL.value)
        self.assertEqual(exp.final_priority_tier, PriorityTier.P0_IMMEDIATE_ACTION.value)

    def test_case_02_des_in_test_fixture_mitigated_low_p4_with_isolation(self) -> None:
        """Verifies DES in test fixture with verified isolation is mitigated to LOW/P4 under R-05A."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.ISOLATED_AIRGAPPED,
            authority=ContextAuthority.LOCAL_REPO_CONFIG,
            complexity=MigrationComplexity.TRIVIAL_QUICK_WIN,
        )

        record = self.engine.evaluate(des_asset, context)

        self.assertEqual(record.risk_category, RiskCategory.LOW)
        self.assertEqual(record.primary_cause, PrimaryRiskCause.NON_PROD_MITIGATED)
        self.assertEqual(record.default_priority, PriorityTier.P4_DEFERRED_MONITORING)
        self.assertFalse(record.mandatory_review_required)
        rule_ids = [r["rule_id"] for r in record.explanation.triggered_rules]
        self.assertIn("R-RISK-05A", rule_ids)

    def test_case_03_des_in_test_fixture_without_isolation_routes_to_review(self) -> None:
        """Verifies DES in test fixture without verified isolation cannot assume mitigation (R-06)."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.UNKNOWN,  # Unverified isolation
            authority=ContextAuthority.LOCAL_REPO_CONFIG,
        )

        record = self.engine.evaluate(des_asset, context)

        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.primary_cause, PrimaryRiskCause.UNRESOLVED_UNCERTAINTY)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertTrue(record.mandatory_review_required)
        self.assertTrue(any("Network exposure is UNKNOWN" in m for m in record.explanation.missing_facts_and_questions))

    def test_case_04_caesar_not_classified_as_aes(self) -> None:
        """Verifies CAESAR is NOT classified as AES despite containing substring 'AES'."""
        caesar_asset = self._create_asset(AlgorithmFamily.UNKNOWN, "CAESAR")
        context = AssetContext(environment=DeploymentEnvironment.PRODUCTION)

        record = self.engine.evaluate(caesar_asset, context)

        self.assertEqual(record.explanation.classical_status, ClassicalSecurityStatus.INDETERMINATE.value)
        self.assertEqual(record.explanation.quantum_exposure_class, QuantumExposureClass.UNCLASSIFIED_QUANTUM_POSTURE.value)
        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertEqual(record.explanation.algorithm_identity, "CAESAR")

    def test_case_05_design_token_not_classified_as_des(self) -> None:
        """Verifies DESIGN_TOKEN is NOT classified as DES despite containing substring 'DES'."""
        design_asset = self._create_asset(AlgorithmFamily.UNKNOWN, "DESIGN_TOKEN")
        context = AssetContext(environment=DeploymentEnvironment.PRODUCTION)

        record = self.engine.evaluate(design_asset, context)

        self.assertEqual(record.explanation.classical_status, ClassicalSecurityStatus.INDETERMINATE.value)
        self.assertEqual(record.explanation.quantum_exposure_class, QuantumExposureClass.UNCLASSIFIED_QUANTUM_POSTURE.value)
        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertEqual(record.explanation.algorithm_identity, "DESIGN_TOKEN")

    def test_case_06_des_aliases_and_case_normalization(self) -> None:
        """Verifies supported DES aliases and case variations normalize accurately."""
        for alias in ["3des", "3DES", "TripleDES", "des3", "TDES", "DES-EDE3"]:
            asset = self._create_asset(AlgorithmFamily.DES, alias, key_size=112)
            context = AssetContext(
                environment=DeploymentEnvironment.PRODUCTION,
                network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
            )
            record = self.engine.evaluate(asset, context)
            self.assertEqual(
                record.explanation.classical_status,
                ClassicalSecurityStatus.DISALLOWED.value,
                f"Failed for alias {alias}",
            )
            self.assertEqual(record.risk_category, RiskCategory.CRITICAL)

    def test_case_07_aes_aliases_and_case_normalization(self) -> None:
        """Verifies supported AES aliases and case variations normalize accurately."""
        for alias, expected_class in [
            ("aes-256", QuantumExposureClass.GROVER_RESILIENT_SYMMETRIC_HIGH),
            ("AES_256", QuantumExposureClass.GROVER_RESILIENT_SYMMETRIC_HIGH),
            ("aes-128", QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW),
        ]:
            asset = self._create_asset(AlgorithmFamily.AES, alias)
            context = AssetContext(
                environment=DeploymentEnvironment.TEST_FIXTURE,
                network_exposure=NetworkExposure.ISOLATED_AIRGAPPED,
            )
            record = self.engine.evaluate(asset, context)
            self.assertEqual(
                record.explanation.classical_status,
                ClassicalSecurityStatus.ACCEPTABLE.value,
                f"Failed for alias {alias}",
            )
            self.assertEqual(
                record.explanation.quantum_exposure_class,
                expected_class.value,
                f"Failed quantum class for {alias}",
            )

    def test_case_07b_bare_rijndael_rejected_without_evidence(self) -> None:
        """DEF-04: Verifies bare 'Rijndael' without explicit AES/128-bit evidence evaluates to INDETERMINATE & NEEDS_REVIEW."""
        asset = self._create_asset(AlgorithmFamily.UNKNOWN, "Rijndael")
        context = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.ISOLATED_AIRGAPPED,
        )
        record = self.engine.evaluate(asset, context)
        self.assertEqual(record.explanation.classical_status, ClassicalSecurityStatus.INDETERMINATE.value)
        self.assertEqual(record.explanation.quantum_exposure_class, QuantumExposureClass.UNCLASSIFIED_QUANTUM_POSTURE.value)
        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertTrue(record.mandatory_review_required)

    def test_case_08_aes_256_in_production_policy_decision_required(self) -> None:
        """Verifies AES-256 in production is NOT assigned NON_PROD_MITIGATED; discloses policy gap."""
        aes_asset = self._create_asset(AlgorithmFamily.AES, "AES", key_size=256)
        context = AssetContext(
            environment=DeploymentEnvironment.PRODUCTION,
            network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
            authority=ContextAuthority.CI_DEPLOYMENT_METADATA,
        )

        record = self.engine.evaluate(aes_asset, context)

        # Posture is acceptable
        self.assertEqual(record.explanation.classical_status, ClassicalSecurityStatus.ACCEPTABLE.value)
        self.assertEqual(
            record.explanation.quantum_exposure_class,
            QuantumExposureClass.GROVER_RESILIENT_SYMMETRIC_HIGH.value,
        )

        # Primary cause must NOT be NON_PROD_MITIGATED in production!
        self.assertNotEqual(record.primary_cause, PrimaryRiskCause.NON_PROD_MITIGATED)

        # Overall risk routes to NEEDS_REVIEW pending owner policy decision on acceptable production ciphers
        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertTrue(record.mandatory_review_required)
        self.assertTrue(any("UNRESOLVED_POLICY_DECISION" in m for m in record.explanation.missing_facts_and_questions))

    def test_case_09_aes_missing_key_size_records_high_uncertainty_and_review(self) -> None:
        """Verifies missing AES key size routes to NEEDS_REVIEW / P_REVIEW_REQUIRED, NOT silent LOW/P4."""
        aes_unannotated = self._create_asset(AlgorithmFamily.AES, "AES", key_size=None)
        context = AssetContext(
            environment=DeploymentEnvironment.TEST_FIXTURE,
            network_exposure=NetworkExposure.ISOLATED_AIRGAPPED,
        )

        record = self.engine.evaluate(aes_unannotated, context)

        self.assertEqual(record.risk_category, RiskCategory.NEEDS_REVIEW)
        self.assertEqual(record.default_priority, PriorityTier.P_REVIEW_REQUIRED)
        self.assertTrue(record.mandatory_review_required)
        self.assertEqual(record.explanation.uncertainty_level, UncertaintyLevel.HIGH_UNCERTAINTY.value)
        self.assertTrue(any("Missing key_size_bits" in m for m in record.explanation.missing_facts_and_questions))

    def test_case_10_explainability_contract_completeness(self) -> None:
        """Verifies all 7 required explanation sections exist and conform to PHASE_3C_EXPLAINABILITY_MODEL.md §3."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56, finding_id="find-xyz-999")
        context = AssetContext(
            environment=DeploymentEnvironment.PRODUCTION,
            network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
            authority=ContextAuthority.CI_DEPLOYMENT_METADATA,
        )

        record = self.engine.evaluate(des_asset, context)
        exp = record.explanation

        # Section 1: Observed Facts
        self.assertEqual(exp.asset_id, record.asset_id)
        self.assertIn("find-xyz-999", exp.evidence_ids)
        self.assertTrue(any("src/crypto/service.py" in loc for loc in exp.code_locations))
        self.assertTrue(any("raw_token=DES" in fact for fact in exp.observed_facts))

        # Section 2: Derived Classifications
        self.assertEqual(exp.algorithm_identity, "DES")
        self.assertEqual(exp.classical_status, ClassicalSecurityStatus.DISALLOWED.value)
        self.assertEqual(exp.quantum_exposure_class, QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW.value)

        # Section 3: Context & Provenance
        self.assertEqual(exp.context_summary["deployment_environment"], DeploymentEnvironment.PRODUCTION.value)
        self.assertEqual(exp.context_summary["network_exposure"], NetworkExposure.INTERNET_FACING_PUBLIC.value)
        self.assertEqual(exp.context_authority, ContextAuthority.CI_DEPLOYMENT_METADATA.value)

        # Section 4: Triggered Rules (Structured records)
        self.assertTrue(len(exp.triggered_rules) >= 2)
        r01 = next(r for r in exp.triggered_rules if r["rule_id"] == "R-RISK-01")
        self.assertEqual(r01["authority"], "NIST SP 800-131A Rev 2")
        self.assertIn("https://csrc.nist.gov", r01["citation_url"])

        # Section 5: Assumptions (Deferred features explicitly disclosed)
        self.assertTrue(any("NIST SP 800-131A" in a for a in exp.assumptions))
        self.assertTrue(any("HNDL" in a and "deferred" in a.lower() for a in exp.assumptions))
        self.assertTrue(any("Mosca" in a and "deferred" in a.lower() for a in exp.assumptions))
        self.assertTrue(any("override" in a and "deferred" in a.lower() for a in exp.assumptions))

        # Section 6: Uncertainty
        self.assertEqual(exp.uncertainty_level, UncertaintyLevel.CONFIRMED.value)

        # Section 7: Result
        self.assertEqual(exp.risk_category, RiskCategory.CRITICAL.value)
        self.assertEqual(exp.final_priority_tier, PriorityTier.P0_IMMEDIATE_ACTION.value)
        self.assertTrue(len(exp.actionable_remediation_summary) > 10)

        # Serialization to dict
        data = exp.to_dict()
        self.assertIsInstance(data["observed_facts"], list)
        self.assertIsInstance(data["triggered_rules"], list)
        self.assertIsInstance(data["context_summary"], dict)

    def test_case_11_deep_immutability(self) -> None:
        """Verifies explanation and nested mappings/sequences cannot be mutated after construction."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(environment=DeploymentEnvironment.PRODUCTION)
        record = self.engine.evaluate(des_asset, context)
        exp = record.explanation

        # 1. Attempt to mutate nested context_summary through returned mapping
        with self.assertRaises((TypeError, AttributeError)):
            exp.context_summary["deployment_environment"] = "HACKED_ENV"  # type: ignore

        # 2. Attempt to mutate triggered_rules entry
        with self.assertRaises((TypeError, AttributeError)):
            exp.triggered_rules[0]["rule_id"] = "HACKED_RULE"  # type: ignore

        # 3. Attempt to mutate tuple containers
        with self.assertRaises(AttributeError):
            exp.observed_facts.append("new_fact")  # type: ignore

    def test_case_12_deterministic_repeatability(self) -> None:
        """Verifies evaluating identical inputs multiple times yields byte-for-byte identical output."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(environment=DeploymentEnvironment.PRODUCTION)

        record1 = self.engine.evaluate(des_asset, context)
        record2 = self.engine.evaluate(des_asset, context)

        self.assertEqual(record1.to_dict(), record2.to_dict())
        self.assertEqual(record1.asset_id, record2.asset_id)
        self.assertEqual(record1.default_priority, record2.default_priority)
        self.assertEqual(record1.risk_category, record2.risk_category)

    def test_case_13_invalid_risk_state_fails_closed(self) -> None:
        """Verifies invalid or unreachable state pair raises InvalidRiskStateError."""
        with self.assertRaises(InvalidRiskStateError):
            # Impossible pair: CRITICAL with NON_PROD_MITIGATED
            derive_default_priority(
                risk_category=RiskCategory.CRITICAL,
                primary_cause=PrimaryRiskCause.NON_PROD_MITIGATED,
            )

    def test_case_14_critical_precedence_with_context_uncertainty(self) -> None:
        """Verifies confirmed classical break retains CRITICAL/P0 even when context is uncertain."""
        des_asset = self._create_asset(AlgorithmFamily.DES, "DES", key_size=56)
        context = AssetContext(
            environment=DeploymentEnvironment.UNVERIFIED_ENVIRONMENT,
            network_exposure=NetworkExposure.UNKNOWN,
            authority=ContextAuthority.UNASSESSED_DEFAULT,
        )

        record = self.engine.evaluate(des_asset, context)

        self.assertEqual(record.risk_category, RiskCategory.CRITICAL)
        self.assertEqual(record.primary_cause, PrimaryRiskCause.CLASSICAL_DISALLOWED_PROD)
        self.assertEqual(record.default_priority, PriorityTier.P0_IMMEDIATE_ACTION)
        # Mandatory review must be preserved alongside P0
        self.assertTrue(record.mandatory_review_required)
        self.assertEqual(record.explanation.uncertainty_level, UncertaintyLevel.NEEDS_REVIEW.value)


if __name__ == "__main__":
    unittest.main()
