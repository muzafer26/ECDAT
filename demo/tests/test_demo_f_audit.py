"""
ECDAT Demo Final Functional Traceability Audit Test Suite (F1-F6).

Validates:
- F1: Enterprise Cryptographic Inventory Representation (Organization -> System -> Component -> Asset)
- F2: Context Completeness (Criticality, sensitivity, data lifetime, network exposure)
- F3: Quantum-Risk Explanation (Quantum exposure, classical strength, uncertainty, citations)
- F4: Migration Intelligence & Real Phase 4B Hybrid Candidates Propagation
- F5: End-to-End Golden Path State Isolation (TC01 -> TC02 -> TC06 -> TC01)
- F6: SIH Problem Statement Traceability
"""

import unittest
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus


class TestDemoFunctionalTraceabilityAudit(unittest.TestCase):
    """Rigorous audit test suite for F1-F6 objectives."""

    def setUp(self) -> None:
        self.orchestrator = DemoOrchestrator()

    def test_f1_enterprise_inventory_representation(self) -> None:
        """F1: Cryptographic assets are organized under Enterprise System and Component hierarchy."""
        res = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(res.status, DemoExecutionStatus.SUCCESS)
        self.assertGreater(len(res.assets), 0)

        asset = res.assets[0]
        self.assertIsNotNone(asset.organization)
        self.assertIn("FinTech", asset.organization)
        self.assertIsNotNone(asset.system)
        self.assertEqual(asset.system, "Payment Gateway & Ingestion API")
        self.assertIsNotNone(asset.component)
        self.assertEqual(asset.component, "Session Key Negotiation Service")

    def test_f2_context_completeness(self) -> None:
        """F2: Operational context (criticality, sensitivity, lifetime, exposure) is fully preserved."""
        res = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = res.assets[0]

        self.assertEqual(asset.business_criticality, "Tier 1 Mission-Critical")
        self.assertIn("Session Keys", asset.data_sensitivity)
        self.assertIn("5 to 10 Years", asset.data_lifetime)
        self.assertEqual(asset.network_exposure, "Internet-Facing Public Endpoint")
        self.assertEqual(asset.environment, "production")

        # Missing key size must remain indeterminate and not guessed
        self.assertIsNone(asset.key_size_bits)
        self.assertEqual(asset.classical_status, "INDETERMINATE")
        self.assertEqual(asset.priority_tier, "P_REVIEW_REQUIRED")

    def test_f3_quantum_risk_explanation(self) -> None:
        """F3: Quantum risk explains Shor vulnerability and uncertainty without manufactured scores."""
        res_rsa = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset_rsa = res_rsa.assets[0]
        self.assertEqual(asset_rsa.quantum_exposure_class, "SHOR_VULNERABLE_ASYMMETRIC")
        self.assertIn("R-RISK-06", [r["rule_id"] for r in asset_rsa.triggered_rules])

        # Symmetric contrast
        res_aes = self.orchestrator.run_scenario("tc02_symmetric_aes")
        asset_aes = res_aes.assets[0]
        self.assertIn("GROVER", asset_aes.quantum_exposure_class)

    def test_f4_migration_intelligence_and_hybrid_propagation(self) -> None:
        """F4: Role-aware PQC targets and real core Phase 4B hybrid candidates are propagated."""
        # 1. TC01: RSA key_generation -> ML-KEM-768 + real core hybrid candidate
        res_rsa = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset_rsa = res_rsa.assets[0]
        self.assertIn("ML-KEM-768", asset_rsa.candidate_targets)
        self.assertGreater(len(asset_rsa.hybrid_candidates), 0)
        hybrid_rsa = asset_rsa.hybrid_candidates[0]
        self.assertEqual(hybrid_rsa["scheme_name"], "RSA_OAEP_MLKEM768_DUAL_WRAP")
        self.assertEqual(hybrid_rsa["standards_status"], "PROFILE_DEPLOYMENT_PATTERN")
        self.assertIn("NIST SP 800-227", hybrid_rsa["security_property"])

        # 2. TC02: AES encryption -> OUT_OF_SCOPE, zero hybrid candidates
        res_aes = self.orchestrator.run_scenario("tc02_symmetric_aes")
        asset_aes = res_aes.assets[0]
        self.assertEqual(asset_aes.pqc_mapping_status, "OUT_OF_SCOPE")
        self.assertEqual(len(asset_aes.hybrid_candidates), 0)

        # 3. TC06: Ed25519 digital_signature -> ML-DSA-65 / SLH-DSA + signature hybrid
        res_ed = self.orchestrator.run_scenario("tc06_ed25519")
        asset_ed = res_ed.assets[0]
        self.assertTrue(any("ML-DSA" in t or "SLH-DSA" in t for t in asset_ed.candidate_targets))
        self.assertFalse(any("ML-KEM" in t for t in asset_ed.candidate_targets))
        self.assertGreater(len(asset_ed.hybrid_candidates), 0)
        self.assertEqual(asset_ed.hybrid_candidates[0]["scheme_name"], "MLDSA65-ECDSA-P256-SHA512")

    def test_f5_golden_path_state_isolation(self) -> None:
        """F5: Multi-scenario cycling maintains strict state isolation without cross-contamination."""
        res_tc01 = self.orchestrator.run_scenario("tc01_direct_rsa")
        res_tc02 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        res_tc06 = self.orchestrator.run_scenario("tc06_ed25519")
        res_tc01_re = self.orchestrator.run_scenario("tc01_direct_rsa")

        self.assertEqual(res_tc01.assets[0].family, "RSA")
        self.assertEqual(res_tc02.assets[0].family, "AES")
        self.assertEqual(res_tc06.assets[0].family, "EDWARDS")
        self.assertEqual(res_tc01_re.assets[0].family, "RSA")

        # Zero AES leakage in RSA
        self.assertEqual(res_tc01_re.assets[0].candidate_targets[0], "ML-KEM-768")
        self.assertEqual(len(res_tc02.assets[0].hybrid_candidates), 0)

    def test_f6_problem_statement_traceability(self) -> None:
        """F6: Core pipeline artifacts (CBOM, findings, risk, schedule, report) are verifiable."""
        res = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertGreater(len(res.evidence_records), 0)
        self.assertGreater(len(res.findings), 0)
        self.assertGreater(len(res.assets), 0)
        self.assertIn("components_count", res.cbom_summary)
        self.assertGreater(res.risk_summary.total_assets_evaluated, 0)
        self.assertGreater(res.migration_summary.total_milestones, 0)
        self.assertGreater(res.migration_summary.blocking_gates_count, 0)


if __name__ == "__main__":
    unittest.main()
