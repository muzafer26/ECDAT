"""
ECDAT Phase D5 Demo Truth & Product Projection Test Suite.

Verifies the 10 D5 Truth and Projection Requirements (Section 20):
1. Every important projected value has provenance.
2. Scenario context cannot masquerade as core evidence.
3. Benchmark ground truth cannot masquerade as observed evidence.
4. Future capabilities cannot appear as completed.
5. TC01 cannot leak into TC02.
6. TC02 cannot inherit TC01 gates/milestones.
7. TC06 preserves signature role semantics.
8. Missing values remain missing.
9. Frontend does not independently calculate security conclusions.
10. Demo projection does not modify product behavior.
"""

from pathlib import Path
import re
import unittest

from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import (
    DemoExecutionStatus,
    DemoRunResult,
    ProvenanceSourceType,
)
from demo.scenarios.registry import ScenarioRegistry
from product.core.workflow.engine import ECDATWorkflowEngine


class TestDemoD5TruthAndProjection(unittest.TestCase):
    """Rigorous verification of Phase D5 truth contracts and projection integrity."""

    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parent.parent.parent
        self.scenario_registry = ScenarioRegistry(workspace_root=self.workspace_root)
        self.orchestrator = DemoOrchestrator(scenario_registry=self.scenario_registry)

    # --- Test 1: Every Important Projected Value Has Provenance ---
    def test_01_projected_values_have_provenance(self) -> None:
        """Requirement 1: Every node and context item has explicit provenance classification."""
        res_tc01 = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(res_tc01.status, DemoExecutionStatus.SUCCESS)

        # 1. Provenance chain nodes have valid ProvenanceSourceType
        valid_types = {t.value for t in ProvenanceSourceType}
        for chain in res_tc01.provenance_chain:
            self.assertGreater(len(chain), 0)
            for node in chain:
                self.assertIn(node.source_type, valid_types)
                self.assertIsNotNone(node.entity_id)
                self.assertIsNotNone(node.step)

        # 2. Asset summaries declare context provenance
        for asset in res_tc01.assets:
            self.assertEqual(
                asset.context_provenance,
                ProvenanceSourceType.CONTROLLED_SCENARIO_CONTEXT.value,
            )

    # --- Test 2: Scenario Context Cannot Masquerade as Core Evidence ---
    def test_02_scenario_context_cannot_masquerade_as_evidence(self) -> None:
        """Requirement 2: Scenario context is separated from empirical scanner records."""
        res_tc01 = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = res_tc01.assets[0]

        # Context fields exist in scenario configuration
        self.assertEqual(asset.organization, "Global FinTech Enterprise (Demo Scope)")
        self.assertEqual(asset.system, "Payment Gateway & Ingestion API")

        # But scanner evidence records contain ZERO organization/system strings
        for ev in res_tc01.evidence_records:
            self.assertNotIn("Global FinTech", ev.matched_text)
            self.assertNotIn("Payment Gateway", ev.matched_text)
            self.assertNotIn("Payment Gateway", ev.code_snippet)
            self.assertEqual(ev.scanner_name, "CryptoScan")

    # --- Test 3: Benchmark Ground Truth Cannot Masquerade as Observed Evidence ---
    def test_03_benchmark_ground_truth_cannot_masquerade_as_evidence(self) -> None:
        """Requirement 3: TC01 key size is None in scanner evidence, 2048 only in ground truth."""
        res_tc01 = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = res_tc01.assets[0]

        # Core evidence did NOT extract key size
        self.assertIsNone(asset.key_size_bits, "Scanner AST did not establish key size")
        self.assertEqual(asset.classical_status, "INDETERMINATE")
        self.assertEqual(asset.priority_tier, "P_REVIEW_REQUIRED")

        # Benchmark ground truth is isolated and explicit
        self.assertIsNotNone(asset.benchmark_ground_truth)
        bgt = asset.benchmark_ground_truth
        self.assertEqual(bgt.get("ground_truth_key_size_bits"), 2048)
        self.assertEqual(bgt.get("scanner_evidence_status"), "UNEVIDENCED_IN_AST")

    # --- Test 4: Future Capabilities Cannot Appear as Completed ---
    def test_04_future_capabilities_cannot_appear_completed(self) -> None:
        """Requirement 4: No completed migration, verification, or remediation verdicts."""
        for scenario_id in ["tc01_direct_rsa", "tc02_symmetric_aes", "tc06_ed25519"]:
            res = self.orchestrator.run_scenario(scenario_id)
            self.assertIn("ADVISORY", res.migration_summary.advisory_notice)
            for asset in res.assets:
                self.assertNotIn("Quantum Safe ✓", asset.remediation_summary or "")
                self.assertNotIn("Migration Complete", asset.remediation_summary or "")
                self.assertNotIn("Verified PQC", asset.remediation_summary or "")

    # --- Test 5: TC01 Cannot Leak into TC02 ---
    def test_05_tc01_cannot_leak_into_tc02(self) -> None:
        """Requirement 5: Switching to TC02 completely isolates state from TC01."""
        res_tc01 = self.orchestrator.run_scenario("tc01_direct_rsa")
        res_tc02 = self.orchestrator.run_scenario("tc02_symmetric_aes")

        tc01_asset_ids = {a.asset_id for a in res_tc01.assets}
        tc02_asset_ids = {a.asset_id for a in res_tc02.assets}
        self.assertEqual(len(tc01_asset_ids.intersection(tc02_asset_ids)), 0)

        # Context isolation
        self.assertEqual(res_tc02.assets[0].system, "Core Ledger & Storage Service")
        self.assertNotEqual(res_tc02.assets[0].system, res_tc01.assets[0].system)

    # --- Test 6: TC02 Cannot Inherit TC01 Gates or Milestones ---
    def test_06_tc02_cannot_inherit_tc01_gates_or_milestones(self) -> None:
        """Requirement 6: TC02 has zero blocking review gates and OUT_OF_SCOPE PQC status."""
        res_tc02 = self.orchestrator.run_scenario("tc02_symmetric_aes")

        # TC02 has 0 review gates
        self.assertEqual(res_tc02.migration_summary.blocking_gates_count, 0)
        self.assertEqual(len(res_tc02.migration_summary.review_gates), 0)

        # TC02 assets have OUT_OF_SCOPE mapping
        for asset in res_tc02.assets:
            self.assertEqual(asset.pqc_mapping_status, "OUT_OF_SCOPE")
            self.assertEqual(asset.candidate_targets, [])
            self.assertEqual(asset.hybrid_candidates, [])

    # --- Test 7: TC06 Preserves Signature Role Semantics ---
    def test_07_tc06_preserves_signature_role_semantics(self) -> None:
        """Requirement 7: Ed25519 digital signature maps to ML-DSA/SLH-DSA, not KEMs."""
        res_tc06 = self.orchestrator.run_scenario("tc06_ed25519")
        asset = res_tc06.assets[0]

        self.assertEqual(asset.family, "EDWARDS")
        self.assertEqual(asset.role, "digital_signature")
        self.assertEqual(asset.pqc_mapping_status, "MAPPED")

        # Candidate targets must be signature standards (FIPS 204 / 205), not FIPS 203 ML-KEM
        targets = asset.candidate_targets
        self.assertIn("ML-DSA-65", targets)
        self.assertNotIn("ML-KEM-768", targets)
        self.assertNotIn("ML-KEM-1024", targets)

        # Hybrid schemes must be signature composites, not dual-wraps
        hybrid_types = {h["construction_type"] for h in asset.hybrid_candidates}
        self.assertTrue(
            hybrid_types.issubset({"COMPOSITE_SIGNATURE", "DUAL_CERTIFICATE"}),
            f"Unexpected hybrid construction types: {hybrid_types}",
        )

    # --- Test 8: Missing Values Remain Missing ---
    def test_08_missing_values_remain_missing(self) -> None:
        """Requirement 8: Unannotated values in scenario metadata or AST remain None/empty."""
        # Create minimal scenario with empty metadata
        from demo.scenarios.models import DemoScenario, ScenarioClassification
        tc01_path = self.workspace_root / "product" / "benchmark" / "tools" / "raw_outputs" / "cryptoscan" / "tc01_direct_rsa" / "run1_output.json"
        minimal_scenario = DemoScenario(
            scenario_id="tc_minimal_test",
            name="Minimal Scenario",
            description="Scenario with empty metadata",
            target_name="minimal",
            adapter_id="cryptoscan",
            fixture_path=tc01_path,
            classification=ScenarioClassification.CONTROLLED_DEMO,
            expected_primary_family="RSA",
            metadata={},  # No organization, system, etc.
        )
        self.scenario_registry.register(minimal_scenario)
        res = self.orchestrator.run_scenario("tc_minimal_test")
        asset = res.assets[0]

        # Must NOT fall back to "Demo Enterprise" or "Payment Gateway"
        self.assertIsNone(asset.organization)
        self.assertIsNone(asset.system)
        self.assertIsNone(asset.component)
        self.assertIsNone(asset.business_criticality)
        self.assertIsNone(asset.data_sensitivity)

    # --- Test 9: Frontend Does Not Calculate Security Conclusions ---
    def test_09_frontend_does_not_calculate_security_conclusions(self) -> None:
        """Requirement 9: Frontend JS acts purely as presentation layer without analytical logic."""
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")

        # Prohibited frontend analytical logic patterns
        forbidden = [
            r"function\s+calculate",
            r"function\s+deriveRisk",
            r"function\s+evaluateQuantum",
            r"function\s+scheduleMilestone",
            r"function\s+inferTarget",
        ]
        for pattern in forbidden:
            self.assertEqual(
                len(re.findall(pattern, app_js, re.IGNORECASE)),
                0,
                f"Prohibited frontend analytical function found matching {pattern}",
            )

    # --- Test 10: Demo Projection Does Not Modify Product Behavior ---
    def test_10_demo_projection_does_not_modify_product_behavior(self) -> None:
        """Requirement 10: Direct core run and orchestrator run yield identical analytical values."""
        core_engine = ECDATWorkflowEngine()
        tc01_path = self.workspace_root / "product" / "benchmark" / "tools" / "raw_outputs" / "cryptoscan" / "tc01_direct_rsa" / "run1_output.json"
        core_res = core_engine.run(raw_input=tc01_path, adapter_id="cryptoscan", target_name="tc01-direct-rsa")

        demo_res = self.orchestrator.run_scenario("tc01_direct_rsa")

        # Verify 1:1 fidelity
        self.assertEqual(len(demo_res.assets), len(core_res.assets))
        core_asset = core_res.assets[0]
        demo_asset = demo_res.assets[0]

        self.assertEqual(demo_asset.asset_id, core_asset.asset_id)
        self.assertEqual(demo_asset.family, core_asset.algorithm_identity.family.value)
        self.assertEqual(demo_asset.role, core_asset.role.value)
        self.assertEqual(demo_asset.key_size_bits, core_asset.parameters.key_size_bits)

        # Priority and risk match core
        core_risk = core_res.risk_records[0]
        self.assertEqual(demo_asset.priority_tier, core_risk.effective_priority.value)
        self.assertEqual(demo_asset.risk_category, core_risk.risk_category.value)


if __name__ == "__main__":
    unittest.main()
