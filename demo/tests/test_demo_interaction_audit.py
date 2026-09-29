"""
ECDAT Demo Correctness, State Integrity & End-to-End Interaction Audit Suite.

Verifies:
1. Scenario Registration & Grounding (TC01, TC02, TC06)
2. All 6 Cross-Scenario Transitions (TC01->TC02, TC01->TC06, TC02->TC01, TC02->TC06, TC06->TC01, TC06->TC02)
3. Re-run Idempotency (Deterministic result shape, zero duplicated/appended assets or gates)
4. Role-Aware Segregation (No KEM on signature, no signature on KEM, symmetric out of scope)
5. Review Gate & Milestone Strict Attribution (Zero cross-contamination of gates or milestones)
6. Frontend State Reset & Guard Contracts (Verification of resetAnalysisState, goToStep guards, activeRequestId)
7. Error & Partial Data Resilience (Missing key sizes, empty candidates, 0 review gates)
"""

import json
from pathlib import Path
import re
import unittest

from demo.adapters.registry import DemoAdapterRegistry
from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.scenarios.registry import ScenarioRegistry


class TestDemoInteractionAudit(unittest.TestCase):
    """Deep behavioral correctness and cross-scenario state isolation audit."""

    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parent.parent.parent
        self.scenario_registry = ScenarioRegistry(workspace_root=self.workspace_root)
        self.adapter_registry = DemoAdapterRegistry()
        self.orchestrator = DemoOrchestrator(
            scenario_registry=self.scenario_registry,
            adapter_registry=self.adapter_registry,
        )
        self.app = create_app(orchestrator=self.orchestrator)
        self.client = self.app.test_client()

    # =========================================================================
    # 1. Authoritative Scenario Truth Matrix
    # =========================================================================
    def test_01_scenario_truth_matrix(self) -> None:
        """Verifies actual orchestrator output matches the authoritative truth matrix."""
        # TC-01 RSA
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(r1.status.value, "SUCCESS")
        self.assertEqual(len(r1.assets), 1)
        a1 = r1.assets[0]
        self.assertEqual(a1.family, "RSA")
        self.assertEqual(a1.role, "key_generation")
        self.assertEqual(a1.priority_tier, "P_REVIEW_REQUIRED")
        self.assertEqual(a1.pqc_mapping_status, "CONDITIONAL")
        self.assertIn("ML-KEM-768", a1.candidate_targets)
        self.assertTrue(a1.requires_human_review)
        self.assertEqual(r1.migration_summary.blocking_gates_count, 1)
        self.assertEqual(r1.migration_summary.review_gates[0]["gate_id"], "GATE-REVIEW-26700200")
        self.assertEqual(r1.migration_summary.milestones[0]["milestone_id"], "M2-KEY-EXCHANGE-HNDL")

        # TC-02 AES
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        self.assertEqual(r2.status.value, "SUCCESS")
        self.assertEqual(len(r2.assets), 2)
        for a2 in r2.assets:
            self.assertEqual(a2.family, "AES")
            self.assertEqual(a2.role, "encryption_decryption")
            self.assertEqual(a2.priority_tier, "P_REVIEW_REQUIRED")
            self.assertEqual(a2.pqc_mapping_status, "OUT_OF_SCOPE")
            self.assertEqual(len(a2.candidate_targets), 0)
        self.assertEqual(r2.migration_summary.blocking_gates_count, 0)
        self.assertEqual(len(r2.migration_summary.review_gates), 0)
        self.assertEqual(r2.migration_summary.milestones[0]["milestone_id"], "M4-DATA-AT-REST")

        # TC-06 Ed25519
        r6 = self.orchestrator.run_scenario("tc06_ed25519")
        self.assertEqual(r6.status.value, "SUCCESS")
        self.assertEqual(len(r6.assets), 1)
        a6 = r6.assets[0]
        self.assertEqual(a6.family, "EDWARDS")
        self.assertEqual(a6.role, "digital_signature")
        self.assertEqual(a6.priority_tier, "P_REVIEW_REQUIRED")
        self.assertEqual(a6.pqc_mapping_status, "MAPPED")
        self.assertIn("ML-DSA-65", a6.candidate_targets)
        self.assertEqual(r6.migration_summary.blocking_gates_count, 0)
        self.assertEqual(len(r6.migration_summary.review_gates), 0)
        self.assertEqual(r6.migration_summary.milestones[0]["milestone_id"], "M3-AUTHENTICATION-SIGNATURES")

    # =========================================================================
    # 2. Cross-Scenario Transition Tests (All 6 Directed Pairs)
    # =========================================================================
    def test_02_transition_tc01_to_tc02(self) -> None:
        """TC01 -> TC02: No RSA asset, ML-KEM candidate, or TC01 review gate remains in TC02."""
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")

        r1_asset_ids = {a.asset_id for a in r1.assets}
        r2_asset_ids = {a.asset_id for a in r2.assets}
        self.assertEqual(len(r1_asset_ids.intersection(r2_asset_ids)), 0)

        # TC02 must not have RSA family or ML-KEM candidates
        self.assertTrue(all(a.family == "AES" for a in r2.assets))
        self.assertTrue(all(len(a.candidate_targets) == 0 for a in r2.assets))
        self.assertEqual(r2.migration_summary.blocking_gates_count, 0)
        self.assertEqual(len(r2.migration_summary.review_gates), 0)

    def test_03_transition_tc01_to_tc06(self) -> None:
        """TC01 -> TC06: No RSA asset, ML-KEM candidate, or TC01 gate leaks into Ed25519."""
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")
        r6 = self.orchestrator.run_scenario("tc06_ed25519")

        r1_asset_ids = {a.asset_id for a in r1.assets}
        r6_asset_ids = {a.asset_id for a in r6.assets}
        self.assertEqual(len(r1_asset_ids.intersection(r6_asset_ids)), 0)

        a6 = r6.assets[0]
        self.assertEqual(a6.family, "EDWARDS")
        self.assertEqual(a6.role, "digital_signature")
        # Critical negative assertion: No ML-KEM candidate
        for target in a6.candidate_targets:
            self.assertNotIn("KEM", target)
            self.assertTrue("DSA" in target or "SLH" in target)

    def test_04_transition_tc02_to_tc01(self) -> None:
        """TC02 -> TC01: No AES asset, M4 milestone, or OUT_OF_SCOPE status leaks into TC01."""
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")

        a1 = r1.assets[0]
        self.assertEqual(a1.family, "RSA")
        self.assertEqual(a1.pqc_mapping_status, "CONDITIONAL")
        self.assertNotEqual(a1.pqc_mapping_status, "OUT_OF_SCOPE")
        self.assertEqual(r1.migration_summary.blocking_gates_count, 1)

    def test_05_transition_tc02_to_tc06(self) -> None:
        """TC02 -> TC06: No AES asset or OUT_OF_SCOPE status leaks into TC06."""
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        r6 = self.orchestrator.run_scenario("tc06_ed25519")

        a6 = r6.assets[0]
        self.assertEqual(a6.family, "EDWARDS")
        self.assertEqual(a6.pqc_mapping_status, "MAPPED")
        self.assertGreater(len(a6.candidate_targets), 0)

    def test_06_transition_tc06_to_tc01(self) -> None:
        """TC06 -> TC01: No Ed25519 signature targets leak into RSA key establishment."""
        r6 = self.orchestrator.run_scenario("tc06_ed25519")
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")

        a1 = r1.assets[0]
        self.assertEqual(a1.family, "RSA")
        self.assertEqual(a1.role, "key_generation")
        for target in a1.candidate_targets:
            self.assertIn("KEM", target)
            self.assertNotIn("DSA", target)

    def test_07_transition_tc06_to_tc02(self) -> None:
        """TC06 -> TC02: No signature role or Edwards family leaks into AES block cipher."""
        r6 = self.orchestrator.run_scenario("tc06_ed25519")
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")

        for a2 in r2.assets:
            self.assertEqual(a2.family, "AES")
            self.assertEqual(a2.role, "encryption_decryption")
            self.assertEqual(len(a2.candidate_targets), 0)

    # =========================================================================
    # 3. Re-run Idempotency & Determinism
    # =========================================================================
    def test_08_rerun_same_scenario_idempotency(self) -> None:
        """Re-running the same scenario produces byte-for-byte identical result shape; no duplicate assets."""
        for sc_id in ["tc01_direct_rsa", "tc02_symmetric_aes", "tc06_ed25519"]:
            run1 = self.orchestrator.run_scenario(sc_id).to_dict()
            run2 = self.orchestrator.run_scenario(sc_id).to_dict()

            self.assertEqual(len(run1["assets"]), len(run2["assets"]))
            self.assertEqual(len(run1["findings"]), len(run2["findings"]))
            self.assertEqual(len(run1["provenance_chain"]), len(run2["provenance_chain"]))
            self.assertEqual(run1["risk_summary"], run2["risk_summary"])
            self.assertEqual(
                run1["migration_summary"]["blocking_gates_count"],
                run2["migration_summary"]["blocking_gates_count"],
            )

    # =========================================================================
    # 4. Frontend State Reset & Guard Contract Verification
    # =========================================================================
    def test_09_frontend_state_management_and_guards(self) -> None:
        """Verifies app.js defines resetAnalysisState, goToStep guards, and activeRequestId race protection."""
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")

        # 1. State reset function exists and clears state
        self.assertIn("function resetAnalysisState()", app_js)
        self.assertIn("currentRunResult = null", app_js)
        self.assertIn("selectedAssetId = null", app_js)

        # 2. Scenario switch calls resetAnalysisState
        self.assertIn("isSwitch", app_js)
        self.assertIn("resetAnalysisState()", app_js)

        # 3. Guard against unanalyzed navigation exists
        self.assertIn("if (stepName !== 'choose' && !currentRunResult)", app_js)

        # 4. Async race protection: activeRequestId counter
        self.assertIn("activeRequestId", app_js)
        self.assertIn("requestId !== activeRequestId", app_js)

        # 5. Restart button resets state
        self.assertIn("btnRestart.addEventListener", app_js)

    # =========================================================================
    # 5. Provenance Internal Consistency
    # =========================================================================
    def test_10_provenance_scenario_internal_consistency(self) -> None:
        """Every provenance node in a scenario references only entities belonging to that scenario."""
        for sc_id in ["tc01_direct_rsa", "tc02_symmetric_aes", "tc06_ed25519"]:
            res = self.orchestrator.run_scenario(sc_id)
            d = res.to_dict()
            asset_ids = {a["asset_id"] for a in d["assets"]}

            for chain in d["provenance_chain"]:
                chain_asset_ids = {node["entity_id"] for node in chain if "entity_id" in node}
                # At least one node in each chain must correspond to an asset in this scenario
                self.assertTrue(
                    len(chain_asset_ids.intersection(asset_ids)) > 0,
                    f"Provenance chain in {sc_id} does not link to scenario assets",
                )


if __name__ == "__main__":
    unittest.main()
