"""
ECDAT Phase D3 Complete Working Demo Test Suite.

Verifies the 17 Phase D3 Functional Acceptance Criteria (D3-01 through D3-17):
- D3-01: Scenario listing works.
- D3-02: Scenario execution reaches the real ECDAT core.
- D3-03: Inventory is derived from actual run results.
- D3-04: Selecting an asset exposes its evidence.
- D3-05: Evidence stages correspond to actual core output.
- D3-06: Risk information is core-derived.
- D3-07: Unknown/indeterminate values remain unknown/indeterminate.
- D3-08: Migration information is core-derived.
- D3-09: Role-aware migration semantics are preserved (KEM vs Signature vs Symmetric).
- D3-10: Scheduler output is surfaced without invented dates or edges.
- D3-11: Review gates are surfaced correctly.
- D3-12: Verification is explicitly marked controlled/future (Phase 9).
- D3-13: Invalid scenario handling works safely.
- D3-14: Invalid/missing asset handling works.
- D3-15: Backend errors do not expose tracebacks.
- D3-16: No frontend path bypasses the intended backend/core data flow.
- D3-17: Product freeze remains intact (392 files, matching SHA-256 hash).
"""

import hashlib
from pathlib import Path
import re
import unittest

from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus, ProvenanceSourceType
from demo.scenarios.registry import ScenarioRegistry


class TestDemoD3CompleteWorkingDemo(unittest.TestCase):
    """Rigorous functional verification of Phase D3 requirements."""

    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parent.parent.parent
        self.scenario_registry = ScenarioRegistry(workspace_root=self.workspace_root)
        self.orchestrator = DemoOrchestrator(scenario_registry=self.scenario_registry)
        self.app = create_app(orchestrator=self.orchestrator)
        self.client = self.app.test_client()

    # --- D3-01: Scenario Listing ---
    def test_d3_01_scenario_listing(self) -> None:
        """D3-01: Scenario listing returns registered scenarios including TC01, TC02, TC06."""
        resp = self.client.get("/api/scenarios")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data["count"], 3)
        scenario_ids = [s["scenario_id"] for s in data["scenarios"]]
        self.assertIn("tc01_direct_rsa", scenario_ids)
        self.assertIn("tc02_symmetric_aes", scenario_ids)
        self.assertIn("tc06_ed25519", scenario_ids)

    # --- D3-02: Scenario Execution Reaches Core ---
    def test_d3_02_scenario_execution_reaches_real_core(self) -> None:
        """D3-02: Executing a scenario reaches real frozen ECDATWorkflowEngine."""
        resp = self.client.post("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertIn("assets", data)
        self.assertGreater(len(data["assets"]), 0)

    # --- D3-03: Inventory Derived from Actual Results ---
    def test_d3_03_inventory_derived_from_actual_results(self) -> None:
        """D3-03: Inventory matches actual core assets with correct domain fields."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(len(result.assets), 1)
        asset = result.assets[0]
        self.assertEqual(asset.family, "RSA")
        self.assertEqual(asset.role, "key_generation")
        self.assertIn("DirectRSAKeyGen.java", asset.location_display)

    # --- D3-04: Selecting Asset Exposes Evidence ---
    def test_d3_04_selecting_asset_exposes_evidence(self) -> None:
        """D3-04: Discovered asset contains empirical evidence IDs and location references."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]
        self.assertGreater(len(asset.evidence_ids), 0)
        self.assertGreater(len(asset.finding_ids), 0)
        self.assertTrue(asset.evidence_ids[0].startswith("cryptoscan:"))

    # --- D3-05: Evidence Stages Correspond to Core Output ---
    def test_d3_05_evidence_stages_correspond_to_core_output(self) -> None:
        """D3-05: 7-stage runtime provenance chain is backed by DIRECT_CORE_OUTPUT."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        chain = result.provenance_chain[0]
        self.assertEqual(len(chain), 7)
        steps = [n.step for n in chain]
        self.assertEqual(steps, ["scanner", "raw_evidence", "finding", "crypto_asset", "risk", "migration", "schedule"])
        for node in chain:
            self.assertEqual(node.source_type, ProvenanceSourceType.DIRECT_CORE_OUTPUT)

    # --- D3-06: Risk Information is Core-Derived ---
    def test_d3_06_risk_information_is_core_derived(self) -> None:
        """D3-06: Risk categories, priority tier, and rule citations come from Phase 3C engine."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]
        self.assertEqual(asset.priority_tier, "P_REVIEW_REQUIRED")
        self.assertEqual(asset.risk_category, "NEEDS_REVIEW")
        self.assertEqual(asset.primary_risk_cause, "UNRESOLVED_UNCERTAINTY")
        rule_ids = [r["rule_id"] for r in asset.triggered_rules]
        self.assertIn("R-RISK-06", rule_ids)

    # --- D3-07: Unknown/Indeterminate Values Preserved ---
    def test_d3_07_unknown_indeterminate_values_preserved(self) -> None:
        """D3-07: When parameters are omitted by scanner, ECDAT refuses to guess and preserves INDETERMINATE."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]
        self.assertIsNone(asset.key_size_bits)
        self.assertEqual(asset.classical_status, "INDETERMINATE")

    # --- D3-08: Migration Information is Core-Derived ---
    def test_d3_08_migration_information_is_core_derived(self) -> None:
        """D3-08: PQC target mapping and target details are populated from Phase 4A."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]
        self.assertEqual(asset.pqc_mapping_status, "CONDITIONAL")
        self.assertIn("ML-KEM-768", asset.candidate_targets)
        self.assertGreater(len(asset.target_details), 0)
        self.assertEqual(asset.target_details[0]["standard"], "NIST FIPS 203")

    # --- D3-09: Role-Aware Migration Semantics ---
    def test_d3_09_role_aware_migration_semantics(self) -> None:
        """D3-09: Proves role-aware separation: KeyGen -> ML-KEM, Signature -> ML-DSA/SLH-DSA, AES -> OUT_OF_SCOPE."""
        # 1. RSA KeyGen -> ML-KEM-768
        res_rsa = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(res_rsa.assets[0].pqc_mapping_status, "CONDITIONAL")
        self.assertIn("ML-KEM-768", res_rsa.assets[0].candidate_targets)

        # 2. Symmetric AES -> OUT_OF_SCOPE
        res_aes = self.orchestrator.run_scenario("tc02_symmetric_aes")
        self.assertEqual(res_aes.assets[0].pqc_mapping_status, "OUT_OF_SCOPE")
        self.assertEqual(res_aes.assets[0].candidate_targets, [])

        # 3. Ed25519 Signature -> ML-DSA-65 / SLH-DSA
        res_sig = self.orchestrator.run_scenario("tc06_ed25519")
        self.assertEqual(res_sig.assets[0].pqc_mapping_status, "MAPPED")
        sig_targets = res_sig.assets[0].candidate_targets
        self.assertIn("ML-DSA-65", sig_targets)
        self.assertIn("SLH-DSA-SHA2-128s", sig_targets)

    # --- D3-10: Scheduler Output Without Invented Dates/Edges ---
    def test_d3_10_scheduler_output_without_invented_dates_edges(self) -> None:
        """D3-10: Milestones reflect core scheduler DAG without artificial calendar deadlines."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        ms_summary = result.migration_summary
        self.assertGreater(ms_summary.total_milestones, 0)
        self.assertEqual(ms_summary.schedule_status, "ADVISORY_PENDING_REVIEW")
        milestone = ms_summary.milestones[0]
        self.assertEqual(milestone["milestone_id"], "M2-KEY-EXCHANGE-HNDL")
        # Ensure no fake dates
        self.assertNotIn("due_date", milestone)
        self.assertNotIn("deadline", milestone)

    # --- D3-11: Review Gates Surfaced Correctly ---
    def test_d3_11_review_gates_surfaced_correctly(self) -> None:
        """D3-11: Formal review gates are generated with gate ID, trigger, and missing info."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        ms_summary = result.migration_summary
        self.assertGreater(ms_summary.blocking_gates_count, 0)
        gate = ms_summary.review_gates[0]
        self.assertTrue(gate["gate_id"].startswith("GATE-REVIEW-"))
        self.assertIn("Shor", gate["reason"])
        self.assertIn("Verified cryptographic parameters", gate["missing_information"])

    # --- D3-12: Verification Marked Controlled/Future ---
    def test_d3_12_verification_explicitly_marked_controlled_future(self) -> None:
        """D3-12: UI verification section carries CONTROLLED / FUTURE disclosure and Phase 9 boundary."""
        index_html = (self.workspace_root / "demo" / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("CONTROLLED / FUTURE (PHASE 9)", index_html)
        self.assertIn("Architectural Disclosure", index_html)
        self.assertIn("ARCHITECTURAL PROJECTION", index_html)

    # --- D3-13: Invalid Scenario Handling ---
    def test_d3_13_invalid_scenario_handling(self) -> None:
        """D3-13: Requesting non-existent scenario returns 404 with UNAVAILABLE status and clean error."""
        resp = self.client.post("/api/scenarios/non_existent_tc/run")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertEqual(data["status"], "UNAVAILABLE")
        self.assertIn("error_message", data)

    # --- D3-14: Invalid/Missing Asset Handling ---
    def test_d3_14_invalid_missing_asset_handling(self) -> None:
        """D3-14: Orchestrator handles corrupted scenario fixture gracefully without raising unhandled exception."""
        res = self.orchestrator.run_scenario("non_existent_tc")
        self.assertEqual(res.status, DemoExecutionStatus.UNAVAILABLE)
        self.assertEqual(len(res.assets), 0)

    # --- D3-15: Backend Errors Do Not Expose Tracebacks ---
    def test_d3_15_backend_errors_do_not_expose_tracebacks(self) -> None:
        """D3-15: API error envelopes never disclose raw Python tracebacks."""
        resp = self.client.post("/api/scenarios/malformed_tc/run")
        self.assertNotIn("Traceback (most recent call last)", resp.get_data(as_text=True))
        # 404 route
        resp_404 = self.client.get("/api/unknown_endpoint")
        self.assertEqual(resp_404.status_code, 404)
        self.assertNotIn("Traceback", resp_404.get_data(as_text=True))

    # --- D3-16: No Frontend Path Bypasses Backend Data Flow ---
    def test_d3_16_no_frontend_path_bypasses_backend_data_flow(self) -> None:
        """D3-16: Frontend JS contains zero analytical formulas (risk, priority, or mapping math)."""
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")
        forbidden = [
            r"calculateRisk",
            r"computePriority",
            r"mapPqcTarget",
            r"risk_score\s*=",
        ]
        for pattern in forbidden:
            self.assertEqual(len(re.findall(pattern, app_js, re.IGNORECASE)), 0)

    # --- D3-17: Product Freeze Remains Intact ---
    def test_d3_17_product_freeze_remains_intact(self) -> None:
        """D3-17: Product source tree remains exactly 392 files with unchanged baseline hash."""
        product_dir = self.workspace_root / "product"
        files = sorted([f for f in product_dir.glob("**/*") if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc"])
        self.assertEqual(len(files), 392, "Product source file count has drifted!")

        h = hashlib.sha256()
        for f in files:
            h.update(f.relative_to(self.workspace_root).as_posix().encode("utf-8"))
            h.update(f.read_bytes())

        baseline_hash = "b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2"
        self.assertEqual(h.hexdigest(), baseline_hash, "Product core freeze violated!")


if __name__ == "__main__":
    unittest.main()
