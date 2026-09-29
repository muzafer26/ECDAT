"""
ECDAT Phase D2 Hero Scenario and Evidence / Risk / Migration Flow Test Suite.

Verifies the 8 D2 Core Technical Tests (A through H):
- Test A: TC01 produces the verified 7-stage evidence and provenance chain.
- Test B: TC01 preserves unresolved key-size uncertainty (INDETERMINATE classical status).
- Test C: TC01 exposes conditional migration mapping (ML-KEM-768) and blocking review gate.
- Test D: TC02 remains OUT_OF_SCOPE for public-key PQC replacement.
- Test E: Frontend/Backend API contract returns all enriched D2 analytical fields.
- Test F: No analytical logic (risk calculation or mapping) exists in frontend client code.
- Test G: Missing/unknown data renders honestly without fallback fabrication.
- Test H: Pipeline failure states render cleanly without stack traces or traceback disclosure.
"""

from pathlib import Path
import re
import unittest

from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus, ProvenanceSourceType
from demo.scenarios.registry import ScenarioRegistry


class TestDemoD2HeroFlow(unittest.TestCase):
    """Rigorous verification of Phase D2 requirements."""

    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parent.parent.parent
        self.scenario_registry = ScenarioRegistry(workspace_root=self.workspace_root)
        self.orchestrator = DemoOrchestrator(scenario_registry=self.scenario_registry)
        self.app = create_app(orchestrator=self.orchestrator)
        self.client = self.app.test_client()

    # --- Test A: TC01 Evidence Chain ---
    def test_a_tc01_evidence_chain(self) -> None:
        """Test A: Verifies TC01 produces the complete 7-stage verified provenance chain."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(result.status, DemoExecutionStatus.SUCCESS)
        self.assertGreater(len(result.assets), 0)
        self.assertGreater(len(result.provenance_chain), 0)

        chain = result.provenance_chain[0]
        step_names = [node.step for node in chain]
        expected_steps = ["scanner", "raw_evidence", "finding", "crypto_asset", "risk", "migration", "schedule"]
        self.assertEqual(step_names, expected_steps)

        # Verify all nodes have direct core output attribution
        for node in chain:
            self.assertEqual(node.source_type, ProvenanceSourceType.DIRECT_CORE_OUTPUT)

        # Verify raw evidence details
        raw_node = chain[1]
        self.assertIn("location", raw_node.details)
        self.assertIn("DirectRSAKeyGen.java", raw_node.details["location"])
        self.assertEqual(raw_node.details.get("line_start"), 16)
        self.assertEqual(raw_node.details.get("matched_text"), "RSA")

    # --- Test B: TC01 Preserves Unresolved Key-Size Uncertainty ---
    def test_b_tc01_preserves_unresolved_key_size_uncertainty(self) -> None:
        """Test B: Verifies TC01 preserves missing key-size uncertainty and classical INDETERMINATE status."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]

        # Key size was omitted by scanner AST visitor; ECDAT must NOT guess 2048
        self.assertIsNone(asset.key_size_bits, "ECDAT must not fabricate key size when scanner omits it")

        # Classical status must be INDETERMINATE
        self.assertEqual(asset.classical_status, "INDETERMINATE")

        # Risk categorization must reflect unresolved uncertainty
        self.assertEqual(asset.primary_risk_cause, "UNRESOLVED_UNCERTAINTY")
        self.assertEqual(asset.priority_tier, "P_REVIEW_REQUIRED")
        self.assertEqual(asset.risk_category, "NEEDS_REVIEW")

        # Quantum exposure must still be recognized as Shor-vulnerable
        self.assertEqual(asset.quantum_exposure_class, "SHOR_VULNERABLE_ASYMMETRIC")

    # --- Test C: TC01 Conditional Mapping and Review Gate ---
    def test_c_tc01_conditional_mapping_and_review_gate(self) -> None:
        """Test C: Verifies TC01 produces conditional ML-KEM-768 mapping and blocking review gate."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]

        # Mapping status must be CONDITIONAL
        self.assertEqual(asset.pqc_mapping_status, "CONDITIONAL")
        self.assertIn("ML-KEM-768", asset.candidate_targets)

        # Human review must be required
        self.assertTrue(asset.requires_human_review)
        self.assertGreater(len(asset.review_reasons), 0)

        # Migration summary must contain formal review gate and advisory status
        ms = result.migration_summary
        self.assertEqual(ms.schedule_status, "ADVISORY_PENDING_REVIEW")
        self.assertGreaterEqual(ms.blocking_gates_count, 1)

        # Verify gate attributes
        self.assertGreater(len(ms.review_gates), 0)
        gate = ms.review_gates[0]
        self.assertTrue(gate["gate_id"].startswith("GATE-REVIEW-"))
        self.assertEqual(gate["asset_id"], asset.asset_id)
        self.assertIn("Shor", gate["reason"])
        self.assertIn("Verified cryptographic parameters", gate["missing_information"])

    # --- Test D: TC02 Remains Out-of-Scope for Public-Key PQC ---
    def test_d_tc02_out_of_scope_symmetric(self) -> None:
        """Test D: Verifies TC02 (AES) is NOT mapped to public-key PQC and evaluates to OUT_OF_SCOPE."""
        result = self.orchestrator.run_scenario("tc02_symmetric_aes")
        self.assertEqual(result.status, DemoExecutionStatus.SUCCESS)

        # Should find symmetric AES asset
        aes_assets = [a for a in result.assets if a.family == "AES"]
        self.assertGreater(len(aes_assets), 0)

        aes_asset = aes_assets[0]
        self.assertEqual(aes_asset.pqc_mapping_status, "OUT_OF_SCOPE")
        self.assertEqual(aes_asset.candidate_targets, [])

        # Migration summary out_of_scope count
        self.assertGreaterEqual(result.migration_summary.out_of_scope_count, 1)

    # --- Test E: Backend API D2 Contract ---
    def test_e_backend_api_d2_contract(self) -> None:
        """Test E: Verifies the Flask API returns all enriched D2 analytical fields."""
        resp = self.client.post("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp.status_code, 200)

        data = resp.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertIn("assets", data)
        self.assertIn("migration_summary", data)
        self.assertIn("provenance_chain", data)

        asset = data["assets"][0]
        # Check required D2 analytical fields
        required_fields = [
            "observed_facts",
            "triggered_rules",
            "assumptions",
            "missing_facts",
            "target_details",
            "mapping_rationale",
            "standards_references",
            "agility_factors",
            "review_reasons",
            "classical_status",
            "quantum_exposure_class",
        ]
        for field in required_fields:
            self.assertIn(field, asset, f"Missing required D2 field: {field}")

        # Check migration summary milestones and review gates
        self.assertIn("milestones", data["migration_summary"])
        self.assertIn("review_gates", data["migration_summary"])
        self.assertIn("blocked_assets", data["migration_summary"])

    # --- Test F: No Analytical Logic in Frontend Code ---
    def test_f_no_analytical_logic_in_frontend(self) -> None:
        """Test F: Verifies no risk calculation, priority scoring, or PQC mapping formulas exist in frontend code."""
        frontend_js = self.workspace_root / "demo" / "frontend" / "app.js"
        self.assertTrue(frontend_js.exists())

        js_content = frontend_js.read_text(encoding="utf-8")

        # Prohibit risk formula patterns (e.g. score = ... * ..., priority = if score > ...)
        forbidden_patterns = [
            r"risk_score\s*=\s*[\d\w\+\-\*\/]+",
            r"calculateRisk",
            r"derivePriority",
            r"mapPqcTarget",
            r"computeScore",
        ]
        for pattern in forbidden_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            self.assertEqual(len(matches), 0, f"Found forbidden analytical logic in frontend: {matches}")

    # --- Test G: Missing / Unknown Data Renders Honestly ---
    def test_g_missing_unknown_data_honesty(self) -> None:
        """Test G: Verifies missing parameters remain None/null and are not defaulted or guessed."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        asset = result.assets[0]

        # Key size bits must remain None
        self.assertIsNone(asset.key_size_bits)
        # Curve name must remain None (not an EC curve)
        self.assertIsNone(asset.curve_name)
        # Agility level was unannotated in raw evidence, so must not be fabricated
        self.assertIsNone(asset.agility_level)

    # --- Test H: Failure State Renders Without Stack Traces ---
    def test_h_failure_state_renders_without_stack_traces(self) -> None:
        """Test H: Verifies invalid scenario requests fail safely with JSON error and no stack traces."""
        resp = self.client.post("/api/scenarios/tc99_nonexistent/run")
        self.assertEqual(resp.status_code, 404)

        data = resp.get_json()
        self.assertEqual(data["status"], "UNAVAILABLE")
        self.assertIn("error_message", data)
        self.assertNotIn("Traceback (most recent call last)", data["error_message"])
        self.assertNotIn("Traceback", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
