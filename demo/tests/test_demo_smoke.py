"""
ECDAT Demo Automated Smoke & Integration Test Suite.

Verifies the current Demo API and Frontend/Backend contract:
- Backend Endpoints:
    GET  /api/health
    GET  /api/scenarios
    GET  /api/adapters
    POST /api/scenarios/<scenario_id>/run
- Rejection of stale contracts:
    POST /api/run-scenario/... -> 404
    GET  /api/scenarios/<id>/run -> 405
- Scenario Grounding & Truthful Execution:
    TC-01: Direct RSA Keypair (tc01_direct_rsa)
    TC-02: Symmetric AES Cipher (tc02_symmetric_aes)
    TC-06: Ed25519 Digital Signature (tc06_ed25519)
- Frontend-Backend Contract Alignment:
    Scenario IDs, endpoint URLs, response keys consumed by app.js.
- Guided Journey Integrity:
    8 sequential steps (choose -> discover -> evidence -> risk -> migration -> plan -> review -> verify).
"""

import json
from pathlib import Path
import re
import unittest

from demo.adapters.registry import DemoAdapterRegistry
from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.scenarios.registry import ScenarioRegistry


class TestDemoSmokeContract(unittest.TestCase):
    """Authoritative smoke and integration test for ECDAT Demo contract."""

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

    # -------------------------------------------------------------------------
    # 1. API Health Contract
    # -------------------------------------------------------------------------
    def test_01_api_health_contract(self) -> None:
        """GET /api/health returns 200 with service, classifications, and healthy status."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "ECDAT Demo API")
        self.assertIn("classifications", data)
        self.assertIn("LIVE", data["classifications"])
        self.assertIn("CONTROLLED_DEMO", data["classifications"])
        self.assertIn("ARCHITECTURAL", data["classifications"])

    # -------------------------------------------------------------------------
    # 2. Scenario Listing Contract
    # -------------------------------------------------------------------------
    def test_02_scenario_listing_contract(self) -> None:
        """GET /api/scenarios returns exactly the controlled scenarios grounded in benchmarks."""
        resp = self.client.get("/api/scenarios")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("scenarios", data)
        self.assertIn("count", data)

        scenario_ids = [s["scenario_id"] for s in data["scenarios"]]
        self.assertEqual(data["count"], len(scenario_ids))
        self.assertIn("tc01_direct_rsa", scenario_ids)
        self.assertIn("tc02_symmetric_aes", scenario_ids)
        self.assertIn("tc06_ed25519", scenario_ids)
        # Ensure stale scenario ID does not exist
        self.assertNotIn("ecommerce_payment_gateway", scenario_ids)

    # -------------------------------------------------------------------------
    # 3. Discovery Adapters Contract
    # -------------------------------------------------------------------------
    def test_03_scenario_adapters_contract(self) -> None:
        """GET /api/adapters lists discovery adapters and their capability classification."""
        resp = self.client.get("/api/adapters")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("adapters", data)
        adapter_ids = [a["adapter_id"] for a in data["adapters"]]
        self.assertIn("cryptoscan", adapter_ids)

    # -------------------------------------------------------------------------
    # 4. HTTP Method Safety & Stale Contract Rejection
    # -------------------------------------------------------------------------
    def test_04_http_method_safety_and_stale_rejection(self) -> None:
        """Rejects non-POST on run endpoints and rejects stale URL paths."""
        # GET on run endpoint is method not allowed (405)
        resp_get = self.client.get("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp_get.status_code, 405)

        # Stale endpoint /api/run-scenario/... is not a valid endpoint (returns 404 or 405 Method Not Allowed)
        resp_stale = self.client.post("/api/run-scenario/ecommerce_payment_gateway")
        self.assertIn(resp_stale.status_code, (404, 405))
        self.assertNotEqual(resp_stale.status_code, 200)

        resp_stale_get = self.client.get("/api/run-scenario/ecommerce_payment_gateway")
        self.assertEqual(resp_stale_get.status_code, 404)

        # Non-existent scenario returns 404
        resp_missing = self.client.post("/api/scenarios/non_existent_id/run")
        self.assertEqual(resp_missing.status_code, 404)

    # -------------------------------------------------------------------------
    # 5. Controlled Scenario Execution: TC-01 RSA
    # -------------------------------------------------------------------------
    def test_05_scenario_tc01_rsa_execution(self) -> None:
        """POST /api/scenarios/tc01_direct_rsa/run executes real core and returns expected structure."""
        resp = self.client.post("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["scenario_id"], "tc01_direct_rsa")

        # Result collections exist
        self.assertIn("assets", data)
        self.assertIn("findings", data)
        self.assertIn("provenance_chain", data)
        self.assertIn("risk_summary", data)
        self.assertIn("migration_summary", data)

        # Assets: exactly 1 RSA asset
        self.assertEqual(len(data["assets"]), 1)
        asset = data["assets"][0]
        self.assertEqual(asset["family"], "RSA")
        self.assertEqual(asset["role"], "key_generation")
        self.assertEqual(asset["priority_tier"], "P_REVIEW_REQUIRED")
        self.assertEqual(asset["pqc_mapping_status"], "CONDITIONAL")
        self.assertIn("ML-KEM-768", asset["candidate_targets"])
        self.assertTrue(asset["requires_human_review"])

        # Risk Summary
        self.assertEqual(data["risk_summary"]["total_assets_evaluated"], 1)
        self.assertEqual(data["risk_summary"]["mandatory_review_count"], 1)

        # Migration Summary & Review Gate
        mig = data["migration_summary"]
        self.assertEqual(mig["blocking_gates_count"], 1)
        self.assertEqual(len(mig["review_gates"]), 1)
        self.assertEqual(mig["review_gates"][0]["gate_id"], "GATE-REVIEW-26700200")
        self.assertEqual(mig["schedule_status"], "ADVISORY_PENDING_REVIEW")
        self.assertGreaterEqual(len(mig["milestones"]), 1)

        # Provenance Chain
        self.assertEqual(len(data["provenance_chain"]), 1)

    # -------------------------------------------------------------------------
    # 6. Controlled Scenario Execution: TC-02 Symmetric AES
    # -------------------------------------------------------------------------
    def test_06_scenario_tc02_aes_execution(self) -> None:
        """POST /api/scenarios/tc02_symmetric_aes/run returns OUT_OF_SCOPE for PQC replacement."""
        resp = self.client.post("/api/scenarios/tc02_symmetric_aes/run")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["scenario_id"], "tc02_symmetric_aes")

        # 2 AES assets
        self.assertEqual(len(data["assets"]), 2)
        for asset in data["assets"]:
            self.assertEqual(asset["family"], "AES")
            self.assertEqual(asset["role"], "encryption_decryption")
            self.assertEqual(asset["pqc_mapping_status"], "OUT_OF_SCOPE")
            self.assertEqual(len(asset["candidate_targets"]), 0)

        # Risk Summary
        self.assertEqual(data["risk_summary"]["total_assets_evaluated"], 2)
        self.assertEqual(data["risk_summary"]["mandatory_review_count"], 2)

        # Migration: Zero blocking review gates for symmetric out-of-scope
        mig = data["migration_summary"]
        self.assertEqual(mig["blocking_gates_count"], 0)
        self.assertEqual(len(mig["review_gates"]), 0)

    # -------------------------------------------------------------------------
    # 7. Controlled Scenario Execution: TC-06 Ed25519
    # -------------------------------------------------------------------------
    def test_07_scenario_tc06_ed25519_execution(self) -> None:
        """POST /api/scenarios/tc06_ed25519/run returns digital signature mappings (ML-DSA / SLH-DSA)."""
        resp = self.client.post("/api/scenarios/tc06_ed25519/run")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["scenario_id"], "tc06_ed25519")

        # 1 Edwards asset
        self.assertEqual(len(data["assets"]), 1)
        asset = data["assets"][0]
        self.assertEqual(asset["family"], "EDWARDS")
        self.assertEqual(asset["role"], "digital_signature")
        self.assertEqual(asset["pqc_mapping_status"], "MAPPED")
        # Must map to signature algorithms, never KEMs
        for target in asset["candidate_targets"]:
            self.assertTrue("DSA" in target or "SLH" in target, f"Expected signature target, got {target}")
            self.assertNotIn("KEM", target)

        # Migration summary
        mig = data["migration_summary"]
        self.assertEqual(mig["blocking_gates_count"], 0)
        self.assertEqual(len(mig["review_gates"]), 0)

    # -------------------------------------------------------------------------
    # 8. Frontend-Backend Contract Alignment
    # -------------------------------------------------------------------------
    def test_08_frontend_backend_contract_alignment(self) -> None:
        """Verifies frontend HTML/JS uses authoritative scenario IDs, endpoints, and response keys."""
        index_html = (self.workspace_root / "demo" / "frontend" / "index.html").read_text(encoding="utf-8")
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")

        # 1. No stale scenario references
        self.assertNotIn("ecommerce_payment_gateway", index_html)
        self.assertNotIn("ecommerce_payment_gateway", app_js)
        self.assertNotIn("/api/run-scenario", app_js)

        # 2. Scenario IDs in HTML scenario cards
        cards = re.findall(r'data-scenario=[\'"]([^\'"]+)[\'"]', index_html)
        self.assertIn("tc01_direct_rsa", cards)
        self.assertIn("tc02_symmetric_aes", cards)
        self.assertIn("tc06_ed25519", cards)

        registered_ids = [s.scenario_id for s in self.scenario_registry.list_scenarios()]
        for card_id in cards:
            self.assertIn(card_id, registered_ids, f"Card scenario {card_id} not registered in backend")

        # 3. Frontend API fetch call matches backend route pattern
        self.assertIn("fetch(`/api/scenarios/${selectedScenarioId}/run`", app_js)
        self.assertIn("fetch('/api/health')", app_js)

        # 4. Verify fields consumed by app.js exist in backend response
        resp = self.client.post("/api/scenarios/tc01_direct_rsa/run")
        data = resp.get_json()
        primary_asset = data["assets"][0]

        consumed_response_keys = [
            "status", "scenario_id", "execution_time_ms", "assets",
            "findings", "provenance_chain", "risk_summary", "migration_summary",
        ]
        for key in consumed_response_keys:
            self.assertIn(key, data, f"Backend response missing consumed key: {key}")

        consumed_asset_keys = [
            "asset_id", "algorithm", "family", "role", "confidence",
            "priority_tier", "risk_category", "pqc_mapping_status",
            "candidate_targets", "requires_human_review",
        ]
        for key in consumed_asset_keys:
            self.assertIn(key, primary_asset, f"Asset missing consumed key: {key}")

    # -------------------------------------------------------------------------
    # 9. Guided Journey Structural Integrity
    # -------------------------------------------------------------------------
    def test_09_guided_journey_structural_integrity(self) -> None:
        """Verifies all 8 journey steps exist in HTML and are bound cleanly in JS."""
        index_html = (self.workspace_root / "demo" / "frontend" / "index.html").read_text(encoding="utf-8")
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")

        expected_steps = [
            "choose", "discover", "evidence", "risk",
            "migration", "plan", "review", "verify",
        ]

        # Check HTML panels
        for step in expected_steps:
            panel_id = f'id="step-{step}"'
            self.assertIn(panel_id, index_html, f"Missing HTML panel for step: {step}")

        # Check JS STEPS array
        steps_match = re.search(r"STEPS\s*=\s*\[([^\]]+)\]", app_js)
        self.assertIsNotNone(steps_match, "STEPS array not found in app.js")
        js_steps = [s.strip().strip("'\"") for s in steps_match.group(1).split(",")]
        self.assertEqual(js_steps, expected_steps)

        # Check DOM element lookups in app.js all resolve in index.html
        by_id_calls = set(re.findall(r"(?:getElementById|el)\(['\"]([^'\"]+)['\"]\)", app_js))
        for el_id in by_id_calls:
            self.assertIn(
                f'id="{el_id}"',
                index_html,
                f"Element ID '{el_id}' referenced in app.js not found in index.html",
            )

    # -------------------------------------------------------------------------
    # 10. Verification Boundary & Truthful Disclosure
    # -------------------------------------------------------------------------
    def test_10_verification_boundary_truthfulness(self) -> None:
        """Step 8 carries explicit CONTROLLED / FUTURE disclosure and zero unprojected claims."""
        index_html = (self.workspace_root / "demo" / "frontend" / "index.html").read_text(encoding="utf-8")

        # Explicit future disclosures
        self.assertIn("CONTROLLED / FUTURE (PHASE 9)", index_html)
        self.assertIn("Architectural Disclosure", index_html)
        self.assertIn("ARCHITECTURAL PROJECTION", index_html)
        self.assertIn("PROJECTED: QUANTUM-RESILIENT (PHASE 9)", index_html)

        # Absolute or fake completed claims forbidden
        self.assertNotIn("VERIFIED QUANTUM-SAFE", index_html)


if __name__ == "__main__":
    unittest.main()
