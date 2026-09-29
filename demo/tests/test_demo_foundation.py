"""
ECDAT Phase D1 Foundation & Integration Test Suite.

Verifies the 12 Phase D1 Acceptance Criteria and Hardening Gate:
- Test 1: Demo Import & Startup
- Test 2: Real Core Integration (TC01 Direct RSA -> Real ECDAT Core -> FIPS 203 ML-KEM)
- Test 3: Result Transformation & Provenance Integrity (7-Step Tracing & Classification)
- Test 4: Failure Propagation (Honest error handling, zero false successes, malformed inputs)
- Test 5: Product Core Freeze Verification (Byte-exact baseline verification across 392 files)
- Test 6: Dynamic Processing (Distinct real outputs for distinct inputs, no hardcoding)
- Test 7: API / Backend Boundary Contract (Flask endpoints)
- Test 8: Dynamic In-Memory Input Processing (Proves real execution without cached fixtures)
- Test 9: API Safety & Traversal Rejection (Path traversal rejection, HTTP method safety)
"""

import hashlib
import json
from pathlib import Path
import unittest

# Demo imports
from demo.adapters.models import CapabilityClassification
from demo.adapters.registry import DemoAdapterRegistry
from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus, DemoRunResult, ProvenanceSourceType
from demo.scenarios.models import DemoScenario, ScenarioClassification
from demo.scenarios.registry import ScenarioRegistry

# Real frozen core imports
from product.core.workflow.engine import ECDATWorkflowEngine


class TestDemoFoundation(unittest.TestCase):
    """Test suite for Phase D1 Foundation and Frozen Core Integration."""

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

    # --- Test 1: Demo Import & Startup ---
    def test_01_demo_import_and_startup(self) -> None:
        """AC-D1-01: Verifies all demo foundation components import and initialize cleanly."""
        self.assertIsNotNone(self.scenario_registry)
        self.assertIsNotNone(self.adapter_registry)
        self.assertIsNotNone(self.orchestrator)
        self.assertIsNotNone(self.app)

        scenarios = self.scenario_registry.list_scenarios()
        self.assertGreaterEqual(len(scenarios), 2)
        scenario_ids = [s.scenario_id for s in scenarios]
        self.assertIn("tc01_direct_rsa", scenario_ids)
        self.assertIn("tc02_symmetric_aes", scenario_ids)

        adapters = self.adapter_registry.list_adapters()
        self.assertGreaterEqual(len(adapters), 2)
        adapter_ids = [a.adapter_id for a in adapters]
        self.assertIn("cryptoscan", adapter_ids)
        self.assertIn("syft", adapter_ids)
        # Architectural adapters must also be registered but flagged ARCHITECTURAL
        self.assertIn("sonar", adapter_ids)
        self.assertEqual(self.adapter_registry.get_status("sonar").status, CapabilityClassification.ARCHITECTURAL)
        self.assertEqual(self.adapter_registry.get_status("cryptoscan").status, CapabilityClassification.LIVE)

    # --- Test 2: Real Core Integration ---
    def test_02_real_core_integration_tc01_rsa(self) -> None:
        """AC-D1-04 & AC-D1-05: Verifies controlled scenario reaches actual ECDAT core and produces real output."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")

        self.assertIsInstance(result, DemoRunResult)
        self.assertEqual(result.status, DemoExecutionStatus.SUCCESS)
        self.assertEqual(result.classification, "LIVE")
        self.assertEqual(result.scenario_id, "tc01_direct_rsa")
        self.assertGreater(result.execution_time_ms, 0.0)

        # Real assets discovered
        self.assertEqual(len(result.assets), 1)
        asset = result.assets[0]
        self.assertEqual(asset.family, "RSA")
        self.assertEqual(asset.algorithm, "RSA")
        self.assertEqual(asset.role, "key_generation")

        # Real categorical risk & explainability derived by product/core/risk/
        # Scanner omitted key_size parameter -> engine fails closed to review
        self.assertEqual(asset.priority_tier, "P_REVIEW_REQUIRED")
        self.assertEqual(asset.risk_category, "NEEDS_REVIEW")
        self.assertEqual(asset.primary_risk_cause, "UNRESOLVED_UNCERTAINTY")
        self.assertEqual(asset.classical_status, "INDETERMINATE")
        self.assertEqual(asset.quantum_exposure_class, "SHOR_VULNERABLE_ASYMMETRIC")
        self.assertTrue(asset.requires_human_review)

        # Real Phase 4 PQC Target Mapping performed by product/core/migration/
        self.assertEqual(result.migration_summary.phase_4_status, "COMPLETED")
        self.assertEqual(asset.pqc_mapping_status, "CONDITIONAL")
        self.assertIn("ML-KEM-768", asset.candidate_targets)

        # CycloneDX CBOM projection produced by product/core/cbom/
        self.assertEqual(result.cbom_summary["bom_format"], "CycloneDX")
        self.assertEqual(result.cbom_summary["spec_version"], "1.7")
        self.assertGreater(result.cbom_summary["components_count"], 0)

    # --- Test 3: Result Transformation & Provenance Integrity ---
    def test_03_result_transformation_and_provenance(self) -> None:
        """AC-D1-06 & AC-D1-07: Verifies presentation-safe models preserve the full provenance chain."""
        result = self.orchestrator.run_scenario("tc01_direct_rsa")
        serialized = result.to_dict()

        # Check presentation-safety (all JSON-serializable primitives)
        json_str = json.dumps(serialized)
        self.assertIsInstance(json_str, str)

        # Verify provenance chain exists for the asset
        self.assertGreater(len(result.provenance_chain), 0)
        chain = result.provenance_chain[0]
        steps = [node.step for node in chain]

        # Invariant: Provenance must trace through the 7 intellectual stages
        expected_steps = ["scanner", "raw_evidence", "finding", "crypto_asset", "risk", "migration", "schedule"]
        for expected in expected_steps:
            self.assertIn(expected, steps, f"Provenance chain missing step: {expected}")

        # Invariant: Every provenance node must declare an internal source_type classification
        for node in chain:
            self.assertEqual(node.source_type, ProvenanceSourceType.DIRECT_CORE_OUTPUT.value)

        # Verify linked evidence IDs match between asset, finding, and evidence
        asset = result.assets[0]
        self.assertGreater(len(asset.finding_ids), 0)
        self.assertGreater(len(asset.evidence_ids), 0)
        evidence_ids_in_record = {e.evidence_id for e in result.evidence_records}
        for ev_id in asset.evidence_ids:
            self.assertIn(ev_id, evidence_ids_in_record)

    # --- Test 4: Failure Propagation ---
    def test_04_failure_propagation(self) -> None:
        """AC-D1-08: Verifies controlled failures are preserved and never fabricated into successes."""
        # Case A: Non-existent scenario ID
        res_missing = self.orchestrator.run_scenario("non_existent_scenario_id")
        self.assertEqual(res_missing.status, DemoExecutionStatus.UNAVAILABLE)
        self.assertIn("not found", res_missing.error_message)
        self.assertEqual(len(res_missing.assets), 0)

        # Case B: Scenario with missing fixture file
        broken_scenario = DemoScenario(
            scenario_id="broken_scenario",
            name="Broken Scenario",
            description="Scenario with missing fixture",
            target_name="broken",
            adapter_id="cryptoscan",
            fixture_path=self.workspace_root / "non_existent_path" / "missing.json",
            classification=ScenarioClassification.CONTROLLED_DEMO,
            expected_primary_family="UNKNOWN",
        )
        self.scenario_registry.register(broken_scenario)
        res_broken = self.orchestrator.run_scenario("broken_scenario")
        self.assertEqual(res_broken.status, DemoExecutionStatus.FAILED)
        self.assertIn("missing", res_broken.error_message)
        self.assertEqual(len(res_broken.assets), 0)

        # Case C: Malformed scanner input (invalid JSON syntax)
        malformed_scenario = DemoScenario(
            scenario_id="malformed_scenario",
            name="Malformed JSON Scenario",
            description="Scenario with corrupted JSON content",
            target_name="malformed",
            adapter_id="cryptoscan",
            fixture_path=self.workspace_root / "demo" / "backend" / "app.py",  # Not a JSON file
            classification=ScenarioClassification.CONTROLLED_DEMO,
            expected_primary_family="UNKNOWN",
        )
        self.scenario_registry.register(malformed_scenario)
        res_malformed = self.orchestrator.run_scenario("malformed_scenario")
        self.assertEqual(res_malformed.status, DemoExecutionStatus.FAILED)
        self.assertEqual(len(res_malformed.assets), 0)
        self.assertEqual(res_malformed.migration_summary.phase_4_status, "SKIPPED_NO_ASSETS")

    # --- Test 5: Product Core Freeze Verification ---
    def test_05_product_freeze_verification(self) -> None:
        """AC-D1-02: Verifies that product/ tree source files remain 100% byte-identical to the baseline."""
        product_dir = self.workspace_root / "product"
        files = sorted([f for f in product_dir.glob("**/*") if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc"])
        self.assertEqual(len(files), 392, "Source file count in product/ has changed!")

        h = hashlib.sha256()
        for f in files:
            h.update(f.relative_to(self.workspace_root).as_posix().encode("utf-8"))
            h.update(f.read_bytes())
        current_hash = h.hexdigest()

        # Authoritative Phase D0 baseline for source tree
        baseline_hash = "b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2"
        self.assertEqual(
            current_hash,
            baseline_hash,
            "CRITICAL: product/ tree has been modified! Freeze rule violated.",
        )

    # --- Test 6: Dynamic Processing (No Hardcoding) ---
    def test_06_no_hardcoded_analytical_results(self) -> None:
        """AC-D1-03: Proves results depend dynamically on real core processing of distinct inputs."""
        res_rsa = self.orchestrator.run_scenario("tc01_direct_rsa")
        res_aes = self.orchestrator.run_scenario("tc02_symmetric_aes")

        self.assertEqual(res_rsa.status, DemoExecutionStatus.SUCCESS)
        self.assertEqual(res_aes.status, DemoExecutionStatus.SUCCESS)

        # Distinct asset families inferred by real engine
        rsa_families = {a.family for a in res_rsa.assets}
        aes_families = {a.family for a in res_aes.assets}
        self.assertEqual(rsa_families, {"RSA"})
        self.assertEqual(aes_families, {"AES"})

        # Distinct migration outcomes
        rsa_pqc_statuses = {a.pqc_mapping_status for a in res_rsa.assets}
        aes_pqc_statuses = {a.pqc_mapping_status for a in res_aes.assets}
        self.assertEqual(rsa_pqc_statuses, {"CONDITIONAL"})
        self.assertEqual(aes_pqc_statuses, {"OUT_OF_SCOPE"})

    # --- Test 7: API / Backend Boundary Endpoints ---
    def test_07_api_boundary_endpoints(self) -> None:
        """AC-D1-07: Verifies HTTP contract for /api/health, /api/scenarios, /api/adapters, and execution."""
        # Health check
        resp_health = self.client.get("/api/health")
        self.assertEqual(resp_health.status_code, 200)
        data_health = resp_health.get_json()
        self.assertEqual(data_health["status"], "healthy")
        self.assertEqual(data_health["core_status"], "CONNECTED_FROZEN")

        # Scenarios list
        resp_scenarios = self.client.get("/api/scenarios")
        self.assertEqual(resp_scenarios.status_code, 200)
        data_scenarios = resp_scenarios.get_json()
        self.assertGreaterEqual(data_scenarios["count"], 2)

        # Adapters list
        resp_adapters = self.client.get("/api/adapters")
        self.assertEqual(resp_adapters.status_code, 200)
        data_adapters = resp_adapters.get_json()
        self.assertGreaterEqual(data_adapters["count"], 2)

        # Scenario run
        resp_run = self.client.post("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp_run.status_code, 200)
        data_run = resp_run.get_json()
        self.assertEqual(data_run["status"], "SUCCESS")
        self.assertEqual(data_run["scenario_id"], "tc01_direct_rsa")
        self.assertEqual(data_run["assets_count"], 1)

        # 404 on invalid scenario run
        resp_404 = self.client.post("/api/scenarios/invalid_scenario_id/run")
        self.assertEqual(resp_404.status_code, 404)

    # --- Test 8: Dynamic In-Memory Input Processing ---
    def test_08_dynamic_in_memory_input_processing(self) -> None:
        """Check 3: Proves real core computes dynamically from novel input bytes (not a cached lookup)."""
        # Synthesize a novel CryptoScan finding with a different algorithm in memory
        dynamic_payload = {
            "tool": {"name": "CryptoScan", "version": "1.4.0"},
            "findings": [
                {
                    "id": "DYNAMIC-ECC-001",
                    "type": "ECC Algorithm",
                    "category": "Asymmetric",
                    "algorithm": "ECDSA",
                    "primitive": "signature",
                    "file": "src/SecurityService.java",
                    "line": 42,
                    "match": "SHA256withECDSA",
                }
            ]
        }
        raw_json_str = json.dumps(dynamic_payload)

        # Run real workflow engine directly with in-memory string input
        workflow_res = self.orchestrator.engine.run(
            raw_input=raw_json_str,
            adapter_id="cryptoscan",
            target_name="dynamic-test",
        )

        self.assertGreater(len(workflow_res.assets), 0)
        dynamic_asset = workflow_res.assets[0]
        self.assertEqual(dynamic_asset.algorithm_identity.family.value, "EC")
        self.assertEqual(dynamic_asset.algorithm_identity.algorithm, "ECDSA")
        self.assertEqual(dynamic_asset.primary_location.file_path, "src/SecurityService.java")
        self.assertEqual(dynamic_asset.primary_location.line_start, 42)

        # Transforms safely
        from demo.orchestration.transformer import DemoResultTransformer
        demo_res = DemoResultTransformer.transform(
            result=workflow_res,
            scenario_id="dynamic_in_memory",
            classification="LIVE",
        )
        self.assertEqual(demo_res.assets[0].family, "EC")
        self.assertEqual(demo_res.assets[0].algorithm, "ECDSA")
        self.assertEqual(demo_res.assets[0].location_display, "src/SecurityService.java:42")

    # --- Test 9: API Safety & Traversal Rejection ---
    def test_09_api_safety_and_traversal_rejection(self) -> None:
        """Check 7: Verifies HTTP error handling, path traversal protection, and safe JSON responses."""
        # Path traversal rejection on static endpoint
        resp_traversal = self.client.get("/../backend/app.py")
        self.assertIn(resp_traversal.status_code, (404, 400))

        # Unsupported method on health check
        resp_method = self.client.delete("/api/health")
        self.assertEqual(resp_method.status_code, 405)
        self.assertEqual(resp_method.get_json(), {"error": "Method not allowed"})

        # Unsupported method on scenario run (GET instead of POST)
        resp_get_run = self.client.get("/api/scenarios/tc01_direct_rsa/run")
        self.assertEqual(resp_get_run.status_code, 405)

        # 404 handler returns clean JSON, not HTML stack trace
        resp_notfound = self.client.get("/api/nonexistent_endpoint")
        self.assertEqual(resp_notfound.status_code, 404)
        self.assertEqual(resp_notfound.get_json(), {"error": "Resource not found"})


if __name__ == "__main__":
    unittest.main()
