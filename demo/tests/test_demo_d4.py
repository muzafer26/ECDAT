"""
ECDAT Phase D4 Adversarial & Product Integrity Test Suite.

Verifies the system against active attacks, misinterpretation risks, and boundary violations:
- Test 1: API path traversal hardening on static routes.
- Test 2: API malformed inputs and massive payloads fail safely without tracebacks.
- Test 3: Zero state leakage or contamination between scenario switches (TC01 -> TC02 -> TC06).
- Test 4: Verification boundary contains zero false "verified quantum-safe" claims (strictly PROJECTED Phase 9).
- Test 5: "No findings" semantics: absence of detections does not certify safety.
- Test 6: Dependency presence is not conflated with active cryptographic usage.
- Test 7: Multi-asset provenance isolation by entity_id.
- Test 8: Claims audit: prohibition of forbidden marketing/absolute claims.
- Test 9: Frozen product core byte-exact baseline verification.
"""

import hashlib
from pathlib import Path
import re
import unittest

from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus
from demo.scenarios.registry import ScenarioRegistry
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.role import CryptographicRole
from product.core.migration.models import TargetMappingStatus
from product.core.migration.target_mapper import PqcTargetMapper


class TestDemoD4AdversarialIntegrity(unittest.TestCase):
    """Adversarial and security integrity verification suite."""

    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parent.parent.parent
        self.scenario_registry = ScenarioRegistry(workspace_root=self.workspace_root)
        self.orchestrator = DemoOrchestrator(scenario_registry=self.scenario_registry)
        self.app = create_app(orchestrator=self.orchestrator)
        self.client = self.app.test_client()

    # --- Test 1: Path Traversal Hardening ---
    def test_01_api_path_traversal_hardened(self) -> None:
        """Attack Class K: Verifies static route rejects path traversal attempts."""
        traversal_payloads = [
            "/..%2fbackend%2fapp.py",
            "/../../README.md",
            "/..\\backend\\app.py",
            "/demo/../../product/core/workflow/engine.py",
        ]
        for payload in traversal_payloads:
            resp = self.client.get(payload)
            self.assertEqual(resp.status_code, 404, f"Payload {payload} did not return 404")
            self.assertNotIn("ECDATWorkflowEngine", resp.get_data(as_text=True))

    # --- Test 2: Malformed Inputs Fail Without Tracebacks ---
    def test_02_api_malformed_inputs_traceback_free(self) -> None:
        """Attack Class K: Malformed, oversized, or null inputs do not leak tracebacks."""
        # 1. 10,000 char identifier
        resp_large = self.client.post("/api/scenarios/" + ("A" * 10000) + "/run")
        self.assertEqual(resp_large.status_code, 404)
        self.assertNotIn("Traceback", resp_large.get_data(as_text=True))

        # 2. Malformed JSON body
        resp_bad_json = self.client.post(
            "/api/scenarios/tc01_direct_rsa/run",
            data="{not_valid_json: 123",
            content_type="application/json",
        )
        self.assertIn(resp_bad_json.status_code, (200, 400))
        self.assertNotIn("Traceback", resp_bad_json.get_data(as_text=True))

        # 3. Path traversal in scenario ID
        resp_trav = self.client.post("/api/scenarios/..%2f..%2fetc%2fpasswd/run")
        self.assertIn(resp_trav.status_code, (404, 405))
        self.assertNotIn("Traceback", resp_trav.get_data(as_text=True))

    # --- Test 3: Zero State Leakage Across Scenario Switching ---
    def test_03_no_state_leakage_between_scenarios(self) -> None:
        """Attack Class L: Switching between TC01, TC02, and TC06 preserves mutually exclusive results."""
        # 1. Run TC01 (RSA KeyGen)
        r1 = self.orchestrator.run_scenario("tc01_direct_rsa")
        self.assertEqual(r1.assets[0].family, "RSA")
        self.assertEqual(r1.migration_summary.blocking_gates_count, 1)
        self.assertEqual(r1.migration_summary.milestones[0]["milestone_id"], "M2-KEY-EXCHANGE-HNDL")

        # 2. Run TC02 (AES Symmetric)
        r2 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        self.assertEqual(r2.assets[0].family, "AES")
        self.assertEqual(r2.migration_summary.blocking_gates_count, 0)
        self.assertEqual(r2.migration_summary.out_of_scope_count, 2)
        # Verify TC02 did not inherit TC01's review gate or milestone
        gate_ids_tc02 = [g["gate_id"] for g in r2.migration_summary.review_gates]
        self.assertNotIn("GATE-REVIEW-26700200", gate_ids_tc02)

        # 3. Run TC06 (Ed25519 Signature)
        r6 = self.orchestrator.run_scenario("tc06_ed25519")
        self.assertEqual(r6.assets[0].family, "EDWARDS")
        self.assertEqual(r6.assets[0].pqc_mapping_status, "MAPPED")
        self.assertEqual(r6.migration_summary.milestones[0]["milestone_id"], "M3-AUTHENTICATION-SIGNATURES")
        self.assertIn("ML-DSA-65", r6.assets[0].candidate_targets)
        # Verify TC06 does not have TC01 KEM targets
        self.assertNotIn("ML-KEM-768", r6.assets[0].candidate_targets)

    # --- Test 4: Verification Boundary Does Not Fake Verification ---
    def test_04_verification_boundary_no_fake_success(self) -> None:
        """Attack Class J: Verifies that UI never displays 'VERIFIED QUANTUM-SAFE' as an active status."""
        index_html = (self.workspace_root / "demo" / "frontend" / "index.html").read_text(encoding="utf-8")
        # Prohibit unprojected claims of active verification
        self.assertNotIn("VERIFIED QUANTUM-SAFE", index_html)
        self.assertIn("PROJECTED: QUANTUM-RESILIENT (PHASE 9)", index_html)
        self.assertIn("CONTROLLED / FUTURE (PHASE 9)", index_html)

    # --- Test 5: "No Findings" Semantics ---
    def test_05_no_findings_semantics_safe_guard(self) -> None:
        """Attack Class G: Empty findings/assets must not state the environment is safe."""
        app_js = (self.workspace_root / "demo" / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("does not certify cryptographic safety", app_js)

        transformer_py = (self.workspace_root / "demo" / "orchestration" / "transformer.py").read_text(encoding="utf-8")
        self.assertIn("does not certify cryptographic safety", transformer_py)

    # --- Test 6: Dependency Presence != Cryptographic Usage ---
    def test_06_dependency_not_conflated_with_usage(self) -> None:
        """Attack Class F: Package dependencies evaluate to OUT_OF_SCOPE and do not trigger algorithm replacement."""
        from product.core.domain.parameters import AlgorithmParameters
        from product.core.evidence.evidence import EvidenceLocation, LocationType

        mapper = PqcTargetMapper()
        dep_asset = CryptoAsset(
            asset_id="test-dep-001",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.RSA, algorithm="bcprov-jdk15on"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["finding-dep-01"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="org.bouncycastle:bcprov-jdk15on:1.70"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="sbom_package_manifest",
        )
        mapping = mapper.map_asset(dep_asset)
        self.assertEqual(mapping.mapping_status, TargetMappingStatus.OUT_OF_SCOPE)
        self.assertEqual(mapping.candidate_targets, ())
        self.assertIn("Library dependency manifests represent software package presence", mapping.mapping_rationale)

    # --- Test 7: Strict Provenance Entity ID Matching ---
    def test_07_strict_provenance_entity_id_matching(self) -> None:
        """Attack Class C & L: Provenance chains in multi-asset runs carry distinct asset IDs."""
        res_tc02 = self.orchestrator.run_scenario("tc02_symmetric_aes")
        self.assertEqual(len(res_tc02.assets), 2)
        asset_ids = {a.asset_id for a in res_tc02.assets}
        self.assertEqual(len(asset_ids), 2, "Asset IDs in TC02 must be distinct")

        # Each provenance chain must be tied to its distinct asset_id
        chain_asset_ids = set()
        for chain in res_tc02.provenance_chain:
            for node in chain:
                if node.step == "crypto_asset":
                    chain_asset_ids.add(node.entity_id)
        self.assertEqual(chain_asset_ids, asset_ids, "Provenance chains must match distinct assets")

    # --- Test 8: Claims Audit: Prohibition of Forbidden Absolutes ---
    def test_08_claims_audit_no_forbidden_absolutes(self) -> None:
        """Attack Class A, N, P: Audits demo files for prohibited marketing/absolute claims."""
        files_to_check = [
            self.workspace_root / "demo" / "frontend" / "index.html",
            self.workspace_root / "demo" / "frontend" / "app.js",
            self.workspace_root / "demo" / "backend" / "app.py",
        ]
        forbidden_regexes = [
            r"we\s+never\s+see\s+your\s+code",
            r"zero\s+source\s+retention\s+guarantee",
            r"100%\s+quantum\s+safe",
            r"universal\s+pqc\s+replacement",
            r"automatically\s+remediated",
            r"production\s+ready\s+patching",
        ]

        for file_path in files_to_check:
            content = file_path.read_text(encoding="utf-8")
            for pattern in forbidden_regexes:
                matches = re.findall(pattern, content, re.IGNORECASE)
                self.assertEqual(len(matches), 0, f"Found forbidden claim '{pattern}' in {file_path}")

    # --- Test 9: Frozen Product Core Baseline Integrity ---
    def test_09_product_freeze_uncompromised(self) -> None:
        """Attack Class Non-Negotiable: Confirms product core source files remain 100% byte-identical."""
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
