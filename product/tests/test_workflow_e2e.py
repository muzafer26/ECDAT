"""
ECDAT End-to-End Workflow Integration Test Suite.

Validates the full vertical slice:
Input -> Ingestion -> Evidence -> Canonical Inventory -> CBOM -> Risk Analysis -> Technical Report

Covers:
1. Known positive cryptographic fixture (tc02_symmetric_aes).
2. Second positive cryptographic fixture (tc01_direct_rsa).
3. Negative/misleading decoy fixture (tc10_misleading_comments).
4. Ambiguous/zero-finding fixture (tc11_ambiguous_dynamic).
5. Ingestion failure / malformed JSON input containment.
6. Unsupported adapter ID handling.
7. End-to-end traceability (Evidence ID -> Finding ID -> Asset ID -> BOM Ref -> Report).
8. CBOM projection and consistency.
9. Risk, priority, and uncertainty preservation.
10. Deterministic report generation.
"""

import hashlib
from pathlib import Path
import unittest

from product.core.domain.observation import ObservationType
from product.core.ingestion.adapter import IngestionStatus
from product.core.risk.enums import PriorityTier, RiskCategory
from product.core.risk.models import AssetContext
from product.core.workflow import ECDATWorkflowEngine, TechnicalReport, WorkflowRunResult


class TestWorkflowE2E(unittest.TestCase):
    """Integration test suite for the end-to-end ECDAT workflow."""

    def setUp(self) -> None:
        self.engine = ECDATWorkflowEngine()
        self.raw_base = Path("product/benchmark/tools/raw_outputs/cryptoscan")

    def test_01_known_positive_tc02_symmetric_aes(self) -> None:
        """TC-02: End-to-end execution on real CryptoScan AES output."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        self.assertTrue(fixture_path.exists(), f"Fixture missing: {fixture_path}")

        result: WorkflowRunResult = self.engine.run(
            raw_input=fixture_path,
            target_name="tc02-aes-service",
            run_id="run-test-tc02-001",
        )

        # 1. Ingestion
        self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(result.ingestion_result.evidence_records), 2)

        # 2. Normalization & Correlation
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len(result.assets), 2)
        for asset in result.assets:
            self.assertEqual(asset.algorithm_identity.family.value, "AES")

        # 3. CBOM Projection
        cbom = result.cbom
        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.7")
        self.assertIn("components", cbom)
        self.assertEqual(len(cbom["components"]), 2)
        for comp in cbom["components"]:
            self.assertTrue(comp["bom-ref"].startswith("ecdat:asset:"))
            self.assertEqual(comp["type"], "cryptographic-asset")

        # 4. Risk Analysis
        self.assertEqual(len(result.risk_records), 2)
        for rec in result.risk_records:
            # Missing key size from AST output routes safely to review
            self.assertEqual(rec.risk_category, RiskCategory.NEEDS_REVIEW)
            self.assertEqual(rec.default_priority, PriorityTier.P_REVIEW_REQUIRED)
            self.assertTrue(rec.mandatory_review_required)

        # 5. Technical Report
        rep = result.report
        self.assertEqual(rep.run_id, "run-test-tc02-001")
        self.assertEqual(rep.target_name, "tc02-aes-service")
        self.assertEqual(rep.execution_status, "success")
        self.assertEqual(rep.scanner_attribution["scanner_name"], "CryptoScan")
        self.assertEqual(rep.scanner_attribution["scanner_version"], "1.4.0")
        self.assertEqual(rep.evidence_summary["canonical_assets_count"], 2)
        self.assertEqual(rep.cbom_summary["components_count"], 2)
        self.assertEqual(rep.priority_summary["p_review_required_count"], 2)
        self.assertTrue(len(rep.detailed_findings) == 2)
        self.assertTrue(len(rep.deferred_capabilities) >= 4)

        # 6. Markdown Report
        md = rep.to_markdown()
        self.assertIn("# ECDAT Cryptographic Analysis & Risk Technical Report", md)
        self.assertIn("CryptoScan", md)
        self.assertIn("CycloneDX", md)
        self.assertIn("NEEDS_REVIEW", md)

    def test_02_known_positive_tc01_direct_rsa(self) -> None:
        """TC-01: End-to-end execution on real CryptoScan RSA output."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        self.assertTrue(fixture_path.exists(), f"Fixture missing: {fixture_path}")

        result: WorkflowRunResult = self.engine.run(
            raw_input=fixture_path,
            target_name="tc01-rsa-keygen",
            run_id="run-test-tc01-001",
        )

        self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(result.ingestion_result.evidence_records), 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.assets), 1)
        self.assertEqual(result.assets[0].algorithm_identity.family.value, "RSA")
        self.assertEqual(len(result.cbom["components"]), 1)
        self.assertEqual(len(result.risk_records), 1)
        self.assertEqual(result.report.evidence_summary["canonical_assets_count"], 1)

    def test_03_negative_decoy_tc10_misleading_comments(self) -> None:
        """TC-10: Verifies comments/decoys produce findings but zero canonical assets and zero CBOM components."""
        fixture_path = self.raw_base / "tc10_misleading_comments" / "run1_output.json"
        self.assertTrue(fixture_path.exists(), f"Fixture missing: {fixture_path}")

        result: WorkflowRunResult = self.engine.run(
            raw_input=fixture_path,
            target_name="tc10-decoys",
            run_id="run-test-tc10-001",
        )

        self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].observation_type, ObservationType.NON_CRYPTOGRAPHIC_DECOY)

        # Crucial invariant: Decoys must NEVER be instantiated as canonical crypto assets!
        self.assertEqual(len(result.assets), 0)
        self.assertEqual(len(result.cbom.get("components", [])), 0)
        self.assertEqual(len(result.risk_records), 0)

        rep = result.report
        self.assertEqual(rep.evidence_summary["decoys_filtered"], 1)
        self.assertEqual(rep.evidence_summary["canonical_assets_count"], 0)
        self.assertEqual(rep.cbom_summary["components_count"], 0)
        self.assertTrue(any("non-cryptographic decoys" in gap for gap in rep.uncertainty_and_gaps))

    def test_04_ambiguous_zero_finding_tc11_dynamic(self) -> None:
        """TC-11: Verifies scanner output with zero findings completes cleanly without crash."""
        fixture_path = self.raw_base / "tc11_ambiguous_dynamic" / "run1_output.json"
        self.assertTrue(fixture_path.exists(), f"Fixture missing: {fixture_path}")

        result: WorkflowRunResult = self.engine.run(
            raw_input=fixture_path,
            target_name="tc11-dynamic",
            run_id="run-test-tc11-001",
        )

        # Scanner completed cleanly with zero findings: IngestionStatus.NO_FINDINGS
        self.assertEqual(result.ingestion_result.status, IngestionStatus.NO_FINDINGS)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.assets), 0)
        self.assertEqual(len(result.cbom.get("components", [])), 0)
        self.assertEqual(result.report.evidence_summary["canonical_assets_count"], 0)

        # Critical: Zero findings MUST disclose limitation notice, NOT clean bill of health
        has_zero_finding_notice = any(
            "NOTICE (ZERO CONFIRMED FINDINGS)" in gap
            for gap in result.report.uncertainty_and_gaps
        )
        self.assertTrue(
            has_zero_finding_notice,
            "Expected explicit uncertainty gap explaining that 0 findings is not proof of safety."
        )
        # Verify markdown report does not claim safety
        md = result.report.to_markdown()
        self.assertIn("NOTICE (ZERO CONFIRMED FINDINGS)", md)
        self.assertIn("No cryptographic assets evaluated in this run", md)

    def test_05_ingestion_failure_containment_on_malformed_json(self) -> None:
        """Verifies malformed/hostile scanner input is safely contained and reported without crash."""
        malformed_bytes = b"{\x00 invalid JSON payload truncated..."

        result: WorkflowRunResult = self.engine.run(
            raw_input=malformed_bytes,
            target_name="hostile-test",
            run_id="run-test-malformed-001",
        )

        self.assertEqual(result.ingestion_result.status, IngestionStatus.PARSER_ERROR)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.assets), 0)
        self.assertEqual(len(result.cbom.get("components", [])), 0)
        self.assertEqual(result.report.execution_status, "parser_error")

    def test_06_unsupported_adapter_id_handling(self) -> None:
        """Verifies unrecognized adapter ID produces explicit invalid_input result."""
        result: WorkflowRunResult = self.engine.run(
            raw_input=b'{"findings": []}',
            adapter_id="unsupported_scanner_xyz",
            run_id="run-test-unsupported-001",
        )

        self.assertEqual(result.ingestion_result.status, IngestionStatus.INVALID_INPUT)
        self.assertEqual(result.report.execution_status, "invalid_input")

    def test_07_end_to_end_traceability(self) -> None:
        """Verifies strict chain of custody: Raw Hash -> Evidence ID -> Finding ID -> Asset ID -> BOM Ref -> Report."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        raw_bytes = fixture_path.read_bytes()
        expected_hash = hashlib.sha256(raw_bytes).hexdigest()

        result = self.engine.run(
            raw_input=fixture_path,
            run_id="trace-test-001",
        )

        # 1. Scanner Attribution Hash
        self.assertIn(expected_hash, result.report.scanner_attribution["raw_output_sha256"])

        # 2. Evidence ID
        ev = result.ingestion_result.evidence_records[0]
        self.assertEqual(ev.evidence_id, "cryptoscan:RSA-001-16-64")

        # 3. Finding ID references Evidence ID
        finding = result.findings[0]
        self.assertIn(ev.evidence_id, finding.evidence_ids)

        # 4. Asset ID references Finding ID
        asset = result.assets[0]
        self.assertIn(finding.finding_id, asset.finding_ids)

        # 5. CBOM Ref references Asset ID
        cbom_comp = result.cbom["components"][0]
        self.assertEqual(cbom_comp["bom-ref"], f"ecdat:asset:{asset.asset_id}")

        # 6. Report Detailed Finding maps all identifiers
        rep_finding = result.report.detailed_findings[0]
        self.assertEqual(rep_finding["asset_id"], asset.asset_id)
        self.assertEqual(rep_finding["bom_ref"], f"ecdat:asset:{asset.asset_id}")
        self.assertIn(finding.finding_id, rep_finding["finding_ids"])

    def test_08_deterministic_report_generation(self) -> None:
        """Verifies repeated evaluation on identical inputs yields byte-for-byte identical reports."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"

        result1 = self.engine.run(raw_input=fixture_path, run_id="fixed-run-id")
        result2 = self.engine.run(raw_input=fixture_path, run_id="fixed-run-id")

        self.assertEqual(result1.report.to_dict(), result2.report.to_dict())
        self.assertEqual(result1.report.to_markdown(), result2.report.to_markdown())

    def test_09_all_11_benchmark_cases_coverage(self) -> None:
        """
        Validates end-to-end execution across all 11 frozen benchmark raw fixtures (TC-01 through TC-11).
        Verifies that:
        - None of the 11 fixtures cause an unhandled exception or crash.
        - TC01..TC07, TC09, TC10 produce expected ingestion statuses.
        - TC08 and TC11 (where scanner emitted 0 findings) receive IngestionStatus.NO_FINDINGS with explicit limitation disclosures.
        - Decoy case TC10 instantiates 0 canonical assets and 0 CBOM components.
        """
        for i in range(1, 12):
            tc_id = f"tc{i:02d}"
            matches = list(self.raw_base.glob(f"{tc_id}_*"))
            self.assertTrue(len(matches) > 0, f"Fixture directory for {tc_id} missing")
            fixture = matches[0] / "run1_output.json"
            self.assertTrue(fixture.exists(), f"run1_output.json for {tc_id} missing")

            result = self.engine.run(raw_input=fixture, target_name=f"test-{tc_id}", run_id=f"run-{tc_id}-verify")
            
            # 1. Pipeline never crashes and produces a valid report
            self.assertIsNotNone(result.report)
            self.assertEqual(result.report.run_id, f"run-{tc_id}-verify")

            # 2. Specific case assertions
            if tc_id in ("tc08", "tc11"):
                # CryptoScan emitted 0 findings on wrapper and dynamic calls
                self.assertEqual(result.ingestion_result.status, IngestionStatus.NO_FINDINGS)
                self.assertEqual(len(result.assets), 0)
                self.assertEqual(len(result.cbom.get("components", [])), 0)
                # Must disclose zero-finding uncertainty notice
                self.assertTrue(
                    any("NOTICE (ZERO CONFIRMED FINDINGS)" in g for g in result.report.uncertainty_and_gaps),
                    f"{tc_id} must disclose zero-finding uncertainty notice"
                )
            elif tc_id == "tc10":
                # Decoy comments/logger strings: finding produced, but 0 assets
                self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
                self.assertEqual(len(result.assets), 0)
                self.assertEqual(len(result.cbom.get("components", [])), 0)
                self.assertTrue(
                    any("non-cryptographic decoys" in g for g in result.report.uncertainty_and_gaps)
                )
            else:
                # TC01-TC07, TC09: produced canonical assets
                self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
                self.assertGreater(len(result.assets), 0, f"{tc_id} should have canonical assets")
                self.assertGreater(len(result.cbom.get("components", [])), 0)


if __name__ == "__main__":
    unittest.main()
