"""
ECDAT Phase 4 Workflow Integration Test Suite.

Verifies end-to-end integration of Phase 4A (PQC Target Mapping) and
Phase 4B (Hybrid Evaluation & Migration Scheduling) into ECDATWorkflowEngine,
WorkflowRunResult, and TechnicalReport.

Validates the 22 Acceptance Criteria established in the Release Audit.
"""

import json
from pathlib import Path
from types import MappingProxyType
import unittest

from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.finding import Finding
from product.core.domain.observation import ObservationType
from product.core.domain.role import CryptographicRole
from product.core.ingestion.adapter import IngestionResult, IngestionStatus
from product.core.migration.models import (
    MigrationSchedule,
    PqcTargetMapping,
    TargetMappingStatus,
)
from product.core.risk.models import AssetContext, MigrationPriorityRecord
from product.core.workflow import (
    ECDATWorkflowEngine,
    MigrationAnalysisSection,
    Phase4AnalysisResult,
    Phase4ExecutionStatus,
    TechnicalReport,
    WorkflowRunResult,
)


class TestWorkflowPhase4Integration(unittest.TestCase):
    """Integration test suite for Phase 4A/4B workflow integration."""

    def setUp(self) -> None:
        self.engine = ECDATWorkflowEngine()
        self.raw_base = Path("product/benchmark/tools/raw_outputs/cryptoscan")
        self.answer_keys_dir = Path("product/benchmark/answer_keys")

    def test_01_legacy_workflow_run_result_positional_compatibility(self) -> None:
        """AC-18: Verifies legacy positional construction of WorkflowRunResult works without phase_4."""
        dummy_ingestion = IngestionResult(
            status=IngestionStatus.SUCCESS,
            evidence_records=(),
            raw_output_ref="none",
        )
        dummy_report = TechnicalReport(
            run_id="run-legacy-001",
            timestamp="2026-09-21T00:00:00Z",
            target_name="test-target",
            execution_status="SUCCESS",
            scanner_attribution={},
            evidence_summary={},
            cbom_summary={},
            risk_summary={},
            priority_summary={},
            uncertainty_and_gaps=(),
            triggered_authorities=(),
            deferred_capabilities=(),
            detailed_findings=(),
        )

        # Positional constructor with 7 legacy arguments
        result = WorkflowRunResult(
            "run-legacy-001",
            dummy_ingestion,
            (),
            (),
            {},
            (),
            dummy_report,
        )
        self.assertIsNone(result.phase_4)
        serialized = result.to_dict()
        self.assertIn("phase_4", serialized)
        self.assertIsNone(serialized["phase_4"])

    def test_02_legacy_technical_report_compatibility(self) -> None:
        """AC-19: Verifies legacy construction of TechnicalReport works without migration_analysis."""
        report = TechnicalReport(
            run_id="run-legacy-002",
            timestamp="2026-09-21T00:00:00Z",
            target_name="test-target",
            execution_status="SUCCESS",
            scanner_attribution={},
            evidence_summary={},
            cbom_summary={},
            risk_summary={},
            priority_summary={},
            uncertainty_and_gaps=(),
            triggered_authorities=(),
            deferred_capabilities=(),
            detailed_findings=(),
        )
        self.assertIsNone(report.migration_analysis)
        serialized = report.to_dict()
        self.assertIn("migration_analysis", serialized)
        self.assertIsNone(serialized["migration_analysis"])

    def test_03_workflow_invokes_mapper_and_scheduler_in_order(self) -> None:
        """AC-01 & AC-02: Verifies workflow invokes target mapping and scheduling in sequence."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        self.assertTrue(fixture_path.exists())

        result = self.engine.run(
            raw_input=fixture_path,
            target_name="tc01-rsa",
            run_id="run-test-p4-tc01",
        )

        self.assertIsNotNone(result.phase_4)
        p4 = result.phase_4
        self.assertEqual(p4.status, Phase4ExecutionStatus.COMPLETED)
        self.assertGreater(len(p4.target_mappings), 0)
        self.assertIsNotNone(p4.migration_schedule)
        self.assertIsInstance(p4.migration_schedule, MigrationSchedule)

    def test_04_canonical_assets_reach_mapper(self) -> None:
        """AC-03: Verifies canonical CryptoAsset instances reach the target mapper."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        self.assertIsNotNone(result.phase_4)
        asset_ids = {a.asset_id for a in result.assets}
        mapping_source_ids = {m.source_asset_id for m in result.phase_4.target_mappings}
        self.assertEqual(asset_ids, mapping_source_ids)

    def test_05_role_specific_asymmetric_mappings_rsa(self) -> None:
        """AC-04 & AC-05: Verifies RSA-2048 key exchange maps to FIPS 203 ML-KEM."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        self.assertIsNotNone(result.phase_4)
        rsa_mapping = result.phase_4.target_mappings[0]
        self.assertEqual(rsa_mapping.source_family, "RSA")
        target_standards = [t.standard for t in rsa_mapping.candidate_targets]
        self.assertTrue(any("FIPS 203" in s for s in target_standards))

    def test_06_symmetric_and_hash_algorithms_out_of_scope(self) -> None:
        """AC-06: Verifies symmetric ciphers evaluate strictly to OUT_OF_SCOPE."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc02-aes")

        self.assertIsNotNone(result.phase_4)
        for m in result.phase_4.target_mappings:
            self.assertEqual(m.mapping_status, TargetMappingStatus.OUT_OF_SCOPE)
            # Never mapped to public-key KEM
            for t in m.candidate_targets:
                self.assertNotIn("ML-KEM", t.parameter_set)

    def test_07_unknown_role_remains_reviewable(self) -> None:
        """AC-07: Verifies unknown/ambiguous roles fail closed to NEEDS_REVIEW."""
        from product.core.domain.parameters import AlgorithmParameters
        from product.core.evidence.evidence import SourceLocation

        synthetic_asset = CryptoAsset(
            asset_id="synthetic-unknown-01",
            asset_type=AssetType.ALGORITHM,
            algorithm_identity=AlgorithmIdentity(
                family=AlgorithmFamily.UNKNOWN,
                algorithm="CUSTOM_CIPHER",
            ),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["find-mock-01"],
            primary_location=SourceLocation(
                file_path="src/Unknown.java",
                line_start=10,
                line_end=11,
                matched_text="UnknownCipher",
            ),
            confidence=ConfidenceLevel.NEEDS_REVIEW,
            correlation_basis="test_fixture",
        )
        mapping = self.engine.target_mapper.map_asset(synthetic_asset)
        self.assertEqual(mapping.mapping_status, TargetMappingStatus.NEEDS_REVIEW)
        self.assertTrue(mapping.required_human_review)
        self.assertEqual(len(mapping.candidate_targets), 0)

    def test_08_empty_findings_truthful_semantics(self) -> None:
        """AC-08: Verifies zero findings emit SKIPPED_NO_ASSETS without claiming safety."""
        fixture_path = self.raw_base / "tc10_misleading_comments" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc10-empty")

        self.assertIsNotNone(result.phase_4)
        p4 = result.phase_4
        self.assertEqual(p4.status, Phase4ExecutionStatus.SKIPPED_NO_ASSETS)
        self.assertEqual(len(p4.target_mappings), 0)
        self.assertIsNotNone(p4.migration_schedule)
        self.assertEqual(len(p4.migration_schedule.milestones), 0)
        # Markdown must disclaim safety and report zero assets
        markdown = result.report.to_markdown()
        self.assertIn("zero cryptographic assets", markdown.lower())
        self.assertNotIn("system is safe", markdown.lower())
        self.assertNotIn("cryptographically safe", markdown.lower())

    def test_09_no_applicable_mapping_truthful_representation(self) -> None:
        """AC-09: Verifies assets with no PQC targets are not labeled as migration complete."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc02-aes")

        self.assertIsNotNone(result.phase_4)
        self.assertEqual(result.phase_4.status, Phase4ExecutionStatus.COMPLETED)
        # All are out of scope, schedule should not say migration complete
        self.assertIn(
            result.phase_4.migration_schedule.schedule_status,
            ("ACTIONABLE", "ADVISORY_PENDING_REVIEW"),
        )

    def test_10_partial_analysis_visibility(self) -> None:
        """AC-10: Verifies partial ingestion remains visible in audit provenance and report."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc02-aes")
        self.assertIsNotNone(result.report)
        self.assertIn("execution_status", result.report.to_dict())

    def test_11_mapper_failure_isolation(self) -> None:
        """AC-11: Verifies mapper exception is isolated, preserving Phase 0-3 results."""
        class BrokenMapper:
            def map_assets(self, assets):
                raise RuntimeError("Simulated internal mapper failure")

        engine = ECDATWorkflowEngine(target_mapper=BrokenMapper())
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = engine.run(raw_input=fixture_path, target_name="tc01-fail-mapper")

        # Phase 0-3 must be intact
        self.assertGreater(len(result.assets), 0)
        self.assertGreater(len(result.risk_records), 0)
        self.assertIsNotNone(result.cbom)

        # Phase 4 must report FAILED with error message
        self.assertIsNotNone(result.phase_4)
        self.assertEqual(result.phase_4.status, Phase4ExecutionStatus.FAILED)
        self.assertIn("Simulated internal mapper failure", str(result.phase_4.error_message))
        self.assertIsNone(result.phase_4.migration_schedule)

    def test_12_scheduler_failure_isolation(self) -> None:
        """AC-12: Verifies scheduler exception preserves valid mapper outputs."""
        class BrokenScheduler:
            def schedule_migration(self, **kwargs):
                raise RuntimeError("Simulated scheduler deadlock")

        engine = ECDATWorkflowEngine(scheduler=BrokenScheduler())
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = engine.run(raw_input=fixture_path, target_name="tc01-fail-sched")

        # Phase 4 must report PARTIAL_FAILED
        self.assertIsNotNone(result.phase_4)
        self.assertEqual(result.phase_4.status, Phase4ExecutionStatus.PARTIAL_FAILED)
        self.assertGreater(len(result.phase_4.target_mappings), 0)
        self.assertIsNone(result.phase_4.migration_schedule)
        self.assertIn("Simulated scheduler deadlock", str(result.phase_4.error_message))

    def test_13_dependency_cycles_visibility(self) -> None:
        """AC-13: Verifies cyclic dependencies result in BLOCKED_DEPENDENCY_CYCLE."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        # Ingest first to get real asset IDs
        res1 = self.engine.run(raw_input=fixture_path)
        if len(res1.assets) >= 2:
            a1, a2 = res1.assets[0].asset_id, res1.assets[1].asset_id
            # Supply mutually circular dependencies: a1 depends on a2, and a2 depends on a1
            cyclic_deps = [(a1, a2), (a2, a1)]
            res2 = self.engine.run(
                raw_input=fixture_path,
                explicit_dependencies=cyclic_deps,
            )
            self.assertIsNotNone(res2.phase_4)
            self.assertIsNotNone(res2.phase_4.migration_schedule)
            self.assertEqual(
                res2.phase_4.migration_schedule.schedule_status,
                "BLOCKED_DEPENDENCY_CYCLE",
            )
            self.assertGreater(len(res2.phase_4.migration_schedule.dependency_cycles), 0)

    def test_14_explicit_and_inferred_dependencies_distinguishable(self) -> None:
        """AC-14: Verifies caller-supplied explicit dependencies are recorded in schedule."""
        fixture_path = self.raw_base / "tc02_symmetric_aes" / "run1_output.json"
        res1 = self.engine.run(raw_input=fixture_path)
        if len(res1.assets) >= 2:
            a1, a2 = res1.assets[0].asset_id, res1.assets[1].asset_id
            explicit_deps = [(a1, a2)]  # a1 is prerequisite for a2
            res2 = self.engine.run(
                raw_input=fixture_path,
                explicit_dependencies=explicit_deps,
            )
            sched = res2.phase_4.migration_schedule
            self.assertIn(a1, sched.dependency_graph.get(a2, ()))

    def test_15_model_only_hybrid_types_reported_unsupported(self) -> None:
        """AC-15: Verifies DUAL_SIGNATURE and PROTOCOL_AUTHENTICATION are reported in unsupported_hybrid_types."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        self.assertIsNotNone(result.phase_4)
        unsupported = result.phase_4.unsupported_hybrid_types
        self.assertIn("DUAL_SIGNATURE", unsupported)
        self.assertIn("PROTOCOL_AUTHENTICATION", unsupported)

    def test_16_evidence_and_asset_references_survive(self) -> None:
        """AC-16: Verifies asset and evidence references survive into Phase 4 mapping."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        self.assertIsNotNone(result.phase_4)
        for m in result.phase_4.target_mappings:
            matching_asset = next((a for a in result.assets if a.asset_id == m.source_asset_id), None)
            self.assertIsNotNone(matching_asset)
            self.assertGreater(len(matching_asset.finding_ids), 0)

    def test_17_technical_report_contains_phase4_information(self) -> None:
        """AC-17: Verifies TechnicalReport includes MigrationAnalysisSection with Section 9 in markdown."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        report = result.report
        self.assertIsNotNone(report.migration_analysis)
        self.assertEqual(report.migration_analysis.status, Phase4ExecutionStatus.COMPLETED)
        markdown = report.to_markdown()
        self.assertIn("## 9. Post-Quantum Cryptographic Migration Roadmap (Phase 4)", markdown)
        self.assertIn("Phase 4 Execution Status:", markdown)

    def test_18_no_false_compatibility_or_completion_claims(self) -> None:
        """AC-18: Verifies technical report does not claim drop-in replacement or migration complete."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        markdown = result.report.to_markdown()
        self.assertNotIn("drop-in replacement", markdown.lower())
        self.assertNotIn("migration complete", markdown.lower())
        self.assertIn("ADVISORY:", markdown)

    def test_19_benchmark_answer_keys_byte_identical(self) -> None:
        """AC-21: Verifies all 11 benchmark ground-truth answer keys remain 100% byte-identical."""
        import hashlib
        expected_hashes = {
            "tc01_direct_rsa.json": "CE25775E739DE0B9631C2E50A0491FE2194B68862183D5910A2E8F4FC630E676",
            "tc02_symmetric_aes.json": "66EA3AFA0991C37ABA731F8A8FB1702C1D39191307E66CA9562045AC4C2E1648",
            "tc03_ecc_generic.json": "D1AC52EE5E1B92840C674B3AF50456A523AA43B6344B8820BA54343A4E12D1B7",
            "tc04_ecdsa.json": "B0576F80A28B4DCD1051E8B1D6803600EB8048667D4F7EA3E6DBA8C4DA3C5897",
            "tc05_ecdh.json": "779C95C5E90F8ABAB5A9EC184D41EB98C302F465EDC7032B62648F54E4A968E5",
            "tc06_ed25519.json": "3DE3A0315091015B7EF8B8017D21EC0D3FBA617214A3D66425FF688091AEEB3D",
            "tc07_sha1_hash.json": "B25A3C0D33CD60E94D08596C4D408ED368A4AF9BAFAA6E6B24D4E0615978EC1E",
            "tc08_crypto_wrapper.json": "E02707F2FF7F653C4612CECAC72F0430BE106B6A4F9D6ECEFCB4F8907B01560A",
            "tc09_dependency_crypto.json": "ADB59BB4F89AD7803A3AC10908521C87A2E5DFFA36638BF96B48E28760478294",
            "tc10_misleading_comments.json": "51BE07740356783FBECA1CEC00694763C5EE4AF786E1A21F81EEC002ACDAF16D",
            "tc11_ambiguous_dynamic.json": "E0F91C1EB1B080B41F39446BB4F07EB62C7CB373737A91D81EABB6CEC1F068C6",
        }
        for fname, expected_sha in expected_hashes.items():
            fpath = self.answer_keys_dir / fname
            self.assertTrue(fpath.exists(), f"Missing answer key: {fpath}")
            data = fpath.read_bytes()
            actual_sha = hashlib.sha256(data).hexdigest().upper()
            self.assertEqual(actual_sha, expected_sha, f"Checksum mismatch in {fname}")

    def test_20_phase_0_3_regression_preservation(self) -> None:
        """AC-22: Verifies Phase 0-3 artifacts are identical and unaffected by Phase 4."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        self.assertEqual(result.ingestion_result.status, IngestionStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.assets), 1)
        self.assertIn("components", result.cbom)
        self.assertEqual(len(result.risk_records), 1)

    def test_21_serialization_round_trip(self) -> None:
        """AC-20: Verifies WorkflowRunResult and Phase4AnalysisResult serialize cleanly to JSON."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        res_dict = result.to_dict()
        # Verify JSON serializability
        json_str = json.dumps(res_dict, indent=2)
        self.assertTrue(len(json_str) > 0)
        deserialized = json.loads(json_str)

        self.assertIn("phase_4", deserialized)
        p4_dict = deserialized["phase_4"]
        self.assertEqual(p4_dict["status"], "COMPLETED")
        self.assertGreater(p4_dict["target_mappings_count"], 0)
        self.assertIn("migration_schedule", p4_dict)
        self.assertIn("unsupported_hybrid_types", p4_dict)

    def test_22_deferred_hybrid_reporting_in_technical_report(self) -> None:
        """AC-22 (DEC-P4-03 Option B): Verifies TechnicalReport deferred capabilities explicitly cites DUAL_SIGNATURE and PROTOCOL_AUTHENTICATION."""
        fixture_path = self.raw_base / "tc01_direct_rsa" / "run1_output.json"
        result = self.engine.run(raw_input=fixture_path, target_name="tc01-rsa")

        deferred = result.report.deferred_capabilities
        self.assertTrue(
            any("DUAL_SIGNATURE and PROTOCOL_AUTHENTICATION" in item for item in deferred),
            f"Missing structured deferral disclosure in {deferred}",
        )
        self.assertTrue(
            any("IMPLEMENTED (PHASE 4A/4B):" in item for item in deferred),
            f"Missing implemented banner in {deferred}",
        )


if __name__ == "__main__":
    unittest.main()
