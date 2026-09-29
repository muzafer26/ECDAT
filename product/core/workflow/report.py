"""
ECDAT Technical Report Generator.

Synthesizes the complete end-to-end execution across ingestion, evidence,
canonical inventory, CBOM projection, and risk analysis into an auditable report.
"""

from collections import Counter
from typing import Any, Dict, List, Mapping, Optional, Sequence

from product.core.domain.asset import CryptoAsset
from product.core.domain.finding import Finding
from product.core.domain.observation import ObservationType
from product.core.ingestion.adapter import IngestionResult, IngestionStatus
from product.core.risk.models import AssetContext, MigrationPriorityRecord
from .models import (
    MigrationAnalysisSection,
    Phase4AnalysisResult,
    Phase4ExecutionStatus,
    TechnicalReport,
)


class TechnicalReportGenerator:
    """
    Assembles an auditable, deterministic TechnicalReport from pipeline artifacts.
    """

    @classmethod
    def generate(
        cls,
        run_id: str,
        timestamp: str,
        target_name: str,
        ingestion_result: IngestionResult,
        findings: Sequence[Finding],
        assets: Sequence[CryptoAsset],
        cbom: Dict[str, Any],
        risk_records: Sequence[MigrationPriorityRecord],
        context: Optional[AssetContext] = None,
        raw_output_sha256: Optional[str] = None,
        phase_4: Optional[Phase4AnalysisResult] = None,
    ) -> TechnicalReport:
        meta = ingestion_result.scan_metadata

        # 1. Scanner Attribution
        effective_raw_hash = raw_output_sha256 or (
            ingestion_result.raw_output_ref[len("sha256:"):]
            if ingestion_result.raw_output_ref.startswith("sha256:")
            else ingestion_result.raw_output_ref
        ) or "none"

        scanner_attribution: Dict[str, str] = {
            "scanner_name": meta.scanner_name if meta else "unknown",
            "scanner_version": meta.scanner_version if meta else "unknown",
            "adapter_id": meta.adapter_id if meta else "unknown",
            "raw_output_ref": ingestion_result.raw_output_ref or "none",
            "raw_output_sha256": effective_raw_hash,
        }

        # 2. Evidence Summary
        decoys = sum(
            1 for f in findings
            if f.observation_type in (ObservationType.NON_CRYPTOGRAPHIC_DECOY, ObservationType.COMMENT_ONLY)
        )
        evidence_summary: Dict[str, Any] = {
            "total_evidence_records": len(ingestion_result.evidence_records),
            "total_findings": len(findings),
            "decoys_filtered": decoys,
            "canonical_assets_count": len(assets),
        }

        # 3. CBOM Summary
        cbom_summary: Dict[str, Any] = {
            "spec_version": str(cbom.get("specVersion", "1.7")),
            "bom_format": str(cbom.get("bomFormat", "CycloneDX")),
            "serial_number": str(cbom.get("serialNumber", "")),
            "components_count": len(cbom.get("components", [])),
        }

        # 4. Risk Summary
        cat_counts: Dict[str, int] = Counter(r.risk_category.value for r in risk_records)
        cause_counts: Dict[str, int] = Counter(r.primary_cause.value for r in risk_records)
        risk_summary: Dict[str, Any] = {
            "category_distribution": dict(cat_counts),
            "cause_distribution": dict(cause_counts),
        }

        # 5. Priority Summary
        prio_counts: Dict[str, int] = Counter(r.default_priority.value for r in risk_records)
        priority_summary: Dict[str, Any] = {
            "priority_distribution": dict(prio_counts),
            "p0_immediate_action_count": prio_counts.get("P0_IMMEDIATE_ACTION", 0),
            "p1_near_term_migration_count": prio_counts.get("P1_NEAR_TERM_MIGRATION", 0),
            "p2_planned_transition_count": prio_counts.get("P2_PLANNED_TRANSITION", 0),
            "p3_opportunistic_quick_win_count": prio_counts.get("P3_OPPORTUNISTIC_QUICK_WIN", 0),
            "p4_deferred_monitoring_count": prio_counts.get("P4_DEFERRED_MONITORING", 0),
            "p_review_required_count": prio_counts.get("P_REVIEW_REQUIRED", 0),
        }

        # 6. Uncertainty and Gaps (Deduplicated)
        gaps: List[str] = []
        for r in risk_records:
            for gap in r.explanation.missing_facts_and_questions:
                if gap not in gaps:
                    gaps.append(gap)
        if not assets and findings:
            gaps.append("All observations were filtered as non-cryptographic decoys or comments; zero cryptographic assets instantiated.")
        if not findings and ingestion_result.evidence_records:
            gaps.append("Raw evidence was present but could not be normalized into findings.")
        if ingestion_result.status == IngestionStatus.NO_FINDINGS:
            gaps.append(
                "NOTICE (ZERO CONFIRMED FINDINGS): The scanner completed execution with zero reported cryptographic findings. "
                "This indicates zero static AST matches detected by this tool, NOT proof that the application is cryptographically safe "
                "or free of runtime, dynamic, or unmodeled cryptographic operations."
            )
        elif ingestion_result.status == IngestionStatus.PARTIAL:
            gaps.append("PARTIAL SCAN: Scanner coverage was incomplete; some files or scopes could not be analyzed.")
        elif ingestion_result.status == IngestionStatus.PARSER_ERROR:
            gaps.append("PARSER ERROR: Scanner raw output could not be completely parsed.")
        elif ingestion_result.status == IngestionStatus.INVALID_INPUT:
            gaps.append("INVALID INPUT: Target path or scanner payload rejected by validation.")

        # 7. Triggered Authorities (Deduplicated)
        authorities: List[Dict[str, str]] = []
        seen_rules = set()
        for r in risk_records:
            for rule in r.explanation.triggered_rules:
                r_id = rule.get("rule_id", "")
                if r_id and r_id not in seen_rules:
                    seen_rules.add(r_id)
                    authorities.append(dict(rule))

        # 8. Deferred Capabilities Notice
        deferred_capabilities: List[str] = [
            "DEFERRED: Multi-dimensional HNDL matrix evaluation (requires network exposure authority & adversary capture feasibility)",
            "DEFERRED: Mosca planning horizon heuristic X + Y > Z (requires enterprise transition deadline Z)",
            "DEFERRED: Enterprise signed policy overrides (requires HMAC-SHA256 authorization registry)",
            "IMPLEMENTED (PHASE 3C-C): Classical cryptographic policy for RSA and SHA-1 (NIST SP 800-131A Rev 2 aligned fail-safe classification)",
        ]

        if phase_4 is not None and phase_4.status in (
            Phase4ExecutionStatus.COMPLETED,
            Phase4ExecutionStatus.PARTIAL_FAILED,
            Phase4ExecutionStatus.SKIPPED_NO_ASSETS,
        ):
            deferred_capabilities.append(
                "IMPLEMENTED (PHASE 4A/4B): Role-aware PQC replacement target mapping (NIST FIPS 203/204/205) and dependency-aware migration scheduling"
            )
            deferred_capabilities.append(
                "DEFERRED (MODEL-ONLY): DUAL_SIGNATURE and PROTOCOL_AUTHENTICATION hybrid constructions remain model tokens without candidate generation (deferred to future scope)"
            )
        else:
            deferred_capabilities.append(
                "DEFERRED: Extended asymmetric and hash primitives (DH/FFDH, ECDSA, ECDH, Ed25519, X25519, SHA-2/3, PQC replacement mapping)"
            )

        # 9. Detailed Findings Traceability
        detailed_findings: List[Dict[str, Any]] = []
        # Map records by asset_id
        record_map = {r.asset_id: r for r in risk_records}
        for asset in assets:
            rec = record_map.get(asset.asset_id)
            if rec:
                exp = rec.explanation
                detailed_findings.append({
                    "asset_id": asset.asset_id,
                    "bom_ref": f"ecdat:asset:{asset.asset_id}",
                    "algorithm": f"{asset.algorithm_identity.family.value} ({asset.algorithm_identity.algorithm})",
                    "key_size_bits": asset.parameters.key_size_bits,
                    "role": asset.role.value,
                    "confidence": asset.confidence.value,
                    "finding_ids": list(asset.finding_ids),
                    "code_locations": list(exp.code_locations),
                    "risk_category": rec.risk_category.value,
                    "priority": rec.default_priority.value,
                    "uncertainty_level": exp.uncertainty_level,
                    "rules_applied": [rule.get("rule_id") for rule in exp.triggered_rules],
                    "remediation_summary": exp.actionable_remediation_summary,
                })

        # 10. Migration Analysis Section (Phase 4)
        migration_analysis: Optional[MigrationAnalysisSection] = None
        if phase_4 is not None:
            mappings_summary: List[Dict[str, Any]] = []
            pqc_rec = 0
            oos_count = 0
            rev_count = 0
            for m in phase_4.target_mappings:
                status_str = m.mapping_status.value if hasattr(m.mapping_status, "value") else str(m.mapping_status)
                if status_str in ("RECOMMENDED_PQC", "MAPPED"):
                    pqc_rec += 1
                elif status_str == "OUT_OF_SCOPE":
                    oos_count += 1
                else:
                    rev_count += 1

                targets_desc = [f"{t.parameter_set} ({t.standard})" for t in m.candidate_targets]
                mappings_summary.append({
                    "source_asset_id": m.source_asset_id,
                    "source_algorithm": m.source_algorithm,
                    "source_role": m.source_role,
                    "status": status_str,
                    "candidate_targets": targets_desc,
                    "hybrid_options_count": len(m.hybrid_candidates),
                    "rationale": m.mapping_rationale,
                    "required_human_review": m.required_human_review,
                })

            sched = phase_4.migration_schedule
            milestones_summary: List[Dict[str, Any]] = []
            gates_summary: List[Dict[str, Any]] = []
            sched_status = sched.schedule_status if sched else "NOT_SCHEDULED"
            blocking_gates = 0
            if sched:
                for ms in sched.milestones:
                    milestones_summary.append({
                        "milestone_id": ms.milestone_id,
                        "phase": ms.phase.value if hasattr(ms.phase, "value") else str(ms.phase),
                        "title": ms.title,
                        "target_asset_ids": list(ms.target_asset_ids),
                        "review_gates_count": len(ms.review_gates),
                        "blockers_count": len(ms.blockers),
                    })
                blocking_gates = len(sched.review_gates)
                for gate in sched.review_gates:
                    gates_summary.append({
                        "gate_id": gate.gate_id,
                        "asset_id": gate.asset_id,
                        "reason": gate.reason,
                        "evidence_summary": gate.evidence_summary,
                        "missing_information": gate.missing_information,
                        "consequence_if_unresolved": gate.consequence_if_unresolved,
                    })

            migration_analysis = MigrationAnalysisSection(
                status=phase_4.status,
                total_assets=len(phase_4.target_mappings),
                pqc_recommended_count=pqc_rec,
                out_of_scope_count=oos_count,
                needs_review_count=rev_count,
                total_milestones=len(milestones_summary),
                blocking_gates_count=blocking_gates,
                schedule_status=sched_status,
                target_mappings_summary=tuple(mappings_summary),
                milestones_summary=tuple(milestones_summary),
                review_gates_summary=tuple(gates_summary),
                unsupported_hybrid_types=phase_4.unsupported_hybrid_types,
            )

        return TechnicalReport(
            run_id=run_id,
            timestamp=timestamp,
            target_name=target_name,
            execution_status=ingestion_result.status.value,
            scanner_attribution=scanner_attribution,
            evidence_summary=evidence_summary,
            cbom_summary=cbom_summary,
            risk_summary=risk_summary,
            priority_summary=priority_summary,
            uncertainty_and_gaps=tuple(gaps),
            triggered_authorities=tuple(authorities),
            deferred_capabilities=tuple(deferred_capabilities),
            detailed_findings=tuple(detailed_findings),
            migration_analysis=migration_analysis,
        )
