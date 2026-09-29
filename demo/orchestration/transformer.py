"""
ECDAT Demo Result Transformer.

Transforms internal WorkflowRunResult dataclasses into clean, presentation-safe,
serializable DemoRunResult objects while preserving the full provenance chain,
contextual risk explanation, and migration scheduling details.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from product.core.workflow.models import WorkflowRunResult
from .models import (
    DemoAssetSummary,
    DemoEvidenceSummary,
    DemoExecutionStatus,
    DemoFindingSummary,
    DemoMigrationSummary,
    DemoRiskSummary,
    DemoRunResult,
    ProvenanceNode,
    ProvenanceSourceType,
)


def _normalize_display_path(raw_path: Optional[str]) -> str:
    """Normalizes host absolute paths into clean, relative repository paths."""
    if not raw_path:
        return "unknown"
    normalized = raw_path.replace("\\", "/")
    # If path contains 'product/', trim leading absolute drive/user folders
    idx = normalized.find("product/")
    if idx != -1:
        return normalized[idx:]
    # If path contains 'demo/', trim leading path
    idx_demo = normalized.find("demo/")
    if idx_demo != -1:
        return normalized[idx_demo:]
    # If already a clean relative path without drive letters or root slashes
    if not (":" in normalized or normalized.startswith("/")):
        return normalized
    # Otherwise return file basename
    return Path(raw_path).name


class DemoResultTransformer:
    """Transforms frozen ECDAT WorkflowRunResult into presentation-safe DemoRunResult."""

    @staticmethod
    def transform(
        result: WorkflowRunResult,
        scenario_id: str,
        classification: str,
        execution_time_ms: float = 0.0,
        known_limitations: Optional[List[str]] = None,
        scenario_metadata: Optional[Dict[str, Any]] = None,
    ) -> DemoRunResult:
        sec_meta = scenario_metadata or {}
        org_name = sec_meta.get("organization")
        sys_name = sec_meta.get("system")
        comp_name = sec_meta.get("component")
        biz_crit = sec_meta.get("business_criticality")
        data_sens = sec_meta.get("data_sensitivity")
        data_life = sec_meta.get("data_lifetime")
        net_exp = sec_meta.get("network_exposure")
        env_name = sec_meta.get("environment")

        # 1. Build lookup dictionaries
        evidence_map = {e.evidence_id: e for e in result.ingestion_result.evidence_records}
        finding_map = {f.finding_id: f for f in result.findings}
        risk_map = {r.asset_id: r for r in result.risk_records}

        target_mapping_map = {}
        if result.phase_4 and result.phase_4.target_mappings:
            for tm in result.phase_4.target_mappings:
                target_mapping_map[tm.source_asset_id] = tm

        # 2. Transform Evidence Records
        evidence_summaries: List[DemoEvidenceSummary] = []
        for e in result.ingestion_result.evidence_records:
            loc = e.location
            file_path = getattr(loc, "file_path", None)
            display_file = _normalize_display_path(file_path) if file_path else None
            line_start = getattr(loc, "line_start", None)
            line_end = getattr(loc, "line_end", None)
            matched_text = getattr(loc, "matched_text", "")
            code_snippet = getattr(loc, "code_snippet", "")
            loc_type = loc.location_type.value if hasattr(loc, "location_type") else "source"

            evidence_summaries.append(
                DemoEvidenceSummary(
                    evidence_id=e.evidence_id,
                    scanner_name=e.scanner_name,
                    scanner_version=e.scanner_version,
                    detection_method=e.detection_method.value if hasattr(e.detection_method, "value") else str(e.detection_method),
                    location_type=loc_type,
                    file_path=display_file,
                    line_start=line_start,
                    line_end=line_end,
                    matched_text=matched_text,
                    code_snippet=code_snippet,
                    scanner_category=e.scanner_category,
                    scanner_confidence=e.scanner_confidence,
                    timestamp=e.timestamp,
                )
            )

        # 3. Transform Findings
        finding_summaries: List[DemoFindingSummary] = []
        for f in result.findings:
            loc = f.primary_location
            file_path = getattr(loc, "file_path", "unknown")
            display_file = _normalize_display_path(file_path)
            line_start = getattr(loc, "line_start", 0)
            loc_display = f"{display_file}:{line_start}" if line_start else display_file

            finding_summaries.append(
                DemoFindingSummary(
                    finding_id=f.finding_id,
                    evidence_ids=list(f.evidence_ids),
                    observation_type=f.observation_type.value if hasattr(f.observation_type, "value") else str(f.observation_type),
                    family=f.algorithm_identity.family.value if hasattr(f.algorithm_identity.family, "value") else str(f.algorithm_identity.family),
                    algorithm=f.algorithm_identity.algorithm,
                    role=f.role.value if hasattr(f.role, "value") else str(f.role),
                    confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    disposition=f.disposition.value if hasattr(f.disposition, "value") else str(f.disposition),
                    location_display=loc_display,
                    interpretation_basis=f.interpretation_basis,
                )
            )

        # 4. Transform Crypto Assets
        asset_summaries: List[DemoAssetSummary] = []
        provenance_chains: List[List[ProvenanceNode]] = []

        for asset in result.assets:
            loc = asset.primary_location
            file_path = getattr(loc, "file_path", "unknown")
            display_file = _normalize_display_path(file_path)
            line_start = getattr(loc, "line_start", 0)
            loc_display = f"{display_file}:{line_start}" if line_start else display_file

            # Gather all evidence IDs linked through this asset's findings
            linked_evidence_ids: List[str] = []
            for fid in asset.finding_ids:
                if fid in finding_map:
                    linked_evidence_ids.extend(finding_map[fid].evidence_ids)

            # Match risk
            risk_rec = risk_map.get(asset.asset_id)
            priority_tier = None
            risk_cat = None
            primary_cause = None
            classical_status = None
            quantum_exposure_class = None
            uncertainty_level = None
            remediation_summary = None
            observed_facts = []
            triggered_rules = []
            assumptions = []
            missing_facts = []
            review_required_risk = False
            if risk_rec:
                priority_tier = risk_rec.effective_priority.value if hasattr(risk_rec.effective_priority, "value") else str(risk_rec.effective_priority)
                risk_cat = risk_rec.risk_category.value if hasattr(risk_rec.risk_category, "value") else str(risk_rec.risk_category)
                primary_cause = risk_rec.primary_cause.value if hasattr(risk_rec.primary_cause, "value") else str(risk_rec.primary_cause)
                if hasattr(risk_rec, "explanation") and risk_rec.explanation:
                    expl = risk_rec.explanation
                    classical_status = getattr(expl, "classical_status", None)
                    quantum_exposure_class = getattr(expl, "quantum_exposure_class", None)
                    uncertainty_level = getattr(expl, "uncertainty_level", None)
                    remediation_summary = getattr(expl, "actionable_remediation_summary", None)
                    observed_facts = list(getattr(expl, "observed_facts", []))
                    triggered_rules = [dict(r) for r in getattr(expl, "triggered_rules", [])]
                    assumptions = list(getattr(expl, "assumptions", []))
                    missing_facts = list(getattr(expl, "missing_facts_and_questions", []))
                review_required_risk = getattr(risk_rec, "mandatory_review_required", False)

            # Match PQC target mapping
            mapping = target_mapping_map.get(asset.asset_id)
            pqc_mapping_status = mapping.mapping_status.value if mapping and hasattr(mapping.mapping_status, "value") else None
            candidate_targets = [t.parameter_set for t in mapping.candidate_targets] if mapping else []
            target_details = [t.to_dict() for t in mapping.candidate_targets] if mapping else []
            mapping_rationale = mapping.mapping_rationale if mapping else None
            standards_references = list(mapping.standards_references) if mapping else []
            agility_level = None
            agility_factors = []
            review_reasons = []
            if mapping:
                if hasattr(mapping.agility_assessment, "agility_level"):
                    ag_lvl = mapping.agility_assessment.agility_level
                    agility_level = ag_lvl.value if hasattr(ag_lvl, "value") else str(ag_lvl)
                if hasattr(mapping.agility_assessment, "evidenced_factors"):
                    agility_factors = list(mapping.agility_assessment.evidenced_factors)
                review_reasons = list(mapping.assumptions_and_questions)
            requires_human_review = (mapping.required_human_review if mapping else False) or review_required_risk
            hybrid_candidates = [h.to_dict() for h in mapping.hybrid_candidates] if (mapping and mapping.hybrid_candidates) else []

            asset_summaries.append(
                DemoAssetSummary(
                    asset_id=asset.asset_id,
                    asset_type=asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type),
                    family=asset.algorithm_identity.family.value if hasattr(asset.algorithm_identity.family, "value") else str(asset.algorithm_identity.family),
                    algorithm=asset.algorithm_identity.algorithm,
                    role=asset.role.value if hasattr(asset.role, "value") else str(asset.role),
                    key_size_bits=asset.parameters.key_size_bits,
                    curve_name=asset.parameters.curve_name,
                    confidence=asset.confidence.value if hasattr(asset.confidence, "value") else str(asset.confidence),
                    location_display=loc_display,
                    correlation_basis=asset.correlation_basis,
                    finding_ids=list(asset.finding_ids),
                    evidence_ids=list(dict.fromkeys(linked_evidence_ids)),
                    priority_tier=priority_tier,
                    risk_category=risk_cat,
                    primary_risk_cause=primary_cause,
                    classical_status=classical_status,
                    quantum_exposure_class=quantum_exposure_class,
                    uncertainty_level=uncertainty_level,
                    remediation_summary=remediation_summary,
                    observed_facts=observed_facts,
                    triggered_rules=triggered_rules,
                    assumptions=assumptions,
                    missing_facts=missing_facts,
                    pqc_mapping_status=pqc_mapping_status,
                    candidate_targets=candidate_targets,
                    target_details=target_details,
                    mapping_rationale=mapping_rationale,
                    standards_references=standards_references,
                    agility_level=agility_level,
                    agility_factors=agility_factors,
                    requires_human_review=requires_human_review,
                    review_reasons=review_reasons,
                    organization=org_name,
                    system=sys_name,
                    component=comp_name,
                    business_criticality=biz_crit,
                    data_sensitivity=data_sens,
                    data_lifetime=data_life,
                    network_exposure=net_exp,
                    environment=env_name,
                    hybrid_candidates=hybrid_candidates,
                    context_provenance=sec_meta.get("context_provenance", ProvenanceSourceType.CONTROLLED_SCENARIO_CONTEXT.value),
                    benchmark_ground_truth={
                        "tc01_direct_rsa": {
                            "benchmark_id": "TC-01",
                            "source_fixture": "product/benchmark/corpus/seed/tc01_direct_rsa/DirectRSAKeyGen.java",
                            "ground_truth_key_size_bits": 2048,
                            "scanner_evidence_status": "UNEVIDENCED_IN_AST",
                            "explanation": "Benchmark ground truth contains 2048-bit initialization (keyGen.initialize(2048)), but scanner AST evidence did not establish key size.",
                        },
                        "tc02_symmetric_aes": {
                            "benchmark_id": "TC-02",
                            "source_fixture": "product/benchmark/corpus/seed/tc02_symmetric_aes/DirectAESCipher.java",
                            "ground_truth_key_size_bits": None,
                            "scanner_evidence_status": "UNEVIDENCED_IN_AST",
                            "explanation": "Symmetric AES-GCM cipher; evaluated OUT_OF_SCOPE for public-key PQC.",
                        },
                        "tc06_ed25519": {
                            "benchmark_id": "TC-06",
                            "source_fixture": "product/benchmark/corpus/seed/tc06_ed25519/DirectEd25519Signature.java",
                            "ground_truth_curve": "ed25519",
                            "scanner_evidence_status": "CONFIRMED_IN_AST",
                            "explanation": "Edwards curve digital signature; mapped to NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA).",
                        },
                    }.get(scenario_id),
                )
            )

            # Build Provenance Trace Chain for this Asset
            chain: List[ProvenanceNode] = []
            # Step 1: Scanner (Direct core ingestion metadata)
            scanner_name = result.ingestion_result.scan_metadata.scanner_name or "Discovery Scanner"
            scanner_ver = result.ingestion_result.scan_metadata.scanner_version or "1.0"
            chain.append(
                ProvenanceNode(
                    step="scanner",
                    entity_id=scanner_name,
                    label=f"Scanner: {scanner_name} (v{scanner_ver})",
                    source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                    details={
                        "scanner_name": scanner_name,
                        "scanner_version": scanner_ver,
                        "adapter_id": result.ingestion_result.scan_metadata.adapter_id,
                    },
                )
            )

            # Step 2: Evidence Records (Direct core empirical observations)
            for ev_id in linked_evidence_ids:
                if ev_id in evidence_map:
                    ev = evidence_map[ev_id]
                    ev_loc_str = _normalize_display_path(getattr(ev.location, "file_path", ""))
                    chain.append(
                        ProvenanceNode(
                            step="raw_evidence",
                            entity_id=ev.evidence_id,
                            label=f"Raw Evidence: {ev.scanner_category} via {ev.detection_method.value}",
                            source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                            details={
                                "location": ev_loc_str,
                                "matched_text": getattr(ev.location, "matched_text", ""),
                                "category": ev.scanner_category,
                                "line_start": getattr(ev.location, "line_start", None),
                            },
                        )
                    )

            # Step 3: Finding (Direct core normalization finding)
            for fid in asset.finding_ids:
                if fid in finding_map:
                    f = finding_map[fid]
                    chain.append(
                        ProvenanceNode(
                            step="finding",
                            entity_id=f.finding_id,
                            label=f"Finding: {f.algorithm_identity.algorithm} ({f.confidence.value})",
                            source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                            details={
                                "algorithm": f.algorithm_identity.algorithm,
                                "role": f.role.value,
                                "confidence": f.confidence.value,
                            },
                        )
                    )

            # Step 4: Canonical Asset (Direct core canonical asset)
            chain.append(
                ProvenanceNode(
                    step="crypto_asset",
                    entity_id=asset.asset_id,
                    label=f"Asset: {asset.algorithm_identity.family.value} ({asset.role.value})",
                    source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                    details={
                        "family": asset.algorithm_identity.family.value,
                        "key_size": asset.parameters.key_size_bits,
                        "confidence": asset.confidence.value,
                    },
                )
            )

            # Step 5: Risk (Direct core risk & priority assessment)
            if risk_rec:
                tier_val = risk_rec.effective_priority.value if hasattr(risk_rec.effective_priority, "value") else str(risk_rec.effective_priority)
                cat_val = risk_rec.risk_category.value if hasattr(risk_rec.risk_category, "value") else str(risk_rec.risk_category)
                cause_val = risk_rec.primary_cause.value if hasattr(risk_rec.primary_cause, "value") else str(risk_rec.primary_cause)
                chain.append(
                    ProvenanceNode(
                        step="risk",
                        entity_id=asset.asset_id,
                        label=f"Risk: Priority {tier_val} ({cat_val})",
                        source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                        details={
                            "priority_tier": tier_val,
                            "risk_category": cat_val,
                            "primary_cause": cause_val,
                            "actionable_remediation": remediation_summary or "",
                        },
                    )
                )

            # Step 6: Migration Candidate (Direct core Phase 4A target mapping)
            if mapping:
                targets_str = ", ".join([t.parameter_set for t in mapping.candidate_targets]) or "None"
                chain.append(
                    ProvenanceNode(
                        step="migration",
                        entity_id=asset.asset_id,
                        label=f"Target: {mapping.mapping_status.value} -> {targets_str}",
                        source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                        details={
                            "mapping_status": mapping.mapping_status.value,
                            "candidate_targets": candidate_targets,
                            "review_required": mapping.required_human_review,
                        },
                    )
                )

            # Step 7: Migration Schedule (Direct core Phase 4B milestone)
            if result.phase_4 and result.phase_4.migration_schedule:
                sched = result.phase_4.migration_schedule
                asset_milestones = [m.milestone_id for m in sched.milestones if asset.asset_id in getattr(m, "target_asset_ids", ())]
                if asset_milestones:
                    chain.append(
                        ProvenanceNode(
                            step="schedule",
                            entity_id=asset.asset_id,
                            label=f"Milestone: {asset_milestones[0]} (Schedule: {sched.schedule_status})",
                            source_type=ProvenanceSourceType.DIRECT_CORE_OUTPUT.value,
                            details={
                                "milestones": asset_milestones,
                                "schedule_status": sched.schedule_status,
                            },
                        )
                    )

            provenance_chains.append(chain)

        # 5. Risk Summary
        crit_cnt = sum(1 for r in result.risk_records if r.effective_priority.value == "CRITICAL")
        high_cnt = sum(1 for r in result.risk_records if r.effective_priority.value == "HIGH")
        med_cnt = sum(1 for r in result.risk_records if r.effective_priority.value == "MEDIUM")
        low_cnt = sum(1 for r in result.risk_records if r.effective_priority.value == "LOW")
        info_cnt = sum(1 for r in result.risk_records if r.effective_priority.value == "INFORMATIONAL")
        mand_cnt = sum(1 for r in result.risk_records if r.mandatory_review_required)

        risk_summary = DemoRiskSummary(
            total_assets_evaluated=len(result.risk_records),
            critical_priority_count=crit_cnt,
            high_priority_count=high_cnt,
            medium_priority_count=med_cnt,
            low_priority_count=low_cnt,
            informational_priority_count=info_cnt,
            mandatory_review_count=mand_cnt,
        )

        # 6. Migration Summary with Milestones & Review Gates
        p4 = result.phase_4
        if p4:
            pqc_rec_cnt = sum(1 for m in p4.target_mappings if m.mapping_status.value in ("STANDARDIZED_DIRECT", "CONDITIONAL"))
            oos_cnt = sum(1 for m in p4.target_mappings if m.mapping_status.value == "OUT_OF_SCOPE")
            rev_cnt = sum(1 for m in p4.target_mappings if m.required_human_review or m.mapping_status.value == "NEEDS_REVIEW")
            milestones_cnt = len(p4.migration_schedule.milestones) if p4.migration_schedule else 0
            blocking_cnt = len(p4.migration_schedule.review_gates) if p4.migration_schedule else 0
            sched_status = p4.migration_schedule.schedule_status if p4.migration_schedule else "UNAVAILABLE"
            advisory = (
                "ADVISORY: Migration targets and schedule are decision-support models based on observed "
                "evidence and standards compliance. They do not constitute drop-in binary replacements."
            )
            candidate_summaries = []
            for tm in p4.target_mappings:
                candidate_summaries.append({
                    "asset_id": tm.source_asset_id,
                    "family": tm.source_family,
                    "status": tm.mapping_status.value,
                    "targets": [t.parameter_set for t in tm.candidate_targets],
                    "requires_review": tm.required_human_review,
                })

            sched_milestones = [ms.to_dict() for ms in p4.migration_schedule.milestones] if p4.migration_schedule else []
            sched_review_gates = [rg.to_dict() for rg in p4.migration_schedule.review_gates] if p4.migration_schedule else []
            sched_blocked = list(p4.migration_schedule.blocked_assets) if p4.migration_schedule else []

            migration_summary = DemoMigrationSummary(
                phase_4_status=p4.status.value,
                pqc_recommended_count=pqc_rec_cnt,
                out_of_scope_count=oos_cnt,
                needs_review_count=rev_cnt,
                total_milestones=milestones_cnt,
                blocking_gates_count=blocking_cnt,
                schedule_status=sched_status,
                advisory_notice=advisory,
                candidate_target_summary=candidate_summaries,
                milestones=sched_milestones,
                review_gates=sched_review_gates,
                blocked_assets=sched_blocked,
            )
        else:
            migration_summary = DemoMigrationSummary(
                phase_4_status="NOT_RUN",
                pqc_recommended_count=0,
                out_of_scope_count=0,
                needs_review_count=0,
                total_milestones=0,
                blocking_gates_count=0,
                schedule_status="NOT_RUN",
                advisory_notice="Phase 4 analysis not run.",
                milestones=[],
                review_gates=[],
                blocked_assets=[],
            )

        # 7. CBOM Summary
        cbom_summary = {
            "bom_format": result.cbom.get("bomFormat", "CycloneDX"),
            "spec_version": result.cbom.get("specVersion", "1.7"),
            "serial_number": result.cbom.get("serialNumber", ""),
            "components_count": len(result.cbom.get("components", [])),
            "dependencies_count": len(result.cbom.get("dependencies", [])),
        }

        # 8. Known limitations
        effective_limitations = known_limitations or [
            "Benchmark TC08/TC11 scanner false negatives observed in raw scanner outputs.",
            "Empty findings indicate zero scanner observations in evaluated scope; does not certify cryptographic safety.",
            "CycloneDX Draft-07 runtime schema validation is offline two-tier; external validator deferred.",
            "Migration recommendations are decision-support models; drop-in binary replacement is not guaranteed.",
        ]

        # 9. Determine overall status
        status = DemoExecutionStatus.SUCCESS
        if result.ingestion_result.status.value in ("failed", "parser_error", "timeout"):
            status = DemoExecutionStatus.FAILED
        elif result.ingestion_result.status.value in ("partial", "invalid_input"):
            status = DemoExecutionStatus.PARTIAL

        return DemoRunResult(
            run_id=result.run_id,
            scenario_id=scenario_id,
            status=status,
            classification=classification,
            raw_input_ref=result.ingestion_result.raw_output_ref,
            scanner_name=result.ingestion_result.scan_metadata.scanner_name or ("DemoSourceScanner" if scenario_id == "demo_project" else "Discovery Scanner"),
            scanner_version=result.ingestion_result.scan_metadata.scanner_version or ("1.0.0-demo" if scenario_id == "demo_project" else "1.0"),
            execution_time_ms=round(execution_time_ms, 2),
            assets=asset_summaries,
            evidence_records=evidence_summaries,
            findings=finding_summaries,
            risk_summary=risk_summary,
            migration_summary=migration_summary,
            cbom_summary=cbom_summary,
            provenance_chain=provenance_chains,
            known_limitations=effective_limitations,
            error_message=None,
        )
