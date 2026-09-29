"""
ECDAT Workflow and Technical Report Models.

Provides immutable dataclasses for end-to-end workflow execution results
and structured, auditable technical reports.
"""

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from product.core.domain.asset import CryptoAsset
from product.core.domain.finding import Finding
from product.core.ingestion.adapter import IngestionResult
from product.core.migration.models import MigrationSchedule, PqcTargetMapping
from product.core.risk.models import MigrationPriorityRecord


class Phase4ExecutionStatus(str, Enum):
    """
    Categorical execution state of the Phase 4 migration and scheduling analysis.
    """
    COMPLETED = "COMPLETED"
    PARTIAL_FAILED = "PARTIAL_FAILED"
    FAILED = "FAILED"
    SKIPPED_NO_ASSETS = "SKIPPED_NO_ASSETS"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class MigrationAnalysisSection:
    """
    Structured summary of Phase 4 PQC migration targets, hybrid transition options,
    and dependency-aware scheduling.
    """
    status: Phase4ExecutionStatus
    total_assets: int
    pqc_recommended_count: int
    out_of_scope_count: int
    needs_review_count: int
    total_milestones: int
    blocking_gates_count: int
    schedule_status: str
    target_mappings_summary: Tuple[Mapping[str, Any], ...] = ()
    milestones_summary: Tuple[Mapping[str, Any], ...] = ()
    review_gates_summary: Tuple[Mapping[str, Any], ...] = ()
    unsupported_hybrid_types: Tuple[str, ...] = ("DUAL_SIGNATURE", "PROTOCOL_AUTHENTICATION")
    advisory_notice: str = (
        "ADVISORY: Migration targets and schedule are decision-support models based on observed "
        "evidence and standards compliance. They do not constitute drop-in binary replacements, "
        "guaranteed runtime compatibility, or approved change-management authorizations."
    )

    def __post_init__(self) -> None:
        if not isinstance(self.status, Phase4ExecutionStatus):
            object.__setattr__(self, "status", Phase4ExecutionStatus(str(self.status)))
        object.__setattr__(
            self,
            "target_mappings_summary",
            tuple(MappingProxyType(dict(m)) for m in self.target_mappings_summary),
        )
        object.__setattr__(
            self,
            "milestones_summary",
            tuple(MappingProxyType(dict(m)) for m in self.milestones_summary),
        )
        object.__setattr__(
            self,
            "review_gates_summary",
            tuple(MappingProxyType(dict(g)) for g in self.review_gates_summary),
        )
        object.__setattr__(self, "unsupported_hybrid_types", tuple(self.unsupported_hybrid_types))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "total_assets": self.total_assets,
            "pqc_recommended_count": self.pqc_recommended_count,
            "out_of_scope_count": self.out_of_scope_count,
            "needs_review_count": self.needs_review_count,
            "total_milestones": self.total_milestones,
            "blocking_gates_count": self.blocking_gates_count,
            "schedule_status": self.schedule_status,
            "target_mappings_summary": [dict(m) for m in self.target_mappings_summary],
            "milestones_summary": [dict(m) for m in self.milestones_summary],
            "review_gates_summary": [dict(g) for g in self.review_gates_summary],
            "unsupported_hybrid_types": list(self.unsupported_hybrid_types),
            "advisory_notice": self.advisory_notice,
        }


@dataclass(frozen=True)
class TechnicalReport:
    """
    Structured, auditable technical report synthesizing the end-to-end ECDAT execution.
    
    Preserves full traceability:
    Input -> Ingestion -> Evidence -> Canonical Inventory -> CBOM -> Risk Analysis -> Report
    """
    run_id: str
    timestamp: str
    target_name: str
    execution_status: str
    scanner_attribution: Mapping[str, str]
    evidence_summary: Mapping[str, Any]
    cbom_summary: Mapping[str, Any]
    risk_summary: Mapping[str, Any]
    priority_summary: Mapping[str, Any]
    uncertainty_and_gaps: Tuple[str, ...]
    triggered_authorities: Tuple[Mapping[str, str], ...]
    deferred_capabilities: Tuple[str, ...]
    detailed_findings: Tuple[Mapping[str, Any], ...]
    migration_analysis: Optional[MigrationAnalysisSection] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scanner_attribution", MappingProxyType(dict(self.scanner_attribution)))
        object.__setattr__(self, "evidence_summary", MappingProxyType(dict(self.evidence_summary)))
        object.__setattr__(self, "cbom_summary", MappingProxyType(dict(self.cbom_summary)))
        object.__setattr__(self, "risk_summary", MappingProxyType(dict(self.risk_summary)))
        object.__setattr__(self, "priority_summary", MappingProxyType(dict(self.priority_summary)))
        object.__setattr__(self, "uncertainty_and_gaps", tuple(self.uncertainty_and_gaps))
        object.__setattr__(
            self,
            "triggered_authorities",
            tuple(MappingProxyType(dict(a)) for a in self.triggered_authorities),
        )
        object.__setattr__(self, "deferred_capabilities", tuple(self.deferred_capabilities))
        object.__setattr__(
            self,
            "detailed_findings",
            tuple(MappingProxyType(dict(f)) for f in self.detailed_findings),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the technical report to a JSON-compatible dictionary."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "target_name": self.target_name,
            "execution_status": self.execution_status,
            "scanner_attribution": dict(self.scanner_attribution),
            "evidence_summary": dict(self.evidence_summary),
            "cbom_summary": dict(self.cbom_summary),
            "risk_summary": dict(self.risk_summary),
            "priority_summary": dict(self.priority_summary),
            "uncertainty_and_gaps": list(self.uncertainty_and_gaps),
            "triggered_authorities": [dict(a) for a in self.triggered_authorities],
            "deferred_capabilities": list(self.deferred_capabilities),
            "detailed_findings": [dict(f) for f in self.detailed_findings],
            "migration_analysis": self.migration_analysis.to_dict() if self.migration_analysis else None,
        }

    def to_markdown(self) -> str:
        """Formats a human-readable, auditable markdown summary."""
        lines = [
            f"# ECDAT Cryptographic Analysis & Risk Technical Report",
            f"",
            f"**Run ID:** `{self.run_id}`  ",
            f"**Timestamp:** {self.timestamp}  ",
            f"**Target:** `{self.target_name}`  ",
            f"**Status:** `{self.execution_status}`  ",
            f"",
            f"## 1. Scanner Attribution & Provenance",
            f"* **Scanner:** {self.scanner_attribution.get('scanner_name', 'Unknown')} (v{self.scanner_attribution.get('scanner_version', 'Unknown')})",
            f"* **Adapter ID:** `{self.scanner_attribution.get('adapter_id', 'Unknown')}`",
            f"* **Raw Output SHA-256:** `{self.scanner_attribution.get('raw_output_sha256', 'None')}`",
            f"",
            f"## 2. Evidence & Canonical Inventory Summary",
            f"* **Raw Evidence Records Ingested:** {self.evidence_summary.get('total_evidence_records', 0)}",
            f"* **Normalized Findings:** {self.evidence_summary.get('total_findings', 0)}",
            f"* **Non-Cryptographic Decoys Filtered:** {self.evidence_summary.get('decoys_filtered', 0)}",
            f"* **Canonical Cryptographic Assets:** {self.evidence_summary.get('canonical_assets_count', 0)}",
            f"",
            f"## 3. CycloneDX 1.7 CBOM Projection",
            f"* **Spec Version:** {self.cbom_summary.get('spec_version', 'Unknown')}",
            f"* **BOM Format:** {self.cbom_summary.get('bom_format', 'Unknown')}",
            f"* **Serial Number:** `{self.cbom_summary.get('serial_number', 'None')}`",
            f"* **Components Exported:** {self.cbom_summary.get('components_count', 0)}",
            f"",
            f"## 4. Contextual Risk & Priority Assessment",
            f"* **Immediate Action Required (P0):** {self.priority_summary.get('p0_immediate_action_count', 0)}",
            f"* **Near-Term Migration (P1):** {self.priority_summary.get('p1_near_term_migration_count', 0)}",
            f"* **Planned Transition (P2):** {self.priority_summary.get('p2_planned_transition_count', 0)}",
            f"* **Opportunistic Quick Wins (P3):** {self.priority_summary.get('p3_opportunistic_quick_win_count', 0)}",
            f"* **Deferred Monitoring (P4):** {self.priority_summary.get('p4_deferred_monitoring_count', 0)}",
            f"* **Human Review Required (P_REVIEW):** {self.priority_summary.get('p_review_required_count', 0)}",
            f"",
            f"### Risk Category Breakdown",
        ]
        if self.risk_summary.get("category_distribution"):
            for cat, cnt in self.risk_summary.get("category_distribution", {}).items():
                lines.append(f"* **{cat}:** {cnt}")
        else:
            lines.append("* *No cryptographic assets evaluated in this run.*")

        lines.extend([
            f"",
            f"## 5. Uncertainty & Disclosed Gaps",
        ])
        if self.uncertainty_and_gaps:
            for gap in self.uncertainty_and_gaps:
                lines.append(f"* {gap}")
        else:
            lines.append("* Zero analytical uncertainty gaps disclosed.")

        lines.extend([
            f"",
            f"## 6. Triggered Regulatory & Statutory Standards",
        ])
        if self.triggered_authorities:
            for auth in self.triggered_authorities:
                lines.append(
                    f"* **{auth.get('rule_id', 'Rule')}:** {auth.get('authority', 'N/A')} ({auth.get('section', '')}) — {auth.get('statement', '')}"
                )
        else:
            lines.append("* No standard violation rules triggered.")

        lines.extend([
            f"",
            f"## 7. Deferred Capabilities & Planning Notice",
        ])
        for cap in self.deferred_capabilities:
            lines.append(f"* {cap}")

        lines.extend([
            f"",
            f"## 8. Detailed Asset Inventory & Traceability",
            f"| Asset ID | BOM Ref | Algorithm | Role | Confidence | Risk | Priority | Code Location |",
            f"| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in self.detailed_findings:
            locs = ", ".join(f.get("code_locations", [])) or "N/A"
            lines.append(
                f"| `{f.get('asset_id', '')[:8]}...` | `{f.get('bom_ref', '')}` | {f.get('algorithm', '')} "
                f"| {f.get('role', '')} | {f.get('confidence', '')} | **{f.get('risk_category', '')}** "
                f"| **{f.get('priority', '')}** | `{locs}` |"
            )

        if self.migration_analysis:
            ma = self.migration_analysis
            lines.extend([
                f"",
                f"## 9. Post-Quantum Cryptographic Migration Roadmap (Phase 4)",
                f"* **Phase 4 Execution Status:** `{ma.status.value}`",
                f"* **Schedule Status:** `{ma.schedule_status}`",
                f"* **Total Evaluated Targets:** {ma.total_assets} (PQC Recommended: {ma.pqc_recommended_count}, Out-of-Scope: {ma.out_of_scope_count}, Needs Review: {ma.needs_review_count})",
                f"* **Migration Milestones:** {ma.total_milestones}",
                f"* **Blocking Review Gates:** {ma.blocking_gates_count}",
                f"* **Unsupported/Deferred Hybrid Constructions:** {', '.join(ma.unsupported_hybrid_types)}",
                f"* **Advisory Notice:** {ma.advisory_notice}",
            ])
            if ma.milestones_summary:
                lines.append("")
                lines.append("### Advisory Migration Milestones")
                for ms in ma.milestones_summary:
                    lines.append(f"* **{ms.get('phase', 'Phase')}: {ms.get('title', 'Milestone')}** — Target Assets: {len(ms.get('target_asset_ids', []))}, Review Gates: {ms.get('review_gates_count', 0)}, Blockers: {ms.get('blockers_count', 0)}")

        return "\n".join(lines)


@dataclass(frozen=True)
class Phase4AnalysisResult:
    """
    Immutable container holding Phase 4 PQC target mappings,
    advisory migration schedule, and hybrid capability status.
    """
    status: Phase4ExecutionStatus
    target_mappings: Tuple[PqcTargetMapping, ...] = ()
    migration_schedule: Optional[MigrationSchedule] = None
    unsupported_hybrid_types: Tuple[str, ...] = ("DUAL_SIGNATURE", "PROTOCOL_AUTHENTICATION")
    error_message: Optional[str] = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.status, Phase4ExecutionStatus):
            object.__setattr__(self, "status", Phase4ExecutionStatus(str(self.status)))
        object.__setattr__(self, "target_mappings", tuple(self.target_mappings))
        object.__setattr__(self, "unsupported_hybrid_types", tuple(self.unsupported_hybrid_types))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "target_mappings_count": len(self.target_mappings),
            "target_mappings": [m.to_dict() for m in self.target_mappings],
            "migration_schedule": self.migration_schedule.to_dict() if self.migration_schedule else None,
            "unsupported_hybrid_types": list(self.unsupported_hybrid_types),
            "error_message": self.error_message,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class WorkflowRunResult:
    """
    Immutable container holding all artifacts produced by an end-to-end workflow execution.
    """
    run_id: str
    ingestion_result: IngestionResult
    findings: Tuple[Finding, ...]
    assets: Tuple[CryptoAsset, ...]
    cbom: Dict[str, Any]
    risk_records: Tuple[MigrationPriorityRecord, ...]
    report: TechnicalReport
    phase_4: Optional[Phase4AnalysisResult] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "assets", tuple(self.assets))
        object.__setattr__(self, "cbom", MappingProxyType(dict(self.cbom)))
        object.__setattr__(self, "risk_records", tuple(self.risk_records))

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the workflow execution result to a dictionary."""
        return {
            "run_id": self.run_id,
            "status": self.ingestion_result.status.value,
            "evidence_count": len(self.ingestion_result.evidence_records),
            "findings_count": len(self.findings),
            "assets_count": len(self.assets),
            "cbom_components_count": len(self.cbom.get("components", [])),
            "risk_records_count": len(self.risk_records),
            "report": self.report.to_dict(),
            "phase_4": self.phase_4.to_dict() if self.phase_4 else None,
        }
