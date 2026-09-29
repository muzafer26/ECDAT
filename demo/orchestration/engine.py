"""
ECDAT Demo Orchestrator.

Coordinates execution between controlled scenarios, the frozen ECDAT core workflow
engine, and the presentation-safe result models.
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import zipfile

from product.core.risk.enums import DeploymentEnvironment, NetworkExposure
from product.core.risk.models import AssetContext
from product.core.workflow.engine import ECDATWorkflowEngine
from demo.adapters.demo_source_adapter import BoundedDemoSourceAdapter
from demo.adapters.registry import DemoAdapterRegistry
from demo.scenarios.models import DemoScenario
from demo.scenarios.registry import ScenarioRegistry
from .models import (
    DemoExecutionStatus,
    DemoMigrationSummary,
    DemoRiskSummary,
    DemoRunResult,
)
from .transformer import DemoResultTransformer


class DemoOrchestrator:
    """
    Thin demo orchestration layer.
    
    Responsibilities:
    - Selects controlled scenarios
    - Invokes frozen ECDATWorkflowEngine
    - Preserves execution errors without fabricating results
    - Produces stable, presentation-safe DemoRunResult
    """

    def __init__(
        self,
        workflow_engine: Optional[ECDATWorkflowEngine] = None,
        scenario_registry: Optional[ScenarioRegistry] = None,
        adapter_registry: Optional[DemoAdapterRegistry] = None,
    ) -> None:
        self.scenario_registry = scenario_registry or ScenarioRegistry()
        self.adapter_registry = adapter_registry or DemoAdapterRegistry()
        self.engine = workflow_engine or ECDATWorkflowEngine()
        if not self.engine.orchestrator.registry.has(BoundedDemoSourceAdapter.ADAPTER_ID):
            self.engine.orchestrator.registry.register(BoundedDemoSourceAdapter())

    def run_scenario(
        self,
        scenario_id: str,
        context: Optional[AssetContext] = None,
    ) -> DemoRunResult:
        """
        Executes a controlled scenario through the frozen ECDAT core pipeline.
        """
        scenario = self.scenario_registry.get(scenario_id)
        if not scenario:
            return self._build_error_result(
                scenario_id=scenario_id,
                error_message=f"Scenario '{scenario_id}' not found in registry.",
                status=DemoExecutionStatus.UNAVAILABLE,
            )

        if not scenario.fixture_path.exists():
            return self._build_error_result(
                scenario_id=scenario_id,
                error_message=f"Scenario fixture missing at: {scenario.fixture_path}",
                status=DemoExecutionStatus.FAILED,
            )

        start_time = time.perf_counter()
        try:
            effective_context = context
            if effective_context is None and scenario.metadata:
                from product.core.risk.enums import DeploymentEnvironment, NetworkExposure
                effective_context = AssetContext(
                    environment=DeploymentEnvironment.from_str(scenario.metadata.get("environment")),
                    network_exposure=NetworkExposure.from_str(scenario.metadata.get("network_exposure")),
                    system_criticality=scenario.metadata.get("business_criticality"),
                    data_sensitivity=scenario.metadata.get("data_sensitivity"),
                )

            # Real invocation of frozen ECDAT workflow engine
            workflow_res = self.engine.run(
                raw_input=scenario.fixture_path,
                adapter_id=scenario.adapter_id,
                target_name=scenario.target_name,
                context=effective_context,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Transform into presentation-safe result
            return DemoResultTransformer.transform(
                result=workflow_res,
                scenario_id=scenario.scenario_id,
                classification=scenario.classification.value,
                execution_time_ms=elapsed_ms,
                scenario_metadata=scenario.metadata,
            )

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_error_result(
                scenario_id=scenario_id,
                error_message=f"Pipeline execution failed: {type(exc).__name__}: {str(exc)}",
                status=DemoExecutionStatus.FAILED,
                execution_time_ms=elapsed_ms,
            )

    def run_demo_project(
        self,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        context: Optional[AssetContext] = None,
        use_sample: bool = False,
    ) -> DemoRunResult:
        """
        Executes bounded discovery and analysis on the demonstration project or uploaded sample code.
        Never fabricates results.
        """
        start_time = time.perf_counter()
        adapter = BoundedDemoSourceAdapter()
        findings: List[Dict[str, Any]] = []
        target_name = "ECDAT-Demo-Application"

        # 1. Validation: Explicit project file or explicit sample request required.
        if (file_bytes is None or len(file_bytes) == 0) and not use_sample:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_error_result(
                scenario_id="demo_project",
                error_message="Add a demonstration project to begin. No file provided.",
                status=DemoExecutionStatus.UNAVAILABLE,
                execution_time_ms=elapsed_ms,
            )

        # 2. Check maximum size (20MB limit)
        if file_bytes is not None and len(file_bytes) > 20 * 1024 * 1024:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_error_result(
                scenario_id="demo_project",
                error_message="Uploaded demonstration file exceeds the 20MB limit for this prototype.",
                status=DemoExecutionStatus.UNAVAILABLE,
                execution_time_ms=elapsed_ms,
            )

        try:
            if file_bytes is not None and len(file_bytes) > 0:
                clean_name = (filename or "uploaded_sample.java").lower()
                target_name = Path(clean_name).name
                if clean_name.endswith(".zip"):
                    try:
                        findings = adapter.scan_zip(file_bytes)
                    except (zipfile.BadZipFile, zipfile.LargeZipFile):
                        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                        return self._build_error_result(
                            scenario_id="demo_project",
                            error_message="The uploaded archive is not a valid or readable ZIP file.",
                            status=DemoExecutionStatus.FAILED,
                            execution_time_ms=elapsed_ms,
                        )
                elif clean_name.endswith(".java"):
                    content = file_bytes.decode("utf-8", errors="replace")
                    findings = adapter.scan_file_content(content, target_name)
                else:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    return self._build_error_result(
                        scenario_id="demo_project",
                        error_message="Unsupported file format. The bounded demo adapter accepts Java source files (.java) or sample project archives (.zip).",
                        status=DemoExecutionStatus.UNAVAILABLE,
                        execution_time_ms=elapsed_ms,
                    )
            elif use_sample:
                target_name = "ECDAT-Demo-Application"
                sample_dir = Path(__file__).resolve().parent.parent / "sample_project" / "ECDAT-Demo-Application"
                if sample_dir.is_dir():
                    findings = adapter.scan_directory(sample_dir)
                else:
                    sample_zip = Path(__file__).resolve().parent.parent / "sample_project" / "ECDAT-Demo-Application.zip"
                    if sample_zip.is_file():
                        findings = adapter.scan_zip(sample_zip)
                    else:
                        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                        return self._build_error_result(
                            scenario_id="demo_project",
                            error_message="Official demonstration project files not found on server.",
                            status=DemoExecutionStatus.UNAVAILABLE,
                            execution_time_ms=elapsed_ms,
                        )

            payload = adapter.build_scanner_payload(findings)
            raw_input_json = json.dumps(payload)

            effective_context = context or AssetContext(
                environment=DeploymentEnvironment.PRODUCTION,
                network_exposure=NetworkExposure.INTERNET_FACING_PUBLIC,
                system_criticality="MISSION_CRITICAL",
                data_sensitivity="CONFIDENTIAL",
            )

            # Direct invocation of frozen ECDAT analytical core using the bounded demo source adapter
            workflow_res = self.engine.run(
                raw_input=raw_input_json,
                adapter_id=BoundedDemoSourceAdapter.ADAPTER_ID,
                target_name=target_name,
                context=effective_context,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            return DemoResultTransformer.transform(
                result=workflow_res,
                scenario_id="demo_project",
                classification="LIVE",
                execution_time_ms=elapsed_ms,
                known_limitations=[
                    "Bounded strictly to demonstration cryptographic constructs (RSA, AES, Ed25519).",
                    "Bounded Java source pattern discovery does not execute code or verify runtime dynamics.",
                    "Does not imply whole-enterprise scanner coverage.",
                ],
                scenario_metadata={
                    "title": f"Demo Application Discovery: {target_name}",
                    "description": f"Real bounded source-discovery scan of {target_name} ({len(findings)} findings detected).",
                    "environment": "production",
                    "network_exposure": "Internet-Facing Public Endpoint",
                    "business_criticality": "Tier 1 Mission-Critical",
                    "data_sensitivity": "Financial Session Keys & Secrets",
                    "organization": "Global FinTech Enterprise (Demo Scope)",
                    "system": "Payment Gateway & Ingestion API",
                    "component": target_name,
                    "context_provenance": "CONTROLLED_DEMONSTRATION_CONTEXT",
                },
            )

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_error_result(
                scenario_id="demo_project",
                error_message=f"Bounded demo discovery pipeline failed: {type(exc).__name__}: {str(exc)}",
                status=DemoExecutionStatus.FAILED,
                execution_time_ms=elapsed_ms,
            )

    def _build_error_result(
        self,
        scenario_id: str,
        error_message: str,
        status: DemoExecutionStatus,
        execution_time_ms: float = 0.0,
    ) -> DemoRunResult:
        """Builds an honest error result without fabricating data."""
        return DemoRunResult(
            run_id=f"error-{int(time.time())}",
            scenario_id=scenario_id,
            status=status,
            classification="UNKNOWN",
            raw_input_ref="",
            scanner_name="unknown",
            scanner_version="unknown",
            execution_time_ms=round(execution_time_ms, 2),
            assets=[],
            evidence_records=[],
            findings=[],
            risk_summary=DemoRiskSummary(
                total_assets_evaluated=0,
                critical_priority_count=0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                informational_priority_count=0,
                mandatory_review_count=0,
            ),
            migration_summary=DemoMigrationSummary(
                phase_4_status="FAILED",
                pqc_recommended_count=0,
                out_of_scope_count=0,
                needs_review_count=0,
                total_milestones=0,
                blocking_gates_count=0,
                schedule_status="FAILED",
                advisory_notice="Analysis halted due to an unhandled execution error.",
            ),
            cbom_summary={},
            provenance_chain=[],
            known_limitations=[
                "Pipeline execution aborted with error.",
                "Zero findings or assets synthesized on failure.",
            ],
            error_message=error_message,
        )
