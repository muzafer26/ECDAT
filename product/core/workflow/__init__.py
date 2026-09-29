"""
ECDAT End-to-End Workflow Integration Package.

Provides the integrated, verifiable vertical slice:
Input -> Ingestion -> Evidence -> Canonical Inventory -> CBOM -> Risk Analysis -> Technical Report
"""

from .engine import ECDATWorkflowEngine
from .models import (
    MigrationAnalysisSection,
    Phase4AnalysisResult,
    Phase4ExecutionStatus,
    TechnicalReport,
    WorkflowRunResult,
)
from .report import TechnicalReportGenerator

__all__ = [
    "ECDATWorkflowEngine",
    "WorkflowRunResult",
    "TechnicalReport",
    "TechnicalReportGenerator",
    "Phase4ExecutionStatus",
    "Phase4AnalysisResult",
    "MigrationAnalysisSection",
]
