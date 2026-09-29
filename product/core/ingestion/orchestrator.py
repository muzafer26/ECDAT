"""
ECDAT Ingestion Orchestrator.

Coordinates scanner adapter execution and raw output ingestion, enforcing
the orchestrator exception containment boundary and providing a pipeline bridge
to Phase 1D Normalization and Asset Correlation.
"""

from datetime import datetime, timezone
import traceback
from typing import Any, List, Optional, Tuple
import uuid

from product.core.domain.asset import CryptoAsset
from product.core.domain.finding import Finding
from product.core.evidence.evidence import EvidenceRecord
from product.core.normalization.correlation import AssetCorrelationEngine
from product.core.normalization.normalizer import NormalizationEngine

from .adapter import (
    IngestionError,
    IngestionResult,
    IngestionStatus,
    RawScannerOutput,
    ScanExecutionMetadata,
    ScanTarget,
    ScannerAdapter,
)
from .registry import AdapterRegistry


class IngestionOrchestrator:
    """
    Coordinates discovery ingestion while enforcing the exception containment boundary.
    
    Invariants:
    1. Unexpected adapter exceptions are caught at the execution boundary and converted
       to IngestionStatus.FAILED with diagnostic details.
    2. Expected operational failures are represented as structured results.
    3. Bridges cleanly to Phase 1D NormalizationEngine and AssetCorrelationEngine
       without altering Phase 1D code or semantics.
    """

    def __init__(
        self,
        registry: Optional[AdapterRegistry] = None,
        normalizer: Optional[NormalizationEngine] = None,
        correlator: Optional[AssetCorrelationEngine] = None,
    ) -> None:
        self.registry = registry or AdapterRegistry()
        self.normalizer = normalizer or NormalizationEngine()
        self.correlator = correlator or AssetCorrelationEngine()

    def ingest_raw_output(
        self,
        adapter_id: str,
        raw_output: RawScannerOutput,
    ) -> IngestionResult:
        """
        Ingests pre-captured raw scanner output through the registered adapter,
        safely containing any unexpected adapter runtime exceptions.
        """
        adapter = self.registry.get(adapter_id)
        if not adapter:
            meta = ScanExecutionMetadata(
                scan_id=raw_output.scan_id if raw_output else str(uuid.uuid4()),
                adapter_id=adapter_id,
                adapter_version="unknown",
                scanner_name="unknown",
                scanner_version="unknown",
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0,
            )
            return IngestionResult(
                status=IngestionStatus.INVALID_INPUT,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="ADAPTER_NOT_FOUND",
                        error_message=f"No adapter registered with ID '{adapter_id}'",
                        error_source="orchestrator",
                    ),
                ),
            )

        # Enforce orchestrator exception containment boundary
        try:
            return adapter.ingest_raw_output(raw_output)
        except Exception as e:
            tb = traceback.format_exc()
            meta = ScanExecutionMetadata(
                scan_id=raw_output.scan_id,
                adapter_id=adapter.adapter_id,
                adapter_version=adapter.adapter_version,
                scanner_name=adapter.scanner_name,
                scanner_version=adapter.scanner_version,
                timestamp=raw_output.timestamp,
                duration_ms=raw_output.duration_ms,
                exit_code=raw_output.exit_code,
            )
            return IngestionResult(
                status=IngestionStatus.FAILED,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="UNEXPECTED_ADAPTER_EXCEPTION",
                        error_message=f"Unexpected exception in adapter '{adapter_id}': {type(e).__name__}: {e}",
                        error_source="orchestrator",
                    ),
                ),
                warnings=(f"Traceback: {tb.splitlines()[-1]}",),
                raw_output_ref=raw_output.storage_ref or f"sha256:{raw_output.sha256_hash}",
            )

    def ingest_from_file(
        self,
        adapter_id: str,
        file_path: str,
        scan_id: Optional[str] = None,
        duration_ms: int = 0,
    ) -> IngestionResult:
        """
        Convenience method: Reads raw bytes from a file and runs ingestion through the adapter.
        """
        adapter = self.registry.get(adapter_id)
        if not adapter:
            meta = ScanExecutionMetadata(
                scan_id=scan_id or str(uuid.uuid4()),
                adapter_id=adapter_id,
                adapter_version="unknown",
                scanner_name="unknown",
                scanner_version="unknown",
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0,
            )
            return IngestionResult(
                status=IngestionStatus.INVALID_INPUT,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="ADAPTER_NOT_FOUND",
                        error_message=f"No adapter registered with ID '{adapter_id}'",
                        error_source="orchestrator",
                    ),
                ),
            )

        try:
            return adapter.ingest_from_file(file_path, scan_id=scan_id, duration_ms=duration_ms)
        except Exception as e:
            meta = ScanExecutionMetadata(
                scan_id=scan_id or str(uuid.uuid4()),
                adapter_id=adapter.adapter_id,
                adapter_version=adapter.adapter_version,
                scanner_name=adapter.scanner_name,
                scanner_version=adapter.scanner_version,
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
            )
            return IngestionResult(
                status=IngestionStatus.FAILED,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="UNEXPECTED_ADAPTER_EXCEPTION",
                        error_message=f"Unexpected exception ingesting file with adapter '{adapter_id}': {e}",
                        error_source="orchestrator",
                    ),
                ),
            )

    def run_pipeline(
        self,
        adapter_id: str,
        raw_output: RawScannerOutput,
    ) -> Tuple[IngestionResult, List[Finding], List[CryptoAsset]]:
        """
        Executes the end-to-end ECDAT pipeline:
        RawScannerOutput -> Adapter -> EvidenceRecord[] -> NormalizationEngine -> Finding[] -> AssetCorrelationEngine -> CryptoAsset[]
        
        Returns: (ingestion_result, normalized_findings, correlated_assets)
        """
        ingestion_res = self.ingest_raw_output(adapter_id, raw_output)

        if ingestion_res.status not in (IngestionStatus.SUCCESS, IngestionStatus.PARTIAL):
            return ingestion_res, [], []

        evidence_list = list(ingestion_res.evidence_records)
        if not evidence_list:
            return ingestion_res, [], []

        # Phase 1D Normalization
        findings = self.normalizer.normalize_batch(evidence_list)

        # Phase 1D Conservative Asset Correlation
        assets = self.correlator.correlate(findings)

        return ingestion_res, findings, assets
