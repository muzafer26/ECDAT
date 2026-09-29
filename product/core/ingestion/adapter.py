"""
ECDAT Scanner Adapter Contract & Ingestion Models.

Establishes the anti-corruption boundary between heterogeneous external discovery
tools and the stable, generic ECDAT evidence model.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import os
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence
import uuid

from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceLocation,
    EvidenceRecord,
    LocationType,
    SourceLocation,
)
from product.core.evidence.sanitization import (
    freeze_value,
    sanitize_bounded_string,
    sanitize_relative_path,
)


class IngestionStatus(str, Enum):
    """Execution and ingestion status states."""
    SUCCESS = "success"                      # Clean execution, parser succeeded, evidence created
    PARTIAL = "partial"                      # Processed subset of target scope; scope coverage captured
    FAILED = "failed"                        # Scanner execution crashed, fatal error, or unhandled exception
    TIMEOUT = "timeout"                      # Scanner or parser exceeded execution deadline
    INVALID_INPUT = "invalid_input"          # Target path invalid, inaccessible, or rejected by validation
    UNSUPPORTED = "unsupported"              # Target language/format not supported by this scanner
    PARSER_ERROR = "parser_error"            # Raw output captured but could not be parsed safely
    VALIDATION_FAILED = "validation_failed"  # Binary missing, version mismatch, or hash mismatch
    NO_FINDINGS = "no_findings"              # Scan completed cleanly with zero findings (valid result)


@dataclass(frozen=True)
class ScanTarget:
    """Designates the target filesystem path and scanning options."""
    target_id: str
    filesystem_path: str
    target_type: str = "source_dir"
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", sanitize_bounded_string(self.target_id, max_chars=100))
        object.__setattr__(self, "filesystem_path", sanitize_bounded_string(self.filesystem_path, max_chars=500))
        object.__setattr__(self, "target_type", sanitize_bounded_string(self.target_type, max_chars=50))
        object.__setattr__(self, "options", freeze_value(dict(self.options)))


@dataclass(frozen=True)
class ScannerCapabilities:
    """Declared tool capability metadata."""
    target_types: Sequence[LocationType]
    languages: Sequence[str]
    detection_mechanisms: Sequence[DetectionMethod]
    output_formats: Sequence[str]
    extracts_parameters: bool = False
    distinguishes_comments: bool = False
    provides_native_ids: bool = False
    provides_confidence: bool = False
    known_limitations: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_types", tuple(self.target_types))
        object.__setattr__(self, "languages", tuple(self.languages))
        object.__setattr__(self, "detection_mechanisms", tuple(self.detection_mechanisms))
        object.__setattr__(self, "output_formats", tuple(self.output_formats))
        object.__setattr__(self, "known_limitations", tuple(self.known_limitations))


@dataclass(frozen=True)
class RawScannerOutput:
    """
    Verbatim captured discovery tool output.
    
    Invariants:
    - sha256_hash represents the EXACT captured stdout_bytes before decoding or alteration.
    - stderr_bytes is preserved separately.
    - Deeply frozen for provenance integrity.
    """
    scan_id: str
    adapter_id: str
    scanner_name: str
    scanner_version: str
    stdout_bytes: bytes
    stderr_bytes: bytes
    exit_code: Optional[int]
    duration_ms: int
    sha256_hash: str
    timestamp: str
    cli_arguments: Sequence[str] = field(default_factory=tuple)
    storage_ref: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scan_id", sanitize_bounded_string(self.scan_id, max_chars=100))
        object.__setattr__(self, "adapter_id", sanitize_bounded_string(self.adapter_id, max_chars=100))
        object.__setattr__(self, "scanner_name", sanitize_bounded_string(self.scanner_name, max_chars=100))
        object.__setattr__(self, "scanner_version", sanitize_bounded_string(self.scanner_version, max_chars=50))
        object.__setattr__(self, "timestamp", sanitize_bounded_string(self.timestamp, max_chars=50))
        object.__setattr__(self, "cli_arguments", tuple(self.cli_arguments))
        object.__setattr__(self, "storage_ref", sanitize_bounded_string(self.storage_ref, max_chars=500))

    @classmethod
    def from_bytes(
        cls,
        stdout_bytes: bytes,
        adapter_id: str,
        scanner_name: str,
        scanner_version: str,
        stderr_bytes: bytes = b"",
        exit_code: Optional[int] = 0,
        duration_ms: int = 0,
        scan_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        cli_arguments: Sequence[str] = (),
        storage_ref: str = "",
    ) -> "RawScannerOutput":
        """Factory computing verbatim SHA-256 hash before any modification."""
        stdout = stdout_bytes if isinstance(stdout_bytes, bytes) else b""
        stderr = stderr_bytes if isinstance(stderr_bytes, bytes) else b""
        computed_hash = hashlib.sha256(stdout).hexdigest()
        sid = scan_id or str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        ref = storage_ref or f"sha256:{computed_hash}"

        return cls(
            scan_id=sid,
            adapter_id=adapter_id,
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            stdout_bytes=stdout,
            stderr_bytes=stderr,
            exit_code=exit_code,
            duration_ms=duration_ms,
            sha256_hash=computed_hash,
            timestamp=ts,
            cli_arguments=tuple(cli_arguments),
            storage_ref=ref,
        )


@dataclass(frozen=True)
class ScanInputScope:
    """Scope description of target input."""
    target_path: str
    target_type: str = "source_dir"
    file_count: Optional[int] = None


@dataclass(frozen=True)
class ScanExecutionMetadata:
    """Structured audit metadata for an execution or ingestion run."""
    scan_id: str
    adapter_id: str
    adapter_version: str
    scanner_name: str
    scanner_version: str
    timestamp: str
    duration_ms: int
    exit_code: Optional[int] = None
    input_scope: Optional[ScanInputScope] = None


@dataclass(frozen=True)
class ScopeCoverage:
    """Scope coverage representation for partial scan assessment."""
    total_files: Optional[int] = None
    processed_files: Optional[int] = None
    failed_files: Optional[int] = None
    failure_reasons: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "failure_reasons", tuple(self.failure_reasons))


@dataclass(frozen=True)
class IngestionError:
    """Structured diagnostic error."""
    error_code: str
    error_message: str
    error_source: str = "adapter"  # "scanner" | "parser" | "adapter" | "orchestrator"
    recoverable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "error_code", sanitize_bounded_string(self.error_code, max_chars=100))
        object.__setattr__(self, "error_message", sanitize_bounded_string(self.error_message, max_chars=1000))
        object.__setattr__(self, "error_source", sanitize_bounded_string(self.error_source, max_chars=50))


@dataclass(frozen=True)
class ValidationResult:
    """Result of pre-execution validation."""
    is_valid: bool
    error_message: str = ""


@dataclass(frozen=True)
class PrepareResult:
    """Result of scanner invocation preparation."""
    is_ready: bool
    cli_arguments: Sequence[str] = field(default_factory=tuple)
    working_directory: str = ""
    environment: Mapping[str, str] = field(default_factory=dict)
    error_message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "cli_arguments", tuple(self.cli_arguments))
        object.__setattr__(self, "environment", freeze_value(dict(self.environment)))


@dataclass(frozen=True)
class ExecutionResult:
    """Result of subprocess execution."""
    status: IngestionStatus
    exit_code: Optional[int] = None
    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""
    duration_ms: int = 0
    error_message: str = ""


@dataclass(frozen=True)
class ParseResult:
    """Result of defensive raw output parsing."""
    status: IngestionStatus
    parsed_records: Sequence[Any] = field(default_factory=tuple)
    errors: Sequence[IngestionError] = field(default_factory=tuple)
    warnings: Sequence[str] = field(default_factory=tuple)
    coverage: Optional[ScopeCoverage] = None
    raw_payload: Optional[Any] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "parsed_records", tuple(self.parsed_records))
        object.__setattr__(self, "errors", tuple(self.errors))
        object.__setattr__(self, "warnings", tuple(self.warnings))


@dataclass(frozen=True)
class IngestionResult:
    """Terminal result of scanner adapter ingestion."""
    status: IngestionStatus
    evidence_records: Sequence[EvidenceRecord] = field(default_factory=tuple)
    scan_metadata: ScanExecutionMetadata = field(
        default_factory=lambda: ScanExecutionMetadata(
            scan_id="", adapter_id="", adapter_version="",
            scanner_name="", scanner_version="", timestamp="", duration_ms=0
        )
    )
    errors: Sequence[IngestionError] = field(default_factory=tuple)
    warnings: Sequence[str] = field(default_factory=tuple)
    raw_output_ref: str = ""
    scope_coverage: Optional[ScopeCoverage] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_records", tuple(self.evidence_records))
        object.__setattr__(self, "errors", tuple(self.errors))
        object.__setattr__(self, "warnings", tuple(self.warnings))


class ScannerAdapter(ABC):
    """
    Abstract base class for all discovery tool adapters.
    
    Enforces separation between process execution and raw output ingestion.
    """

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Unique identifier of this adapter (e.g. 'cryptoscan')."""
        pass

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Version of this adapter implementation (e.g. '1.0.0')."""
        pass

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Canonical name of the external scanner (e.g. 'CryptoScan')."""
        pass

    @property
    @abstractmethod
    def scanner_version(self) -> str:
        """Expected / validated scanner version (e.g. '1.4.0')."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> ScannerCapabilities:
        """Declared capabilities of this scanner and adapter."""
        pass

    # --- Lifecycle Methods ---

    def validate(self) -> ValidationResult:
        """
        Verify prerequisites (e.g. executable exists, environment ready).
        Default implementation returns valid; concrete adapters with local CLI execution override.
        """
        return ValidationResult(is_valid=True)

    def prepare(self, target: ScanTarget) -> PrepareResult:
        """
        Prepare execution command line and working environment.
        """
        return PrepareResult(is_ready=True)

    def execute(self, target: ScanTarget) -> ExecutionResult:
        """
        Execute scanner subprocess with timeout and isolation.
        Subclasses implementing live execution override this.
        """
        return ExecutionResult(
            status=IngestionStatus.UNSUPPORTED,
            error_message=f"Live execution not configured for adapter '{self.adapter_id}'"
        )

    @abstractmethod
    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        """
        Defensively parse raw bytes into intermediate structured records.
        Must NOT raise uncaught exceptions on malformed input.
        """
        pass

    @abstractmethod
    def create_evidence(
        self,
        parsed: ParseResult,
        scan_id: str = "",
        raw_output_ref: str = "",
    ) -> List[EvidenceRecord]:
        """
        Map intermediate parsed records to generic EvidenceRecord instances.
        Must enforce evidence identity hierarchy and native ID collision handling.
        """
        pass

    # --- Decoupled Ingestion Pipeline Entry Points ---

    def ingest_raw_output(self, raw_output: RawScannerOutput) -> IngestionResult:
        """
        Ingests pre-captured raw output directly without requiring scanner process execution.
        This provides pure, offline, testable ingestion of historical benchmark runs.
        """
        start_time = datetime.now(timezone.utc)
        parse_res = self.parse(raw_output)

        if parse_res.status not in (IngestionStatus.SUCCESS, IngestionStatus.PARTIAL):
            meta = ScanExecutionMetadata(
                scan_id=raw_output.scan_id,
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                timestamp=raw_output.timestamp,
                duration_ms=raw_output.duration_ms,
                exit_code=raw_output.exit_code,
            )
            return IngestionResult(
                status=parse_res.status,
                evidence_records=(),
                scan_metadata=meta,
                errors=parse_res.errors,
                warnings=parse_res.warnings,
                raw_output_ref=raw_output.storage_ref or f"sha256:{raw_output.sha256_hash}",
                scope_coverage=parse_res.coverage,
            )

        evidence = self.create_evidence(
            parse_res,
            scan_id=raw_output.scan_id,
            raw_output_ref=raw_output.storage_ref or f"sha256:{raw_output.sha256_hash}",
        )

        status = IngestionStatus.NO_FINDINGS if (len(evidence) == 0 and parse_res.status == IngestionStatus.SUCCESS) else parse_res.status

        meta = ScanExecutionMetadata(
            scan_id=raw_output.scan_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            scanner_name=self.scanner_name,
            scanner_version=self.scanner_version,
            timestamp=raw_output.timestamp,
            duration_ms=raw_output.duration_ms,
            exit_code=raw_output.exit_code,
        )

        warnings_all = list(parse_res.warnings)
        if hasattr(self, "_active_warnings") and getattr(self, "_active_warnings"):
            warnings_all.extend(getattr(self, "_active_warnings"))

        return IngestionResult(
            status=status,
            evidence_records=tuple(evidence),
            scan_metadata=meta,
            errors=parse_res.errors,
            warnings=tuple(warnings_all),
            raw_output_ref=raw_output.storage_ref or f"sha256:{raw_output.sha256_hash}",
            scope_coverage=parse_res.coverage,
        )

    def ingest_from_file(
        self,
        file_path: str,
        scan_id: Optional[str] = None,
        duration_ms: int = 0,
    ) -> IngestionResult:
        """
        Convenience method: Reads verbatim bytes from file and ingests as raw output.
        """
        if not os.path.isfile(file_path):
            meta = ScanExecutionMetadata(
                scan_id=scan_id or str(uuid.uuid4()),
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0,
                exit_code=None,
            )
            return IngestionResult(
                status=IngestionStatus.INVALID_INPUT,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="FILE_NOT_FOUND",
                        error_message=f"Raw output file does not exist: {file_path}",
                        error_source="adapter",
                    ),
                ),
            )

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            meta = ScanExecutionMetadata(
                scan_id=scan_id or str(uuid.uuid4()),
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0,
                exit_code=None,
            )
            return IngestionResult(
                status=IngestionStatus.INVALID_INPUT,
                evidence_records=(),
                scan_metadata=meta,
                errors=(
                    IngestionError(
                        error_code="FILE_READ_ERROR",
                        error_message=f"Failed to read raw output file {file_path}: {e}",
                        error_source="adapter",
                    ),
                ),
            )

        raw_output = RawScannerOutput.from_bytes(
            stdout_bytes=raw_bytes,
            adapter_id=self.adapter_id,
            scanner_name=self.scanner_name,
            scanner_version=self.scanner_version,
            scan_id=scan_id,
            duration_ms=duration_ms,
            storage_ref=f"file://{file_path}",
        )
        return self.ingest_raw_output(raw_output)
