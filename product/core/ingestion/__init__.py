"""
ECDAT Scanner Adapter & Ingestion Framework.

Provides the anti-corruption boundary between external discovery tools
and the internal canonical cryptographic evidence and domain models.
"""

from .adapter import (
    IngestionError,
    IngestionResult,
    IngestionStatus,
    ParseResult,
    PrepareResult,
    RawScannerOutput,
    ScanExecutionMetadata,
    ScanInputScope,
    ScannerAdapter,
    ScannerCapabilities,
    ScanTarget,
    ScopeCoverage,
    ValidationResult,
)
from .orchestrator import IngestionOrchestrator
from .parser import (
    DefensiveJSONParser,
    DefensiveXMLParser,
)
from .registry import AdapterRegistry

__all__ = [
    "IngestionError",
    "IngestionResult",
    "IngestionStatus",
    "ParseResult",
    "PrepareResult",
    "RawScannerOutput",
    "ScanExecutionMetadata",
    "ScanInputScope",
    "ScannerAdapter",
    "ScannerCapabilities",
    "ScanTarget",
    "ScopeCoverage",
    "ValidationResult",
    "DefensiveJSONParser",
    "DefensiveXMLParser",
    "AdapterRegistry",
    "IngestionOrchestrator",
]
