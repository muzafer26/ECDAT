"""
ECDAT Core Evidence Package.
Provides immutable evidence representation, sanitization, and provenance tracking.
"""

from .evidence import EvidenceRecord, SourceLocation, DetectionMethod
from .provenance import ProvenanceChain, ScannerMetadata
from .sanitization import (
    sanitize_relative_path,
    bound_code_snippet,
    sanitize_bounded_string,
    SecurityValidationError,
)

__all__ = [
    "EvidenceRecord",
    "SourceLocation",
    "DetectionMethod",
    "ProvenanceChain",
    "ScannerMetadata",
    "sanitize_relative_path",
    "bound_code_snippet",
    "sanitize_bounded_string",
    "SecurityValidationError",
]
