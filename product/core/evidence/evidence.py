"""
ECDAT Evidence Domain Model.

Represents immutable empirical observations captured by discovery engines.
Evidence records MUST NOT be modified or deleted by normalization.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional
import uuid
from datetime import datetime, timezone

from .sanitization import (
    sanitize_relative_path,
    bound_code_snippet,
    sanitize_bounded_string,
    SecurityValidationError,
    freeze_value,
)


class DetectionMethod(str, Enum):
    """Detection technique utilized by the discovering tool."""
    AST_ANALYSIS = "ast_analysis"
    SEMANTIC_REGEX = "semantic_regex"
    LOCKFILE_PARSE = "lockfile_parse"
    COMMENT_MATCH = "comment_match"
    WRAPPER_INSPECTION = "wrapper_inspection"
    MANUAL = "manual"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "DetectionMethod":
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        return cls.UNKNOWN


class LocationType(str, Enum):
    """Classification of discovery target evidence location."""
    SOURCE = "source"
    CONTAINER = "container"
    DEPENDENCY = "dependency"
    NETWORK = "network"
    CERTIFICATE = "certificate"
    BINARY = "binary"
    OTHER = "other"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "LocationType":
        if not value:
            return cls.SOURCE
        val = value.strip().lower()
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        return cls.OTHER


@dataclass(frozen=True)
class EvidenceLocation:
    """
    Generalized discovery location supporting multiple scanner types.
    
    For SOURCE locations:
    - Enforces relative path sanitization and non-negative line numbers.
    For non-source locations (NETWORK, CONTAINER, DEPENDENCY, CERTIFICATE, BINARY):
    - Preserves appropriate bounded locators without forcing filesystem constraints.
    """
    location_type: LocationType = LocationType.SOURCE
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    matched_text: str = ""
    code_snippet: str = ""
    endpoint: Optional[str] = None
    port: Optional[int] = None
    package_coordinate: Optional[str] = None
    container_image: Optional[str] = None
    layer_digest: Optional[str] = None
    certificate_id: Optional[str] = None
    binary_artifact: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.location_type, LocationType):
            object.__setattr__(self, "location_type", LocationType.from_str(str(self.location_type)))

        # Sanitize text & snippet
        bounded_snippet = bound_code_snippet(self.code_snippet)
        bounded_text = sanitize_bounded_string(self.matched_text, max_chars=500)
        object.__setattr__(self, "code_snippet", bounded_snippet)
        object.__setattr__(self, "matched_text", bounded_text)

        # Validation for SOURCE locations
        if self.location_type == LocationType.SOURCE:
            if not self.file_path:
                raise SecurityValidationError("file_path is required for SOURCE locations")
            sanitized_path = sanitize_relative_path(self.file_path)
            object.__setattr__(self, "file_path", sanitized_path)

            if not isinstance(self.line_start, int) or self.line_start < 0:
                raise SecurityValidationError(f"line_start must be a non-negative integer: {self.line_start}")
            if not isinstance(self.line_end, int) or self.line_end < self.line_start:
                raise SecurityValidationError(
                    f"line_end ({self.line_end}) must be >= line_start ({self.line_start})"
                )
        else:
            # Bound non-source locator fields
            if self.endpoint:
                object.__setattr__(self, "endpoint", sanitize_bounded_string(self.endpoint, max_chars=255))
            if self.package_coordinate:
                object.__setattr__(self, "package_coordinate", sanitize_bounded_string(self.package_coordinate, max_chars=255))
            if self.container_image:
                object.__setattr__(self, "container_image", sanitize_bounded_string(self.container_image, max_chars=255))
            if self.layer_digest:
                object.__setattr__(self, "layer_digest", sanitize_bounded_string(self.layer_digest, max_chars=128))
            if self.certificate_id:
                object.__setattr__(self, "certificate_id", sanitize_bounded_string(self.certificate_id, max_chars=255))
            if self.binary_artifact:
                object.__setattr__(self, "binary_artifact", sanitize_bounded_string(self.binary_artifact, max_chars=500))

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "location_type": self.location_type.value,
            "matched_text": self.matched_text,
            "code_snippet": self.code_snippet,
        }
        if self.file_path is not None:
            d["file_path"] = self.file_path
        if self.line_start is not None:
            d["line_start"] = self.line_start
        if self.line_end is not None:
            d["line_end"] = self.line_end
        if self.column_start is not None:
            d["column_start"] = self.column_start
        if self.column_end is not None:
            d["column_end"] = self.column_end
        if self.endpoint is not None:
            d["endpoint"] = self.endpoint
        if self.port is not None:
            d["port"] = self.port
        if self.package_coordinate is not None:
            d["package_coordinate"] = self.package_coordinate
        if self.container_image is not None:
            d["container_image"] = self.container_image
        if self.layer_digest is not None:
            d["layer_digest"] = self.layer_digest
        if self.certificate_id is not None:
            d["certificate_id"] = self.certificate_id
        if self.binary_artifact is not None:
            d["binary_artifact"] = self.binary_artifact
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceLocation":
        loc_type = LocationType.from_str(data.get("location_type"))
        if loc_type == LocationType.SOURCE:
            return SourceLocation(
                file_path=data.get("file_path", ""),
                line_start=int(data.get("line_start", 0)),
                line_end=int(data.get("line_end", 0)),
                column_start=data.get("column_start"),
                column_end=data.get("column_end"),
                matched_text=data.get("matched_text", ""),
                code_snippet=data.get("code_snippet", ""),
            )
        return cls(
            location_type=loc_type,
            file_path=data.get("file_path"),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            column_start=data.get("column_start"),
            column_end=data.get("column_end"),
            matched_text=data.get("matched_text", ""),
            code_snippet=data.get("code_snippet", ""),
            endpoint=data.get("endpoint"),
            port=data.get("port"),
            package_coordinate=data.get("package_coordinate"),
            container_image=data.get("container_image"),
            layer_digest=data.get("layer_digest"),
            certificate_id=data.get("certificate_id"),
            binary_artifact=data.get("binary_artifact"),
        )


@dataclass(frozen=True)
class SourceLocation(EvidenceLocation):
    """
    Backward-compatible source code coordinate location.
    Enforces file_path, line_start, line_end, and path sanitization.
    """
    def __init__(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        matched_text: str = "",
        code_snippet: str = "",
    ) -> None:
        super().__init__(
            location_type=LocationType.SOURCE,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            column_start=column_start,
            column_end=column_end,
            matched_text=matched_text,
            code_snippet=code_snippet,
        )


@dataclass(frozen=True)
class EvidenceRecord:
    """
    Immutable empirical discovery finding.
    
    Invariants:
    - Immutable after instantiation (frozen=True).
    - raw_attributes is recursively frozen (deep immutability).
    - scanner_category preserves the raw scanner observation and is NEVER overwritten.
    - Cannot be deleted or dropped by downstream normalization.
    """
    evidence_id: str
    location: EvidenceLocation
    scanner_name: str
    scanner_version: str
    detection_method: DetectionMethod
    scanner_category: str
    scanner_confidence: str = ""
    raw_attributes: Mapping[str, Any] = field(default_factory=dict)
    scan_id: str = ""
    raw_output_ref: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        # Validate ID: if omitted, derive a deterministic observation fingerprint
        if not self.evidence_id:
            raw_fingerprint = (
                f"{getattr(self.location, 'file_path', '')}:"
                f"{getattr(self.location, 'line_start', 0)}:"
                f"{getattr(self.location, 'line_end', 0)}:"
                f"{getattr(self.location, 'column_start', 0)}:"
                f"{getattr(self.location, 'column_end', 0)}:"
                f"{self.location.matched_text}:"
                f"{self.scanner_name}:"
                f"{self.scanner_version}:"
                f"{self.scanner_category}"
            )
            derived_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:evidence:{raw_fingerprint}"))
            object.__setattr__(self, "evidence_id", derived_id)
        else:
            object.__setattr__(self, "evidence_id", sanitize_bounded_string(self.evidence_id, max_chars=100))

        # Sanitize scanner metadata
        object.__setattr__(self, "scanner_name", sanitize_bounded_string(self.scanner_name, max_chars=100, default="unknown_scanner"))
        object.__setattr__(self, "scanner_version", sanitize_bounded_string(self.scanner_version, max_chars=50, default="unknown_version"))
        object.__setattr__(self, "scanner_category", sanitize_bounded_string(self.scanner_category, max_chars=200, default="UNKNOWN"))
        object.__setattr__(self, "scanner_confidence", sanitize_bounded_string(self.scanner_confidence, max_chars=50, default=""))
        object.__setattr__(self, "scan_id", sanitize_bounded_string(self.scan_id, max_chars=100, default=""))
        object.__setattr__(self, "raw_output_ref", sanitize_bounded_string(self.raw_output_ref, max_chars=500, default=""))

        # Default timestamp to ISO 8601 UTC if absent
        if not self.timestamp:
            object.__setattr__(self, "timestamp", datetime.now(timezone.utc).isoformat())
        else:
            object.__setattr__(self, "timestamp", sanitize_bounded_string(self.timestamp, max_chars=50))

        if not isinstance(self.detection_method, DetectionMethod):
            object.__setattr__(self, "detection_method", DetectionMethod.from_str(str(self.detection_method)))

        # Deep recursive freezing for raw_attributes (M-02 fix)
        object.__setattr__(self, "raw_attributes", freeze_value(dict(self.raw_attributes) if isinstance(self.raw_attributes, (dict, MappingProxyType)) else {}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "location": self.location.to_dict(),
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "detection_method": self.detection_method.value,
            "scanner_category": self.scanner_category,
            "scanner_confidence": self.scanner_confidence,
            "raw_attributes": dict(self.raw_attributes),
            "scan_id": self.scan_id,
            "raw_output_ref": self.raw_output_ref,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRecord":
        return cls(
            evidence_id=data.get("evidence_id", ""),
            location=EvidenceLocation.from_dict(data["location"]),
            scanner_name=data.get("scanner_name", "unknown"),
            scanner_version=data.get("scanner_version", "unknown"),
            detection_method=DetectionMethod.from_str(data.get("detection_method")),
            scanner_category=data.get("scanner_category", "UNKNOWN"),
            scanner_confidence=data.get("scanner_confidence", ""),
            raw_attributes=data.get("raw_attributes", {}),
            scan_id=data.get("scan_id", ""),
            raw_output_ref=data.get("raw_output_ref", ""),
            timestamp=data.get("timestamp", ""),
        )
