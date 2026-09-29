"""
ECDAT Anchore Syft Scanner Adapter (v1.51.1).

Translates Syft SBOM JSON output into generic ECDAT EvidenceRecord instances
with LocationType.DEPENDENCY, strictly preventing algorithm inference from package names.
"""

from datetime import datetime, timezone
import os
import re
from typing import Any, Callable, Dict, List, Optional, Sequence
import uuid

from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceLocation,
    EvidenceRecord,
    LocationType,
)
from product.core.evidence.sanitization import (
    SecurityValidationError,
    freeze_value,
    sanitize_bounded_string,
    sanitize_relative_path,
)
from ..adapter import (
    IngestionError,
    IngestionStatus,
    ParseResult,
    RawScannerOutput,
    ScannerAdapter,
    ScannerCapabilities,
    ScopeCoverage,
)
from ..parser import DefensiveJSONParser


def normalize_manifest_path(raw_path: str) -> Optional[str]:
    """Normalizes manifest file paths (e.g. '\\pom.xml' or '/pom.xml') to relative paths."""
    if not raw_path or not isinstance(raw_path, str):
        return None
    cleaned = raw_path.replace("\\", "/").lstrip("/")
    if not cleaned:
        return None
    try:
        return sanitize_relative_path(cleaned)
    except SecurityValidationError:
        return None


class SyftAdapter(ScannerAdapter):
    """
    Adapter for Anchore Syft v1.51.1 dependency cataloger.
    
    Invariants:
    1. Produces dependency evidence (LocationType.DEPENDENCY) only.
    2. Never manufactures or infers cryptographic algorithms from package names.
    3. DetectionMethod is strictly UNKNOWN (cataloger preserved in raw_attributes).
    4. Package coordinates are handled defensively without fabricating missing PURLs.
    5. Relevance filtering, if enabled, is explicit, configurable, and observable.
    """

    def __init__(
        self,
        parser: Optional[DefensiveJSONParser] = None,
        relevance_policy: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> None:
        self._parser = parser or DefensiveJSONParser()
        self.relevance_policy = relevance_policy

    @property
    def adapter_id(self) -> str:
        return "syft"

    @property
    def adapter_version(self) -> str:
        return "1.0.0"

    @property
    def scanner_name(self) -> str:
        return "syft"

    @property
    def scanner_version(self) -> str:
        return "1.51.1"

    @property
    def capabilities(self) -> ScannerCapabilities:
        return ScannerCapabilities(
            target_types=(LocationType.DEPENDENCY,),
            languages=("java", "python", "javascript", "go", "ruby", "rust"),
            detection_mechanisms=(DetectionMethod.UNKNOWN,),
            output_formats=("json",),
            extracts_parameters=False,
            distinguishes_comments=False,
            provides_native_ids=True,
            provides_confidence=False,
            known_limitations=(
                "Cataloging only; observes dependency declarations, not code or runtime algorithm usage",
                "Does not extract cryptographic parameters or operational roles",
            ),
        )

    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        """Defensively parses raw Syft JSON SBOM output."""
        success, payload, error = self._parser.parse(raw_output.stdout_bytes)
        if not success or payload is None:
            err = error or IngestionError(
                error_code="PARSER_ERROR",
                error_message="Defensive parsing failed on Syft output",
                error_source="parser",
            )
            return ParseResult(
                status=IngestionStatus.PARSER_ERROR,
                errors=(err,),
            )

        if not isinstance(payload, dict):
            return ParseResult(
                status=IngestionStatus.PARSER_ERROR,
                errors=(
                    IngestionError(
                        error_code="INVALID_PAYLOAD_STRUCTURE",
                        error_message="Expected top-level JSON object in Syft output",
                        error_source="parser",
                    ),
                ),
            )

        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            return ParseResult(
                status=IngestionStatus.PARSER_ERROR,
                errors=(
                    IngestionError(
                        error_code="INVALID_ARTIFACTS_STRUCTURE",
                        error_message="Expected 'artifacts' to be a list in Syft output",
                        error_source="parser",
                    ),
                ),
            )

        id_counts: Dict[str, int] = {}
        for a in artifacts:
            if isinstance(a, dict):
                raw_id = a.get("id")
                if isinstance(raw_id, str) and raw_id.strip():
                    clean_id = raw_id.strip()
                    id_counts[clean_id] = id_counts.get(clean_id, 0) + 1

        warnings = []
        for raw_id, count in id_counts.items():
            if count > 1:
                warnings.append(
                    f"Duplicate native artifact ID '{raw_id}' detected in scanner output ({count} occurrences)"
                )

        return ParseResult(
            status=IngestionStatus.SUCCESS,
            parsed_records=tuple(artifacts),
            raw_payload=payload,
            warnings=tuple(warnings),
        )

    def create_evidence(
        self,
        parsed: ParseResult,
        scan_id: str = "",
        raw_output_ref: str = "",
    ) -> List[EvidenceRecord]:
        """
        Maps parsed Syft artifacts to EvidenceRecord instances with LocationType.DEPENDENCY.
        Applies optional relevance filtering observably without silent evidence loss.
        """
        evidence_list: List[EvidenceRecord] = []
        artifacts = parsed.parsed_records
        if not artifacts:
            return evidence_list

        warnings_list: List[str] = list(parsed.warnings)
        filtered_count = 0
        total_artifacts = len(artifacts)

        # Pre-scan native artifact IDs for uniqueness validation
        id_counts: Dict[str, int] = {}
        for art in artifacts:
            if isinstance(art, dict):
                art_id = str(art.get("id", "")).strip()
                if art_id:
                    id_counts[art_id] = id_counts.get(art_id, 0) + 1

        collision_counters: Dict[str, int] = {}

        for occurrence_index, art in enumerate(artifacts):
            if not isinstance(art, dict):
                continue

            # Check optional relevance policy
            if self.relevance_policy is not None and not self.relevance_policy(art):
                filtered_count += 1
                continue

            # Defensive package coordinate extraction
            raw_purl = art.get("purl")
            package_coord: Optional[str] = None
            if raw_purl and isinstance(raw_purl, str) and raw_purl.strip():
                package_coord = sanitize_bounded_string(raw_purl.strip(), max_chars=255)

            # Defensive manifest location extraction
            locations = art.get("locations", [])
            manifest_path: Optional[str] = None
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                raw_loc = locations[0].get("path", "")
                manifest_path = normalize_manifest_path(str(raw_loc))

            location = EvidenceLocation(
                location_type=LocationType.DEPENDENCY,
                package_coordinate=package_coord,
                file_path=manifest_path,
                matched_text=package_coord or sanitize_bounded_string(str(art.get("name", "")), max_chars=500),
            )

            # Evidence Identity Resolution
            raw_id = str(art.get("id", "")).strip() if art.get("id") else ""
            native_id_collision = False

            if raw_id:
                if id_counts.get(raw_id, 0) > 1:
                    c_idx = collision_counters.get(raw_id, 0)
                    collision_counters[raw_id] = c_idx + 1
                    evidence_id = f"syft:{raw_id}:collision:{c_idx}"
                    native_id_collision = True
                    warnings_list.append(
                        f"Duplicate native artifact ID '{raw_id}' detected; assigned collision disambiguator '{evidence_id}'"
                    )
                else:
                    evidence_id = f"syft:{raw_id}"
            elif package_coord:
                evidence_id = f"syft:{package_coord}"
            else:
                fp = f"syft:1.51.1:{manifest_path or 'unknown'}:{art.get('name', 'pkg')}:{occurrence_index}"
                evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:adapter-evidence:{fp}"))

            raw_attrs: Dict[str, Any] = {
                "native_finding_id": raw_id,
                "native_id_collision": native_id_collision,
                "package_name": str(art.get("name", "")),
                "package_version": str(art.get("version", "")),
                "package_type": str(art.get("type", "")),
                "cataloger": str(art.get("foundBy", "")),
                "purl": str(art.get("purl", "")),
                "occurrence_index": occurrence_index,
            }
            if "licenses" in art and isinstance(art["licenses"], list):
                raw_attrs["licenses"] = tuple(
                    str(lic.get("value", lic) if isinstance(lic, dict) else lic)
                    for lic in art["licenses"]
                )

            record = EvidenceRecord(
                evidence_id=evidence_id,
                location=location,
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                detection_method=DetectionMethod.UNKNOWN,  # NEVER manufacture LOCKFILE_PARSE
                scanner_category="dependency",            # Fixed category for dependencies
                scanner_confidence="",
                raw_attributes=raw_attrs,
                scan_id=scan_id,
                raw_output_ref=raw_output_ref,
            )
            evidence_list.append(record)

        if filtered_count > 0:
            warnings_list.append(
                f"Relevance policy filtered {filtered_count} of {total_artifacts} packages from active evidence emission"
            )

        self._active_warnings = warnings_list
        return evidence_list
