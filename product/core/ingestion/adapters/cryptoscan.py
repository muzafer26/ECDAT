"""
ECDAT CryptoScan Scanner Adapter (v1.4.0).

Translates CryptoScan discovery output into generic ECDAT EvidenceRecord instances
while preserving raw categories, provenance, and enforcing native ID collision handling.
"""

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional, Sequence
import uuid

from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceRecord,
    LocationType,
    SourceLocation,
)
from product.core.evidence.sanitization import (
    SecurityValidationError,
    bound_code_snippet,
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
    ScanTarget,
)
from ..parser import DefensiveJSONParser


def normalize_source_path(raw_file: str, base_path: Optional[str] = None) -> str:
    """
    Normalizes a source file path from scanner output into a safe relative path.
    Rejects directory traversal attacks immediately.
    """
    if not raw_file or not isinstance(raw_file, str):
        raise SecurityValidationError("Source file path cannot be empty")

    stripped = raw_file.strip()
    # Reject explicit directory traversal sequences
    if ".." in stripped or "%2e" in stripped.lower():
        raise SecurityValidationError(f"Path traversal sequence detected in '{stripped}'")

    # If base_path is provided and raw_file is absolute, attempt relpath
    if base_path and os.path.isabs(stripped):
        try:
            rel = os.path.relpath(stripped, base_path)
            return sanitize_relative_path(rel)
        except (ValueError, SecurityValidationError):
            pass

    # If absolute path, extract relative anchor or basename
    if os.path.isabs(stripped) or re.match(r"^[a-zA-Z]:", stripped):
        # Look for seed corpus fixture or src anchors
        match = re.search(r"[\\/](tc\d+_[^\\/]+[\\/].+)$", stripped)
        if match:
            return sanitize_relative_path(match.group(1))
        match = re.search(r"[\\/](src[\\/].+)$", stripped)
        if match:
            return sanitize_relative_path(match.group(1))
        # Fallback: file basename
        return sanitize_relative_path(os.path.basename(stripped))

    return sanitize_relative_path(stripped)


class CryptoScanAdapter(ScannerAdapter):
    """
    Adapter for CryptoScan v1.4.0 static AST discovery tool.
    
    Invariants:
    1. Preserves raw category verbatim in scanner_category.
    2. DetectionMethod is strictly UNKNOWN (CryptoScan does not emit detection technique).
    3. Validates native finding ID uniqueness across output findings; handles collisions defensively.
    4. Occurrence-index fallback is strictly scan-local observational identity, not semantic identity.
    5. Preserves all raw attributes in deeply frozen mapping.
    """

    def __init__(self, parser: Optional[DefensiveJSONParser] = None) -> None:
        self._parser = parser or DefensiveJSONParser()

    @property
    def adapter_id(self) -> str:
        return "cryptoscan"

    @property
    def adapter_version(self) -> str:
        return "1.0.0"

    @property
    def scanner_name(self) -> str:
        return "CryptoScan"

    @property
    def scanner_version(self) -> str:
        return "1.4.0"

    @property
    def capabilities(self) -> ScannerCapabilities:
        return ScannerCapabilities(
            target_types=(LocationType.SOURCE,),
            languages=("java", "python"),
            detection_mechanisms=(DetectionMethod.UNKNOWN,),
            output_formats=("json",),
            extracts_parameters=False,
            distinguishes_comments=False,
            provides_native_ids=True,
            provides_confidence=True,
            known_limitations=(
                "Reports algorithm families (e.g. ECC) rather than specific algorithms (ECDSA, ECDH)",
                "Matches keywords in comments and logger strings",
                "Misses cryptography inside wrapper classes",
                "Silent failure on dynamic cipher construction",
            ),
        )

    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        """Defensively parses raw CryptoScan JSON output."""
        success, payload, error = self._parser.parse(raw_output.stdout_bytes)
        if not success or payload is None:
            err = error or IngestionError(
                error_code="PARSER_ERROR",
                error_message="Defensive parsing failed on CryptoScan output",
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
                        error_message="Expected top-level JSON object in CryptoScan output",
                        error_source="parser",
                    ),
                ),
            )

        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return ParseResult(
                status=IngestionStatus.PARSER_ERROR,
                errors=(
                    IngestionError(
                        error_code="INVALID_FINDINGS_STRUCTURE",
                        error_message="Expected 'findings' to be a list in CryptoScan output",
                        error_source="parser",
                    ),
                ),
            )

        id_counts: Dict[str, int] = {}
        for f in findings:
            if isinstance(f, dict):
                raw_id = f.get("id")
                if isinstance(raw_id, str) and raw_id.strip():
                    clean_id = raw_id.strip()
                    id_counts[clean_id] = id_counts.get(clean_id, 0) + 1

        warnings = []
        for raw_id, count in id_counts.items():
            if count > 1:
                warnings.append(
                    f"Duplicate native finding ID '{raw_id}' detected in scanner output ({count} occurrences)"
                )

        return ParseResult(
            status=IngestionStatus.SUCCESS,
            parsed_records=tuple(findings),
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
        Maps parsed CryptoScan findings to generic EvidenceRecord instances.
        Enforces native ID uniqueness validation, collision handling, and path sanitization.
        """
        evidence_list: List[EvidenceRecord] = []
        findings = parsed.parsed_records
        if not findings:
            return evidence_list

        # Step 1: Pre-scan native IDs to validate uniqueness
        id_counts: Dict[str, int] = {}
        for f in findings:
            if isinstance(f, dict):
                raw_id = f.get("id")
                if isinstance(raw_id, str) and raw_id.strip():
                    clean_id = raw_id.strip()
                    id_counts[clean_id] = id_counts.get(clean_id, 0) + 1

        collision_counters: Dict[str, int] = {}
        warnings_list: List[str] = list(parsed.warnings)

        # Step 2: Map each finding to an EvidenceRecord
        for occurrence_index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            raw_file = finding.get("file", "")
            try:
                sanitized_file = normalize_source_path(str(raw_file))
            except SecurityValidationError as e:
                # Hostile path detected: fail safe by recording error in attributes, but do not allow traversal
                sanitized_file = f"rejected_path_{occurrence_index}.txt"
                warnings_list.append(f"Rejected hostile path '{raw_file}': {e}")

            line_start = int(finding.get("line", 0)) if finding.get("line") is not None else 0
            line_end = int(finding.get("endLine", line_start)) if finding.get("endLine") is not None else line_start
            if line_end < line_start:
                line_end = line_start

            col_start = int(finding["column"]) if finding.get("column") is not None else None
            col_end = int(finding["endColumn"]) if finding.get("endColumn") is not None else None

            matched_text = sanitize_bounded_string(
                str(finding.get("match", "") or finding.get("context", "")),
                max_chars=500,
            )
            code_snippet = bound_code_snippet(str(finding.get("context", "") or ""))

            location = SourceLocation(
                file_path=sanitized_file,
                line_start=line_start,
                line_end=line_end,
                column_start=col_start,
                column_end=col_end,
                matched_text=matched_text,
                code_snippet=code_snippet,
            )

            raw_category = sanitize_bounded_string(
                str(finding.get("category", "") or finding.get("type", "UNKNOWN")),
                max_chars=200,
            )

            # Evidence Identity Resolution
            raw_id_str = str(finding.get("id", "")).strip() if finding.get("id") else ""
            native_id_collision = False

            if raw_id_str:
                if id_counts.get(raw_id_str, 0) > 1:
                    # Native ID collision detected!
                    c_idx = collision_counters.get(raw_id_str, 0)
                    collision_counters[raw_id_str] = c_idx + 1
                    evidence_id = f"cryptoscan:{raw_id_str}:collision:{c_idx}"
                    native_id_collision = True
                    warnings_list.append(
                        f"Duplicate native finding ID '{raw_id_str}' detected; assigned collision disambiguator '{evidence_id}'"
                    )
                else:
                    evidence_id = f"cryptoscan:{raw_id_str}"
            else:
                # Tier 4 Fallback Fingerprint (occurrence-aware scan-local disambiguation)
                fp = (
                    f"cryptoscan:1.4.0:{sanitized_file}:{line_start}:{line_end}:"
                    f"{col_start or 0}:{col_end or 0}:{raw_category}:{matched_text}:{occurrence_index}"
                )
                evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:adapter-evidence:{fp}"))

            # Build raw_attributes preserving verbatim scanner observations
            raw_attrs: Dict[str, Any] = {
                "native_finding_id": raw_id_str,
                "native_id_collision": native_id_collision,
                "native_rule_id": str(finding.get("ruleId", "") or finding.get("type", "")),
                "native_algorithm": str(finding.get("algorithm", "")),
                "native_primitive": str(finding.get("primitive", "")),
                "native_severity": finding.get("severity", ""),
                "native_confidence": str(finding.get("confidence", "")),
                "native_migration_status": str(finding.get("migrationStatus", "")),
                "raw_context": str(finding.get("context", "")),
                "occurrence_index": occurrence_index,
            }
            if "oid" in finding:
                raw_attrs["oid"] = str(finding["oid"])
            if "qrammMapping" in finding:
                raw_attrs["qramm_mapping"] = finding["qrammMapping"]

            record = EvidenceRecord(
                evidence_id=evidence_id,
                location=location,
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                detection_method=DetectionMethod.UNKNOWN,  # NEVER manufacture AST_ANALYSIS
                scanner_category=raw_category,            # Preserved verbatim
                scanner_confidence=str(finding.get("confidence", "")),
                raw_attributes=raw_attrs,
                scan_id=scan_id,
                raw_output_ref=raw_output_ref,
            )
            evidence_list.append(record)

        self._active_warnings = warnings_list
        return evidence_list
