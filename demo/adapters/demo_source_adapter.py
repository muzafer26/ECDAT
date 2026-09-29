"""
ECDAT Bounded Demonstration Source Code Adapter.

Provides the bounded demonstration Java source discovery adapter, implementing
product.core.ingestion.adapter.ScannerAdapter directly without modifying product/core.

CRITICAL PRODUCT-TRUTH BOUNDARY:
- Performs bounded Java source pattern discovery (regex/lexical JCA inspection).
- Explicitly does NOT claim general-purpose static AST compilation or whole-program data-flow analysis.
- Bounded scope: RSA KeyPairGenerator, AES Cipher/SecretKeySpec, Ed25519 Signature.
- Adapter ID: 'demo_source_adapter' (distinct from 'cryptoscan').
- Scanner Name: 'DemoSourceScanner' (v1.0.0-demo).
"""

from datetime import datetime, timezone
from io import BytesIO
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid
import zipfile

from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceRecord,
    LocationType,
    SourceLocation,
)
from product.core.evidence.sanitization import (
    bound_code_snippet,
    freeze_value,
    sanitize_bounded_string,
    sanitize_relative_path,
)
from product.core.ingestion.adapter import (
    IngestionError,
    IngestionStatus,
    ParseResult,
    RawScannerOutput,
    ScannerAdapter,
    ScannerCapabilities,
)
from product.core.ingestion.parser import DefensiveJSONParser


class BoundedDemoSourceScanner:
    """
    Underlying pattern recognition scanner for demonstration Java source code.
    Performs bounded regex/lexical matching for RSA, AES, and Ed25519 JCA instantiations.
    """

    SCANNER_NAME = "DemoSourceScanner"
    SCANNER_VERSION = "1.0.0-demo"

    # Precise patterns bounded to the demonstration scope
    PATTERNS: List[Tuple[str, str, str, str, str, re.Pattern]] = [
        # (algorithm, primitive, category, finding_type, match_str, compiled_regex)
        (
            "RSA",
            "pke",
            "Asymmetric Encryption",
            "RSA Algorithm",
            "RSA",
            re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\s*\)', re.IGNORECASE),
        ),
        (
            "AES",
            "symmetric_cipher",
            "Symmetric Encryption",
            "AES Algorithm",
            "AES",
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES(?:/[^"\']+)?["\']\s*\)|SecretKeySpec\s*\([^,]+,\s*["\']AES["\']\s*\)', re.IGNORECASE),
        ),
        (
            "Ed25519",
            "digital_signature",
            "Signature",
            "Ed25519 Algorithm",
            "Ed25519",
            re.compile(r'Signature\.getInstance\s*\(\s*["\']Ed25519["\']\s*\)|(?:String|ALGORITHM)\s*=\s*["\']Ed25519["\']', re.IGNORECASE),
        ),
    ]

    def scan_file_content(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Scans Java source text using bounded pattern discovery."""
        findings: List[Dict[str, Any]] = []
        clean_filename = self._sanitize_filename(filename)
        lines = content.splitlines()

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1

            # Skip comments to avoid false positives
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for algo, primitive, category, finding_type, match_str, pattern in self.PATTERNS:
                match = pattern.search(line)
                if match:
                    col_start = match.start() + 1
                    finding_id = f"DEMO-{algo}-{clean_filename.replace('/', '_').replace('.', '_')}-{line_no}"

                    # Context window (+/- 2 lines)
                    ctx_start = max(0, line_idx - 2)
                    ctx_end = min(len(lines), line_idx + 3)
                    context_lines = [
                        {"number": i + 1, "content": lines[i], "isMatch": (i == line_idx)}
                        for i in range(ctx_start, ctx_end)
                    ]

                    finding: Dict[str, Any] = {
                        "id": finding_id,
                        "type": finding_type,
                        "findingType": "algorithm",
                        "category": category,
                        "algorithm": algo,
                        "primitive": primitive,
                        "migrationStatus": "VULNERABLE" if algo in ("RSA", "Ed25519") else "BENCHMARK_CONFORMANT",
                        "file": clean_filename,
                        "line": line_no,
                        "column": col_start,
                        "match": match_str,
                        "context": line.strip(),
                        "sourceContext": {
                            "lines": context_lines,
                        },
                    }
                    findings.append(finding)
                    break  # One finding per pattern match per line

        return findings

    def scan_file(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Reads a local Java source file and extracts bounded cryptographic findings."""
        path = Path(file_path)
        if not path.is_file():
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return self.scan_file_content(content, path.name)
        except Exception:
            return []

    def scan_directory(self, dir_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Walks a directory of Java source files and extracts bounded findings."""
        path = Path(dir_path)
        if not path.is_dir():
            return []

        all_findings: List[Dict[str, Any]] = []
        for root, _, files in os.walk(path):
            for file in sorted(files):
                if file.endswith(".java"):
                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(path).as_posix()
                    content = full_path.read_text(encoding="utf-8", errors="replace")
                    all_findings.extend(self.scan_file_content(content, rel_path))

        return all_findings

    def scan_zip(self, zip_source: Union[bytes, str, Path]) -> List[Dict[str, Any]]:
        """Inspects a zip archive of the demo application and extracts bounded findings."""
        all_findings: List[Dict[str, Any]] = []
        if isinstance(zip_source, bytes):
            zf = zipfile.ZipFile(BytesIO(zip_source))
        else:
            zf = zipfile.ZipFile(zip_source)

        with zf:
            for file_info in zf.infolist():
                if file_info.filename.endswith(".java") and not file_info.is_dir():
                    if ".." in file_info.filename:
                        continue
                    content = zf.read(file_info).decode("utf-8", errors="replace")
                    clean_name = file_info.filename.replace("\\", "/")
                    all_findings.extend(self.scan_file_content(content, clean_name))

        return all_findings

    def build_scanner_payload(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Packages findings into standard scanner schema."""
        return {
            "tool": {
                "name": self.SCANNER_NAME,
                "version": self.SCANNER_VERSION,
            },
            "findings": findings,
        }

    def _sanitize_filename(self, filename: str) -> str:
        clean = filename.replace("\\", "/").strip()
        while "../" in clean or "..\\" in clean:
            clean = clean.replace("../", "").replace("..\\", "")
        clean = re.sub(r"^/+", "", clean)
        return clean or "DemoSource.java"


class DemoSourceAdapter(ScannerAdapter):
    """
    ECDAT Bounded Demonstration Java Source Code Discovery Adapter.
    
    Subclasses product.core.ingestion.adapter.ScannerAdapter directly to establish
    honest provenance for the demonstration source scanner without modifying product/core.
    """

    ADAPTER_ID = "demo_source_adapter"
    ADAPTER_VERSION = "1.0.0"
    SCANNER_NAME = "DemoSourceScanner"
    SCANNER_VERSION = "1.0.0-demo"

    def __init__(self, parser: Optional[DefensiveJSONParser] = None) -> None:
        self._parser = parser or DefensiveJSONParser()
        self._scanner = BoundedDemoSourceScanner()

    @property
    def adapter_id(self) -> str:
        return self.ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return self.ADAPTER_VERSION

    @property
    def scanner_name(self) -> str:
        return self.SCANNER_NAME

    @property
    def scanner_version(self) -> str:
        return self.SCANNER_VERSION

    @property
    def capabilities(self) -> ScannerCapabilities:
        return ScannerCapabilities(
            target_types=(LocationType.SOURCE,),
            languages=("java",),
            detection_mechanisms=(DetectionMethod.SEMANTIC_REGEX,),
            output_formats=("json",),
            extracts_parameters=False,
            distinguishes_comments=True,
            provides_native_ids=True,
            provides_confidence=True,
            known_limitations=(
                "Bounded strictly to demonstration cryptographic constructs (RSA, AES, Ed25519).",
                "Performs bounded Java source pattern discovery, not whole-program AST semantic analysis.",
            ),
        )

    def scan_file_content(self, content: str, filename: str) -> List[Dict[str, Any]]:
        return self._scanner.scan_file_content(content, filename)

    def scan_file(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        return self._scanner.scan_file(file_path)

    def scan_directory(self, dir_path: Union[str, Path]) -> List[Dict[str, Any]]:
        return self._scanner.scan_directory(dir_path)

    def scan_zip(self, zip_source: Union[bytes, str, Path]) -> List[Dict[str, Any]]:
        return self._scanner.scan_zip(zip_source)

    def build_scanner_payload(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self._scanner.build_scanner_payload(findings)

    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        """Defensively parses raw DemoSourceScanner JSON output."""
        success, payload, error = self._parser.parse(raw_output.stdout_bytes)
        if not success or payload is None:
            err = error or IngestionError(
                error_code="PARSER_ERROR",
                error_message="Defensive parsing failed on DemoSourceScanner output",
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
                        error_message="Expected top-level JSON object in DemoSourceScanner output",
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
                        error_message="Expected 'findings' to be a list in DemoSourceScanner output",
                        error_source="parser",
                    ),
                ),
            )

        return ParseResult(
            status=IngestionStatus.SUCCESS,
            parsed_records=tuple(findings),
            raw_payload=payload,
            warnings=(),
        )

    def create_evidence(
        self,
        parsed: ParseResult,
        scan_id: str = "",
        raw_output_ref: str = "",
    ) -> List[EvidenceRecord]:
        """Maps parsed findings to immutable EvidenceRecords identifying DemoSourceScanner."""
        evidence_list: List[EvidenceRecord] = []
        findings = parsed.parsed_records
        if not findings:
            return evidence_list

        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            raw_file = finding.get("file", "unknown.java")
            sanitized_file = sanitize_relative_path(str(raw_file).replace("\\", "/"))

            line_start = int(finding.get("line", 0)) if finding.get("line") is not None else 0
            line_end = int(finding.get("endLine", line_start)) if finding.get("endLine") is not None else line_start
            col_start = int(finding["column"]) if finding.get("column") is not None else None

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
                column_end=None,
                matched_text=matched_text,
                code_snippet=code_snippet,
            )

            raw_id_str = str(finding.get("id", "")).strip() or f"demo-{idx}"
            evidence_id = f"demo_source_scanner:{raw_id_str}"
            category = str(finding.get("category", "") or finding.get("type", "UNKNOWN"))

            ev = EvidenceRecord(
                evidence_id=evidence_id,
                location=location,
                scanner_name=self.SCANNER_NAME,
                scanner_version=self.SCANNER_VERSION,
                detection_method=DetectionMethod.SEMANTIC_REGEX,
                scanner_category=category,
                scanner_confidence="HIGH",
                raw_attributes=freeze_value({
                    "raw_finding": finding,
                    "scanner": self.SCANNER_NAME,
                    "scanner_version": self.SCANNER_VERSION,
                    "adapter_id": self.ADAPTER_ID,
                    "method": "bounded_source_pattern_discovery",
                }),
                scan_id=scan_id,
                raw_output_ref=raw_output_ref,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            evidence_list.append(ev)

        return evidence_list


# Backward compatibility alias
BoundedDemoSourceAdapter = DemoSourceAdapter
