"""
ECDAT Ingestion Framework Unit & Security Test Suite.

Validates the adapter contract, identity hierarchy, native ID collision handling,
defensive parsing bounds, XML security, failure containment, and provenance.
"""

import json
import unittest
import uuid
import xml.etree.ElementTree as ET

from product.core.evidence.evidence import (
    DetectionMethod,
    EvidenceLocation,
    EvidenceRecord,
    LocationType,
    SourceLocation,
)
from product.core.ingestion.adapter import (
    IngestionError,
    IngestionResult,
    IngestionStatus,
    ParseResult,
    PrepareResult,
    RawScannerOutput,
    ScanExecutionMetadata,
    ScannerAdapter,
    ScannerCapabilities,
    ScanTarget,
    ScopeCoverage,
    ValidationResult,
)
from product.core.ingestion.orchestrator import IngestionOrchestrator
from product.core.ingestion.parser import DefensiveJSONParser, DefensiveXMLParser
from product.core.ingestion.registry import AdapterRegistry


class DummyThrowingAdapter(ScannerAdapter):
    """Adapter designed to simulate an unexpected programming bug / exception."""

    @property
    def adapter_id(self) -> str:
        return "throwing_adapter"

    @property
    def adapter_version(self) -> str:
        return "0.1.0"

    @property
    def scanner_name(self) -> str:
        return "DummyCrashScanner"

    @property
    def scanner_version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> ScannerCapabilities:
        return ScannerCapabilities(
            target_types=(LocationType.SOURCE,),
            languages=("java",),
            detection_mechanisms=(DetectionMethod.UNKNOWN,),
            output_formats=("json",),
        )

    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        # Simulate unexpected zero division or bug
        raise ZeroDivisionError("Simulated unexpected crash in adapter parsing logic")

    def create_evidence(self, parsed: ParseResult, scan_id: str = "", raw_output_ref: str = ""):
        return []


class DummyCustomAdapter(ScannerAdapter):
    """Configurable adapter for identity and collision unit tests."""

    def __init__(self, adapter_id: str = "custom_test", findings_to_return=None) -> None:
        self._aid = adapter_id
        self._findings = findings_to_return or []

    @property
    def adapter_id(self) -> str:
        return self._aid

    @property
    def adapter_version(self) -> str:
        return "1.0.0"

    @property
    def scanner_name(self) -> str:
        return "CustomTestScanner"

    @property
    def scanner_version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> ScannerCapabilities:
        return ScannerCapabilities(
            target_types=(LocationType.SOURCE,),
            languages=("java",),
            detection_mechanisms=(DetectionMethod.UNKNOWN,),
            output_formats=("json",),
        )

    def parse(self, raw_output: RawScannerOutput) -> ParseResult:
        return ParseResult(
            status=IngestionStatus.SUCCESS,
            parsed_records=tuple(self._findings),
        )

    def create_evidence(self, parsed: ParseResult, scan_id: str = "", raw_output_ref: str = ""):
        records = []
        id_counts = {}
        for f in parsed.parsed_records:
            fid = f.get("id")
            if fid:
                id_counts[fid] = id_counts.get(fid, 0) + 1

        collision_counters = {}
        for idx, f in enumerate(parsed.parsed_records):
            fid = f.get("id")
            is_collision = False
            if fid:
                if id_counts[fid] > 1:
                    c_idx = collision_counters.get(fid, 0)
                    collision_counters[fid] = c_idx + 1
                    evidence_id = f"{self.adapter_id}:{fid}:collision:{c_idx}"
                    is_collision = True
                else:
                    evidence_id = f"{self.adapter_id}:{fid}"
            else:
                fp = f"{self.adapter_id}:{f.get('file', 'src/App.java')}:{f.get('line', 1)}:{idx}"
                evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:test:{fp}"))

            rec = EvidenceRecord(
                evidence_id=evidence_id,
                location=SourceLocation(
                    file_path=f.get("file", "src/App.java"),
                    line_start=f.get("line", 1),
                    line_end=f.get("line", 1),
                ),
                scanner_name=self.scanner_name,
                scanner_version=self.scanner_version,
                detection_method=DetectionMethod.UNKNOWN,
                scanner_category=f.get("category", "RAW_CATEGORY"),
                raw_attributes={
                    "native_finding_id": fid or "",
                    "native_id_collision": is_collision,
                },
                scan_id=scan_id,
                raw_output_ref=raw_output_ref,
            )
            records.append(rec)
        return records


class TestIngestionFramework(unittest.TestCase):
    """Comprehensive test suite for the ingestion framework."""

    def test_verbatim_raw_bytes_hashing(self) -> None:
        """Verifies that SHA-256 is computed strictly on verbatim stdout bytes before any processing."""
        import hashlib
        raw_payload = b'{"findings": [{"id": 1}], "status": "ok"}\n\r\t'
        expected_hash = hashlib.sha256(raw_payload).hexdigest()
        
        raw_output = RawScannerOutput.from_bytes(
            stdout_bytes=raw_payload,
            adapter_id="test_adapter",
            scanner_name="TestScanner",
            scanner_version="1.0.0",
        )
        self.assertEqual(raw_output.sha256_hash, expected_hash)
        self.assertEqual(raw_output.stdout_bytes, raw_payload)

    def test_native_id_collision_validation(self) -> None:
        """
        Validates duplicate native IDs:
        1. All observations survive (count preserved).
        2. Original native IDs are preserved in raw_attributes['native_finding_id'].
        3. Evidence IDs are distinct ({adapter}:{id}:collision:{idx}).
        4. native_id_collision flag is True on both records.
        """
        duplicate_findings = [
            {"id": "RULE-001", "file": "src/Crypto.java", "line": 10, "category": "AES"},
            {"id": "RULE-001", "file": "src/Crypto.java", "line": 20, "category": "AES"},
        ]
        adapter = DummyCustomAdapter(findings_to_return=duplicate_findings)
        raw_out = RawScannerOutput.from_bytes(b"[]", "custom_test", "Custom", "1.0")
        ing_res = adapter.ingest_raw_output(raw_out)

        self.assertEqual(len(ing_res.evidence_records), 2)
        ev1, ev2 = ing_res.evidence_records

        # 1. Distinct evidence IDs
        self.assertEqual(ev1.evidence_id, "custom_test:RULE-001:collision:0")
        self.assertEqual(ev2.evidence_id, "custom_test:RULE-001:collision:1")
        self.assertNotEqual(ev1.evidence_id, ev2.evidence_id)

        # 2. Original native ID retained
        self.assertEqual(ev1.raw_attributes["native_finding_id"], "RULE-001")
        self.assertEqual(ev2.raw_attributes["native_finding_id"], "RULE-001")

        # 3. Collision flag set
        self.assertTrue(ev1.raw_attributes["native_id_collision"])
        self.assertTrue(ev2.raw_attributes["native_id_collision"])

    def test_cross_adapter_namespace_collision_prevention(self) -> None:
        """Verifies that identical native IDs across different adapters get distinct evidence IDs."""
        f = [{"id": "001", "file": "src/App.java", "line": 10}]
        adapter_a = DummyCustomAdapter(adapter_id="adapter_a", findings_to_return=f)
        adapter_b = DummyCustomAdapter(adapter_id="adapter_b", findings_to_return=f)

        raw = RawScannerOutput.from_bytes(b"[]", "dummy", "Scanner", "1.0")
        ev_a = adapter_a.ingest_raw_output(raw).evidence_records[0]
        ev_b = adapter_b.ingest_raw_output(raw).evidence_records[0]

        self.assertEqual(ev_a.evidence_id, "adapter_a:001")
        self.assertEqual(ev_b.evidence_id, "adapter_b:001")
        self.assertNotEqual(ev_a.evidence_id, ev_b.evidence_id)

    def test_missing_native_id_fallback_fingerprint(self) -> None:
        """Verifies that findings without native IDs receive deterministic scan-local disambiguated IDs."""
        f = [
            {"id": "", "file": "src/Key.java", "line": 42, "category": "RSA"},
            {"id": None, "file": "src/Key.java", "line": 42, "category": "RSA"},
        ]
        adapter = DummyCustomAdapter(findings_to_return=f)
        raw = RawScannerOutput.from_bytes(b"[]", "custom_test", "Custom", "1.0")
        records = adapter.ingest_raw_output(raw).evidence_records

        self.assertEqual(len(records), 2)
        self.assertTrue(records[0].evidence_id.startswith("2") or "-" in records[0].evidence_id)
        self.assertNotEqual(records[0].evidence_id, records[1].evidence_id)
        self.assertFalse(records[0].raw_attributes["native_id_collision"])

    def test_semantic_preservation_under_reordering(self) -> None:
        """
        Validates that permuting the order of scanner output findings:
        - preserves all observations without loss or accidental merging.
        - acknowledges that occurrence-based fallback IDs are scan-output-relative.
        """
        f1 = {"id": "ID_A", "file": "src/A.java", "line": 10}
        f2 = {"id": "ID_B", "file": "src/B.java", "line": 20}

        adapter1 = DummyCustomAdapter(findings_to_return=[f1, f2])
        adapter2 = DummyCustomAdapter(findings_to_return=[f2, f1])
        raw = RawScannerOutput.from_bytes(b"[]", "custom_test", "Custom", "1.0")

        res1 = adapter1.ingest_raw_output(raw)
        res2 = adapter2.ingest_raw_output(raw)

        self.assertEqual(len(res1.evidence_records), 2)
        self.assertEqual(len(res2.evidence_records), 2)

        # Both observations survive in both runs
        files_run1 = {ev.location.file_path for ev in res1.evidence_records}
        files_run2 = {ev.location.file_path for ev in res2.evidence_records}
        self.assertEqual(files_run1, {"src/A.java", "src/B.java"})
        self.assertEqual(files_run2, {"src/A.java", "src/B.java"})

    def test_orchestrator_exception_containment(self) -> None:
        """
        Critical invariant: An unexpected runtime exception in an adapter MUST be contained
        at the orchestrator boundary and converted to IngestionStatus.FAILED.
        The overall pipeline MUST NOT crash.
        """
        reg = AdapterRegistry()
        crashing_adapter = DummyThrowingAdapter()
        reg.register(crashing_adapter)

        orch = IngestionOrchestrator(registry=reg)
        raw = RawScannerOutput.from_bytes(b'{"test": 1}', "throwing_adapter", "CrashScanner", "1.0")

        res = orch.ingest_raw_output("throwing_adapter", raw)
        self.assertEqual(res.status, IngestionStatus.FAILED)
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].error_code, "UNEXPECTED_ADAPTER_EXCEPTION")
        self.assertIn("Simulated unexpected crash", res.errors[0].error_message)
        self.assertEqual(res.errors[0].error_source, "orchestrator")

    def test_orchestrator_unregistered_adapter(self) -> None:
        """Orchestrator cleanly returns INVALID_INPUT when requested adapter is not registered."""
        orch = IngestionOrchestrator()
        raw = RawScannerOutput.from_bytes(b"[]", "missing", "Scanner", "1.0")
        res = orch.ingest_raw_output("non_existent_adapter", raw)
        self.assertEqual(res.status, IngestionStatus.INVALID_INPUT)
        self.assertEqual(res.errors[0].error_code, "ADAPTER_NOT_FOUND")

    # --- Parser Security Limits Tests ---

    def test_json_oversized_payload_rejection(self) -> None:
        """Defensive parser actively rejects payloads exceeding max_bytes."""
        parser = DefensiveJSONParser(max_bytes=100)
        large_payload = b"x" * 150
        ok, data, err = parser.parse(large_payload)
        self.assertFalse(ok)
        self.assertIsNone(data)
        self.assertEqual(err.error_code, "PAYLOAD_TOO_LARGE")

    def test_json_deep_nesting_rejection(self) -> None:
        """Defensive parser actively rejects payloads exceeding max_depth."""
        parser = DefensiveJSONParser(max_depth=5)
        # Nest 7 levels deep: {"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}
        deep_obj = 1
        for _ in range(7):
            deep_obj = {"level": deep_obj}
        payload = json.dumps(deep_obj).encode("utf-8")

        ok, data, err = parser.parse(payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "MAX_DEPTH_EXCEEDED")

    def test_json_collection_count_rejection(self) -> None:
        """Defensive parser actively rejects arrays/objects exceeding max_collection_elements."""
        parser = DefensiveJSONParser(max_collection_elements=50)
        large_list = list(range(100))
        payload = json.dumps({"items": large_list}).encode("utf-8")

        ok, data, err = parser.parse(payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "COLLECTION_LIMIT_EXCEEDED")

    def test_json_string_length_rejection(self) -> None:
        """Defensive parser actively rejects string fields exceeding max_string_length."""
        parser = DefensiveJSONParser(max_string_length=100)
        long_str = "A" * 150
        payload = json.dumps({"key": long_str}).encode("utf-8")

        ok, data, err = parser.parse(payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "STRING_LENGTH_EXCEEDED")

    def test_json_malformed_and_truncated(self) -> None:
        """Defensive parser returns PARSER_ERROR on malformed JSON without raising uncaught exceptions."""
        parser = DefensiveJSONParser()
        malformed = b'{"key": "value", "unclosed": ['
        ok, data, err = parser.parse(malformed)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "MALFORMED_JSON")

    # --- XML Security Tests ---

    def test_xml_doctype_rejection(self) -> None:
        """Defensive XML parser strictly blocks any DOCTYPE declaration."""
        parser = DefensiveXMLParser()
        xml_payload = b'<!DOCTYPE root SYSTEM "http://evil.com/xxe"><root><tag>val</tag></root>'
        ok, root, err = parser.parse(xml_payload)
        self.assertFalse(ok)
        self.assertIsNone(root)
        self.assertEqual(err.error_code, "XML_DOCTYPE_FORBIDDEN")

    def test_xml_entity_declaration_rejection(self) -> None:
        """Defensive XML parser strictly blocks ENTITY declarations (XXE defense)."""
        parser = DefensiveXMLParser()
        xml_payload = b'<!ENTITY xxe "malicious"><root>&xxe;</root>'
        ok, root, err = parser.parse(xml_payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "XML_ENTITY_FORBIDDEN")

    def test_xml_custom_entity_reference_rejection(self) -> None:
        """Defensive XML parser blocks custom entity references (billion laughs defense)."""
        parser = DefensiveXMLParser()
        xml_payload = b'<root><tag>&customEntity;</tag></root>'
        ok, root, err = parser.parse(xml_payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "XML_CUSTOM_ENTITY_REF_FORBIDDEN")

    def test_xml_depth_limit_rejection(self) -> None:
        """Defensive XML parser rejects element hierarchy exceeding max_depth."""
        parser = DefensiveXMLParser(max_depth=3)
        xml_payload = b'<a><b><c><d><e>too deep</e></d></c></b></a>'
        ok, root, err = parser.parse(xml_payload)
        self.assertFalse(ok)
        self.assertEqual(err.error_code, "MAX_DEPTH_EXCEEDED")

    def test_xml_valid_parsing(self) -> None:
        """Defensive XML parser cleanly parses safe XML documents with built-in entities."""
        parser = DefensiveXMLParser()
        xml_payload = b'<root><item id="1">safe &amp; clean</item></root>'
        ok, root, err = parser.parse(xml_payload)
        self.assertTrue(ok)
        self.assertIsNotNone(root)
        self.assertEqual(root.tag, "root")
        self.assertEqual(root.find("item").text, "safe & clean")


if __name__ == "__main__":
    unittest.main()
