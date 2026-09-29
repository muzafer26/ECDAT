"""
Tests for EvidenceRecord, SourceLocation, and Immutability Invariants.
"""

from dataclasses import FrozenInstanceError
import unittest

from product.core.evidence.evidence import EvidenceRecord, SourceLocation, DetectionMethod
from product.core.evidence.sanitization import SecurityValidationError


class TestEvidenceModel(unittest.TestCase):

    def setUp(self) -> None:
        self.location = SourceLocation(
            file_path="src/main/App.java",
            line_start=10,
            line_end=12,
            column_start=4,
            column_end=35,
            matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\")",
            code_snippet="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\ncipher.init(Cipher.ENCRYPT_MODE, key);",
        )
        self.evidence = EvidenceRecord(
            evidence_id="ev-12345",
            location=self.location,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CERT-SYM-001",
            scanner_confidence="HIGH",
            raw_attributes={"rule_id": "rule-aes-gcm", "severity": "MEDIUM"},
            scan_id="scan-001",
            raw_output_ref="reports/raw_output.json",
        )

    def test_evidence_record_immutability(self) -> None:
        """Verifies that EvidenceRecord is strictly frozen and cannot be mutated."""
        with self.assertRaises(FrozenInstanceError):
            self.evidence.scanner_category = "MUTATED"

        with self.assertRaises(FrozenInstanceError):
            self.evidence.scanner_name = "NewScanner"

        with self.assertRaises(FrozenInstanceError):
            self.evidence.evidence_id = "ev-mutated"

    def test_source_location_immutability(self) -> None:
        """Verifies that SourceLocation is strictly frozen and cannot be mutated."""
        with self.assertRaises(FrozenInstanceError):
            self.location.line_start = 999

        with self.assertRaises(FrozenInstanceError):
            self.location.file_path = "other/Path.java"

    def test_raw_attributes_is_read_only_mapping(self) -> None:
        """Verifies that raw_attributes cannot be modified in-place."""
        with self.assertRaises(TypeError):
            self.evidence.raw_attributes["new_key"] = "forbidden"  # type: ignore

    def test_serialization_round_trip(self) -> None:
        """Verifies lossless serialization and deserialization."""
        d = self.evidence.to_dict()
        restored = EvidenceRecord.from_dict(d)

        self.assertEqual(restored.evidence_id, self.evidence.evidence_id)
        self.assertEqual(restored.scanner_name, self.evidence.scanner_name)
        self.assertEqual(restored.scanner_version, self.evidence.scanner_version)
        self.assertEqual(restored.detection_method, self.evidence.detection_method)
        self.assertEqual(restored.scanner_category, self.evidence.scanner_category)
        self.assertEqual(restored.location.file_path, self.evidence.location.file_path)
        self.assertEqual(restored.location.line_start, self.evidence.location.line_start)
        self.assertEqual(restored.location.line_end, self.evidence.location.line_end)
        self.assertEqual(restored.raw_attributes["rule_id"], "rule-aes-gcm")

    def test_coordinate_validation(self) -> None:
        """Verifies that invalid coordinates raise SecurityValidationError."""
        with self.assertRaises(SecurityValidationError):
            SourceLocation(file_path="valid/path.java", line_start=-1, line_end=5)

        with self.assertRaises(SecurityValidationError):
            SourceLocation(file_path="valid/path.java", line_start=15, line_end=10)

    def test_m02_deep_evidence_immutability(self) -> None:
        """M-02: Verifies nested dictionaries and lists in raw_attributes cannot be mutated."""
        ev = EvidenceRecord(
            evidence_id="ev-deep-immut",
            location=self.location,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CERT-SYM-001",
            raw_attributes={
                "nested": {"param": "value", "sub": {"level": 2}},
                "items": ["a", "b", "c"],
                "tags": {"fast", "secure"},
            },
        )

        # 1. Nested dict mutation rejection
        with self.assertRaises(TypeError):
            ev.raw_attributes["nested"]["param"] = "tampered"  # type: ignore

        with self.assertRaises(TypeError):
            ev.raw_attributes["nested"]["sub"]["level"] = 999  # type: ignore

        # 2. Nested list mutation rejection
        with self.assertRaises(AttributeError):
            ev.raw_attributes["items"].append("d")  # type: ignore

        with self.assertRaises(TypeError):
            ev.raw_attributes["items"][0] = "tampered"  # type: ignore

        # 3. Nested set mutation rejection (frozen to frozenset)
        with self.assertRaises(AttributeError):
            ev.raw_attributes["tags"].add("tampered")  # type: ignore

    def test_h02_generalized_location_types(self) -> None:
        """H-02: Verifies EvidenceLocation models non-source locators without path constraints."""
        from product.core.evidence.evidence import EvidenceLocation, LocationType

        # Network evidence
        net_loc = EvidenceLocation(
            location_type=LocationType.NETWORK,
            endpoint="tls.example.com",
            port=8443,
            matched_text="TLSv1.3",
        )
        self.assertEqual(net_loc.location_type, LocationType.NETWORK)
        self.assertEqual(net_loc.endpoint, "tls.example.com")
        self.assertEqual(net_loc.port, 8443)
        self.assertIsNone(net_loc.file_path)

        # Dependency evidence
        dep_loc = EvidenceLocation(
            location_type=LocationType.DEPENDENCY,
            package_coordinate="org.bouncycastle:bcprov-jdk18on:1.78.1",
        )
        self.assertEqual(dep_loc.location_type, LocationType.DEPENDENCY)
        self.assertEqual(dep_loc.package_coordinate, "org.bouncycastle:bcprov-jdk18on:1.78.1")

        # Container evidence
        cont_loc = EvidenceLocation(
            location_type=LocationType.CONTAINER,
            container_image="registry.internal/crypto-service:2.1",
            layer_digest="sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        )
        self.assertEqual(cont_loc.location_type, LocationType.CONTAINER)
        self.assertEqual(cont_loc.layer_digest, "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069")

        # Certificate evidence
        cert_loc = EvidenceLocation(
            location_type=LocationType.CERTIFICATE,
            certificate_id="x509-fingerprint-sha256:abcd1234ef",
        )
        self.assertEqual(cert_loc.location_type, LocationType.CERTIFICATE)
        self.assertEqual(cert_loc.certificate_id, "x509-fingerprint-sha256:abcd1234ef")

        # Binary evidence
        bin_loc = EvidenceLocation(
            location_type=LocationType.BINARY,
            binary_artifact="/usr/lib/libcrypto.so.3",
        )
        self.assertEqual(bin_loc.location_type, LocationType.BINARY)

        # Serialization round-trip for generalized location
        d = net_loc.to_dict()
        restored = EvidenceLocation.from_dict(d)
        self.assertEqual(restored.location_type, LocationType.NETWORK)
        self.assertEqual(restored.endpoint, "tls.example.com")
        self.assertEqual(restored.port, 8443)

    def test_m04_real_scanner_output_schema_compatibility(self) -> None:
        """
        M-04: Verifies EvidenceRecord model compatibility with real Phase 1C-B scanner JSON structures.
        Note: Real scanner ingestion compatibility is a Phase 2 adapter acceptance requirement.
        """
        import json
        import os

        raw_output_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "benchmark",
            "tools",
            "raw_outputs",
            "cryptoscan",
            "tc02_symmetric_aes",
            "run1_output.json",
        )
        if not os.path.exists(raw_output_path):
            self.skipTest(f"Raw output fixture not found at {raw_output_path}")

        with open(raw_output_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        tool_info = raw_data.get("tool", {})
        findings = raw_data.get("findings", [])
        self.assertTrue(len(findings) > 0, "Expected at least one raw finding")

        first_finding = findings[0]
        # Verify compatibility with domain EvidenceRecord
        # Notice: relative path extraction is an adapter responsibility in Phase 2
        raw_file = first_finding.get("file", "")
        # Derive relative path from workspace root
        if "product" in raw_file:
            rel_file = raw_file[raw_file.index("product"):].replace("\\", "/")
        else:
            rel_file = "benchmark/corpus/seed/tc02_symmetric_aes/AesGcmCipher.java"

        ev = EvidenceRecord(
            evidence_id=first_finding["id"],
            location=SourceLocation(
                file_path=rel_file,
                line_start=int(first_finding.get("line", 1)),
                line_end=int(first_finding.get("line", 1)),
                column_start=first_finding.get("column"),
                matched_text=first_finding.get("match", ""),
                code_snippet=first_finding.get("context", ""),
            ),
            scanner_name=tool_info.get("name", "CryptoScan"),
            scanner_version=tool_info.get("version", "1.0.0"),
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category=first_finding.get("category", "Symmetric Encryption"),
            raw_attributes=first_finding,
        )

        self.assertEqual(ev.evidence_id, first_finding["id"])
        self.assertEqual(ev.scanner_name, "CryptoScan")
        self.assertEqual(ev.scanner_category, "Symmetric Encryption")
        self.assertEqual(ev.raw_attributes["algorithm"], "AES")
        self.assertEqual(ev.raw_attributes["qrammMapping"]["dimension"], "CVI")

    def test_def01_non_source_location_deserialization_round_trip(self) -> None:
        """DEF-01: Verifies EvidenceRecord.from_dict successfully deserializes non-source locations (e.g. DEPENDENCY, NETWORK)."""
        from product.core.evidence.evidence import EvidenceLocation, LocationType

        # 1. Dependency location (Syft / TC-09 scenario)
        dep_loc = EvidenceLocation(
            location_type=LocationType.DEPENDENCY,
            package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1",
        )
        ev_dep = EvidenceRecord(
            evidence_id="ev-syft-bcprov",
            location=dep_loc,
            scanner_name="syft",
            scanner_version="1.51.1",
            detection_method=DetectionMethod.LOCKFILE_PARSE,
            scanner_category="dependency",
        )
        data = ev_dep.to_dict()
        restored = EvidenceRecord.from_dict(data)

        self.assertEqual(restored.location.location_type, LocationType.DEPENDENCY)
        self.assertEqual(restored.location.package_coordinate, "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1")
        self.assertEqual(restored.evidence_id, "ev-syft-bcprov")

        # 2. Network location
        net_loc = EvidenceLocation(
            location_type=LocationType.NETWORK,
            endpoint="api.internal.bank.com",
            port=8443,
        )
        ev_net = EvidenceRecord(
            evidence_id="ev-ssl-01",
            location=net_loc,
            scanner_name="sslscan",
            scanner_version="2.1.0",
            detection_method=DetectionMethod.UNKNOWN,
            scanner_category="TLS",
        )
        data_net = ev_net.to_dict()
        restored_net = EvidenceRecord.from_dict(data_net)
        self.assertEqual(restored_net.location.location_type, LocationType.NETWORK)
        self.assertEqual(restored_net.location.endpoint, "api.internal.bank.com")
        self.assertEqual(restored_net.location.port, 8443)

    def test_def02_string_detection_method_coercion_and_to_dict(self) -> None:
        """DEF-02: Verifies string detection_method is coerced into DetectionMethod and to_dict does not raise AttributeError."""
        ev = EvidenceRecord(
            evidence_id="ev-str-det",
            location=self.location,
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method="ast_analysis",  # passed as raw string
            scanner_category="RSA",
        )
        self.assertIsInstance(ev.detection_method, DetectionMethod)
        self.assertEqual(ev.detection_method, DetectionMethod.AST_ANALYSIS)

        # Must not raise AttributeError: 'str' object has no attribute 'value'
        d = ev.to_dict()
        self.assertEqual(d["detection_method"], "ast_analysis")


if __name__ == "__main__":
    unittest.main()
