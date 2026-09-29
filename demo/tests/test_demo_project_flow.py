"""
Tests for ECDAT Demo Project Flow, Bounded Discovery Adapter, and Truthful Invariants.

Verifies:
1. Sample project download endpoint
2. Bounded demo source adapter functionality (Java source parsing, pattern discovery, provenance)
3. Demo project analysis endpoint (explicit built-in sample, uploaded zip, uploaded java)
4. Input validation and honest error handling:
   - Empty requests rejected with HTTP 400
   - Unsupported file formats rejected
   - Corrupt / malformed ZIP archives rejected
   - Zip archives without Java files produce honest zero findings
   - Java files without cryptographic constructs produce honest zero findings
   - Path traversal in zip archives safely skipped and sanitized
   - Oversized input files rejected
5. Single primary user experience:
   - No dual-mode switcher
   - Dropzone with drag & drop and click-to-choose
   - Explicit built-in sample button
   - Inspection panel
6. Provenance & controlled context separation:
   - Adapter ID is demo_source_adapter (NOT cryptoscan)
   - Scanner name is DemoSourceScanner
   - Context is labeled CONTROLLED_DEMONSTRATION_CONTEXT
   - No contradictory exposure (e.g. Internet-Facing vs INTERNAL_VPC)
7. Cross-scenario isolation and clean state resets
"""

from io import BytesIO
import json
import os
from pathlib import Path
import zipfile
import pytest

from demo.adapters.demo_source_adapter import BoundedDemoSourceAdapter
from demo.adapters.models import CapabilityClassification
from demo.adapters.registry import DemoAdapterRegistry
from demo.backend.app import create_app
from demo.orchestration.engine import DemoOrchestrator
from demo.orchestration.models import DemoExecutionStatus


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def orchestrator():
    return DemoOrchestrator()


class TestSampleProjectDownload:
    def test_download_sample_project_returns_zip(self, client):
        response = client.get("/api/sample-project/download")
        assert response.status_code == 200
        assert response.mimetype == "application/zip"
        assert len(response.data) > 0

        # Verify it is a valid zip containing expected files
        zf = zipfile.ZipFile(BytesIO(response.data))
        names = zf.namelist()
        assert any("KeyExchangeService.java" in n for n in names)
        assert any("EncryptionService.java" in n for n in names)
        assert any("SignatureService.java" in n for n in names)
        assert any("AuthenticationService.java" in n for n in names)
        assert any("application.properties" in n for n in names)
        assert any("README.md" in n for n in names)


class TestBoundedDemoSourceAdapter:
    def test_adapter_scans_sample_directory(self):
        adapter = BoundedDemoSourceAdapter()
        sample_dir = Path("demo/sample_project/ECDAT-Demo-Application")
        findings = adapter.scan_directory(sample_dir)

        # Must find RSA, AES, Ed25519
        algorithms = {f["algorithm"] for f in findings}
        assert "RSA" in algorithms
        assert "AES" in algorithms
        assert "Ed25519" in algorithms

        for f in findings:
            assert "id" in f
            assert "file" in f
            assert "line" in f
            assert "sourceContext" in f
            assert len(f["sourceContext"]["lines"]) > 0

    def test_adapter_scans_zip_bytes(self):
        adapter = BoundedDemoSourceAdapter()
        zip_path = Path("demo/sample_project/ECDAT-Demo-Application.zip")
        assert zip_path.is_file()
        zip_bytes = zip_path.read_bytes()
        findings = adapter.scan_zip(zip_bytes)
        assert len(findings) >= 3

    def test_adapter_honest_on_unrelated_code(self):
        adapter = BoundedDemoSourceAdapter()
        unrelated = """
        package com.example;
        public class MathHelper {
            public int add(int a, int b) { return a + b; }
        }
        """
        findings = adapter.scan_file_content(unrelated, "MathHelper.java")
        assert len(findings) == 0

    def test_adapter_handles_zip_path_traversal_safely(self):
        adapter = BoundedDemoSourceAdapter()
        bio = BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("../../etc/passwd.java", 'KeyPairGenerator.getInstance("RSA");')
            zf.writestr("safe/Valid.java", 'KeyPairGenerator.getInstance("RSA");')
        
        findings = adapter.scan_zip(bio.getvalue())
        # Path traversal should be skipped or sanitized
        assert len(findings) == 1
        assert "safe/Valid.java" in findings[0]["file"]
        assert "../" not in findings[0]["file"]


class TestDemoProjectAnalysisEndpoint:
    """Tests POST /api/demo-project/analyze contract, validation, and error states."""

    def test_empty_request_rejected_with_400_validation_error(self, client):
        """CRITICAL BUG CHECK: Empty POST must NEVER implicitly run sample project."""
        response = client.post("/api/demo-project/analyze")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "Add a demonstration project to begin" in data["error"]
        assert data.get("status") == "VALIDATION_ERROR"

    def test_empty_multipart_request_rejected_with_400(self, client):
        """Empty multipart request must also be rejected."""
        response = client.post(
            "/api/demo-project/analyze",
            data={},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "Add a demonstration project to begin" in data["error"]

    def test_analyze_explicit_builtin_sample(self, client):
        """Explicit query parameter ?sample=true executes the bundled sample project."""
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        assert data["status"] == "SUCCESS"
        assert data["scenario_id"] == "demo_project"
        assert data["classification"] == "LIVE"
        assert len(data["assets"]) >= 3

        # Check algorithms in discovered assets
        algos = {a["algorithm"] for a in data["assets"]}
        assert "RSA" in algos
        assert "AES" in algos
        assert "Ed25519" in algos

        # Check risk and migration summary
        assert data["risk_summary"]["total_assets_evaluated"] >= 3
        assert data["migration_summary"]["pqc_recommended_count"] >= 1

    def test_analyze_uploaded_zip(self, client):
        """Uploaded zip archive is parsed and analyzed through frozen core."""
        zip_path = Path("demo/sample_project/ECDAT-Demo-Application.zip")
        zip_bytes = zip_path.read_bytes()

        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(zip_bytes), "Custom-App.zip")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "SUCCESS"
        assert len(data["assets"]) >= 3

    def test_analyze_uploaded_single_java(self, client):
        """Single Java source file is parsed and analyzed through frozen core."""
        java_content = (
            "package com.example.service;\n"
            "import java.security.KeyPairGenerator;\n"
            "public class CustomKeyService {\n"
            "    public void generate() throws Exception {\n"
            "        KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n"
            "        kpg.initialize(2048);\n"
            "    }\n"
            "}\n"
        ).encode("utf-8")

        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(java_content), "CustomKeyService.java")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "SUCCESS"
        assert len(data["assets"]) == 1
        assert data["assets"][0]["algorithm"] == "RSA"

    def test_analyze_rejects_unsupported_format_honestly(self, client):
        """Non-supported file format is rejected with clean error."""
        bad_file = b"This is plain text with no crypto."
        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(bad_file), "notes.txt")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["status"] == "UNAVAILABLE"
        assert "Unsupported file format" in data["error_message"]

    def test_analyze_rejects_corrupt_zip_honestly(self, client):
        """Corrupt ZIP archive returns 400 with clean error."""
        corrupt_zip = b"PK\x03\x04corrupted_zip_payload_header_bytes_12345"
        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(corrupt_zip), "BrokenApp.zip")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["status"] == "FAILED"
        assert "not a valid or readable ZIP file" in data["error_message"]

    def test_analyze_zip_without_java_files_yields_zero_findings(self, client):
        """Valid ZIP containing no Java files produces honest zero-finding result."""
        bio = BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("README.txt", "No java files here")
            zf.writestr("config.json", '{"name": "test"}')

        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(bio.getvalue()), "NoJava.zip")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "SUCCESS"
        assert len(data["assets"]) == 0
        assert len(data["evidence_records"]) == 0

    def test_analyze_java_file_with_no_crypto_yields_zero_findings(self, client):
        """Java file with normal code and no crypto patterns yields honest 0 assets."""
        plain_java = b"package com.test;\npublic class Util { public int sum(int a, int b) { return a + b; } }\n"
        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(plain_java), "Util.java")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "SUCCESS"
        assert len(data["assets"]) == 0

    def test_analyze_rejects_oversized_input(self, client):
        """Oversized files (>20MB) are rejected with clear message."""
        huge_file = b"0" * (21 * 1024 * 1024)
        response = client.post(
            "/api/demo-project/analyze",
            data={"file": (BytesIO(huge_file), "huge.zip")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "exceeds the 20MB limit" in data["error_message"]


class TestArchitectureAndAdapterRegistry:
    def test_adapter_registry_exposes_demo_source_adapter(self):
        reg = DemoAdapterRegistry()
        adapter_info = reg.get_status("demo_source_adapter")
        assert adapter_info is not None
        assert adapter_info.status == CapabilityClassification.LIVE
        assert adapter_info.scanner_name == "DemoSourceScanner"
        assert adapter_info.adapter_id == "demo_source_adapter"
        assert adapter_info.adapter_id != "cryptoscan"
        assert "RSA" in adapter_info.limitations

    def test_adapters_api_returns_all_adapters(self, client):
        response = client.get("/api/adapters")
        assert response.status_code == 200
        data = response.get_json()
        adapter_ids = [a["adapter_id"] for a in data["adapters"]]
        assert "demo_source_adapter" in adapter_ids
        assert "cryptoscan" in adapter_ids
        assert "syft" in adapter_ids
        assert "sonar" in adapter_ids
        assert "codeql" in adapter_ids
        assert "sslscan" in adapter_ids


class TestGuidedScenariosPreserved:
    def test_scenarios_list_contains_tc01_tc02_tc06(self, client):
        response = client.get("/api/scenarios")
        assert response.status_code == 200
        scenarios = {s["scenario_id"] for s in response.get_json()["scenarios"]}
        assert "tc01_direct_rsa" in scenarios
        assert "tc02_symmetric_aes" in scenarios
        assert "tc06_ed25519" in scenarios

    def test_tc01_execution_succeeds(self, client):
        response = client.post("/api/scenarios/tc01_direct_rsa/run")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "SUCCESS"
        assert len(data["assets"]) >= 1

    def test_cross_scenario_isolation(self, client):
        # 1. Run TC01
        res1 = client.post("/api/scenarios/tc01_direct_rsa/run")
        assert res1.status_code == 200

        # 2. Run Demo Project (explicit sample request)
        res_dp = client.post("/api/demo-project/analyze?sample=true")
        assert res_dp.status_code == 200

        # 3. Run TC02
        res2 = client.post("/api/scenarios/tc02_symmetric_aes/run")
        assert res2.status_code == 200
        data2 = res2.get_json()
        assert data2["scenario_id"] == "tc02_symmetric_aes"
        # Must only contain AES from TC02, no leakage from Demo Project or TC01
        algos = {a["algorithm"] for a in data2["assets"]}
        assert "AES" in algos
        assert "RSA" not in algos


class TestFrontendDOMAndTruthInvariants:
    @pytest.fixture(autouse=True)
    def load_frontend_html(self):
        html_path = Path("demo/frontend/index.html")
        assert html_path.is_file()
        self.html = html_path.read_text(encoding="utf-8")

        js_path = Path("demo/frontend/app.js")
        assert js_path.is_file()
        self.js = js_path.read_text(encoding="utf-8")

    def test_no_misleading_source_scanning_claims(self):
        """Verifies misleading 'Choose a Java source file' is completely absent."""
        assert "Choose a Java source file" not in self.html
        assert "Choose a Java source file" not in self.js
        assert "scan any Java" not in self.html.lower()

    def test_single_primary_demo_mode_no_dual_mode_switcher(self):
        """Verifies the two-path demo switcher is removed in favor of single primary dropzone flow."""
        assert 'id="mode-btn-guided"' not in self.html
        assert 'id="mode-btn-project"' not in self.html

        required_primary_elements = [
            "demo-dropzone",
            "demo-file-input",
            "btn-choose-file",
            "btn-run-analysis",
            "btn-use-builtin-sample",
            "btn-inspect-sample",
            "sample-inspection-box",
            "btn-download-sample",
            "input-validation-msg",
            "btn-clear-upload",
            "tracker-container",
            "asset-lifecycle-tracker",
            "alt-asset-name",
            "alt-priority-pill",
        ]
        for elem_id in required_primary_elements:
            assert f'id="{elem_id}"' in self.html, f"Missing required element ID: {elem_id}"

    def test_js_controller_handles_single_mode_and_lifecycle(self):
        """Verifies JS controller implements file handling, built-in sample, and lifecycle tracking."""
        assert "handleFileSelection" in self.js
        assert "setBuiltinSample" in self.js
        assert "clearFileSelection" in self.js
        assert "updateInputControls" in self.js
        assert "renderLifecycleTracker" in self.js
        assert "tracker-container" in self.js

    def test_architectural_explanation_sections_present(self):
        """Verifies 'Why ECDAT' and 'About this Prototype' are present in HTML."""
        assert "Why ECDAT? The Architectural Progression" in self.html
        assert "What is Different About the Approach" in self.html
        assert "About this Prototype" in self.html
        assert "Current Prototype" in self.html
        assert "Broader Product Vision" in self.html

    def test_asset_lifecycle_traceability_data(self, client):
        """Verifies that running demo project provides facts across all 8 lifecycle stages."""
        res = client.post("/api/demo-project/analyze?sample=true")
        assert res.status_code == 200
        data = res.get_json()

        # 1. Discover
        assert len(data["assets"]) >= 3
        # 2. Evidence
        assert len(data["evidence_records"]) >= 3
        # 3. Understand
        rsa_asset = next(a for a in data["assets"] if a["algorithm"] == "RSA")
        assert rsa_asset["role"] == "key_generation"
        assert rsa_asset["family"] == "RSA"
        # 4. Risk
        assert rsa_asset["priority_tier"] is not None
        assert "observed_facts" in rsa_asset
        # 5. Migration
        assert len(rsa_asset["candidate_targets"]) >= 1
        assert "ML-KEM-768" in rsa_asset["candidate_targets"]
        # 6. Plan
        assert data["migration_summary"]["total_milestones"] >= 1
        # 7. Review
        assert rsa_asset["requires_human_review"] is True
        # 8. Verify
        assert "ARCHITECTURAL PROJECTION" in self.html
        assert "CONTROLLED / FUTURE (PHASE 9)" in self.html


class TestDemoSourceProvenanceAndControlledContext:
    """
    Specifically tests requirements:
    1. Provenance identifies DemoSourceScanner
    2. Ingestion adapter ID is demo_source_adapter, NOT cryptoscan
    3. Operational context is explicitly marked as CONTROLLED DEMONSTRATION CONTEXT
    4. Source evidence and contextual metadata remain distinguishable
    5. Internally consistent context without Internet-Facing vs INTERNAL_VPC contradiction
    """

    def test_provenance_identifies_demo_source_scanner_not_cryptoscan(self, client):
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        assert data["scanner_name"] == "DemoSourceScanner"
        assert data["scanner_name"] != "CryptoScan"
        assert len(data["provenance_chain"]) >= 1

        for chain in data["provenance_chain"]:
            assert len(chain) > 0
            scanner_node = chain[0]
            assert scanner_node["step"] == "scanner"
            assert scanner_node["entity_id"] == "DemoSourceScanner"
            assert "DemoSourceScanner" in scanner_node["label"]
            assert "CryptoScan" not in scanner_node["label"]
            assert scanner_node["details"]["adapter_id"] == "demo_source_adapter"
            assert scanner_node["details"]["adapter_id"] != "cryptoscan"
            assert scanner_node["source_type"] == "DIRECT_CORE_OUTPUT"

    def test_evidence_records_identify_demo_source_scanner(self, client):
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        assert len(data["evidence_records"]) >= 3
        for ev in data["evidence_records"]:
            assert ev["scanner_name"] == "DemoSourceScanner"
            assert ev["scanner_name"] != "CryptoScan"
            assert ev["scanner_version"] == "1.0.0-demo"
            assert "demo_source_scanner" in ev["evidence_id"]

    def test_controlled_context_marked_as_context(self, client):
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        for asset in data["assets"]:
            assert asset["context_provenance"] == "CONTROLLED_DEMONSTRATION_CONTEXT"
            assert asset["network_exposure"] == "Internet-Facing Public Endpoint"
            assert asset["environment"] == "production"
            assert asset["organization"] == "Global FinTech Enterprise (Demo Scope)"
            assert asset["system"] == "Payment Gateway & Ingestion API"

    def test_source_evidence_and_contextual_metadata_distinguishable(self, client):
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        # Contextual strings must NEVER appear in raw evidence records
        for ev in data["evidence_records"]:
            assert "Global FinTech" not in ev["matched_text"]
            assert "Payment Gateway" not in ev["matched_text"]
            assert "Internet-Facing" not in ev["matched_text"]
            assert "production" not in ev["matched_text"]
            if ev["code_snippet"]:
                assert "Global FinTech" not in ev["code_snippet"]
                assert "Payment Gateway" not in ev["code_snippet"]

        # Empirical findings contain code-level evidence only
        for f in data["findings"]:
            assert "KeyExchangeService" in f["location_display"] or "EncryptionService" in f["location_display"] or "SignatureService" in f["location_display"]

    def test_internally_consistent_exposure_no_internal_vpc_contradiction(self, client):
        response = client.post("/api/demo-project/analyze?sample=true")
        assert response.status_code == 200
        data = response.get_json()

        for asset in data["assets"]:
            assert asset["network_exposure"] == "Internet-Facing Public Endpoint"
            assert asset["network_exposure"] != "INTERNAL_VPC"
