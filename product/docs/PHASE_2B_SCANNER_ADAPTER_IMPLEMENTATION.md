# Phase 2B — Scanner Adapter Framework & Defensive Ingestion Implementation Report

**Document Version:** 1.1.0 (Conditional-Pass Documentation Corrections Applied)  
**Status:** CONDITIONALLY COMPLETE — OFFLINE INGESTION SCOPE  
**Reference Architecture:** `product/docs/PHASE_2A_SCANNER_ADAPTER_INGESTION_ARCHITECTURE.md` (v1.1.0)  
**Execution Scope:** Phase 2B Implementation Authorization (Standard Library Python 3.12 Only)  

---

## 1. Executive Summary

Phase 2B establishes the formal, defensive anti-corruption boundary between external discovery tools (CryptoScan v1.4.0, Anchore Syft v1.51.1) and the immutable ECDAT Phase 1D domain and normalization layer (`product/core/domain/`, `product/core/evidence/`, `product/core/normalization/`).

The completed Phase 2B scope covers:
- Scanner adapter base contract and lifecycle structures
- Offline raw-output ingestion pipeline (`ingest_raw_output` and `ingest_from_file`)
- Defensive parsing engine for JSON and XML payloads
- CryptoScan v1.4.0 adapter
- Anchore Syft v1.51.1 dependency cataloger adapter
- In-memory adapter registry
- Sequential ingestion orchestrator with exception containment boundary
- Phase 1D normalization and asset correlation integration
- Provenance and raw-output hash tracking
- Automated unit, integration, and benchmark semantic verification test suites

**Explicit Scope Boundary:** Live scanner CLI subprocess execution, process timeout enforcement, and operating-system isolation are **NOT IMPLEMENTED IN PHASE 2B** (deferred to Phase 8 deployment runner). `ScannerAdapter.execute()` returns `IngestionStatus.UNSUPPORTED`.

All implemented Phase 2B components use the Python 3.12 standard library, with **zero third-party dependencies**, **zero modifications to Phase 1D implementation**, and **zero alterations to benchmark ground truth or raw outputs**.

The complete test suite of **120 tests** (80 pre-existing baseline + 40 Phase 2B tests) passes with **100% success rate (0 failures, 0 errors)** in ~0.05 seconds.

```
External Scanner (CryptoScan / Syft)
    ↓ raw stdout bytes captured
RawScannerOutput (verbatim SHA-256 computed BEFORE decode/trim/parse)
    ↓
Defensive Parser (Bounded JSON / Forbidden XML DOCTYPE & ENTITY)
    ↓ parsed payload
Scanner Adapter (CryptoScanAdapter / SyftAdapter)
    ↓ creates immutable
EvidenceRecord (LocationType, DetectionMethod.UNKNOWN, verbatim category, provenance)
    ↓ normalized by Phase 1D
Finding (AlgorithmIdentity, Role, Parameters, Confidence)
    ↓ correlated by Phase 1D (same-source statement only)
CryptoAsset (Deterministic UUIDv5 from CanonicalAssetKey; zero scanner/finding ID dependence)
```

---

## 2. File Manifest

### A. Files Created (Phase 2B Implementation)

| File Path | Description | Lines |
| :--- | :--- | :--- |
| `product/core/ingestion/__init__.py` | Ingestion module export root | 38 |
| `product/core/ingestion/adapter.py` | Core lifecycle contracts, dataclasses, status enums, decoupled entry points | 487 |
| `product/core/ingestion/parser.py` | Defensive bounded JSON and XML parsers enforcing DoS & XXE bounds | 258 |
| `product/core/ingestion/registry.py` | In-memory explicit adapter registry and lookup mechanics | 63 |
| `product/core/ingestion/orchestrator.py` | Sequential ingestion orchestrator with exception containment boundary | 179 |
| `product/core/ingestion/adapters/__init__.py` | Adapter package export points | 18 |
| `product/core/ingestion/adapters/cryptoscan.py` | CryptoScan v1.4.0 AST scanner adapter with collision & path defense | 312 |
| `product/core/ingestion/adapters/syft.py` | Anchore Syft v1.51.1 SBOM dependency cataloger adapter | 277 |
| `product/tests/test_ingestion_framework.py` | 17 unit tests: hashing, collisions, namespaces, reordering, parser bounds | 363 |
| `product/tests/test_cryptoscan_adapter.py` | 6 unit & integration tests: path traversal defense, collision, fallback, E2E | 254 |
| `product/tests/test_syft_adapter.py` | 6 unit & integration tests: non-inference, PURLs, filtering, dependency E2E | 258 |
| `product/tests/test_phase2b_semantic_verification.py` | 11 semantic verification tests: TC-01 through TC-11 benchmark raw inputs | 188 |
| `product/docs/PHASE_2B_SCANNER_ADAPTER_IMPLEMENTATION.md` | Authoritative implementation and verification documentation (this file) | ~380 |

### B. Files Modified

| File Path | Description |
| :--- | :--- |
| `product/docs/PROJECT_STATE.md` | Updated Phase 2B status to CONDITIONAL PASS / DOCUMENTATION CORRECTIONS COMPLETE |

### C. Files Explicitly Verified Unchanged (Protected Baselines)

1. `product/core/evidence/*` (8 files verified untouched; 0 bytes modified)
2. `product/core/domain/*` (16 files verified untouched; 0 bytes modified)
3. `product/core/normalization/*` (8 files verified untouched; 0 bytes modified)
4. `product/benchmark/corpus/seed/*` (14 files verified untouched; 0 bytes modified)
5. `product/benchmark/ground_truth/*` (0 ground truth files altered)
6. `product/benchmark/tools/raw_outputs/*` (114 raw scanner outputs verified byte-identical)

---

## 3. Architectural Implementations & Invariants

### 3.1 Raw Output Integrity & Verbatim Hashing
- **Invariant:** The SHA-256 hash representing a scan execution is computed strictly on the unmodified `stdout_bytes` captured directly from the scanner process prior to decoding, whitespace normalization, parsing, or JSON deserialization.
- **Implementation:** `RawScannerOutput.from_bytes()` computes `hashlib.sha256(stdout_bytes).hexdigest()`. Canonicalization or pretty-printing is never performed on raw output bytes.
- **Stderr Separation:** Stderr bytes are preserved independently in `RawScannerOutput.stderr_bytes` and never concatenated into stdout.

### 3.2 Defensive Parsing Security Controls
Implemented via `DefensiveJSONParser` and `DefensiveXMLParser` using Python's standard library:

1. **JSON Size Limitation (TESTED CONTROL):** Enforces a hard maximum payload limit of 100 MB (`104,857,600` bytes). Exceeding inputs are rejected before deserialization with `PAYLOAD_TOO_LARGE`.
2. **JSON Nesting Depth (TESTED CONTROL):** Deeply nested structures exceeding depth 50 are rejected with `MAX_DEPTH_EXCEEDED` (or `RECURSION_LIMIT_EXCEEDED` for extreme nesting).
3. **JSON Collection Limit (QUALIFIED CONTROL — PER CONTAINER):** `max_collection_elements` (default 100,000) is enforced **per individual JSON collection** (dict or list container), not as a cumulative document-wide element counter. Collections exceeding this limit are rejected with `COLLECTION_LIMIT_EXCEEDED`.
4. **JSON String Length Bound (TESTED CONTROL):** Individual string token length bounded to $\le 1\text{ MB}$ (`1,048,576` bytes). Rejections return `STRING_LENGTH_EXCEEDED`.
5. **XML Security Enforcement (TESTED CONTROL):**
   - Immediate rejection of any payload containing `<!DOCTYPE` (`XML_DOCTYPE_FORBIDDEN`).
   - Immediate rejection of any payload containing `<!ENTITY` (`XML_ENTITY_FORBIDDEN`).
   - Custom entity declarations and expansion completely prohibited (`XML_CUSTOM_ENTITY_REF_FORBIDDEN`).
   - Parsing depth bounded to $\le 50$ via ElementTree depth verification (`MAX_DEPTH_EXCEEDED`).
   - Total payload size bounded to $\le 100\text{ MB}$ (`PAYLOAD_TOO_LARGE`).

### 3.3 Evidence Identity vs. Asset Identity Separation
- **Evidence Identity:** Represents a specific empirical observation within a scan.
  - Formatted with adapter namespace: `{adapter_id}:{native_id}`.
  - In collision scenarios: `{adapter_id}:{native_id}:collision:{collision_index}`.
  - Fallback for missing native IDs: Deterministic UUIDv5 fingerprint combining adapter namespace, scanner version, sanitized location, category, matched text, and positional occurrence index.
  - **Critical Rule:** Fallback evidence IDs are scan-local and observational. They do **not** represent semantic asset identity across scans or commits.
- **Asset Identity:** Authoritative semantic identity derived by Phase 1D `CanonicalAssetKey`.
  - Derived strictly from: `(asset_type, location_anchor, algorithm_family, algorithm_name, variant, role, parameter_signature)`.
  - **Zero dependency** on scanner names, scan IDs, finding IDs, evidence IDs, or occurrence indices.

### 3.4 Native ID Collision Handling
If an external scanner emits multiple findings with identical native finding IDs within a single scan run:
1. Every observation is preserved (zero evidence destruction).
2. The original native finding ID is preserved verbatim in `raw_attributes["native_finding_id"]`.
3. `raw_attributes["native_id_collision"] = True` is set on all colliding records.
4. Distinct evidence IDs are assigned: `{adapter_id}:{native_id}:collision:{idx}`.
5. An observable diagnostic warning is emitted on `IngestionResult.warnings`.

### 3.5 CryptoScan v1.4.0 Adapter Specifics
- **Detection Method:** Strictly `DetectionMethod.UNKNOWN`. CryptoScan findings do not declare detection technique in output JSON. ECDAT refuses to manufacture `AST_ANALYSIS`.
- **Category Preservation:** Verbatim string preservation of scanner category (e.g. `"Asymmetric Encryption"`, `"Deprecated Hash"`, `"Certificate"`) in `scanner_category`.
- **Path Sanitization & Absolute Host Path Fallback:**
  - `normalize_source_path()` strictly rejects traversal sequences (`..`, `%2e%2e`).
  - Recognized fixture/scan anchors (e.g., `src/`, `tc\d+_...`) are converted to safe relative paths.
  - Unanchored absolute paths fall back to basename representation (e.g., `C:\Windows\System32\cmd.exe` → `cmd.exe`).
  - **Adapter Limitation:** Unanchored absolute scanner paths may lose directory context when represented as a basename. This safely prevents filesystem traversal outside scan-relative evidence, but does not preserve complete original host-path context.
- **Occurrence Index:** Stored in `raw_attributes["occurrence_index"]` as a scan-output-relative disambiguator, never used as semantic identity.

### 3.6 Anchore Syft v1.51.1 Adapter Specifics
- **Target Type:** Exclusively `LocationType.DEPENDENCY`.
- **Category:** Assigned fixed category `"dependency"`.
- **Zero Algorithm Inference:** The presence of a cryptographic package (e.g. `bcprov-jdk18on`, OpenSSL, PyCryptodome) **never** causes the adapter or normalizer to infer specific cryptographic algorithms (such as AES, RSA, ECDSA). Normalizes to `ObservationType.LIBRARY_DEPENDENCY` with `AlgorithmFamily.UNKNOWN`.
- **Defensive PURL Handling:** PURLs are sanitized if present; missing PURLs are never fabricated. Missing coordinates remain `None`.
- **Observable Relevance Filtering:** If a `relevance_policy` predicate is configured, filtered artifacts are omitted from active evidence emission, but:
  - The total filtered count is explicitly recorded in `IngestionResult.warnings`.
  - The raw scanner payload retains all artifacts untouched in `raw_payload`.

### 3.7 Ingestion Orchestrator & Failure Semantics
`IngestionOrchestrator` governs the offline ingestion pipeline:
- **Status Reporting:** Returns structured `IngestionResult` tracking one of the 9 discrete `IngestionStatus` states defined in `adapter.py`:
  - `SUCCESS`
  - `PARTIAL`
  - `FAILED`
  - `TIMEOUT`
  - `INVALID_INPUT`
  - `UNSUPPORTED`
  - `PARSER_ERROR`
  - `VALIDATION_FAILED`
  - `NO_FINDINGS`
- **Exception Containment Boundary:** Any unexpected exception raised within an adapter or parser is caught at the orchestrator boundary. It never escapes unhandled to the caller; instead, it is safely recorded as an `IngestionError` with status `IngestionStatus.FAILED`.
- **Live Execution Boundary:** `ScannerAdapter.execute()` returns `IngestionStatus.UNSUPPORTED`. Live CLI subprocess execution, timeout enforcement, and process monitoring are **NOT IMPLEMENTED IN PHASE 2B** and are deferred to Phase 8.

---

## 4. Security Controls Matrix

Every security claim is classified below according to strict discipline:

| Security Domain | Control Description | Classification | Implementation / Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Parser DoS** | JSON payload limit $\le 100\text{ MB}$ | **TESTED CONTROL** | `DefensiveJSONParser`, verified in `test_json_size_limit_rejection` |
| **Parser DoS** | JSON recursion depth limit $\le 50$ | **TESTED CONTROL** | `DefensiveJSONParser`, verified in `test_json_deep_nesting_rejection` |
| **Parser DoS** | JSON collection limit $\le 100,000$ per container | **QUALIFIED CONTROL (per-container)** | `DefensiveJSONParser`, verified in `test_json_collection_count_rejection` (bounds per list/dict; not cumulative) |
| **Parser DoS** | JSON string literal limit $\le 1\text{ MB}$ | **TESTED CONTROL** | `DefensiveJSONParser`, verified in `test_json_string_length_rejection` |
| **XML Security** | Rejection of `<!DOCTYPE>` declarations | **TESTED CONTROL** | `DefensiveXMLParser`, verified in `test_xml_doctype_rejection` |
| **XML Security** | Rejection of `<!ENTITY>` (Billion Laughs / XXE) | **TESTED CONTROL** | `DefensiveXMLParser`, verified in `test_xml_entity_declaration_rejection` |
| **XML Security** | Rejection of custom entity references (`&custom;`) | **TESTED CONTROL** | `DefensiveXMLParser`, verified in `test_xml_custom_entity_reference_rejection` |
| **XML Security** | XML nesting depth limit $\le 50$ | **TESTED CONTROL** | `DefensiveXMLParser`, verified in `test_xml_depth_limit_rejection` |
| **XML Security** | XML payload limit $\le 100\text{ MB}$ | **TESTED CONTROL** | `DefensiveXMLParser`, verified in `test_xml_size_limit_rejection` |
| **Path Traversal** | Rejection of `../`, `..\\`, and `%2e%2e` | **TESTED CONTROL** | `normalize_source_path`, verified in `test_path_sanitization_and_traversal_rejection` |
| **Path Traversal** | Host path basename fallback for unanchored paths | **IMPLEMENTED CONTROL (limitation noted)** | `normalize_source_path`, strips unanchored host absolute paths to basename |
| **Path Traversal** | Control character stripping in paths and strings | **TESTED CONTROL** | `sanitize_bounded_string`, verified in `test_control_character_sanitization` |
| **Data Integrity** | SHA-256 computed on raw bytes before decoding/parsing | **TESTED CONTROL** | `RawScannerOutput.from_bytes`, verified in `test_raw_output_sha256_verbatim_bytes` |
| **Data Integrity** | Native finding ID collision preservation | **TESTED CONTROL** | `CryptoScanAdapter`, `SyftAdapter`, verified in collision unit tests |
| **Data Integrity** | Semantic reordering immunity for assets | **TESTED CONTROL** | `CanonicalAssetKey`, verified in `test_semantic_preservation_under_reordering` |
| **Boundary Safety** | Exception containment at orchestration boundary | **TESTED CONTROL** | `IngestionOrchestrator`, verified in `test_orchestrator_exception_containment` |
| **Subprocess Execution** | Parameterized CLI execution without `shell=True` | **NOT IMPLEMENTED IN PHASE 2B** | Planned for Phase 8 Deployment Runner; `execute()` returns `UNSUPPORTED` |
| **Subprocess Execution** | Execution timeout and process termination | **NOT IMPLEMENTED IN PHASE 2B** | Planned for Phase 8 Deployment Runner |
| **Container / cgroup** | OS-level sandbox / cgroup execution jail | **DEPLOYMENT-DEPENDENT / FUTURE** | Requires containerized deployment runtime (Phase 8) |
| **Network Isolation** | Unshare network namespace / offline scan jail | **DEPLOYMENT-DEPENDENT / FUTURE** | Requires Linux namespace / container runner configuration (Phase 8) |
| **Source Retention** | Zero persistent retention of source code in product DB | **DESIGN REQUIREMENT** | Offline ingestion scope operates strictly on scanner output JSON files |

---

## 5. Benchmark Semantic Verification (TC-01 Through TC-11)

All 11 test cases from the benchmark corpus were ingested from their original Phase 1C-B raw tool outputs and processed end-to-end through `NormalizationEngine` and `AssetCorrelationEngine`:

| Test Case | Scenario Description | Ingestion Status | Evidence Records | Findings Produced | Assets Correlated | Verified Semantic Invariant |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Direct RSA usage | `SUCCESS` | 1 | 1 | 1 | Preserved as RSA (family=RSA, algo=RSA, role=KEY_GENERATION) |
| **TC-02** | Symmetric AES | `SUCCESS` | 2 | 2 | 2 | Both preserved as AES (family=AES, algo=AES, role=ENCRYPTION_DECRYPTION) |
| **TC-03** | Generic ECC | `SUCCESS` | 1 | 1 | 1 | Generic ECC remains UNKNOWN algorithm; NEVER promoted to ECDSA |
| **TC-04** | ECDSA | `SUCCESS` | 2 | 2 | 2 | ECDSA preserved where evidence supports it (role=DIGITAL_SIGNATURE) |
| **TC-05** | ECDH Key Agreement | `SUCCESS` | 8 | 8 | 7 | ECDH preserved where evidenced (role=KEY_AGREEMENT); duplicate comments correlated |
| **TC-06** | Ed25519 Edwards | `SUCCESS` | 1 | 1 | 1 | Preserved as Ed25519 (family=EDWARDS, algo=Ed25519); NOT collapsed to generic ECC |
| **TC-07** | SHA-1 Deprecated Hash | `SUCCESS` | 3 | 3 | 3 | SHA-1 preserved; raw category `"Deprecated Hash"` preserved verbatim |
| **TC-08** | Wrapper Blindness | `NO_FINDINGS` | 0 | 0 | 0 | Scanner missed wrapper; ZERO evidence synthesized; status=NO_FINDINGS |
| **TC-09** | Bouncy Castle Dependency | `SUCCESS` | 1 | 1 | 1 | Dependency evidence only; ZERO algorithms manufactured (family=UNKNOWN) |
| **TC-10** | Misleading Comments | `SUCCESS` | 1 | 1 | 0 | Classed as NON_CRYPTOGRAPHIC_DECOY; ZERO crypto assets created |
| **TC-11** | Ambiguous Dynamic Cipher | `NO_FINDINGS` | 0 | 0 | 0 | Scanner missed dynamic call; ZERO evidence synthesized; status=NO_FINDINGS |

---

## 6. Test Suite Execution Summary

```
Ran 120 tests in 0.043s

OK
```

- **Pre-existing Phase 1D tests:** 80 passing
- **Phase 2B Ingestion Framework tests (`test_ingestion_framework.py`):** 17 passing
- **Phase 2B CryptoScan Adapter tests (`test_cryptoscan_adapter.py`):** 6 passing
- **Phase 2B Syft Adapter tests (`test_syft_adapter.py`):** 6 passing
- **Phase 2B Semantic Verification tests (`test_phase2b_semantic_verification.py`):** 11 passing
- **Total:** 120 tests passing, 0 regressions.

---

## 7. Known Limitations & Excluded Scope

1. **Sequential Orchestration Only:** The Phase 2B orchestrator executes adapters sequentially in a single thread. Parallel worker pooling is deferred to Phase 8.
2. **Same-Source Statement Correlation Only:** Correlation across adapters is strictly limited to same-source-statement deduplication as established in Phase 1D. Variable lifecycle correlation, call-graph analysis, and dependency-to-source linking are strictly excluded.
3. **No Dynamic Network / Container Scanning:** Scope is restricted to static source AST (CryptoScan) and dependency SBOM (Syft). Network protocol discovery (sslscan) and container analysis remain future phases.
4. **Zero AI / Heuristic Inferences:** No machine learning, LLMs, or heuristic guessers are employed. All mappings are deterministic, verifiable, and conservative.
5. **Live Scanner Process Execution Not Implemented:** `ScannerAdapter.execute()` returns `IngestionStatus.UNSUPPORTED`. Subprocess execution, CLI argument launching, process timeouts, and signal handling are deferred to Phase 8 deployment runner. CryptoScan and Syft adapters operate strictly via offline raw output ingestion.
6. **Unanchored Absolute Host Path Basename Fallback:** `normalize_source_path()` collapses unanchored absolute host paths to their base filename to prevent directory traversal. This safely prevents arbitrary host filesystem traversal in evidence paths, but loses directory structure when scanner outputs absolute host paths without a recognized anchor.
7. **Per-Container JSON Collection Limit:** `max_collection_elements` bounds the size of any individual array or object, but does not enforce a cumulative global document-wide element counter.

---

## 8. Phase 2B Independent Verification Audit Trail

An independent read-only adversarial review was conducted against the implementation, test suite, and documentation:

- **Independent Review Verdict:** `CONDITIONAL PASS`
- **Automated Tests:** 120/120 passing (80 baseline + 40 Phase 2B tests).
- **Phase 1D Code Integrity:** 32 files across `product/core/evidence/`, `product/core/domain/`, and `product/core/normalization/` verified 100% untouched.
- **Benchmark Integrity:** 14 seed corpus files and 114 raw scanner outputs verified 100% untouched.
- **Dependency Integrity:** Zero external packages added; Python 3.12 standard library only.
- **Documentation Corrections Applied:**
  1. Status enum transcribed to match code (`SUCCESS`, `PARTIAL`, `FAILED`, `TIMEOUT`, `INVALID_INPUT`, `UNSUPPORTED`, `PARSER_ERROR`, `VALIDATION_FAILED`, `NO_FINDINGS`).
  2. Live subprocess execution and process timeout reclassified as `NOT IMPLEMENTED IN PHASE 2B`.
  3. JSON collection element bound clarified as `QUALIFIED CONTROL (per-container)`.
  4. Absolute host path basename fallback documented with adapter limitation.
- **Production Code Changes Required:** None.
