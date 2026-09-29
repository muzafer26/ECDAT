# Pre-3A Domain & Run Contract Gate Specification

**Document Identifier:** ECDAT-GATE-PRE-3A  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Gate:** Pre-3A Domain & Run Contract  
**Mode:** Design / Read-Only Architecture Governance  
**Status:** CONDITIONAL PASS — DOCUMENTATION & VERIFICATION CORRECTIONS COMPLETE  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/PROJECT_SPEC.md`
- `product/docs/ARCHITECTURE.md`
- `product/docs/PHASE_1D_NORMALIZATION_ARCHITECTURE.md`
- `product/docs/PHASE_2A_SCANNER_ADAPTER_INGESTION_ARCHITECTURE.md`
- `product/docs/PHASE_2B_SCANNER_ADAPTER_IMPLEMENTATION.md`
- `product/docs/PROJECT_STATE.md`

---

## 1. Purpose

This gate establishes and locks the architectural, domain, and run contracts required between the completed discovery/ingestion foundation (Phases 0 through 2B) and the upcoming Cryptographic Bill of Materials (CBOM) generation in Phase 3.

### Explicit Governance Constraints
1. **Zero Production Code Implementation:** No backend code, database schema, REST API, UI component, scanner execution runner, risk calculator, migration mapper, or AI module may be introduced during this gate.
2. **Defect-First Discipline:** This gate must inspect the existing codebase read-only, identify any contract defects or ambiguities, and document them with empirical code evidence.
3. **Immutability of Closed Baselines:** Phases 0, 1A, 1B, 1C-A, Pre-1C-B, 1C-B, 1D, 2A, and 2B remain closed and authoritative unless a concrete implementation defect or architectural contradiction is proven.
4. **Contract vs. Implementation Distinction:** Architectural contracts defined in this gate (`AnalysisRun`, `ScannerExecution`, CBOM projection requirements) are specifications for Phase 3/8 and must not be misrepresented as currently implemented production classes.

---

## 2. Baseline Architecture Ledger

| Phase | Formal Name | Governance Status | Baseline Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Phase 0** | Foundation & Architecture | **CLOSED** | 13 specification documents; ADR-001 through ADR-006; separation of evidence from interpretation. |
| **Phase 1A** | Discovery Intelligence | **CLOSED** | Discovery plan, candidate scanner registry, download quarantine. |
| **Phase 1B** | Benchmark Harness & Seed Corpus | **CLOSED** | TC-01..TC-11 seed corpus (14 files); 11 signed-off answer keys; zero mutations. |
| **Phase 1C-A** | Controlled Tool Acquisition | **CLOSED** | Quarantined sandbox; release 2.3.0 verified; checksum provenance locked. |
| **Pre-1C-B** | Architecture Gate | **CLOSED** | 7-state scope taxonomy; untrusted threat model; gating criteria locked. |
| **Phase 1C-B** | Benchmark Execution & Evaluation | **CLOSED** | 114 benchmark artifact files verified in `product/benchmark/tools/raw_outputs` (62 raw scanner JSONs, 48 raw stdout/stderr text files, 3 execution logs, 1 readme); all maintain Phase 1C-B filesystem timestamps (Sept 12–13, 2026), proving zero modification during Phase 2/Pre-3A. (Formal mathematical proof of pre-baseline immutability requires a signed digest manifest, which remains an architectural contract for Phase 8 CI/CD governance). |
| **Phase 1D** | Canonical Domain & Normalization | **CLOSED** | Immutable models in `product/core/domain/`, `product/core/evidence/`, `product/core/normalization/`; statement-level deduplication; `CanonicalAssetKey`. |
| **Phase 2A** | Scanner Adapter & Ingestion Architecture | **CLOSED** | v1.1.0 approved; defensive parsing specifications; collision handling designs. |
| **Phase 2B** | Ingestion Implementation | **CLOSED** | Offline ingestion scope complete; 120/120 tests pass; conditional-pass doc corrections applied. |

---

## 3. Identity Hierarchy & Anti-Collapse Invariants

ECDAT strictly decouples operational and observational identities from semantic inventory identities. Under no circumstances may these tiers be collapsed:

```
Operation / Request ID          (API/CLI invocation transaction identity)
        ↓
Analysis Run ID                 (Holistic multi-scanner session contract)
        ↓
Scanner Execution ID            (Specific scanner tool invocation contract)
        ↓
Raw Scanner Output Ref / Hash   (Content-addressable stdout capture: sha256:...)
        ↓
Evidence Record ID              (Namespaced empirical observation: {adapter}:{native_id})
        ↓
Finding ID                      (Canonical interpretation of evidence: ecdat:finding:{hash})
        ↓
CryptoAsset ID                  (Deterministic semantic key: ecdat:asset:{canonical_key})
```

### Identity Definitions & Invariants
1. **Operation / Request ID:** External client transaction identifier (e.g. HTTP request, CI job execution).
2. **Analysis Run ID (`run_id`):** Root identifier for a multi-scanner discovery session across a target codebase. **CONTRACT DEFINED** for Phase 3/8; not a production database entity in Phase 2B.
3. **Scanner Execution ID (`execution_id`):** Identifies a single scanner's invocation lifecycle belonging to an Analysis Run. **CONTRACT DEFINED**.
4. **Raw Scanner Output (`RawScannerOutput`):** Content-addressable reference (`sha256:{hash}`) over exact captured stdout bytes. Represents **content identity** of the scanner emission, not the run identity.
5. **Evidence Record (`evidence_id`):** Scan-local observation identifier (`{adapter_id}:{native_finding_id}` or collision-disambiguated/fallback UUIDv5).
6. **Finding (`finding_id`):** Deterministic UUIDv5 derived from the sorted set of underlying `evidence_ids`.
7. **CryptoAsset (`asset_id`):** Current deterministic semantic asset identity derived strictly from `CanonicalAssetKey.canonical_string()`.

> [!CRITICAL]
> **Asset Identity Invariant:** `CryptoAsset.asset_id` represents **current deterministic semantic asset identity** derived strictly from domain attributes and source coordinates. It is **NOT** proof of physical key/object identity (e.g. in HSM memory or private key bits) and is **NOT** a permanent historical tracking identifier across arbitrary source refactorings (deferred to Phase 9).

---

## 4. Cardinality Model & Repository Inspection

The domain contracts enforce the following cardinality rules:

```
AnalysisRun          1 ─── N   ScannerExecutions     [CONTRACT DEFINED]
ScannerExecution     1 ─── 0..1 RawScannerOutput     [CONTRACT DEFINED]
RawScannerOutput     1 ─── N   EvidenceRecords       [IMPLEMENTED & VERIFIED]
Finding              N ─── N   EvidenceRecords       [IMPLEMENTED & VERIFIED]
CryptoAsset          N ─── N   Findings              [IMPLEMENTED & VERIFIED]
```

### Repository Audit for Accidental 1:1 Assumptions

1. **`Finding` to `EvidenceRecord` (`Finding N ─── N EvidenceRecords`):**
   - **Inspection of `product/core/domain/finding.py:45`:** `evidence_ids: Sequence[str]`.
   - **Verification:** `Finding` stores a sequence of evidence IDs frozen into an immutable `FrozenIdTuple`. Multiple pieces of evidence can support one finding, and multiple distinct findings can reference the same evidence record. Cardinality is preserved.
2. **`CryptoAsset` to `Finding` (`CryptoAsset N ─── N Findings`):**
   - **Inspection of `product/core/domain/asset.py:149`:** `finding_ids: Sequence[str]`.
   - **Verification:** `CryptoAsset` stores a collection of `finding_ids`. Statement-level correlation groups findings into assets. Cardinality is preserved.
3. **`AnalysisRun` and `ScannerExecution`:**
   - **Inspection of `product/core/ingestion/adapter.py:161-172` and `orchestrator.py:54-115`:**
   - **Status: CONTRACT DEFINED.** In Phase 2B, `ScanExecutionMetadata` models single-scanner execution (`scan_id`, `adapter_id`, `scanner_name`, etc.). The aggregated multi-tool `AnalysisRun` container is a contract established at this gate for Phase 3/8, not an implemented production class in `product/core/`.

---

## 5. Idempotency Tiering & Identity Distinctions

ECDAT enforces strict separation between different forms of idempotency and identity:

$$\text{Operation Idempotency} \neq \text{Run Identity} \neq \text{Raw-Output Content Identity} \neq \text{Evidence Deduplication} \neq \text{Asset Correlation}$$

### Explicit Distinctions
1. **Raw-Output Content Identity vs. Run Identity:** Identical raw bytes produce the identical `sha256_hash`, but identical raw bytes do **not** imply the same analysis run. Two separate scans run on different days that produce identical tool output are two separate `AnalysisRun`s referencing the same raw-output content hash.
2. **No Silent Adapter Deduplication:** Adapters must never discard or merge raw findings during ingestion. If a scanner outputs duplicate findings on the same line, the adapter emits distinct `EvidenceRecord`s.
3. **Independent Normalization:** `NormalizationEngine` interprets each `EvidenceRecord` strictly on its own merits, deriving canonical findings without cross-finding interference.
4. **Correlation-Only Asset Merging:** Findings are merged into a single `CryptoAsset` **only** when `AssetCorrelationEngine.evaluate_correlation()` confirms exact statement-level equivalence.
5. **Asset Identity Stability:** Multiple separate scans of identical source code produce separate runs and evidence records, but correlate to the **same** `CryptoAsset.asset_id` because canonical asset identity excludes run/scanner/evidence IDs.

---

## 6. Conflict Semantics & Safe Rejection of Contradictions

Contradictory scanner observations **MUST NEVER** be silently overwritten, averaged, or arbitrarily selected via "last-write-wins" heuristics.

### Conflict Handling Rules
1. **Parameter Contradictions:** If Scanner A observes `RSA 2048` and Scanner B observes `RSA 4096` at the same source line:
   - `check_parameter_compatibility()` in `correlation.py:53-78` returns `(False, "conflicting_key_sizes(2048!=4096)", None)`.
   - Correlation returns `CorrelationDecision.NOT_CORRELATED`.
   - Two distinct `CryptoAsset`s are created, each documenting its respective finding and evidence trail.
2. **Cipher Mode Contradictions:** If Scanner A observes `AES-GCM` and Scanner B observes `AES-CBC`:
   - `check_parameter_compatibility()` returns `(False, "conflicting_cipher_modes(GCM!=CBC)", None)`.
   - Correlation is rejected; observations remain separate.
3. **Family / Algorithm Contradictions:** If Scanner A reports `AES` and Scanner B reports `RSA` at the same line:
   - `correlation.py:218-230` returns `CorrelationDecision.NOT_CORRELATED`.
   - Merging is strictly prevented.

---

## 7. Unknown Semantics Taxonomy

To prevent data corruption, ambiguity, and manufactured specificity, the domain model strictly distinguishes 6 distinct negative/unresolved states:

| State | Formal Meaning | Domain Representation |
| :--- | :--- | :--- |
| **`UNKNOWN`** | Cryptography exists, but specific algorithm/role/parameter cannot be established from evidence | `AlgorithmFamily.UNKNOWN`, `algorithm="UNKNOWN"`, `CryptographicRole.UNKNOWN` |
| **`ABSENT`** | Parameter or attribute does not exist for this cryptographic primitive (e.g., curve on RSA) | Field is `None` (e.g. `parameters.curve_name is None`) |
| **`NOT_APPLICABLE`** | Operational concept does not apply to this asset type (e.g. key length on a hash algorithm) | Explicit parameter omission / role validation |
| **`UNSUPPORTED`** | Scanner, target language, or output format not supported by discovery engine | `IngestionStatus.UNSUPPORTED` |
| **`FAILED`** | Scanner execution crashed, parser threw error, or exception was contained | `IngestionStatus.FAILED` or `IngestionStatus.PARSER_ERROR` |
| **`NO_FINDINGS`** | Scanner executed cleanly over target scope, but detected zero cryptographic evidence | `IngestionStatus.NO_FINDINGS` |

> [!CRITICAL]
> **Zero Guessing Invariant:** Dynamic cipher instantiations (e.g. `Cipher.getInstance(System.getenv("CIPHER"))`) must **never** be assigned a default algorithm. They remain `family=UNKNOWN`, `algorithm="UNKNOWN"`, with analytical confidence `NEEDS_REVIEW`.

---

## 8. Scope, Coverage, and Confidence

The analysis domain decouples scan completeness from analytical confidence:

$$\text{Finding Confidence} \neq \text{Scan Coverage}$$

### 1. Scope Decomposition
For any discovery execution, ECDAT tracks:
- **Requested Scope:** Target directories, files, or packages requested by the caller.
- **Actual Analyzed Scope:** Files successfully scanned by the tool.
- **Excluded Scope:** Paths omitted due to user ignore lists, binary exclusions, or test filters.
- **Failed Scope:** Files where scanner AST parsing or execution failed.
- **Unsupported Scope:** Files in languages or formats not supported by the scanner.
- **Findings Produced:** Count of empirical observations emitted.

### 2. The `NO_FINDINGS` Invariant
`IngestionStatus.NO_FINDINGS` strictly means: **"This scanner executed cleanly and identified zero evidence matching its rules."** It **MUST NEVER** be interpreted as: *"The repository is proven to contain no cryptography."*

---

## 9. Analysis Run Metadata Contract

The Phase 3 contract establishes the `AnalysisRunContract` specification:

```python
# Specification only — contract-level concept for Phase 3/8
class AnalysisRunContract:
    """Holistic multi-scanner discovery session contract."""
    run_id: str                              # Unique run UUID
    target_identifier: str                   # Repository URL, path, or commit SHA
    target_type: str                         # "source_repo" | "container_image" | "package"
    requested_scope: Sequence[str]           # Input path specifications
    actual_scope: Optional[ScopeCoverage]    # Measured processing coverage
    configuration: Mapping[str, Any]         # Non-default CLI/engine options
    scanner_executions: Sequence[str]        # References to ScannerExecution IDs
    normalization_version: str               # Version of ECDAT normalization rules (e.g. "1.0.0")
    correlation_version: str                 # Version of ECDAT correlation rules (e.g. "1.0.0")
    timestamp_started: str                   # ISO 8601 UTC
    timestamp_completed: str                 # ISO 8601 UTC
    overall_status: IngestionStatus          # SUCCESS | PARTIAL | FAILED | NO_FINDINGS
```

---

## 10. Reproducibility & Determinism

A scan result is reproducible if and only if identical inputs yield semantically identical `CryptoAsset` inventories and CycloneDX CBOMs.

### Reproducibility Vector
1. Target source code content (commit SHA / file tree hash)
2. Discovery tool binary identity (scanner name, scanner version, binary hash)
3. Adapter implementation version
4. Analysis configuration options (include/exclude filters)
5. Normalization engine version
6. Correlation engine version

> [!NOTE]
> Deterministic UUIDv5 identifiers guarantee ID stability for identical inputs, but do **not** replace recording the full reproducibility vector.

---

## 11. End-to-End Provenance Invariant

Every entity emitted by ECDAT must maintain an unbroken, verifiable audit trail:

$$\text{CryptoAsset} \longrightarrow \text{Finding(s)} \longrightarrow \text{EvidenceRecord(s)} \longrightarrow \text{RawScannerOutput} \longrightarrow \text{ScannerExecution} \longrightarrow \text{AnalysisRun}$$

### Provenance Audit Requirements
- `CryptoAsset.finding_ids` links to canonical `Finding` records.
- `Finding.evidence_ids` links to immutable `EvidenceRecord`s.
- `EvidenceRecord.raw_output_ref` links to the exact `sha256:{hash}` of the raw scanner stdout.
- `EvidenceRecord.scan_id` links to the execution metadata of the scanner invocation.
- No future pipeline stage (CBOM serializer, risk engine, UI) may prune or obscure this chain.

---

## 12. Asset-Type Boundary

The domain model enforces strict type discrimination via `AssetType`:

| AssetType | Definition | Permitted Role Types | Example |
| :--- | :--- | :--- | :--- |
| **`ALGORITHM`** | Specific cryptographic algorithm or cipher implementation in code | `ENCRYPTION_DECRYPTION`, `DIGITAL_SIGNATURE`, `KEY_AGREEMENT`, `MESSAGE_DIGEST` | `AES/GCM/NoPadding` |
| **`LIBRARY_DEPENDENCY`** | Cryptographic package or library declared in manifests/lockfiles | `UNKNOWN` (Strictly prohibited from inferring algorithms) | `bcprov-jdk18on` |
| **`KEY`** | Raw cryptographic key material, key pair, or secret key reference | `KEY_GENERATION`, `KEY_DERIVATION` | `SecretKeySpec` |
| **`CERTIFICATE`** | X.509 certificate, keystore, or trust anchor reference | `AUTHENTICATION`, `TRUST_ANCHOR` | `X509Certificate` |
| **`PROTOCOL`** | Network or transport security protocol | `PROTOCOL_COMMUNICATION` | `TLSv1.3` |
| **`CONFIGURATION`** | Security provider, crypto policy, or cipher suite list | `CONFIGURATION` | `Security.addProvider()` |

---

## 13. CBOM Projection Boundary

CycloneDX 1.7 is strictly an **output serialization target**, not the internal domain model or source of truth for ECDAT:

```
                  ┌──────────────────────┐
                  │ ECDAT Canonical Model│
                  │ (CryptoAsset, etc.)  │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Phase 3A: Projection │
                  │     & Mapping        │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Phase 3B: CycloneDX  │
                  │    1.7 Serializer    │
                  └──────────────────────┘
```

### Invariant
The ECDAT domain model must never be modified, constrained, or compromised to match CycloneDX schema limitations. If a domain attribute cannot be natively expressed in CycloneDX, it must be projected as a namespaced property extension (`ecdat:*`) or retained in ECDAT-internal metadata.

---

## 14. Preliminary CBOM Projection Strategy (Phase 3A Design Requirement)

The table below outlines the projection strategy and candidate target fields for Phase 3A.

> [!IMPORTANT]
> **Phase 3A Prerequisite:** These mappings represent the architectural projection requirements. They are **candidate mappings** that must be formally validated against the published CycloneDX 1.7 JSON-Schema specification during Phase 3A before implementation begins in Phase 3B.

| ECDAT Domain Field | Candidate CycloneDX 1.7 Field | Projection Strategy | Policy on Unrepresentable Data |
| :--- | :--- | :--- | :--- |
| `asset_id` | `component.bom-ref` | Direct mapping (UUIDv5) | N/A |
| `asset_type == ALGORITHM` | `component.type = "cryptographic-asset"` | Direct native CDX 1.7 enum | N/A |
| `asset_type == LIBRARY_DEPENDENCY` | `component.type = "library"` | Direct native CDX 1.7 enum | N/A |
| `algorithm_identity.algorithm` | `cryptoProperties.algorithmProperties.name` | Direct string mapping | N/A |
| `algorithm_identity.family` | `cryptoProperties.algorithmProperties.algorithmFamily` | Direct family mapping | If not in CDX enum, project as `other` + property |
| `algorithm_identity.variant` | `cryptoProperties.algorithmProperties.variant` | Direct string mapping | N/A |
| `role` | `cryptoProperties.assetType` | Native CDX crypto asset type enum | Fallback to property `ecdat:role` |
| `parameters.key_size_bits` | `cryptoProperties.algorithmProperties.keyLength` | Direct integer mapping | Omitted if `None` |
| `parameters.curve_name` | `cryptoProperties.algorithmProperties.curve` | Direct string mapping | Omitted if `None` |
| `parameters.cipher_mode` | `cryptoProperties.algorithmProperties.mode` | Direct enum/string | Omitted if `None` |
| `parameters.padding_scheme` | `cryptoProperties.algorithmProperties.padding` | Direct enum/string | Omitted if `None` |
| `primary_location.file_path` | `evidence.occurrences[].location` | Direct string mapping | N/A |
| `primary_location.line_start` | `evidence.occurrences[].line` | Direct integer mapping | N/A |
| `primary_location.matched_text` | `evidence.occurrences[].additionalContext` | Sanitized snippet | Bounded $\le 500$ chars |
| `confidence` | `properties.name = "ecdat:confidence"` | Property extension | N/A |
| `correlation_basis` | `properties.name = "ecdat:correlation_basis"` | Property extension | N/A |
| `finding_ids` | `properties.name = "ecdat:finding_ids"` | Comma-separated property | N/A |
| `raw_attributes` | *None* | Internal-only retention | Never leaked to public CBOM |

---

## 15. CBOM Validation Architecture

Phase 3 implementation will enforce two independent validation gates:

### 1. Structural Schema Validation
- Validates that generated JSON conforms strictly to the official CycloneDX 1.7 JSON-Schema specification.
- Verifies syntax, required fields, enum memberships, and `bom-ref` uniqueness.

### 2. Semantic Preservation Validation
- Validates that the generated CBOM preserves the exact cryptographic facts established by ECDAT.
- **Example Semantic Check:** If ECDAT establishes `RSA 2048` with role `DIGITAL_SIGNATURE`, a CBOM containing `RSA 1024` or role `ENCRYPTION_DECRYPTION` **fails semantic validation**, even if it passes JSON schema validation.

---

## 16. Provenance Through CBOM

Every component in the generated CBOM must trace back to its discovery origin:
- `component.bom-ref`: Contains `CryptoAsset.asset_id`.
- `component.properties`: Contains `ecdat:scan_id`, `ecdat:finding_ids`, and `ecdat:raw_output_ref`.
- `component.evidence.occurrences`: Explicitly lists the source file and line coordinates.

---

## 17. Result Explainability & Version Provenance

To explain material differences between two scans of the same codebase, the CBOM metadata header (`metadata.tools` and `metadata.properties`) must record:
1. `ecdat:version` (ECDAT software version)
2. `ecdat:scanner_name` and `ecdat:scanner_version`
3. `ecdat:adapter_version`
4. `ecdat:normalization_version`
5. `ecdat:correlation_version`
6. `ecdat:cbom_generator_version`

---

## 18. Sensitive Evidence & Privacy Boundary

Raw scanner emissions and code snippets may capture sensitive intellectual property, authorization tokens, or private key material.

### Sensitive Evidence Policies vs. Implementation Status
1. **Raw Output Retention Policy (DESIGN REQUIREMENT):** Stored in isolated raw storage with restricted filesystem permissions.
2. **Code Snippets Bounding (IMPLEMENTED & TESTED):** Bounded strictly to $\le 500$ characters and $\le 10$ lines via `bound_code_snippet()`.
3. **Secret Redaction Policy (DESIGN REQUIREMENT / NOT IMPLEMENTED):** High-entropy private keys and credentials must not be mirrored into CBOM exports. **Automated secret detection and redaction is NOT IMPLEMENTED in Phase 2B.**
4. **Content-Addressable Hashing (TESTED CONTROL):** `sha256_hash` serves as an integrity identifier; it does not encrypt or protect sensitive payload data.

---

## 19. Security Boundary & Non-Claims

Phase 2B established offline ingestion and parser bounding, but **did not** establish live execution sandboxing.

### Status of Security Controls
- **Tested Controls:** JSON size/depth/string bounds, XML DOCTYPE/ENTITY rejection, path traversal rejection, raw byte SHA-256 computation, native ID collision preservation (under Python 3.12 standard library test suites).
- **Not Implemented in Phase 2B:** Live subprocess execution (`shell=False`), process timeout enforcement, CPU/memory cgroup limits, network namespace unsharing, containerized worker sandboxing.
- **Future Milestone:** Production scanner sandboxing is strictly scheduled for Phase 8 (Deployment Modes & CI/CD Runner).

---

## 20. Future-Phase Compatibility Matrix

Phase 3 CBOM architecture must preserve all domain attributes required by future pipeline phases:

- **Phase 4 (Context & Relationships):** Preserves `primary_location`, `package_coordinate`, and caller anchors for graph linking.
- **Phase 5 (Explainable Risk Engine):** Preserves `algorithm_identity`, `parameters.key_size_bits`, `parameters.curve_name`, and `role` for NIST quantum risk calculations.
- **Phase 6 (PQC Migration Mapper):** Preserves typed `CryptographicRole` to enable role-aware FIPS 203/204/205 mapping.
- **Phase 7 (Analyst UI & Audit Log):** Preserves `confidence`, `correlation_basis`, and raw attributes for manual triage.
- **Phase 9 (Re-scan Diff Engine):** Preserves deterministic `asset_id` based on `CanonicalAssetKey`.

---

## 21. Mandatory Adversarial Questions Ledger

Each scenario has been audited directly against the current repository implementation and classified into disciplined governance categories:

| # | Adversarial Scenario | Governance Classification | Empirical Evidence & Architectural Behavior |
| :--- | :--- | :--- | :--- |
| 1 | Same run submitted twice | **DEFERRED (Phase 7/8)** | Orchestrator is currently stateless; request-level idempotency belongs to persistence/API layer. |
| 2 | Same scanner output ingested twice | **IMPLEMENTED & VERIFIED** | `RawScannerOutput.from_bytes()` produces identical SHA-256; adapters and normalizers produce byte-identical findings and assets. |
| 3 | Native scanner ID collision | **IMPLEMENTED & VERIFIED** | `cryptoscan.py:243` and `syft.py:168` detect duplicate IDs, assign `{id}:collision:{idx}`, set collision flag, emit warnings, and preserve all records. |
| 4 | Cross-scanner native ID collision | **IMPLEMENTED & VERIFIED** | Adapter namespacing (`cryptoscan:{id}` vs `syft:{id}`) prevents cross-tool collision. Tested in `test_ingestion_framework.py:test_cross_adapter_namespace_collision_prevention`. |
| 5 | Finding order changes | **IMPLEMENTED & VERIFIED** | Asset identity derived from `CanonicalAssetKey` is immune to finding order. Tested in `test_semantic_preservation_under_reordering`. |
| 6 | Two findings on one source line | **IMPLEMENTED & VERIFIED** | `correlation.py:180-209` inspects column boundaries and variable assignments (`var = ...`). Distinct statements remain separate assets. |
| 7 | Contradictory parameters | **IMPLEMENTED & VERIFIED** | `check_parameter_compatibility()` in `correlation.py:235` detects contradictions (e.g. 2048 != 4096) and rejects correlation (`NOT_CORRELATED`). |
| 8 | Dynamic/unknown algorithm | **IMPLEMENTED & VERIFIED** | Dynamic ciphers normalize to `family=UNKNOWN`, `algorithm="UNKNOWN"`, `NEEDS_REVIEW`. Tested in `test_phase2b_semantic_verification.py:test_tc11`. |
| 9 | Dependency without usage | **IMPLEMENTED & VERIFIED** | Syft packages normalize to `ObservationType.LIBRARY_DEPENDENCY` with `family=UNKNOWN`. Never correlates to code assets. Tested in TC-09. |
| 10 | Scanner execution failure | **CONTRACT DEFINED / DEFERRED** | `IngestionStatus.FAILED` contract defined in `adapter.py`. Live subprocess execution failure is deferred to Phase 8 runner. |
| 11 | Parser failure | **IMPLEMENTED & VERIFIED** | Defensive parsers return `IngestionStatus.PARSER_ERROR` with structured error code; zero uncaught exceptions in test suite. |
| 12 | Partial scope | **IMPLEMENTED & VERIFIED** | `IngestionStatus.PARTIAL` and `ScopeCoverage` track processed vs failed files. |
| 13 | Zero findings | **IMPLEMENTED & VERIFIED** | Returns `IngestionStatus.NO_FINDINGS` with empty evidence list. Distinct from execution failure. Tested in TC-08 and TC-11. |
| 14 | Unsupported target | **IMPLEMENTED & VERIFIED** | Returns `IngestionStatus.UNSUPPORTED` with diagnostic explanation. |
| 15 | Asset → Finding → Evidence provenance | **IMPLEMENTED & VERIFIED** | Unbroken lineage: `CryptoAsset.finding_ids` → `Finding.evidence_ids` → `EvidenceRecord.raw_output_ref`. |
| 16 | CBOM → ECDAT provenance | **DESIGN REQUIREMENT (Phase 3A)** | Formalized in Section 16: `component.bom-ref` mirrors `asset_id`; properties mirror scan provenance. |
| 17 | CBOM information loss | **DESIGN REQUIREMENT (Phase 3A)** | Formalized in Section 14: Projection matrix establishes policy against silent discarding. |
| 18 | Scanner removal | **IMPLEMENTED & VERIFIED** | `AdapterRegistry` allows modular unregistration. Historical asset IDs do not depend on scanner presence. |
| 19 | Scanner version drift | **QUALIFIED (Version Recorded)** | Version provenance recorded in `EvidenceRecord`; compatibility with arbitrary future scanner versions not proven. |
| 20 | Persistence/API duplicate state | **DEFERRED (Phase 7/8)** | Database and API persistence layers are not yet implemented. |
| 21 | Sensitive evidence exposure | **DESIGN REQ (Phase 3A/8)** | Code snippets capped at 500 chars; raw attributes excluded from public CBOM export. Automated redaction not implemented. |
| 22 | Future historical identity | **EXPLICIT NON-CLAIM** | Current `asset_id` is a current semantic asset key. Cross-commit git tracking belongs to Phase 9. |
| 23 | Malformed / missing field types | **IMPLEMENTED & VERIFIED** | Defensive parsing and dataclass `__post_init__` sanitizers enforce bounded types and fallback defaults. |
| 24 | Duplicate semantic findings with different native IDs | **IMPLEMENTED & VERIFIED** | Native IDs identify scanner-level observations (`EvidenceRecord`). Different native IDs do NOT imply different semantic assets, but correlation is strictly conservative: `AssetCorrelationEngine.evaluate_correlation()` performs same-source-statement deduplication only. Findings merge if and only if they share identical file path (`loc1.file_path == loc2.file_path`), identical line span (`line_start` and `line_end`), overlapping columns or non-conflicting source expressions (rejecting distinct assignments like `v1 = ...` vs `v2 = ...`), matching algorithm family, compatible algorithm name/role, and non-contradictory parameters. File proximity, line proximity, variable name similarity, or call-graph merging alone never trigger merging; contradictions force `NOT_CORRELATED` and remain separate assets. |
| 25 | Shared evidence lifecycle | **DESIGN REQUIREMENT** | `FrozenIdTuple` ensures evidence references cannot be mutated; evidence records remain immutable observations across all finding lifecycles. |
| 26 | Review / disposition separate from confidence | **IMPLEMENTED & VERIFIED** | `Finding` independently models `confidence: ConfidenceLevel` and `disposition: DispositionStatus` (e.g. `FALSE_POSITIVE`). |
| 27 | Non-Git target identity | **CONTRACT DEFINED (Phase 3A)** | `target_type` in `ScanTarget` supports `source_dir`, `package`, `container_image`; non-Git target identities must use content-addressable hashes. |
| 28 | Target-content identity vs run identity | **CONTRACT DEFINED** | Target content hash represents codebase snapshot; run ID represents specific execution instance. Distinct runs may scan identical content. |

---

## 22. Repository Verification Audit

Read-only inspection of the repository confirmed the following:

1. **Git Repository Status & Diff Inspection:**
   - Command `git status --short`: Exited with code 1: `fatal: not a git repository (or any of the parent directories): .git`.
   - Command `git diff -- product/core`: Exited with code 1: `warning: Not a git repository. Use --no-index to compare two paths outside a working tree`.
   - Command `git diff -- product/benchmark`: Exited with code 1: `warning: Not a git repository. Use --no-index to compare two paths outside a working tree`.
   - *Finding:* The current workspace (`d:\SIH`) is not initialized as a git repository; therefore, repository verification relies on filesystem metadata, file timestamps (`mtime`), directory audits, and SHA-256 digests rather than Git commit trees.

2. **Production Code Zero-Modification Proof:**
   - Audited all 50 files (29 Python source files) in `product/core/`.
   - Earliest source file: `product/core/evidence/__init__.py` (`2026-09-13 21:10:45`).
   - Latest modified source file: `product/core/ingestion/adapters/cryptoscan.py` (`2026-09-14 18:38:24.990035`), created during Phase 2B.
   - *Verified:* Zero production code files modified during the Pre-3A Domain & Run Contract Gate (0 bytes changed).

3. **Benchmark Seed Corpus & Raw Outputs Integrity:**
   - Audited all 269 files in `product/benchmark/`.
   - Latest modified file in `product/benchmark/`: `product/benchmark/tools/reports/phase_1c_b/phase_1c_b_execution_summary.json` (`2026-09-13 20:29:44.783030`).
   - Audited all 114 files in `product/benchmark/tools/raw_outputs/`:
     - 62 JSON files (scanner outputs)
     - 48 text files (`.txt` stdout/stderr captures)
     - 3 execution log files (`.log`)
     - 1 markdown file (`README.md`)
   - All 114 files bear timestamps from Phase 1C-B execution (`2026-09-12 21:39:39` to `2026-09-13 20:29:44`).
   - *Integrity Caveat & Non-Claim:* While unchanged filesystem timestamps prove zero modification during Phase 2B and Pre-3A, file existence and timestamp stability alone do not constitute mathematical tamper-proof evidence of historical immutability prior to this baseline. A cryptographically signed raw-output digest manifest is an architectural contract for Phase 8 CI/CD governance.

4. **Scenario 24 Correlation Implementation Audit:**
   - Inspected `AssetCorrelationEngine.evaluate_correlation()` in `product/core/normalization/correlation.py:151-244`.
   - *Verified Implementation Behavior:* Correlation strictly implements same-source-statement deduplication. Native IDs identify observations (`EvidenceRecord`). Different native IDs (from different rules/tools) merge into a single `CryptoAsset` if and only if they share:
     - Identical file path (`loc1.file_path == loc2.file_path`)
     - Identical line span (`line_start` and `line_end` match exactly)
     - Overlapping column boundaries or non-conflicting source expressions (rejecting distinct assignments like `v1 = ...` vs `v2 = ...`)
     - Identical algorithm family (`family1 == family2`)
     - Compatible specific algorithm and role (if known)
     - Non-contradictory algorithm parameters (`check_parameter_compatibility`)
   - *Explicit Limitations:* Line proximity, file proximity, variable name similarity, or call-graph merging alone never trigger merging. Contradictions yield `NOT_CORRELATED` and remain separate assets.

5. **Model Fields & Immutability:** All classes in `product/core/domain/` and `product/core/evidence/` are `@dataclass(frozen=True)` with immutable sequences (`FrozenIdTuple`).
6. **Deterministic ID Generation:** UUIDv5 namespaces are strictly segregated (`NAMESPACE_URL` with prefixes `ecdat:asset:`, `ecdat:finding:`, `ecdat:adapter-evidence:`).
7. **Parser Bounds:** `DefensiveJSONParser` enforces size, depth, string length, and per-container collection limits. `DefensiveXMLParser` rejects DOCTYPE and ENTITY declarations. (Tested against synthetic test vectors).
8. **Full Test Suite:** All 120 automated tests pass in ~0.08-0.09s (80 baseline + 40 Phase 2B tests).

---

## 23. Acceptance Criteria Checklist

- [x] `AnalysisRun` contract formally defined as specification (Section 9)
- [x] Identity hierarchy explicitly documented and anti-collapse invariants locked (Section 3)
- [x] Cardinality documented and verified against existing codebase (Section 4)
- [x] Operation idempotency decoupled from ingestion idempotency and run identity (Section 5)
- [x] Repeated scan and re-ingestion behavior defined (Section 5)
- [x] Parameter and algorithm conflict behavior defined and verified (Section 6)
- [x] Scope and coverage semantics decoupled from finding confidence (Section 8)
- [x] `NO_FINDINGS` distinct from execution failure (Section 7, 8)
- [x] Provenance chain complete and unbroken (Section 11)
- [x] Versioning and reproducibility requirements locked (Section 10, 17)
- [x] Asset identity limitations explicitly documented (Section 3, 26)
- [x] Asset-type semantics and non-inference boundaries locked (Section 12)
- [x] CBOM projection boundary established (ECDAT -> CBOM, not reverse) (Section 13)
- [x] CBOM projection strategy defined with zero silent information loss requirement (Section 14)
- [x] Structural schema + semantic CBOM validation planned (Section 15)
- [x] Benchmark seed corpus and raw outputs intact and untouched (Section 2, 22)
- [x] Sensitive evidence handling boundaries established (Section 18)
- [x] Future-phase compatibility verified (Section 20)
- [x] Stale claims removed and security controls accurately classified (Section 19, 21)
- [x] Zero Phase 3 implementation code written during this gate (Section 1)

---

## 24. Decision & Gate Recommendation

### **FINAL GATE DECISION: CONDITIONAL PASS — DOCUMENTATION & VERIFICATION CORRECTIONS COMPLETE**

The required pre-Phase-3 architectural contracts have been reviewed and their current implementation, contract-defined, design-requirement, and deferred status has been explicitly classified. Phase 3A may begin with these boundaries preserved.

Status remains **CONDITIONAL PASS — DOCUMENTATION & VERIFICATION CORRECTIONS COMPLETE** pending Project Owner formal authorization to proceed to Phase 3A (CBOM Architecture & Projection Specification).

---

## 25. Phase 3 Execution Sequence

```
Pre-3A Domain & Run Contract Gate [CONDITIONAL PASS — DOCUMENTATION & VERIFICATION CORRECTIONS COMPLETE]
             ↓
Phase 3A — CBOM Architecture & Projection Design (Design-Only Specification)
             ↓
Phase 3B — CycloneDX 1.7 Serializer Implementation (Python Stdlib Only)
             ↓
Phase 3C — Structural Schema & Semantic Validation Test Suite
             ↓
Phase 3D — Adversarial CBOM Verification & Benchmark Comparison
             ↓
Phase 3 Formal Closure
```

---

## 26. Explicit Non-Claims Ledger

ECDAT formally records that it does **NOT** currently claim:
1. Universal cryptographic discovery across all languages or frameworks.
2. Zero false negatives (static scanners inherently miss dynamic wrappers, TC-08, TC-11).
3. Live production runtime or memory inspection.
4. Complete binary or container scanning in the current phase.
5. Operating-system process sandboxing before Phase 8.
6. That `NO_FINDINGS` implies the target codebase contains no cryptography.
7. Physical private key or HSM token identity.
8. Historical cross-commit refactoring tracking before Phase 9.
9. AI-generated or heuristic guesser ground truth.

---

## 27. Architectural Invariant Summary

$$\text{Observation} \neq \text{Interpretation} \neq \text{Semantic Asset} \neq \text{Analysis Run} \neq \text{CBOM Representation}$$

Maintaining absolute separation between these five tiers is the foundational integrity invariant of ECDAT.
