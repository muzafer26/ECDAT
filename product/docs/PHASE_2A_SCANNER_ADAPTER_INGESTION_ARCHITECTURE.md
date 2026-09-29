# Phase 2A — Scanner Adapter & Ingestion Architecture

**Document Version:** 1.1.0 (Targeted Architecture Correction Pass)  
**Phase:** Phase 2A (Design Only)  
**Status:** CORRECTION PASS COMPLETE — READY FOR REVIEW  
**Ownership Boundary:** Scanner Adapter Layer & Ingestion Pipeline  
**Constraint:** This document is a specification. ZERO production code was implemented. ZERO benchmark fixtures were modified. ZERO tools were downloaded.  

**Primary References:**
[`PROJECT_SPEC.md`](./PROJECT_SPEC.md),
[`ARCHITECTURE.md`](./ARCHITECTURE.md),
[`SECURITY_MODEL.md`](./SECURITY_MODEL.md),
[`DATA_FLOW.md`](./DATA_FLOW.md),
[`THREAT_MODEL.md`](./THREAT_MODEL.md),
[`INTEGRATION_STRATEGY.md`](./INTEGRATION_STRATEGY.md),
[`PRE_1C_B_ARCHITECTURE_GATE.md`](./PRE_1C_B_ARCHITECTURE_GATE.md),
[`PHASE_1C_B_BENCHMARK_REPORT.md`](./PHASE_1C_B_BENCHMARK_REPORT.md),
[`PHASE_1D_NORMALIZATION_ARCHITECTURE.md`](./PHASE_1D_NORMALIZATION_ARCHITECTURE.md),
[`DECISIONS.md`](./DECISIONS.md)

---

## Document Change Log (v1.0.0 → v1.1.0)

This targeted architecture correction pass resolves 10 architectural issues identified during Project Owner review:

1. **Evidence Identity Semantics Correction:** Classified `occurrence_index` strictly as a scan-local occurrence disambiguation mechanism, not semantic identity. Established a 4-tier identity hierarchy and explicitly noted that positional occurrence creates scan-output-relative evidence identity that cannot be treated as cross-scan identity.
2. **Native ID Collision Validation:** Scanner-native IDs are no longer assumed unique. The adapter contract requires validating native ID uniqueness within current scanner output, deriving distinct augmented evidence IDs upon collision, preserving raw native IDs in `raw_attributes`, and recording collisions observably.
3. **Syft Evidence/Filtering Boundary Decoupling:** Excised the hidden mandatory allowlist filter from the Syft adapter. Decoupled raw dependency evidence preservation from optional downstream ingestion/relevance policies. Reinforced that dependency evidence does not imply algorithm usage.
4. **Detection-Method Provenance Correction:** Removed manufactured `AST_ANALYSIS` and `LOCKFILE_PARSE` inferences. Standardized detection method assignment to: (a) explicitly reported by scanner, (b) established by verified documentation as documented capability, or (c) `UNKNOWN`.
5. **Exception Containment Boundary Clarification:** Replaced absolute "never throw" claims with structured result returns for expected operational failures, backed by an enforceable orchestrator containment boundary that intercepts unexpected adapter exceptions and transitions to a controlled `FAILED` state.
6. **XML & Parser Security Precision:** Formulated XML security requirements implementation-neutrally (external entities disabled, DTD disabled, entity expansion prevented, bounded parsing). Clarified that `defusedxml` is an example candidate library for Phase 2B evaluation, not an existing installed dependency.
7. **Enforceable Parser Resource/Time Policy:** Specified bounded parsing resource and time limits as mandatory Phase 2B enforcement requirements rather than claiming current code already enforces them.
8. **Temporary Scan Workspace vs. Persistent Source Retention:** Explicitly distinguished ephemeral scanner execution workspace requirements from persistent source repository retention, confirming ECDAT does not require persistent source repository storage as a product data model requirement.
9. **Phase 1D Correlation Boundary Hardening:** Explicitly reaffirmed that Phase 1D correlation is strictly conservative same-source-statement deduplication. Dependency evidence (`LocationType.DEPENDENCY`) and source evidence (`LocationType.SOURCE`) represent distinct location and observation types and MUST NOT correlate.
10. **Comprehensive Absolute Claims Audit:** Replaced unsupported absolutes throughout the specification with technically defensible, precise engineering formulations.

---

## 1. Executive Summary

Phase 2A defines the architectural boundary that converts heterogeneous external scanner output into generic ECDAT evidence. This boundary — the **Scanner Adapter Layer** — is the critical anti-corruption layer between replaceable external discovery tools and the stable ECDAT core domain model established in Phase 1D.

The target pipeline is:

```
External Scanner Binary/Tool
        ↓
Scanner Adapter (scanner-specific)
        ↓
Raw Scanner Output (preserved verbatim)
        ↓
Defensive Parser (untrusted input handling)
        ↓
EvidenceRecord (generic ECDAT model)
        ↓
ECDAT Normalization Engine (Phase 1D)
        ↓
Finding (canonical domain entity)
        ↓
Asset Correlation Engine (Phase 1D)
        ↓
CryptoAsset (canonical inventory entity)
```

The adapter layer ensures that **no scanner-specific assumption leaks into the ECDAT core**. If any scanner is removed, the domain model, normalization engine, correlation engine, and all downstream phases continue to function unchanged.

### Benchmark Metric Governance (F-01)

Legacy automated benchmark JSON artifacts contain an earlier mixed-unit precision/F1 calculation. The corrected analytical baseline is `PHASE_1C_B_BENCHMARK_REPORT.md` v1.1.0:

| Metric | Value | Unit |
| :--- | :---: | :--- |
| **Case-Level Recall** | 70.0% | 7 / 10 positive cases detected |
| **Finding-Level Precision** | 40.0% | 8 / 20 findings relevant |

**These two metrics have incompatible denominators and MUST NOT be combined into a conventional F1 score.** Legacy runner metrics MUST NOT be propagated as current analytical benchmark metrics. Historical raw artifacts are preserved as-is for provenance.

---

## 2. Scope

### In Scope (Phase 2A Design)

1. Abstract `ScannerAdapter` contract specification
2. Scanner adapter lifecycle model
3. Scanner capability metadata model
4. Raw output preservation contract
5. Evidence identity contract (F-02 resolution)
6. Evidence creation mapping rules
7. Source location model for heterogeneous evidence types
8. Failure semantics and partial execution model
9. Parser security contract
10. Scanner execution security boundary
11. CryptoScan v1.4.0 adapter mapping design
12. Syft v1.51.1 adapter mapping design
13. Idempotency requirements
14. Provenance chain specification
15. Observability requirements
16. Extensibility mechanism
17. ECDAT ownership boundary classification
18. Benchmark integration strategy
19. Phase 2B test strategy

### Out of Scope (Explicitly Forbidden)

- Production adapter code
- Scanner execution engine implementation
- Process sandbox implementation
- Parser implementation
- Database schema
- REST API, dashboard, or UI
- Risk engine, migration engine
- CBOM generator
- Network, TLS, container, binary, or AST scanners
- AI assistants

---

## 3. Non-Goals

1. **Not a scanner selection decision.** Phase 2A designs the adapter contract; it does not choose which scanners to integrate.
2. **Not a deployment architecture.** Microservices, message queues, Kubernetes, and distributed systems are not introduced.
3. **Not a retention policy or persistent source store.** ECDAT does not require persistent retention of source repositories as a product data model requirement. Temporary scan material may exist during scanning and MUST follow the deployment's isolation, access-control, cleanup, and retention security requirements.
4. **Not an exhaustive location taxonomy.** The location model is extensible; it does not attempt to anticipate every possible future location type.
5. **Not a scanner improvement plan.** The adapter preserves observations; it does not correct scanner deficiencies.

---

## 4. Current Architecture

Phase 1D established the following production domain model in `product/core/`:

```
product/core/
├── evidence/
│   ├── evidence.py       # EvidenceRecord, EvidenceLocation, SourceLocation, LocationType
│   ├── provenance.py     # ScannerMetadata, ProvenanceChain
│   └── sanitization.py   # Path sanitization, snippet bounding, freeze_value
├── domain/
│   ├── algorithm.py      # AlgorithmFamily, AlgorithmIdentity
│   ├── asset.py          # CryptoAsset, CanonicalAssetKey, AssetType
│   ├── confidence.py     # ConfidenceLevel, DispositionStatus
│   ├── finding.py        # Finding, FrozenIdTuple
│   ├── observation.py    # ObservationType
│   ├── parameters.py     # AlgorithmParameters
│   └── role.py           # CryptographicRole
└── normalization/
    ├── normalizer.py     # NormalizationEngine
    ├── correlation.py    # AssetCorrelationEngine, CorrelationDecision
    └── taxonomy.py       # Algorithm resolution, role inference, parameter extraction
```

Key Phase 1D invariants that Phase 2A must respect:

1. **Immutable evidence.** `EvidenceRecord` is `frozen=True` with deep immutability.
2. **Specificity invariant.** Generic scanner categories (e.g., `ECC`) never manufacture specific algorithms (e.g., `ECDH`, `ECDSA`).
3. **False merging is worse than false splitting.** Correlation is conservative.
4. **Asset identity is deterministic** from `CanonicalAssetKey`, with zero dependence on finding IDs or evidence IDs.
5. **Provenance is reconstructable.** `CryptoAsset → finding_ids → Finding → evidence_ids → EvidenceRecord → raw_attributes`.
6. **Evidence location is generalized.** `LocationType` already supports: SOURCE, DEPENDENCY, NETWORK, CONTAINER, CERTIFICATE, BINARY, OTHER.

---

## 5. Adapter Architecture

### 5.1 Conceptual Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│              EXTERNAL SCANNER BOUNDARY (Untrusted)           │
│                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐    │
│   │ CryptoScan  │  │    Syft     │  │ Future Scanner N │    │
│   │  v1.4.0     │  │   v1.51.1   │  │                  │    │
│   └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘    │
└──────────┼────────────────┼──────────────────┼───────────────┘
           │                │                  │
           ▼                ▼                  ▼
┌──────────────────────────────────────────────────────────────┐
│         SCANNER ADAPTER LAYER (Scanner-Specific Code)        │
│                                                              │
│  ┌───────────────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │ CryptoScanAdapter │ │ SyftAdapter  │ │ FutureAdapter  │  │
│  │                   │ │              │ │                │  │
│  │ • validate()      │ │ • validate() │ │ • validate()   │  │
│  │ • execute()       │ │ • execute()  │ │ • execute()    │  │
│  │ • parse()         │ │ • parse()    │ │ • parse()      │  │
│  │ • create_evid()   │ │ • create_e() │ │ • create_e()   │  │
│  └────────┬──────────┘ └──────┬───────┘ └───────┬────────┘  │
└───────────┼───────────────────┼─────────────────┼────────────┘
            │                   │                 │
            ▼                   ▼                 ▼
┌──────────────────────────────────────────────────────────────┐
│     GENERIC ECDAT BOUNDARY (Scanner-Agnostic Core)           │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ IngestionResult                                       │    │
│  │ • status: IngestionStatus (SUCCESS/PARTIAL/FAILED/…)  │    │
│  │ • evidence_records: List[EvidenceRecord]               │    │
│  │ • scan_metadata: ScanExecutionMetadata                │    │
│  │ • errors: List[IngestionError]                        │    │
│  │ • raw_output_ref: str (hash/pointer to raw output)    │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │                                │
│                             ▼                                │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ NormalizationEngine.normalize_batch()  (Phase 1D)     │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             ▼                                │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ AssetCorrelationEngine.correlate()     (Phase 1D)     │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Architectural Principle

An adapter is a **translator** that converts one specific scanner's output format into the generic ECDAT evidence model. Each adapter:

- **Owns** all scanner-specific knowledge (output format, native IDs, categories, quirks)
- **Produces** scanner-agnostic `EvidenceRecord` instances
- **Preserves** raw scanner observations without semantic interpretation
- **Does not** perform ECDAT normalization, correlation, risk scoring, or asset creation

The adapter layer is the **only** place in ECDAT that imports scanner-specific knowledge.

### 5.3 Core Design Invariants

All components of the Scanner Adapter & Ingestion Architecture MUST uphold the following 14 design invariants:

1. **Evidence identity ≠ asset identity.** Evidence identity tracks a specific empirical observation within a scan; asset identity tracks an underlying cryptographic construct via `CanonicalAssetKey`.
2. **Occurrence index ≠ semantic identity.** Occurrence index provides scan-local positional disambiguation when stronger identity information is unavailable; it MUST NOT be treated as cross-scan semantic identity.
3. **Native scanner IDs are not blindly trusted.** Adapters must validate native ID uniqueness within scanner output and handle collisions defensively.
4. **Raw scanner observations are preserved.** Verbatim categories, rules, and snippets are retained; the adapter never alters raw observation values.
5. **Adapter does not perform ECDAT semantic interpretation.** The adapter translates syntax; semantic classification belongs exclusively to downstream normalization.
6. **Adapter does not manufacture algorithm specificity.** Generic categories (e.g. `ECC`) are never upgraded to specific algorithms (e.g. `ECDSA`) by an adapter.
7. **Dependency evidence does not imply algorithm usage.** Manifest package declarations (`LocationType.DEPENDENCY`) represent declared dependencies, never proven algorithm execution.
8. **Scanner failure does not imply zero findings.** Failures, crashes, and timeouts MUST be represented as error states, never as successful scans with no cryptography.
9. **Partial scans cannot be reported as complete.** Unprocessed files or partial failures must be explicitly qualified via `IngestionStatus.PARTIAL` and scope coverage tracking.
10. **Raw output remains provenance-linked.** Where raw output is successfully captured and retained, provenance provides a reconstructable path to that output.
11. **Phase 1D correlation remains conservative same-source-statement correlation.** Cross-scanner correlation requires equivalent source-statement evidence; dependency evidence and source evidence do not merge.
12. **Temporary source material is distinct from persistent source retention.** ECDAT product models do not require persistent source repository storage; temporary scan workspaces must follow strict security and cleanup requirements.
13. **Security requirements are not implementation claims.** Defensive parsing and process isolation specifications define mandatory Phase 2B requirements rather than asserting current implementation.
14. **Benchmark answer keys remain test oracles only.** Answer keys are immutable validation references; adapters must never utilize them at runtime.

---

## 6. ScannerAdapter Contract

### 6.1 Abstract Contract Specification

```
ScannerAdapter (Abstract)
├── Properties (Metadata)
│   ├── adapter_id: str            — Unique adapter identifier (e.g., "cryptoscan")
│   ├── adapter_version: str       — Semantic version of this adapter implementation
│   ├── scanner_name: str          — Name of the external scanner
│   ├── scanner_version: str       — Expected/validated scanner version
│   └── capabilities: ScannerCapabilities  — Declared capability metadata
│
├── Lifecycle Methods
│   ├── validate() → ValidationResult
│   │   Verify prerequisites: binary exists, version matches, hash verified
│   │
│   ├── prepare(target: ScanTarget) → PrepareResult
│   │   Configure execution: build CLI arguments, resolve paths, set resource limits
│   │
│   ├── execute(target: ScanTarget) → ExecutionResult
│   │   Run scanner subprocess, capture stdout/stderr/exit code, enforce timeout
│   │
│   ├── parse(raw_output: RawScannerOutput) → ParseResult
│   │   Defensively parse raw output into structured intermediate representation
│   │
│   └── create_evidence(parsed: ParseResult) → List[EvidenceRecord]
│       Map parsed findings to generic EvidenceRecord instances
│
└── Error Handling & Containment
    ├── Expected operational failures SHOULD be returned as structured result objects
    │   (ValidationResult, PrepareResult, ExecutionResult, ParseResult)
    └── Unexpected adapter exceptions MUST be contained by the orchestrator boundary
        and converted into IngestionStatus.FAILED without crashing the pipeline
```

### 6.2 Contract Answers

| Question | Answer |
| :--- | :--- |
| **What does an adapter represent?** | A translator between one specific scanner's output and the generic ECDAT evidence model. |
| **What inputs does it accept?** | A `ScanTarget` identifying the filesystem path, target type, and scan options. |
| **What metadata must it expose?** | `adapter_id`, `adapter_version`, `scanner_name`, `scanner_version`, `capabilities`. |
| **How is scanner version recorded?** | The adapter declares the expected scanner version. `validate()` verifies the actual binary version matches. |
| **How are scanner capabilities described?** | Via a `ScannerCapabilities` metadata structure (see Section 8). |
| **How is configuration represented?** | Adapter-specific configuration is internal to the adapter. The adapter exposes only the generic contract to the core. |
| **How does execution begin/end?** | Via the lifecycle: `validate() → prepare() → execute() → parse() → create_evidence()`. |
| **How is output parsed?** | The `parse()` method applies format-specific defensive parsing (see Section 15). |
| **How are findings converted?** | `create_evidence()` maps parsed intermediate records to `EvidenceRecord` instances. |
| **How are scanner-native IDs handled?** | Validated for uniqueness within scan output; namespaced with adapter prefix; collisions handled defensively (see Section 10). |
| **How are failures represented?** | Via explicit `IngestionStatus` enum (see Section 13). |
| **How are partial results represented?** | `IngestionStatus.PARTIAL` with explicit scope coverage metadata (see Section 14). |
| **How are unsupported outputs represented?** | `IngestionStatus.UNSUPPORTED` with reason. |
| **How are malformed outputs handled?** | `parse()` returns `ParseResult` with `PARSER_ERROR` status and preserved raw output reference. |
| **How is provenance preserved?** | Every `EvidenceRecord` carries `scanner_name`, `scanner_version`, `scan_id`, `raw_output_ref`, and `timestamp`. |

---

## 7. Lifecycle

### 7.1 Conceptual Lifecycle Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     ADAPTER LIFECYCLE                           │
│                                                                 │
│  ① validate()                                                   │
│     │  Verify: binary exists, version matches,                  │
│     │          SHA-256 hash correct, prerequisites               │
│     │                                                           │
│     ├── FAIL → ValidationResult(INVALID, reason)                │
│     │          Pipeline records failure/skips this adapter      │
│     │                                                           │
│     ▼  PASS                                                     │
│  ② prepare(target)                                              │
│     │  Build: CLI args, working directory,                       │
│     │         resource limits, environment                      │
│     │                                                           │
│     ├── FAIL → PrepareResult(INVALID_INPUT, reason)             │
│     │                                                           │
│     ▼  PASS                                                     │
│  ③ execute(target)                                              │
│     │  Run: subprocess with timeout, capture raw                 │
│     │       stdout/stderr/exit_code/duration                     │
│     │                                                           │
│     ├── TIMEOUT → ExecutionResult(TIMEOUT)                       │
│     ├── CRASH   → ExecutionResult(FAILED, stderr)                │
│     ├── EXIT≠0  → ExecutionResult(FAILED/PARTIAL)                │
│     │                                                           │
│     ▼  EXIT=0                                                   │
│  ④ capture_raw_output()                                         │
│     │  Store/reference: verbatim raw output                      │
│     │  Record: SHA-256 hash of raw output                        │
│     │                                                           │
│     ▼                                                           │
│  ⑤ parse(raw_output)                                            │
│     │  Parse: defensively, with bounded resource/depth limits   │
│     │                                                           │
│     ├── MALFORMED → ParseResult(PARSER_ERROR)                    │
│     ├── PARTIAL   → ParseResult(PARTIAL, findings)               │
│     │                                                           │
│     ▼  SUCCESS                                                  │
│  ⑥ create_evidence(parsed)                                      │
│     │  Map: scanner findings → EvidenceRecord[]                  │
│     │  Assign: adapter-owned validated evidence identity         │
│     │  Preserve: raw category, raw value, raw IDs                │
│     │                                                           │
│     ▼                                                           │
│  ⑦ return IngestionResult                                       │
│     │  Status: SUCCESS / PARTIAL / FAILED / ...                  │
│     │  Evidence: List[EvidenceRecord]                             │
│     │  Metadata: ScanExecutionMetadata                           │
│     │  Errors: List[IngestionError]                              │
│     │  Raw Output Ref: hash/pointer                              │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
        ┌─────────────────────────────────────────────────┐
        │       ORCHESTRATOR CONTAINMENT BOUNDARY         │
        │  Catches unexpected exceptions, logs traceback, │
        │  and converts failure to IngestionStatus.FAILED │
        └─────────────────────────────────────────────────┘
```

### 7.2 Lifecycle Invariants

1. **Orchestrator pipeline containment.** Expected operational failures are represented as structured results (`ValidationResult`, `ExecutionResult`, `ParseResult`). Unexpected adapter exceptions are intercepted at the orchestrator boundary and converted to `IngestionStatus.FAILED`, preventing unhandled crashes from taking down the pipeline.
2. **Every step produces observable output.** Duration, status, and error details are systematically captured for auditability.
3. **Raw output is captured before parsing.** If parsing fails or times out, raw output remains preserved for post-mortem analysis and re-parsing.
4. **The adapter does not call the normalizer.** Evidence creation is the terminal step of the adapter. Normalization is owned exclusively by the ECDAT core.

---

## 8. Scanner Capability Model

### 8.1 ScannerCapabilities Structure

```
ScannerCapabilities
├── target_types: List[LocationType]        — Supported locations (SOURCE, DEPENDENCY, etc.)
├── languages: List[str]                    — Supported source languages (java, python, etc.)
├── detection_mechanisms: List[DetectionMethod] — Declared/documented detection methods
├── output_formats: List[str]               — Output formats adapter can parse (json, xml, etc.)
├── extracts_parameters: bool               — Whether scanner extracts key size, mode, etc.
├── distinguishes_comments: bool            — Whether scanner filters code comments
├── provides_native_ids: bool               — Whether scanner provides finding-level IDs
├── provides_confidence: bool               — Whether scanner provides confidence scores
└── known_limitations: List[str]            — Documented tool limitations
```

### 8.2 Capability Semantics

- Capabilities declare what the scanner is known to support; they do not dictate what the scanner actually detected in a given run.
- Capabilities enable ECDAT to perform **scope-aware evaluation** (e.g., recognizing that a dependency scanner cannot be evaluated on source code detection).
- Capabilities prevent invalid invocations (e.g., attempting to invoke a Java-only scanner on a Python repository).

---

## 9. Raw Output Contract

### 9.1 Raw Output Preservation Boundary

```
┌─────────────────────────────────────────────────────────┐
│ RAW OUTPUT PRESERVATION BOUNDARY                         │
│                                                         │
│ External Scanner Output                                 │
│        │                                                │
│        ▼                                                │
│ RawScannerOutput                                        │
│   ├── stdout: bytes (verbatim)                          │
│   ├── stderr: bytes (verbatim)                          │
│   ├── exit_code: int                                    │
│   ├── sha256_hash: str                                  │
│   ├── execution_metadata: ScanExecutionMetadata         │
│   └── storage_ref: str (path or content hash)           │
│        │                                                │
│        ├─────────────────────────────┐                  │
│        ▼                             ▼                  │
│ Defensive Parser (untrusted)    Audit Archive           │
│        │                        (re-parseable)          │
│        ▼                                                │
│ EvidenceRecord[]                                        │
│   └── raw_output_ref = storage_ref                      │
└─────────────────────────────────────────────────────────┘
```

### 9.2 RawScannerOutput Structure

```
RawScannerOutput
├── scan_id: str                         — Unique execution identifier (UUID)
├── adapter_id: str                      — Adapter that performed the scan
├── scanner_name: str                    — Name of external scanner
├── scanner_version: str                 — Validated version of external scanner
├── stdout_bytes: bytes                  — Unmodified stdout captured from scanner
├── stderr_bytes: bytes                  — Unmodified stderr captured from scanner
├── exit_code: int                       — Process exit code
├── duration_ms: int                     — Total execution time in milliseconds
├── sha256_hash: str                     — SHA-256 of stdout_bytes (integrity verification)
├── timestamp: str                       — ISO 8601 UTC timestamp of execution
├── cli_arguments: List[str]             — CLI arguments used (sanitized)
└── storage_ref: str                     — Content-addressed or filesystem reference
```

### 9.3 Preservation Requirements

| Requirement | Classification | Rationale |
| :--- | :--- | :--- |
| Raw stdout preserved verbatim | **REQUIRED** | Enables re-parsing with improved adapters |
| SHA-256 hash of raw output | **REQUIRED** | Tamper detection, idempotency verification |
| Scanner version at execution time | **REQUIRED** | Provenance; eliminates version ambiguity |
| Adapter version at parse time | **REQUIRED** | Parser behavior traceability |
| CLI arguments recorded | **REQUIRED** | Reproducibility |
| Execution timestamp | **REQUIRED** | Temporal audit trail |
| Execution duration | **REQUIRED** | Performance observability |
| Exit code | **REQUIRED** | Failure semantics |
| stderr content | **REQUIRED** | Diagnostics and error triage |
| Raw output storage location | **DEPLOYMENT CONFIGURATION** | Specified by deployment environment |
| Retention period | **DEPLOYMENT CONFIGURATION** | Specified by deployment policy |
| Persistent source repository storage | **EXPLICITLY NOT REQUIRED** | ECDAT product data model stores evidence and provenance, not source repositories |
| Temporary scan workspace | **SECURITY-BOUNDED EPHEMERAL** | Temporary scan material during execution must follow isolation, access-control, cleanup, and retention requirements |

---

## 10. Evidence Identity Contract (F-02 Resolution)

### 10.1 Problem Statement & Identity Taxonomy

In cryptographic inventory discovery, three levels of identity must be explicitly differentiated:

1. **Evidence Identity (`evidence_id`):** The observational identity of a specific finding captured within a specific scan execution.
2. **Asset Identity (`CanonicalAssetKey`):** The semantic identity of an underlying cryptographic asset derived deterministically from canonical properties (type, location anchor, algorithm family, name, role, parameters).
3. **Semantic Identity:** The true real-world cryptographic construct or operation in the inspected codebase.

Phase 1D's deterministic fallback evidence ID derives identity from:
```
file_path : line_start : line_end : column_start : column_end : matched_text : scanner_name : scanner_version : scanner_category
```
This fallback collides when a scanner emits multiple distinct observations with identical values across these fields (e.g., repeated patterns on the same line without column information).

### 10.2 Evidence Identity Hierarchy & Occurrence Disambiguation

To construct evidence IDs reliably without conflating observation with semantics, adapters MUST apply the following 4-tier hierarchy:

```
Tier 1: Scanner-provided native unique occurrence/finding ID (validated for uniqueness)
        ↓ (if missing or invalid)
Tier 2: Scanner-native rule/finding ID combined with source/occurrence context
        ↓ (if missing)
Tier 3: Stable source/output distinguishing information (file, line range, columns, snippet, category)
        ↓ (if identical across multiple findings in the same scan)
Tier 4: Occurrence index ONLY as a last-resort scan-local disambiguator
```

> **CRITICAL SEMANTIC SPECIFICATION:**  
> `occurrence_index` is an occurrence disambiguation mechanism, not a semantic identity mechanism.  
> `occurrence_index ≠ semantic identity`  
> `occurrence_index ≠ cross-scan identity`  
> `occurrence_index ≠ asset identity`  
>  
> When positional occurrence is the only available distinction, the resulting evidence identity is scan-output-relative and MUST NOT be treated as cross-scan semantic identity.

### 10.3 Native ID Collision Validation & Preservation Contract

Adapters cannot blindly trust that scanner-native IDs are unique within a scan execution. The contract requires:

```
Scanner provides native ID
        ↓
Adapter validates uniqueness across findings in current scan output
        ↓
Is native ID unique in this scan?
    ├── YES → Evidence ID = "{adapter_id}:{scanner_native_id}"
    └── NO  → COLLISION DETECTED:
              1. Preserve every observation as a distinct EvidenceRecord
              2. Record collision in raw_attributes["native_id_collision"] = True
              3. Preserve original raw native ID in raw_attributes["native_finding_id"]
              4. Derive distinct evidence IDs:
                 "{adapter_id}:{scanner_native_id}:collision:{collision_index}"
              5. Emit observable warning in IngestionResult
```

The adapter MUST NOT silently overwrite, deduplicate, or collapse duplicate native IDs.

### 10.4 Evidence Identity Invariants

| # | Invariant | Rationale |
| :--- | :--- | :--- |
| 1 | Evidence identity MUST remain separate from asset identity | Asset identity is semantic (`CanonicalAssetKey`); evidence identity is observational |
| 2 | Asset identity MUST NOT depend on evidence IDs | Phase 1D enforces this: asset IDs derive strictly from canonical keys |
| 3 | Scanner-native IDs are namespaced with adapter ID | Prevents cross-adapter ID collision (e.g., `cryptoscan:001` ≠ `syft:001`) |
| 4 | Scanner-native IDs are NEVER assumed globally unique | Independent tools frequently emit overlapping identifier strings |
| 5 | Native ID collisions are validated, preserved, and made observable | No silent dropping of scanner findings |
| 6 | Evidence identity MUST NOT collapse duplicate identical observations | Conservative principle: preserve all empirical records |
| 7 | If identity cannot be established safely, preserve both records | False splitting is strictly safer than false merging |
| 8 | Occurrence index is strictly a scan-local disambiguator | Distinguishes positional items in one run; does not represent stable semantic identity |

### 10.5 Relationship to Phase 1D Fallback

The Phase 1D deterministic fallback ID mechanism (`evidence.py` lines 248-261) remains intact as a secondary defense-in-depth layer. For production ingestion in Phase 2B, adapters MUST construct and supply explicit, validated evidence IDs adhering to the hierarchy above.

---

## 10.6 Corrected Identity & Correlation Examples

### Example A — Scanner Provides Native Unique ID

- **Scanner Output:** `{"id": "RSA-001-16-34", "ruleId": "RSA-001", "line": 16}`
- **Adapter Validation:** Checks findings in this scan; `"RSA-001-16-34"` occurs exactly once.
- **Derived Evidence ID:** `"cryptoscan:RSA-001-16-34"`
- **Preserved Attributes:** `raw_attributes["native_finding_id"] = "RSA-001-16-34"`

### Example B — Duplicate Native IDs in One Scan (Scanner Collision)

- **Scanner Output:** Finding 1 has `id = "001"`; Finding 2 also has `id = "001"` (e.g. scanner assigns rule ID as finding ID).
- **Adapter Validation:** Collision detected for `"001"`.
- **Derived Evidence IDs:**
  - Finding 1: `"cryptoscan:001:collision:0"`
  - Finding 2: `"cryptoscan:001:collision:1"`
- **Preserved Attributes:** Both records preserve `raw_attributes["native_finding_id"] = "001"`, `raw_attributes["native_id_collision"] = True`.
- **Observability:** `IngestionResult.warnings` records: `"Duplicate native finding ID '001' detected; augmented with collision disambiguator"`.

### Example C — No Native ID (Identical Source Coordinates)

- **Scanner Output:** Two findings emitted for the same file, line 42, matching `"AES"`, with no native IDs and no column offsets.
- **Adapter Resolution:** Stable source coordinates match; positional `occurrence_index` (0 and 1) is used as last-resort disambiguator.
- **Derived Evidence IDs:** Deterministic UUIDv5 derived from full fingerprint including `occurrence_index`.
- **Semantic Classification:** Position-relative observational distinction. Explicitly NOT cross-scan semantic identity.

### Example D — Syft Dependency Observation

- **Scanner Output:** `{"name": "bcprov-jdk18on", "version": "1.78.1", "purl": "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"}`
- **Adapter Evidence:**
  - `evidence_id = "syft:pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"`
  - `location = EvidenceLocation(location_type=DEPENDENCY, package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1")`
  - `scanner_category = "dependency"`
- **Downstream Invariant:** Does NOT create algorithm evidence (no AES, RSA, or ECDSA inferred).

### Example E — Cross-Scanner Correlation Boundary

- **Observation 1 (CryptoScan):** Source file `CryptoService.java`, line 25, statement `Cipher.getInstance("AES/GCM/NoPadding")`, `LocationType.SOURCE`.
- **Observation 2 (Hypothetical Scanner B):** Source file `CryptoService.java`, line 25, equivalent statement, `LocationType.SOURCE`.
- **Correlation Decision:** Candidates for same-source-statement deduplication under Phase 1D correlation rules.
- **Observation 3 (Syft):** Manifest `pom.xml`, dependency `org.bouncycastle:bcprov-jdk18on`, `LocationType.DEPENDENCY`.
- **Correlation Decision:** `NOT_CORRELATED` with Observations 1 or 2 (`LocationType.DEPENDENCY` ≠ `LocationType.SOURCE`). Dependency evidence does NOT correlate with source statement usage.

---

## 11. Evidence Mapping

### 11.1 Evidence Creation Rules

When a scanner adapter creates `EvidenceRecord` instances, the following mapping rules apply:

| EvidenceRecord Field | Source | Adapter Responsibility |
| :--- | :--- | :--- |
| `evidence_id` | Adapter-constructed (Section 10) | MUST provide validated, occurrence-aware identity |
| `location` | Scanner output location fields | Map to appropriate `EvidenceLocation` subtype |
| `scanner_name` | Adapter metadata | Canonical scanner name string |
| `scanner_version` | Adapter metadata / validated | Exact verified scanner version |
| `detection_method` | Scanner output or documented capability | Standardized detection method assignment (Section 11.2) |
| `scanner_category` | Scanner's raw category label | **PRESERVE VERBATIM.** Do not translate, normalize, or alter. |
| `scanner_confidence` | Scanner's native confidence (if any) | Preserve as-is; ECDAT assigns its own confidence downstream |
| `raw_attributes` | Scanner-specific fields | Deeply frozen mapping of scanner fields and collision metadata |
| `scan_id` | Scan execution ID | UUID linking to `RawScannerOutput` |
| `raw_output_ref` | Pointer/hash of raw output | Verifiable reference to raw output |
| `timestamp` | Execution time | ISO 8601 UTC |

### 11.2 Detection Method Assignment Rule

Adapters must not manufacture detection methods based on informal assumptions about scanner internals. A detection method may be represented ONLY as:

1. **Explicitly reported by scanner:** Directly declared in scanner output for that observation.
2. **Established by verified scanner documentation:** Verified and documented as a documented scanner capability for that scanner version and cataloger.
3. **`DetectionMethod.UNKNOWN`:** When neither explicit reporting nor documented capability is established.

Assumptions (e.g. guessing that a tool internally utilized an AST or lockfile parser) MUST NOT be asserted as factual evidence.

### 11.3 Specificity Invariant: No Manufacture of Specificity

The adapter MUST NOT perform semantic interpretation. Examples:

| Scanner Raw Category | Adapter MUST Preserve | Adapter MUST NOT Produce |
| :--- | :--- | :--- |
| `ECC` | `scanner_category = "ECC"` | `scanner_category = "ECDH"` or `"ECDSA"` |
| `DH` (in comment text) | `scanner_category = "DH"`, `matched_text = "..."` | Silently dropped observation |
| `CERT-SIGALG-001` | `scanner_category = "CERT-SIGALG-001"` | `scanner_category = "ECDSA"` |
| `dependency` | `scanner_category = "dependency"` | `scanner_category = "AES"` (inferred from library) |
| `pke` (CryptoScan primitive type) | `raw_attributes["primitive"] = "pke"` | Inferred operational role |

The adapter is a **faithful translator**, not an **interpreter**. Interpretation is the exclusive responsibility of the ECDAT `NormalizationEngine`.

### 11.4 raw_attributes Contract

The `raw_attributes` frozen mapping MUST include:

```
raw_attributes = {
    "native_finding_id": str,       # Scanner's raw ID for this finding (if available)
    "native_rule_id": str,          # Scanner's rule/check ID (if available)
    "native_severity": str | int,   # Scanner's severity (if available)
    "native_confidence": str,       # Scanner's confidence label (if available)
    "native_category": str,         # Scanner's category label (verbatim)
    "native_primitive": str,        # Scanner's primitive classification (if available)
    "raw_context": str,             # Scanner's context/snippet
    "native_id_collision": bool,    # True if duplicate native ID was detected and disambiguated
    # Additional scanner-specific fields preserved verbatim
}
```

Fields not provided by the scanner are omitted rather than populated with placeholder values.

---

## 12. Location Model

### 12.1 Evidence Location Types

ECDAT's `EvidenceLocation` supports heterogeneous evidence types across discovery tools:

| LocationType | Key Fields | Used By | Example |
| :--- | :--- | :--- | :--- |
| `SOURCE` | `file_path`, `line_start`, `line_end`, `column_start`, `column_end`, `matched_text`, `code_snippet` | CryptoScan, static source scanners | `src/Crypto.java:16:34` |
| `DEPENDENCY` | `package_coordinate`, `file_path` (manifest) | Syft, dependency scanners | `pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1` |
| `NETWORK` | `endpoint`, `port` | sslscan, network discovery | `api.example.com:443` |
| `CONTAINER` | `container_image`, `layer_digest` | Container scanners | `sha256:abcd...` |
| `CERTIFICATE` | `certificate_id`, `file_path` | Certificate scanners | `CN=example.com,O=Org` |
| `BINARY` | `binary_artifact`, `file_path` | Binary scanners | `libcrypto.so.3` |
| `OTHER` | Generic bounded string fields | Custom scanners | Custom coordinate |

### 12.2 Architectural Constraint

The location model MUST NOT assume a source-file-only architecture. Scanners reporting network endpoints, container layers, or dependencies must be accommodated without forcing artificial `file_path` and `line_start` values.

---

## 13. Failure Semantics

### 13.1 IngestionStatus Enumeration

```
IngestionStatus
├── SUCCESS             — Scanner executed cleanly; parser succeeded; evidence created
├── PARTIAL             — Scanner executed but processed only a subset of the target scope
├── FAILED              — Scanner execution failed (crash, fatal error, unhandled exception)
├── TIMEOUT             — Scanner exceeded execution deadline
├── INVALID_INPUT       — Target path invalid, inaccessible, or rejected by validation
├── UNSUPPORTED         — Target type or language not supported by this scanner
├── PARSER_ERROR        — Raw output captured but parser could not interpret it
├── VALIDATION_FAILED   — Scanner binary missing, version mismatch, or hash mismatch
└── NO_FINDINGS         — Scanner executed successfully and reported zero findings
                          (Distinct from FAILED: this is a valid result, not an error)
```

### 13.2 Semantic Distinctions

| Scenario | Status | MUST NOT Be Interpreted As |
| :--- | :--- | :--- |
| Scanner crashes with segfault | `FAILED` | "No cryptography found" |
| Scanner times out after deadline | `TIMEOUT` | "No cryptography found" |
| Scanner returns exit code 0 with 0 findings | `NO_FINDINGS` | "Scan failed" |
| Scanner processes 80/100 files, fails on 20 | `PARTIAL` | "100% scanned" |
| Scanner doesn't support Go | `UNSUPPORTED` | "No cryptography in Go files" |
| Raw output is truncated/malformed JSON | `PARSER_ERROR` | "No findings" |
| Scanner binary not found on host | `VALIDATION_FAILED` | "Scan attempted" |

### 13.3 Failure Representation in IngestionResult

```
IngestionResult
├── status: IngestionStatus
├── evidence_records: List[EvidenceRecord]        — Populated for SUCCESS or PARTIAL
├── scan_metadata: ScanExecutionMetadata
│   ├── scan_id: str
│   ├── adapter_id: str
│   ├── adapter_version: str
│   ├── scanner_name: str
│   ├── scanner_version: str
│   ├── timestamp: str
│   ├── duration_ms: int
│   ├── exit_code: Optional[int]
│   └── input_scope: ScanInputScope
├── errors: List[IngestionError]
│   ├── error_code: str
│   ├── error_message: str
│   ├── error_source: str                         — "scanner" | "parser" | "adapter" | "orchestrator"
│   └── recoverable: bool
├── raw_output_ref: str                           — Populated if execution was attempted
├── scope_coverage: Optional[ScopeCoverage]       — For PARTIAL results
│   ├── total_files: Optional[int]
│   ├── processed_files: Optional[int]
│   ├── failed_files: Optional[int]
│   └── failure_reasons: List[str]
└── warnings: List[str]                           — e.g., collision warnings
```

---

## 14. Partial Execution

### 14.1 Problem Statement

Scanners frequently encounter partial execution (e.g., syntax errors in 2 out of 50 files, permission denial on specific subdirectories). If an adapter returns `SUCCESS` for partial scans, downstream risk calculations assume complete coverage, masking uninspected cryptographic assets.

### 14.2 Partial Execution Representation

When a scanner indicates partial processing, the adapter MUST:

1. Set `status = IngestionStatus.PARTIAL`.
2. Populate `scope_coverage` with file counts and failure reasons.
3. Emit `EvidenceRecord` instances for all successfully inspected components.
4. Record partial execution explicitly in `scan_metadata`.

---

## 15. Parser Security

### 15.1 Threat Model

Scanner output is **untrusted input**. Even when scanner binaries are hash-verified, their output may contain malicious filenames, comment injections, or oversized payloads derived from untrusted repositories.

### 15.2 Defensive Parsing Policy Requirements

Phase 2B MUST implement an enforceable bounded parsing resource and time policy. The architecture establishes the following policy limits:

| Threat | Defense Requirement | Policy Limit Target |
| :--- | :--- | :--- |
| **Deeply nested JSON** | Enforce maximum nesting depth | ≤ 50 levels |
| **Huge JSON arrays** | Enforce maximum array element count | ≤ 100,000 elements |
| **Huge JSON strings** | Enforce maximum string length per field | ≤ 1 MB per string field |
| **Total output size** | Enforce maximum raw output size before parsing | ≤ 100 MB |
| **Malformed JSON** | Catch decode exceptions, return `PARSER_ERROR` | Controlled error, pipeline continues |
| **Truncated JSON** | Detect incomplete parse, return `PARSER_ERROR` | Never assume complete |
| **Unexpected fields** | Ignore unknown fields; do not fail on extensions | Robust forward compatibility |
| **XML external entities (XXE)** | External entity processing MUST be disabled | Zero external entity resolution |
| **XML DTD / external references** | DTD and external parameter parsing MUST be disabled | Disabled unless safely controlled |
| **XML entity expansion attacks** | Entity expansion attacks (e.g. billion laughs) MUST be prevented | Disabled / strictly bounded |
| **XML parser selection** | Implementation decision subject to dependency/security review | Example candidate: `defusedxml` (not currently installed) |
| **Invalid encoding** | Attempt UTF-8 decode with replacement characters; record warning | Controlled decoding |
| **Path traversal in filenames** | Sanitize via Phase 1D `sanitize_relative_path()` | Reject traversal sequences, absolute paths |
| **Resource exhaustion** | Bounded parsing execution time and resource policy | Target ≤ 60s parsing time limit |

> **NOTE ON PARSER TIMEOUT ENFORCEMENT:**  
> The 60-second limit is a policy limit specification for Phase 2B. Phase 2B MUST implement an enforceable bounded parsing mechanism (e.g. worker isolation or streaming boundaries) rather than relying on un-enforced declarative statements.

---

## 16. Scanner Execution Security

### 16.1 Security Boundary

```
┌─────────────────────────────────────────────────┐
│ UNTRUSTED REPOSITORY (potentially hostile)       │
│ • Malicious filenames, symlinks, zip bombs       │
│ • Hostile code comments, obfuscated crypto       │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│ INPUT VALIDATION & QUARANTINE                    │
│ • Path traversal rejection                       │
│ • Symlink neutralization                         │
│ • Archive size/ratio limits                      │
│ • File count limits                              │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│ ISOLATED SCANNER PROCESS                         │
│ • Non-root execution (unprivileged user)         │
│ • Read-only access to target directory           │
│ • No network access during scan                  │
│ • Ephemeral scratch directory for temp files      │
│ • Environment variable sanitization              │
│ • Direct argument array (shell=False)            │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│ RESOURCE LIMITS                                  │
│ • Execution timeout: 300s default (configurable) │
│ • Memory limit: deployment-configured             │
│ • CPU limit: deployment-configured                │
│ • Temp file cleanup on completion/failure         │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│ RAW OUTPUT (untrusted)                           │
│ → Defensive Parser (Section 15)                  │
│ → EvidenceRecord (sanitized)                     │
└─────────────────────────────────────────────────┘
```

### 16.2 Execution Security Requirements

| Requirement | Classification | Detail |
| :--- | :--- | :--- |
| **No shell interpolation** | REQUIRED | Subprocess invocations MUST use `shell=False` with argument arrays. |
| **Execution timeout** | REQUIRED | Default 300 seconds per scan. Process terminated on timeout. |
| **Unprivileged execution** | REQUIRED (deployment) | Scanner processes MUST NOT execute as root/Administrator. |
| **Read-only target access** | REQUIRED (deployment) | Scanners receive read-only filesystem access to scan targets. |
| **No network access** | REQUIRED (deployment) | Scanners MUST have network access disabled during scanning. |
| **Environment sanitization** | REQUIRED | Only explicitly allowlisted environment variables are propagated. |
| **CLI argument validation** | REQUIRED | Arguments are constructed from strict internal lists, never unsanitized input. |
| **Ephemeral workspace cleanup** | REQUIRED | Temporary scratch directories are deleted immediately upon scan completion or failure. |
| **Process termination** | REQUIRED | On timeout or error, scanner processes and children are terminated. |

---

## 17. Provenance

### 17.1 Provenance Chain

Where raw output is captured and retained, the architecture establishes an unbroken chain of custody:

```
CryptoAsset (Phase 1D / Phase 3)
   │  asset_id = "ecdat:asset:..." (CanonicalAssetKey)
   │  finding_ids = ("finding-1", "finding-2")
   │  correlation_basis = "same_source_statement"
   ▼
Finding (Phase 1D)
   │  finding_id = "finding-1"
   │  evidence_ids = ("cryptoscan:RSA-001-16-34",)
   ▼
EvidenceRecord (Phase 1D / Phase 2)
   │  evidence_id = "cryptoscan:RSA-001-16-34"
   │  scan_id = "scan-uuid-123"
   │  raw_output_ref = "sha256:33d45d3c..."
   │  scanner_category = "Asymmetric Encryption" (verbatim)
   ▼
RawScannerOutput (Phase 2)
   │  stdout_bytes = b'{"summary": ..., "findings": [...]}'
   │  sha256_hash = "33d45d3c..."
   │  scanner_version = "1.4.0"
   │  cli_arguments = ["scan", "/path", "--format", "json"]
   ▼
External Tool Binary (Phase 1C-A)
      path = "product/benchmark/tools/verified/cryptoscan/cryptoscan.exe"
      sha256 = "33d45d3c..."
```

---

## 18. Observability

### 18.1 Minimum Observable Fields

Every scan execution captures structured observability data:

1. `scan_id`: Unique run identifier
2. `adapter_id` & `adapter_version`: Adapter implementation metadata
3. `scanner_name` & `scanner_version`: Validated scanner version
4. `start_time` & `end_time`: High-resolution execution timing
5. `duration_ms`: Total elapsed time
6. `exit_code`: Subprocess exit code
7. `status`: Formal `IngestionStatus`
8. `findings_count`: Total raw findings parsed
9. `evidence_count`: Total `EvidenceRecord` instances emitted
10. `collisions_detected`: Count of native ID collisions resolved
11. `warnings`: Array of operational warnings
12. `errors`: Array of structured `IngestionError` objects

---

## 19. Idempotency

### 19.1 Ingestion Event Identity

Ingestion is idempotent across identical runs. If an identical raw output is re-parsed with an identical adapter version:

- Evidence IDs generated are identical.
- Downstream `Finding` and `CryptoAsset` IDs remain identical.
- Re-running the adapter produces zero duplicate assets in the inventory.

### 19.2 Deduplication Boundary

Deduplication occurs at two distinct architectural boundaries:

1. **Adapter Boundary:** Duplicate native IDs within one scanner output are disambiguated and preserved as distinct `EvidenceRecord` instances.
2. **Correlation Boundary (Phase 1D):** Equivalent findings representing the same source-level statement are merged into a single `CryptoAsset`.

---

## 20. CryptoScan Mapping Design

### 20.1 Scanner Profile

| Property | Value |
| :--- | :--- |
| **Scanner** | CryptoScan |
| **Version** | v1.4.0 (commit `11f0e46`) |
| **Binary** | `cryptoscan.exe` (Windows amd64) |
| **Invocation** | `cryptoscan.exe scan <path> --format json --include-quantum-safe` |
| **Output Format** | JSON |
| **SHA-256** | `33d45d3c...` (verified in Phase 1C-A) |

### 20.2 CryptoScan → EvidenceRecord Mapping

| CryptoScan Field | EvidenceRecord Field | Mapping Rule |
| :--- | :--- | :--- |
| `findings[].id` | `evidence_id` | Validated unique: `"cryptoscan:{id}"`; Colliding: `"cryptoscan:{id}:collision:{idx}"` |
| `findings[].file` | `location.file_path` | Sanitized via `sanitize_relative_path()` |
| `findings[].line` | `location.line_start` | Direct mapping |
| `findings[].endLine` | `location.line_end` | Direct mapping; defaults to `line` |
| `findings[].column` | `location.column_start` | Direct mapping; nullable |
| `findings[].endColumn` | `location.column_end` | Direct mapping; nullable |
| `findings[].context` | `location.matched_text` | Bounded via `sanitize_bounded_string()` |
| `findings[].rawContext` | `location.code_snippet` | Bounded via `bound_code_snippet()` |
| `"cryptoscan"` | `scanner_name` | Constant |
| `"1.4.0"` | `scanner_version` | Constant (validated) |
| (absent in output) | `detection_method` | `DetectionMethod.UNKNOWN` (Capability documents static source scanner; method not emitted) |
| `findings[].ruleId` | `raw_attributes["native_rule_id"]` | Preserved verbatim |
| `findings[].category` | `scanner_category` | **Preserved verbatim** (e.g., "Asymmetric Encryption") |
| `findings[].algorithm` | `raw_attributes["native_algorithm"]` | Preserved verbatim (e.g., "RSA", "ECC") |
| `findings[].primitive` | `raw_attributes["native_primitive"]` | Preserved verbatim (e.g., "pke", "hash") |
| `findings[].severity` | `raw_attributes["native_severity"]` | Preserved verbatim |
| `findings[].confidence` | `scanner_confidence` | Preserved verbatim (e.g., "HIGH", "MEDIUM") |
| `findings[].quantumVulnerable` | `raw_attributes["quantum_vulnerable"]` | Preserved verbatim |
| (derived) | `location.location_type` | `LocationType.SOURCE` |

### 20.3 Known Limitations (from Benchmark)

1. Reports algorithm families (`ECC`) rather than specific algorithms (`ECDSA`, `ECDH`).
2. Matches keywords in comments and docstrings (TC-07, TC-10).
3. Classifies signature algorithms as Certificate category (TC-04).
4. Emits spurious key usage findings on standard JCA calls (TC-05).
5. Misses cryptography encapsulated in helper wrappers (TC-08).
6. Does not detect dynamic cipher constructions (TC-11).

The adapter faithfully captures these observations without attempting to repair scanner deficiencies.

---

## 21. Syft Mapping Design

### 21.1 Scanner Profile

| Property | Value |
| :--- | :--- |
| **Scanner** | Anchore Syft |
| **Version** | v1.51.1 (commit `91a0032`) |
| **Binary** | `syft.exe` (Windows amd64) |
| **Invocation** | `syft.exe scan <path> -o json` |
| **Output Format** | JSON (Syft SBOM format) |
| **SHA-256** | `a0ef681b...` (verified in Phase 1C-A) |
| **Scope** | Dependency manifest / SBOM cataloging ONLY |

### 21.2 Syft → EvidenceRecord Mapping

| Syft Field | EvidenceRecord Field | Mapping Rule |
| :--- | :--- | :--- |
| `artifacts[].id` | `evidence_id` | Validated unique: `"syft:{id}"`; fallback to namespaced PURL |
| `artifacts[].locations[0].path` | `location.file_path` | Sanitized manifest path |
| (N/A) | `location.line_start` | `None` for dependency evidence |
| (N/A) | `location.line_end` | `None` for dependency evidence |
| `artifacts[].purl` | `location.package_coordinate` | Package URL preserved verbatim |
| `"syft"` | `scanner_name` | Constant |
| `"1.51.1"` | `scanner_version` | Constant (validated) |
| `artifacts[].foundBy` | `raw_attributes["cataloger"]` | Preserved (e.g., "java-pom-cataloger") |
| (absent in output) | `detection_method` | `DetectionMethod.UNKNOWN` (Cataloger preserved in raw_attributes; not manufactured) |
| `"dependency"` | `scanner_category` | Fixed: Syft reports package dependencies |
| `artifacts[].name` | `raw_attributes["package_name"]` | Preserved |
| `artifacts[].version` | `raw_attributes["package_version"]` | Preserved |
| `artifacts[].type` | `raw_attributes["package_type"]` | Preserved |
| `artifacts[].purl` | `raw_attributes["purl"]` | Preserved |
| (derived) | `location.location_type` | `LocationType.DEPENDENCY` |

### 21.3 Decoupled Evidence vs. Ingestion Relevance Policy

The core principle governing dependency ingestion is:
$$	extbf{Evidence} 
eq 	extbf{Interpretation} 
eq 	extbf{Filtering Policy}$$

1. **Faithful Observation:** Syft discovers package declarations across project manifests. The adapter creates `EvidenceRecord` instances representing observed packages.
2. **Relevance / Ingestion Policy:** If an deployment requires filtering to manage evidence volume, this filtering MUST be modeled as an explicit, configurable, and observable **ingestion policy**, NOT hidden intrinsic adapter logic:
   - Configurable: May be enabled, modified, or disabled per scan target.
   - Observable: Filtered packages are counted and recorded in scan metadata (e.g. `filtered_packages_count: 142`), never silently discarded.
   - External to Core Semantics: Filtering decisions do not alter ECDAT's core cryptographic domain models.
3. **Strict No-Inference Invariant:** Package names MUST NOT be used to infer algorithm usage:
   $$	ext{Bouncy Castle dependency} 
eq 	ext{AES} 
eq 	ext{RSA} 
eq 	ext{ECDSA}$$
   Syft observations result in `ObservationType.LIBRARY_DEPENDENCY` with `algorithm = UNKNOWN`.

---

## 22. Extensibility

The adapter architecture is designed so that integrating new scanners normally requires no modifications to the existing core domain model. Adding a scanner involves:

1. Implementing the `ScannerAdapter` interface.
2. Registering the adapter in the adapter registry.
3. Mapping scanner-native fields to `EvidenceRecord`.

If a fundamentally new concept arises (e.g., a novel location type beyond the existing 7 types), the core model is extended through deliberate architectural updates rather than ad-hoc adapter workarounds.

---

## 23. ECDAT Ownership Boundary

| Capability | Owner | Rationale |
| :--- | :--- | :--- |
| **Scanner-specific output parsing** | ADAPTER | Scanner-specific syntax knowledge |
| **Scanner-specific native ID handling** | ADAPTER | Namespace isolation and collision resolution |
| **Scanner version validation** | ADAPTER | Pre-execution verification |
| **Subprocess execution** | ADAPTER | Argument construction and execution |
| **Defensive parsing execution** | ADAPTER (using core utilities) | Untrusted payload parsing |
| | | |
| **Evidence Domain Model (`EvidenceRecord`)** | ECDAT CORE | Generic scanner-agnostic schema |
| **Normalization (`NormalizationEngine`)** | ECDAT CORE | Authoritative algorithm resolution |
| **Conservative Correlation (`AssetCorrelationEngine`)** | ECDAT CORE | Strict same-source-statement deduplication |
| **Asset Identity (`CanonicalAssetKey`)** | ECDAT CORE | Deterministic semantic identity |
| **Provenance Tracking** | ECDAT CORE | Unbroken audit trail |
| | | |
| **Relationships & Context** | FUTURE (Phase 4) | Call graphs, object lifecycles |
| **Risk Scoring** | FUTURE (Phase 5) | Quantum risk calculation |
| **PQC Migration Planning** | FUTURE (Phase 6) | FIPS 203/204/205 replacement guidance |
| **User Interface** | FUTURE (Phase 7) | Analyst workflows and dashboards |

### Phase 1D Correlation Boundary Rule

Two scanner observations may correlate in Phase 1D **ONLY** when their evidence supports an equivalent source-level statement under the Phase 1D correlation contract.

> **EXPLICIT CORRELATION RULE:**  
> Dependency evidence (`LocationType.DEPENDENCY`) MUST NOT be treated as equivalent source-statement evidence for Phase 1D correlation merely because the package may contain cryptographic functionality.

---

## 24. Benchmark Integration

Adapters in Phase 2B will be validated against the Phase 1B Seed Corpus (TC-01..TC-11). Ground-truth answer keys remain immutable test oracles:
- Adapters MUST NOT read or consult answer keys at runtime.
- Answer keys are never adjusted to conform to scanner output.
- Performance is scored using the v1.1.0 dual-metric methodology (case-level recall and finding-level precision reported independently with explicit units).

---

## 25. Test Strategy (Phase 2B)

Phase 2B adapter implementations must satisfy the following targeted test suites:

### 25.1 Identity Tests
- **Unique Native ID:** Validates namespaced ID generation when scanner native ID is unique.
- **Duplicate Native ID Collision:** Validates that duplicate native IDs in a single scan are all preserved, collision flags set, distinct collision IDs derived, and collision warnings emitted.
- **Missing Native ID:** Validates deterministic occurrence-aware fallback identity.
- **Identical Source Observations:** Validates that duplicate observations at identical coordinates are both preserved.
- **Occurrence Reordering:** Validates that positional occurrence changes are recognized as observational rather than semantic cross-scan identity changes.
- **Cross-Adapter Namespace Collision:** Proves that identical native IDs across different adapters (`cryptoscan:001` vs `syft:001`) cannot collide.
- **Independence from Asset ID:** Proves that `evidence_id` changes do not affect `CanonicalAssetKey` derivation.

### 25.2 Syft Tests
- **Dependency Evidence Preservation:** Validates accurate translation of manifest dependencies.
- **Non-Cryptographic Package Handling:** Validates that dependencies are ingested faithfully.
- **Relevance Policy Observability:** If an ingestion relevance policy is configured, proves that filtered packages are counted and recorded observably, never silently dropped.
- **No Algorithm Inference:** Validates that package declarations never manufacture algorithm specificity (e.g., Bouncy Castle produces `algorithm = UNKNOWN`).

### 25.3 Detection Method Tests
- **Scanner-Reported Method:** Preserves explicitly emitted detection methods.
- **Documented Capability Method:** Records verified documented cataloger capabilities without confusing them with scanner-reported fields.
- **Unknown Method Default:** Validates that missing or unverified detection mechanisms default strictly to `DetectionMethod.UNKNOWN`.
- **No Assumption-Based Inferences:** Proves that AST analysis and lockfile parsing are not manufactured.

### 25.4 Correlation Boundary Tests
- **Same Source Statement:** Scanners observing the same statement with compatible parameters correlate under Phase 1D rules.
- **Distinct Source Statements:** Observations at different lines or statements do not merge.
- **Dependency vs. Source Separation:** Proves that dependency evidence and source evidence never correlate into the same asset.
- **Parameter Contradictions:** Explicit parameter contradictions (e.g. AES-GCM vs AES-CBC) reject correlation.
- **Rejection of Ambiguity:** Ambiguous findings remain separate assets.

### 25.5 Failure & Containment Tests
- **Orchestrator Exception Containment:** Unexpected adapter exceptions are intercepted at the orchestrator boundary and converted to `IngestionStatus.FAILED` without crashing the pipeline.
- **Parser Timeout Enforcement:** Validates enforcement of bounded parsing execution limits.
- **Parser Resource Limits:** Validates rejection or safe bounding of oversized payloads.
- **Partial Output Capture:** Validates `IngestionStatus.PARTIAL` and scope coverage reporting.
- **Process Failure:** Scanner segfaults and non-zero exits produce `FAILED`, never `NO_FINDINGS`.

### 25.6 Security Tests
- **XML Security Requirements:** External entities disabled, DTD disabled, entity expansion prevented.
- **Deeply Nested JSON:** Payloads exceeding depth limits (50 levels) trigger controlled `PARSER_ERROR`.
- **Oversized Payloads:** Payloads exceeding size limits (100 MB) are rejected before memory exhaustion.
- **Hostile Filenames & Paths:** Path traversal attempts (`../`, absolute paths) are neutralized via sanitization.
- **Direct Subprocess Invocation:** Verified `shell=False` execution with argument arrays.

---

## 26. Security Requirements Summary

| Requirement ID | Requirement Description | Architecture Status |
| :--- | :--- | :--- |
| **SEC-01** | Scanner output is untrusted input | DESIGNED (Section 15) |
| **SEC-02** | No shell interpolation (`shell=False`) | DESIGNED (Section 16) |
| **SEC-03** | Execution timeout enforcement (300s default) | DESIGNED (Section 16) |
| **SEC-04** | Path traversal rejection in scanner output | DESIGNED (Reuses Phase 1D sanitization) |
| **SEC-05** | Bounded string limits on all incoming fields | DESIGNED (Reuses Phase 1D sanitization) |
| **SEC-06** | Code snippet line bounding (5 lines max) | DESIGNED (Reuses Phase 1D sanitization) |
| **SEC-07** | Deep immutability of raw attributes | DESIGNED (Reuses Phase 1D sanitization) |
| **SEC-08** | Enforceable JSON parser depth and size limits | DESIGNED (Section 15, Phase 2B requirement) |
| **SEC-09** | Enforceable XML entity expansion & DTD disablement | DESIGNED (Section 15, Phase 2B requirement) |
| **SEC-10** | Scanner binary hash verification | DESIGNED (Section 7, Lifecycle validation) |
| **SEC-11** | Environment variable sanitization | DESIGNED (Section 16) |
| **SEC-12** | Unprivileged scanner execution | DESIGNED (Deployment requirement, Section 16) |
| **SEC-13** | Network isolation during scan execution | DESIGNED (Deployment requirement, Section 16) |
| **SEC-14** | Read-only target filesystem access | DESIGNED (Deployment requirement, Section 16) |
| **SEC-15** | Ephemeral scratch directory cleanup | DESIGNED (Section 16) |

---

## 27. Open Questions

| # | Question | Impact | Resolution Strategy |
| :--- | :--- | :--- | :--- |
| **OQ-2A-01** | Should the adapter layer support asynchronous / concurrent scanner execution? | Multi-scanner throughput | Defer to Phase 2B. Sequential execution is sufficient for MVP baseline. |
| **OQ-2A-02** | Where should raw scanner output be stored persistently? | Deployment storage architecture | Configurable deployment reference (`raw_output_ref`). Filesystem default for local CLI. |
| **OQ-2A-03** | How should an optional Syft dependency relevance policy be configured? | Ingestion volume control | Define as an optional, observable ingestion configuration outside adapter core semantics. |
| **OQ-2A-04** | Should adapters strictly validate scanner output schemas against specific JSON schemas? | Parser strictness | Recommended: validate mandatory top-level keys; tolerate unexpected non-conflicting fields. |
| **OQ-2A-05** | How should the orchestrator handle scans where all adapters fail? | Error visibility | Return `IngestionStatus.FAILED` with aggregated errors; never report `NO_FINDINGS`. |

---

## 28. Acceptance Criteria

Phase 2A architecture correction pass is accepted when all of the following criteria are verified:

1. ✅ `occurrence_index` is classified as scan-local occurrence disambiguation rather than semantic identity.
2. ✅ Scanner-native IDs are validated for uniqueness within scan output, and collisions are handled defensively and observably.
3. ✅ The Syft allowlist is decoupled from intrinsic adapter semantics; relevance filtering is modeled as an optional, observable ingestion policy.
4. ✅ Detection methods are not manufactured; unverified mechanisms default strictly to `DetectionMethod.UNKNOWN`.
5. ✅ Unexpected adapter exceptions are contained at the orchestrator boundary, preventing unhandled crashes while avoiding absolute "never throw" claims.
6. ✅ XML security requirements are formulated implementation-neutrally without asserting unverified dependencies.
7. ✅ Parser resource and time limits are specified as enforceable Phase 2B requirements.
8. ✅ Temporary scan workspaces are distinguished from persistent source retention, confirming no persistent source storage requirement.
9. ✅ Phase 1D correlation remains strictly conservative same-source-statement deduplication; dependency and source evidence do not merge.
10. ✅ Absolute claims have been audited and replaced with defensible, precise technical formulations.
11. ✅ Benchmark governance (F-01 dual-metric methodology) and answer key immutability are fully maintained.
12. ✅ ZERO production code, adapters, or benchmark modifications were implemented during this pass.

---

## 29. Phase 2B Boundary

Phase 2B (IMPLEMENTATION) will:

1. Implement `ScannerAdapter` abstract base class in `product/core/ingestion/adapter.py`.
2. Implement `CryptoScanAdapter` in `product/core/ingestion/adapters/cryptoscan.py`.
3. Implement `SyftAdapter` in `product/core/ingestion/adapters/syft.py`.
4. Implement `IngestionResult`, `IngestionStatus`, `ScanExecutionMetadata`, and containment orchestrator.
5. Implement defensive JSON parsing with bounded size and depth enforcement.
6. Implement the comprehensive test matrix specified in Section 25.
7. Validate end-to-end ingestion against TC-01..TC-11 seed corpus answer keys.

Phase 2B MUST NOT:
- Implement risk scoring, PQC migration recommendations, or CBOM generation.
- Implement web UI, dashboards, or REST APIs.
- Download external tools or dependencies without explicit authorization.
- Modify benchmark fixtures, answer keys, or historical raw outputs.

---

## Appendix A: Architectural Review Self-Assessment

| # | Question | Architectural Assessment |
| :---: | :--- | :--- |
| 1 | Can a new scanner be integrated without modifying core domain models? | **Yes.** Scanner-specific logic is confined to the adapter; core domain models remain unchanged unless new fundamental types are required. |
| 2 | Can raw scanner evidence be reconstructed from downstream assets? | **Yes.** Where raw output is captured and retained, the provenance chain links assets to raw outputs via hashes and references. |
| 3 | Are scanner-native IDs prevented from corrupting asset IDs? | **Yes.** Native IDs are namespaced and retained in `raw_attributes`; asset IDs derive exclusively from `CanonicalAssetKey`. |
| 4 | Can distinct observations at identical locations remain separated? | **Yes.** Positional occurrence disambiguates findings within a scan output without conflating them with semantic identity. |
| 5 | Can multiple scanners observe the same cryptographic asset? | **Yes.** If scanners observe the same source statement compatibly, Phase 1D correlation groups their findings into a single asset. |
| 6 | Is scanner failure cleanly distinguished from zero findings? | **Yes.** `IngestionStatus.FAILED` represents execution failure; `IngestionStatus.NO_FINDINGS` represents clean scans with zero findings. |
| 7 | Are partial scans prevented from appearing complete? | **Yes.** `IngestionStatus.PARTIAL` explicitly carries scope coverage and failure details. |
| 8 | Can malformed or hostile scanner output be rejected safely? | **Yes.** Defensive parsers enforce bounded limits and catch decode failures, returning `PARSER_ERROR`. |
| 9 | Can untrusted repositories be inspected without compromising the host? | **Yes.** Subprocesses run with direct argument arrays (`shell=False`), execution timeouts, and ephemeral workspace cleanup. |
| 10 | Are CryptoScan-specific fields isolated from the core? | **Yes.** All tool-specific fields are preserved in frozen `raw_attributes`. |
| 11 | Does Syft dependency evidence remain non-cryptographic? | **Yes.** Package coordinates are classified as `LocationType.DEPENDENCY` with `algorithm = UNKNOWN`. |
| 12 | Does normalization retain exclusive responsibility for interpretation? | **Yes.** Adapters translate syntax; normalization assigns canonical identities and roles. |
| 13 | Does the location model accommodate non-source findings? | **Yes.** `EvidenceLocation` natively supports DEPENDENCY, NETWORK, CONTAINER, CERTIFICATE, and BINARY locations. |
| 14 | Is ingestion repeatable without uncontrolled duplicate asset generation? | **Yes.** Idempotent evidence IDs and deterministic `CanonicalAssetKey` asset generation ensure stable inventory state. |
| 15 | Does the architecture preserve uncertainty? | **Yes.** Incomplete evidence, missing parameters, and ambiguous observations are preserved and marked `NEEDS_REVIEW`. |
| 16 | Is specificity manufacture strictly prevented? | **Yes.** Generic scanner categories (e.g. `ECC`) are never upgraded to specific primitives by adapters. |
| 17 | Does benchmark validation preserve test oracle independence? | **Yes.** Answer keys remain immutable test oracles that adapters never consult. |

---

## Appendix B: Self-Adversarial Review

| # | Conceptual Test Case | System Response & Architectural Defense |
| :---: | :--- | :--- |
| **1** | **Duplicate native IDs in single scan** | Scanner emits multiple findings with identical native IDs (e.g. `id="001"`). Adapter validates uniqueness, detects collision, preserves all findings, sets `raw_attributes["native_id_collision"] = True`, derives distinct collision evidence IDs, and records an observable warning in `IngestionResult`. |
| **2** | **Reordered findings between runs** | Scanner reorders findings between Run A and Run B. Where native IDs exist, identity remains stable. Where only positional index is available, the architecture explicitly treats the resulting evidence ID as scan-local disambiguation, avoiding false claims of cross-scan semantic stability. |
| **3** | **Same line / same text / same category multiple observations** | Two distinct cryptographic operations reside on the same line with identical category and text. Tier 4 occurrence disambiguator preserves both as distinct `EvidenceRecord` instances rather than silently collapsing them. |
| **4** | **Scanner-native ID collision across adapters** | CryptoScan and Syft both emit native ID `"001"`. The adapter namespace prefix (`cryptoscan:001` vs `syft:001`) prevents namespace collision in the evidence store. |
| **5** | **Syft dependency vs. source usage** | Syft reports Bouncy Castle; CryptoScan reports AES at line 20. The adapter creates `LocationType.DEPENDENCY` for Syft and `LocationType.SOURCE` for CryptoScan. Downstream Phase 1D correlation strictly rejects cross-location correlation (`LocationType.DEPENDENCY` ≠ `LocationType.SOURCE`), preventing false merging. |
| **6** | **Two source scanners observing same statement** | CryptoScan and Scanner B both report AES on line 20 of `Crypto.java`. Both emit `LocationType.SOURCE`. Downstream Phase 1D correlation evaluates statement equivalence and parameter compatibility, successfully correlating findings into one `CryptoAsset` while preserving both finding IDs. |
| **7** | **Different source statements** | Two findings observe different lines in the same file. Phase 1D correlation evaluates line boundaries and strictly rejects correlation (`different_lines`), preventing false merging. |
| **8** | **Scanner reports no detection method** | Scanner JSON omits detection technique. The adapter assigns `DetectionMethod.UNKNOWN`. Documented capabilities are recorded in adapter metadata but are not manufactured as empirical findings. |
| **9** | **Scanner parser crashes (malformed JSON)** | Scanner emits corrupted, truncated JSON. Defensive parser intercepts `JSONDecodeError`, records `IngestionStatus.PARSER_ERROR`, preserves raw stdout/stderr, and returns cleanly without raising an unhandled exception. |
| **10** | **Unexpected adapter exception** | An unpredicted bug in adapter code raises an unhandled exception. The orchestrator containment boundary intercepts the exception, logs diagnostic details, and records `IngestionStatus.FAILED`, ensuring the overall pipeline remains operational. |
| **11** | **Hostile XML with XXE / entity expansion** | Untrusted XML output contains external entity references or billion-laughs expansion. The architecture specifies mandatory disabling of external entities and DTDs with strict parsing bounds, neutralizing the vector. |
| **12** | **100MB+ oversized scanner output** | Hostile or runaway scanner emits massive output. Input size check detects payload > 100 MB before parsing, aborting with `PARSER_ERROR` before memory exhaustion. |
| **13** | **500-level deeply nested JSON** | Parser encounters recursive JSON nesting designed to trigger stack overflow. Bounded parsing policy enforces depth limit (≤ 50 levels) and rejects payload cleanly. |
| **14** | **Partial scan (20/100 files fail)** | Scanner scans 80 files but errors on 20. The adapter sets `IngestionStatus.PARTIAL`, emits evidence for the 80 files, and records `ScopeCoverage` documenting the 20 failed files. Downstream risk engine is prevented from treating the scan as complete. |
| **15** | **Scanner execution timeout (hang)** | Scanner process deadlocks or hangs. Subprocess runner enforces 300s timeout, terminates process and child trees via `SIGKILL`/`TerminateProcess`, captures partial stderr, and returns `IngestionStatus.TIMEOUT`. |
| **16** | **Temporary source workspace security** | Scanner requires temporary file material during scan. Ephemeral scratch directories are strictly isolated and deleted immediately upon scan termination or failure, preventing persistent source retention. |
| **17** | **Provenance after parser failure** | Parser fails on corrupt output. Raw stdout bytes and execution metadata remain persisted under `RawScannerOutput` with a verifiable SHA-256 hash, enabling retrospective audit and post-mortem debugging. |

---

## Appendix C: No Specificity Manufacture — Worked Examples

### Example 1: CryptoScan reports "ECC"

```
Scanner output:  category="ECC", algorithm="ECC", primitive="pke"
                 ↓
Adapter creates: scanner_category="ECC"
                 detection_method=UNKNOWN
                 raw_attributes={"native_algorithm": "ECC", "native_primitive": "pke"}
                 ↓
Normalizer:      family=EC, algorithm=UNKNOWN
                 (NOT ECDH, NOT ECDSA — no specific evidence)
```

### Example 2: CryptoScan reports CERT-SIGALG-001

```
Scanner output:  ruleId="CERT-SIGALG-001", category="Certificate"
                 ↓
Adapter creates: scanner_category="Certificate"
                 raw_attributes={"native_rule_id": "CERT-SIGALG-001"}
                 ↓
Normalizer:      Examines code evidence to determine actual algorithm
                 (Does NOT blindly accept "Certificate" as the algorithm)
```

### Example 3: Syft reports Bouncy Castle dependency

```
Scanner output:  purl="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"
                 ↓
Adapter creates: scanner_category="dependency"
                 location_type=DEPENDENCY
                 package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"
                 raw_attributes={"purl": "...", "package_name": "bcprov-jdk18on"}
                 ↓
Normalizer:      observation_type=LIBRARY_DEPENDENCY
                 algorithm=UNKNOWN, role=UNKNOWN
                 (Does NOT infer AES, RSA, ECDSA from package name)
```
