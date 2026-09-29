# ECDAT Phase 3A — Adversarial Scenarios & Boundary Ledger

**Document Identifier:** ECDAT-SPEC-PHASE-3A-ADVERSARIAL  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/DECISIONS.md` (ADR-007 through ADR-015)
- `product/docs/PHASE_3A_CBOM_ARCHITECTURE.md`
- `product/docs/PHASE_3A_CBOM_PROJECTION_MATRIX.md`
- `product/docs/PHASE_3A_INFORMATION_LOSS_POLICY.md`
- `product/docs/PRE_3A_DOMAIN_RUN_CONTRACT_GATE.md`

---

## 1. Purpose & Adversarial Methodology

Static analysis and CBOM generation frequently encounter edge cases, noisy scanner outputs, malformed syntax, dynamic languages, and conflicting evidence. If a tool fails to anticipate these conditions, it produces corrupt CBOMs, hallucinated facts, or silent security omissions.

This ledger defines **twenty design-level adversarial scenarios**, specifying the exact expected CBOM projection behavior, failure modes prevented, and verification criteria for each.

---

## 2. Adversarial Scenarios Ledger

### Scenario 1: Two Findings for Same Asset with Different Native IDs
- **Context:** Scanner rules (e.g. `rule-weak-rsa` and `rule-insecure-key-length`) or different tools emit separate observations with distinct `native_finding_id`s for the exact same statement (`RSA.generate(1024)` on line 45).
- **Domain Behavior:** `AssetCorrelationEngine` identifies identical file, line, overlapping columns, algorithm family, and compatible parameters. It performs same-source-statement deduplication, creating a single `CryptoAsset`.
- **Expected CBOM Representation:** Exactly ONE CBOM component (`type: "cryptographic-asset"`, `name: "RSA-1024"`). Its properties record both finding and evidence IDs: `ecdat:finding_ids = "f1,f2"`, `ecdat:native_finding_ids = "rule-weak-rsa,rule-insecure-key-length"`.
- **Failure Mode Prevented:** Duplicate component emission in CBOM, artificially inflating cryptographic asset counts.

### Scenario 2: Two Different Assets on the Same File and Line
- **Context:** Multiple distinct cipher initializations occur on a single source line (e.g. `Cipher c1 = Cipher.getInstance("AES/GCM"); Cipher c2 = Cipher.getInstance("RSA/ECB");`).
- **Domain Behavior:** `AssetCorrelationEngine` evaluates column boundaries or distinct variable assignments (`c1 = ...` vs `c2 = ...`) and detects conflicting algorithm families (`AES` vs `RSA`). Correlation returns `NOT_CORRELATED`.
- **Expected CBOM Representation:** TWO distinct CBOM components with unique `bom-ref`s: one for `AES-GCM` and one for `RSA-ECB`. Both record line 45 but contain distinct sub-line column spans in `offset` and `ecdat:column_end`.
- **Failure Mode Prevented:** Unsafe merging of distinct algorithms on the same line into a corrupted composite asset.

### Scenario 3: Same Asset Discovered by Two Scanners (Multi-Scanner Agreement)
- **Context:** CryptoScan and a future scanner both detect `AES-256-CBC` on `Crypto.java:88` with identical parameters.
- **Domain Behavior:** Both evidence records merge into a single `CryptoAsset`.
- **Expected CBOM Representation:** Exactly ONE CBOM component. `metadata.tools.components` lists both scanners. `component.properties` records: `ecdat:scanners = "cryptoscan:1.4.0,scannerB:2.0.0"`.
- **Failure Mode Prevented:** Duplicate assets or losing scanner attribution in multi-scanner pipelines.

### Scenario 4: Scanner Disagreement / Contradictory Parameters
- **Context:** Scanner A reports `RSA-1024` and Scanner B reports `RSA-2048` at the exact same location.
- **Domain Behavior:** `check_parameter_compatibility()` detects explicit parameter conflict ($1024 \neq 2048$) and returns `NOT_CORRELATED`.
- **Expected CBOM Representation:** TWO distinct CBOM components (`RSA-1024` and `RSA-2048`), each with property `ecdat:evidence_conflict = "true"` and recording its respective scanner provenance.
- **Failure Mode Prevented:** Arbitrarily picking one scanner's output or silently overwriting contradictory evidence.

### Scenario 5: Dynamic / Unknown Algorithm Call
- **Context:** Source code invokes `Cipher.getInstance(runtimeVariable)`.
- **Domain Behavior:** Normalized to `family: UNKNOWN`, `algorithm: "UNKNOWN"`, `confidence: NEEDS_REVIEW`.
- **Expected CBOM Representation:** A valid CBOM component with `name: "UNKNOWN"`, `cryptoProperties.assetType: "algorithm"`, `algorithmProperties.primitive: "unknown"`, `algorithmProperties.algorithmFamily` omitted (since `"UNKNOWN"` is not in `algorithmFamiliesEnum`), optional parameter fields omitted, and properties `ecdat:confidence = "NEEDS_REVIEW"` and `ecdat:algorithm_family = "UNKNOWN"`.
- **Failure Mode Prevented:** Fabricating a standard algorithm (e.g. guessing AES) to satisfy schema constraints, or emitting an unlisted family string that violates `cryptography-defs.schema.json`.

### Scenario 6: Unknown Role / Function
- **Context:** A custom wrapper initializes a key object whose purpose (encryption vs signing vs key agreement) cannot be inferred statically.
- **Domain Behavior:** `CryptoAsset.role = CryptographicRole.UNKNOWN`.
- **Expected CBOM Representation:** `algorithmProperties.cryptoFunctions` contains `["unknown"]` or is omitted. Property `ecdat:role = "UNKNOWN"` is attached.
- **Failure Mode Prevented:** Guessing a cryptographic role and triggering incorrect PQC migration mapping.

### Scenario 7: Conflicting Algorithm Families
- **Context:** Heuristic scanner flags a statement as both `HASH` (SHA-256) and `SIGNATURE` (ECDSA) due to overlapping regex rules.
- **Domain Behavior:** Correlation rejects merging due to conflicting algorithm families. Distinct findings remain separate.
- **Expected CBOM Representation:** Separate CBOM components with explicit provenance and `NEEDS_REVIEW` confidence.
- **Failure Mode Prevented:** Conflating a hash function with an asymmetric signature scheme.

### Scenario 8: Duplicate Raw Output Ingestion
- **Context:** The identical raw scanner JSON stdout is ingested twice into the same analysis pipeline.
- **Domain Behavior:** `RawScannerOutput.from_bytes()` generates the identical SHA-256 hash. Ingestion is idempotent; normalized findings and asset identities remain byte-identical.
- **Expected CBOM Representation:** Idempotent CBOM generation. Identical components, identical `bom-ref`s, zero duplicate entries.
- **Failure Mode Prevented:** Generating duplicate components or differing serial numbers when re-exporting identical data.

### Scenario 9: Identical Target Content Scanned in Different Runs
- **Context:** The exact same codebase snapshot is scanned in Run 1 (Monday) and Run 2 (Tuesday).
- **Domain Behavior:** Run IDs differ (`run_id_1 != run_id_2`), but `CanonicalAssetKey` produces identical `asset_id`s for all code assets.
- **Expected CBOM Representation:** The two CBOMs have distinct root `serialNumber`s and timestamps, but all component `bom-ref`s (`ecdat:asset:{asset_id}`) are 100% identical.
- **Failure Mode Prevented:** Non-deterministic `bom-ref` generation breaking diff engines and tracking across scans.

### Scenario 10: Code Refactoring / Location Shift
- **Context:** A developer adds 10 lines of comments above a cipher initialization, shifting its location from line 45 to line 55.
- **Domain Behavior:** `asset_id` changes because coordinates shifted. (Cross-commit AST tracking is deferred to Phase 9).
- **Expected CBOM Representation:** A valid CBOM component reflecting line 55. No claim of historical continuity is made in Phase 3A.
- **Failure Mode Prevented:** Making false claims of refactoring-proof historical identity before Phase 9 diff engine implementation.

### Scenario 11: Dependency Manifest with No Code Invocation (TC-09)
- **Context:** A project imports Bouncy Castle (`bcprov-jdk18on`) in its `pom.xml`, but application source code never invokes any Bouncy Castle APIs.
- **Domain Behavior:** Syft normalizes the package as `AssetType.LIBRARY_DEPENDENCY` with `family: UNKNOWN`. Correlation never merges it with code assets.
- **Expected CBOM Representation:** A component with `type: "library"`, `name: "bcprov-jdk18on"`, and valid `purl`. In `dependencies[]`, the library component lists its declared capabilities in `provides: []`, but the application root component does NOT list active usage in `dependsOn: []`. Zero code cryptographic assets are fabricated.
- **Failure Mode Prevented:** Deceptive false positives claiming that 50+ algorithms are active simply because a jar file exists in the classpath.

### Scenario 12: Certificate Discovered Without Associated Private Key
- **Context:** A TLS certificate (`server.crt`) is found in resources, but no corresponding private key file exists.
- **Domain Behavior:** Normalized as `AssetType.CERTIFICATE`. No key asset is created.
- **Expected CBOM Representation:** A component with `cryptoProperties.assetType: "certificate"` and populated `certificateProperties` (subject, issuer, dates). `relatedCryptoMaterialProperties` is omitted.
- **Failure Mode Prevented:** Fabricating a private key component when only a public certificate was observed.

### Scenario 13: Key Configuration Reference Without Key Material
- **Context:** Source code specifies a key alias or keystore path (`keyStore.getKey("my-key")`), but no key material bytes are visible.
- **Domain Behavior:** Normalized as `AssetType.KEY` with `parameters.key_size_bits = None`.
- **Expected CBOM Representation:** Component with `cryptoProperties.assetType: "related-crypto-material"`, `type: "secret-key"`, and key size omitted. No key bytes are exported.
- **Failure Mode Prevented:** Hallucinating key sizes or attempting to extract non-existent key bytes.

### Scenario 14: Malformed Scanner Field / Schema Type Mismatch
- **Context:** Scanner outputs a string `"twenty-forty-eight"` or negative number `-1` for key length.
- **Domain Behavior:** Defensive parsing and dataclass sanitization in Phase 2B reject invalid integer conversion and set `key_size_bits = None`.
- **Expected CBOM Representation:** `parameterSetIdentifier` is omitted from `algorithmProperties`; property `ecdat:raw_key_size = "twenty-forty-eight"` is retained. CBOM remains structurally valid under CycloneDX 1.7 specifications.
- **Failure Mode Prevented:** Emitting invalid types into CycloneDX JSON, causing external schema validation failures.

### Scenario 15: Unsupported CycloneDX 1.7 Field Encountered
- **Context:** An ECDAT-specific analysis metric (e.g. quantum Shor vulnerability score or PQC migration priority queue rank) has no native field in CycloneDX 1.7.
- **Domain Behavior:** Mapped into `component.properties` under the `ecdat:` namespace (ADR-010).
- **Expected CBOM Representation:** Document conforms strictly to `bom-1.7.schema.json` while retaining the metric in standardized name-value property pairs.
- **Failure Mode Prevented:** Adding unrecognized top-level JSON fields that fail official CycloneDX schema validation.

### Scenario 16: Sensitive Evidence Redaction Boundary (ADR-013)
- **Context:** A scanner captures an entire source file containing proprietary business logic and high-entropy authentication tokens in its raw output.
- **Domain Behavior:** Code snippet is capped at $\le 500$ characters and $\le 10$ lines via `bound_code_snippet()`. Raw scanner stdout is quarantined internally.
- **Security Claim Classification:**
  - *IMPLEMENTED & VERIFIED:* Snippet bounding ($\le 500$ chars, $\le 10$ lines) and string sanitization are verified in `test_security.py`.
  - *DESIGN REQUIREMENT:* Raw scanner stdout payloads and AST parse trees MUST NOT be embedded in public CBOMs.
  - *FUTURE VERIFICATION:* Actual serializer output must be tested against sensitive fixtures during Phase 3B/3C to verify absence of secrets. Secret redaction is formally NOT IMPLEMENTED in Phase 2B/3A.
- **Expected CBOM Representation:** `evidence.occurrences[0].additionalContext` contains only the bounded snippet. The raw output is referenced solely by `ecdat:raw_output_ref = "sha256:..."`.
- **Failure Mode Prevented:** Data exfiltration or intellectual property leakage via public CBOM exports.

### Scenario 17: Partial Scan Scope Coverage
- **Context:** A scanner aborts halfway through scanning due to an out-of-memory error on a large file, reporting partial scope.
- **Domain Behavior:** Scanner execution returns `IngestionStatus.PARTIAL`.
- **Expected CBOM Representation:** CBOM is generated containing all valid findings discovered prior to the abort, but `metadata.properties` explicitly includes:
  `{"name": "ecdat:ingestion_status", "value": "PARTIAL"}` and records processed vs skipped file counts.
- **Failure Mode Prevented:** Presenting an incomplete scan as a complete, clean audit report.

### Scenario 18: Scanner Execution Failure (Tool Crash)
- **Context:** A scanner binary crashes or encounters a segmentation fault with zero findings emitted.
- **Domain Behavior:** `IngestionStatus.FAILED` is recorded in the execution contract.
- **Expected CBOM Representation:** Distinct from a clean scan with zero findings. If a CBOM is requested, `metadata.properties` records:
  `{"name": "ecdat:scanner_status", "value": "FAILED"}`.
- **Failure Mode Prevented:** Conflating tool crashes with a clean codebase containing no cryptographic vulnerabilities.

### Scenario 19: Clean Target Codebase with Zero Findings (TC-08 / TC-11)
- **Context:** A codebase containing no cryptographic calls (or wrapper-blindness fixtures where static rules find nothing) is scanned.
- **Domain Behavior:** Ingestion returns `IngestionStatus.NO_FINDINGS` with empty evidence list.
- **Expected CBOM Representation:** A valid CycloneDX 1.7 CBOM document with `components: []`, valid metadata, timestamp, tool entries, and property:
  `{"name": "ecdat:ingestion_status", "value": "NO_FINDINGS"}`.
- **Failure Mode Prevented:** Crashing serializer on empty component list or claiming execution failure when the scan succeeded cleanly.

### Scenario 20: Ambiguous Same-Line Findings
- **Context:** Multiple complex macro expansions or chained calls on a single line produce ambiguous text extracts where sub-line boundaries cannot be cleanly proven.
- **Domain Behavior:** Correlation returns `CorrelationDecision.AMBIGUOUS`. The findings are NOT merged.
- **Expected CBOM Representation:** Two separate CBOM components with property `ecdat:confidence = "NEEDS_REVIEW"` and `ecdat:correlation_basis = "ambiguous_same_line_expressions"`.
- **Failure Mode Prevented:** Speculative merging of potentially separate cryptographic operations.

---

## 3. Summary of Adversarial Guarantees

1. **Structural Alignment:** In all twenty adversarial cases, the exported CBOM conforms to structural and semantic constraints aligned with the official `bom-1.7.schema.json` specification.
2. **Semantic Fidelity:** No case results in fabricated algorithms, hallucinated parameters, or false certainties.
3. **Audit Transparency:** Every anomaly, conflict, or partial state is explicitly documented in standard `properties` extensions for human reviewer inspection.
