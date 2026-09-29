# ECDAT Phase 3A — Information Loss Policy & Ledger

**Document Identifier:** ECDAT-POLICY-PHASE-3A-LOSS  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Policy & Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/DECISIONS.md` (ADR-002, ADR-007, ADR-010, ADR-011, ADR-013)
- `product/docs/PHASE_3A_CBOM_ARCHITECTURE.md`
- `product/docs/PHASE_3A_CBOM_PROJECTION_MATRIX.md`
- Official CycloneDX 1.7 JSON Schema (`https://cyclonedx.org/schema/bom-1.7.schema.json`)

---

## 1. Purpose & Guiding Architectural Principle

The primary purpose of this policy is to establish formal, unbreakable governance rules governing how the ECDAT Canonical Domain Model is projected into external Cryptographic Bill of Materials (CBOM) formats, and to specify exact behavior when external schema limitations prevent direct representation.

### The Foundational Asymmetry Principle
$$\text{ECDAT Canonical Domain Model} \supset \text{CycloneDX 1.7 CBOM Projection}$$

The internal ECDAT domain model is **semantically richer, more granular, and more expressive** than any external serialization standard. CycloneDX 1.7 is a standardized transport format for supply chain interoperability; it is **NOT** the internal source of truth.

---

## 2. The Eight Golden Rules of Information Preservation

When projecting from ECDAT domain entities to CycloneDX 1.7 CBOM:

1. **Rule 1 — Never Silently Discard Authoritative Information:**  
   If an ECDAT domain attribute cannot be mapped to a native CycloneDX schema field, it MUST be projected into the standardized `component.properties` or `metadata.properties` array using the `ecdat:` namespace. Silent truncation or dropping of analytical data is strictly forbidden.
2. **Rule 2 — Never Replace Unknown with a Guessed Value:**  
   If a cryptographic parameter, algorithm, key size, or role cannot be determined statically (e.g. dynamic runtime cipher resolution), the CBOM projection MUST serialize `primitive: "unknown"`, `algorithmFamily: "UNKNOWN"`, omit optional parameter fields, and attach `ecdat:confidence = "NEEDS_REVIEW"`. Under no circumstances may an assumed default (e.g. AES-256, 2048-bit key, GCM mode) be fabricated.
3. **Rule 3 — Never Convert Confidence into Certainty:**  
   A finding with confidence `POSSIBLE` or `LIKELY` must not be represented as an indisputable fact in CBOM. Confidence is preserved explicitly in `component.properties` (`ecdat:confidence`).
4. **Rule 4 — Never Convert Review Disposition into Analytical Confidence:**  
   An analyst's disposition (e.g. marking a finding `FALSE_POSITIVE` or `CONFIRMED`) is an operational workflow state, not an automated AST detection confidence. The two fields (`confidence` vs `disposition`) must remain strictly decoupled in the CBOM projection.
5. **Rule 5 — Never Overwrite Original Evidence:**  
   Normalization, correlation, and projection MUST NEVER mutate the underlying `EvidenceRecord` or `RawScannerOutput`. Even if a scanner miscategorizes an algorithm (e.g. labeling Diffie-Hellman as ECC), the original raw category and raw rule IDs are preserved in CBOM properties alongside ECDAT's corrected classification.
6. **Rule 6 — Preserve ECDAT Identifiers and Lineage:**  
   All native ECDAT identifiers (`asset_id`, `finding_ids`, `evidence_ids`, `run_id`, `raw_output_ref`) must be embedded in the projected CBOM to allow bidirectional auditability.
7. **Rule 7 — Document Unavoidable Projection Loss:**  
   Any structural flattening, integer-to-string conversions, or character truncations necessitated by external schema constraints must be formally cataloged in the Information Loss Ledger.
8. **Rule 8 — Maintain Internal Richness:**  
   The external CBOM export is a lossy or adapted projection; internal database, risk, and migration models must never be degraded to match CBOM schema limitations.

---

## 3. Formal Information Loss Ledger

This ledger catalogs every attribute where projection from ECDAT canonical models into CycloneDX 1.7 entails format adaptation, multi-property splitting, or policy-driven truncation:

| # | ECDAT Canonical Entity & Field | CycloneDX 1.7 Representation | Nature of Projection Adaptation | Rationale & Safety Boundary | Information Loss Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **L-01** | `LocationAnchor.line_start` & `line_end` (Multi-line span) | `evidence.occurrences[].line` + `properties.ecdat:line_end` | CycloneDX `occurrence.line` only accepts a single integer. Multi-line end coordinate is moved to `ecdat:line_end`. | Preserves starting coordinate natively for CycloneDX consumers; preserves full span in ECDAT properties. | **NONE (Adapted Representation)** |
| **L-02** | `LocationAnchor.column_start` & `column_end` (Column span) | `evidence.occurrences[].offset` + `properties.ecdat:column_end` | CycloneDX `occurrence.offset` only accepts a single starting offset integer. Ending column moved to `ecdat:column_end`. | Preserves start offset natively; full span preserved in properties. | **NONE (Adapted Representation)** |
| **L-03** | `LocationAnchor.code_snippet` | `evidence.occurrences[].additionalContext` | Truncated to $\le 500$ characters and $\le 10$ lines (ADR-013). | Mitigates data leakage of source code or credentials in public CBOM exports. | **INTENTIONAL (Security Bounding)** |
| **L-04** | `LocationAnchor.matched_text` | `component.properties.ecdat:matched_text` | Truncated to $\le 200$ characters. | Prevents property value explosion on large AST matches. Full text remains in internal database. | **INTENTIONAL (Data Bounding)** |
| **L-05** | `RawScannerOutput.stdout_payload` (Raw scanner bytes) | `component.properties.ecdat:raw_output_ref` | Full verbatim stdout/JSON payload is omitted from CBOM and replaced with `sha256:{hash}` reference. | Prevents CBOM multi-megabyte bloat and IP/secret leakage (ADR-013). Raw bytes remain in quarantined storage. | **INTENTIONAL (Security Isolation)** |
| **L-06** | `EvidenceRecord.raw_payload` (Parsed scanner dict) | *Omitted from CBOM* | Internal scanner AST parse tree dictionary is omitted from CBOM export. | Proprietary scanner AST representations do not belong in public CBOMs. Standardized facts are fully projected. | **INTENTIONAL (Abstraction Boundary)** |
| **L-07** | `CryptoAsset.raw_attributes` (Internal calculation cache) | *Omitted from CBOM* | Intermediate normalization flags and correlation metadata are omitted from CBOM. | Internal execution mechanics are not part of software bill of materials. | **INTENTIONAL (Internal Lifecycle)** |
| **L-08** | `AlgorithmParameters.key_size_bits` (Integer) | `algorithmProperties.parameterSetIdentifier` (String) | Integer converted to string representation (e.g. `2048` $\to$ `"2048"`). Also preserved in `ecdat:key_size_bits`. | CycloneDX schema defines `parameterSetIdentifier` as string type. | **SYNTACTIC (Type Conversion Only)** |
| **L-09** | `CryptoAsset.confidence` & `disposition` | `component.properties.ecdat:confidence` & `ecdat:disposition` | Projected into extension properties because CycloneDX 1.7 lacks native asset-level confidence fields. | CycloneDX `declarations.confidence` is designed for human compliance assertions, not automated static analysis. | **NONE (Extension Preservation)** |
| **L-10** | `CryptoAsset.correlation_basis` | `component.properties.ecdat:correlation_basis` | Explanation string serialized into property extension. | Retains complete mathematical explanation of why findings were merged. | **NONE (Extension Preservation)** |

---

## 4. Policy for Unknown, Ambiguous, and Conflict States

### 1. The Strict Non-Inference Rule (ADR-011)
When static discovery is unable to extract a definitive algorithm or parameter:
- **`algorithm == "UNKNOWN"`:**
  - `component.name`: `"UNKNOWN"`
  - `cryptoProperties.assetType`: `"algorithm"`
  - `algorithmProperties.primitive`: `"unknown"`
  - `algorithmProperties.algorithmFamily`: *Omitted* (as `"UNKNOWN"` is not in `algorithmFamiliesEnum`; authoritative value preserved in `ecdat:algorithm_family = "UNKNOWN"`)
  - `algorithmProperties.parameterSetIdentifier`: *Omitted*
  - `properties`: `[{"name": "ecdat:confidence", "value": "NEEDS_REVIEW"}, {"name": "ecdat:algorithm_family", "value": "UNKNOWN"}]`
- **Rejection of "Helpful Defaults":**
  Under no circumstances may the serializer insert "AES", "SHA-256", "2048", "GCM", or "TLS 1.3" merely because they are common industry standards. Fabricating cryptographic facts in an audit document is considered a critical security defect.

### 2. Multi-Scanner Disagreement
If Scanner A asserts `AES-128` and Scanner B asserts `AES-256` at the same source coordinate:
- The correlation engine rejects merging (`NOT_CORRELATED`).
- Two separate CBOM components are generated:
  - Component 1: `bom-ref: "ecdat:asset:{id1}"`, `name: "AES-128"`, `ecdat:scanners: "scannerA"`
  - Component 2: `bom-ref: "ecdat:asset:{id2}"`, `name: "AES-256"`, `ecdat:scanners: "scannerB"`
- Both components receive the property:
  `{"name": "ecdat:evidence_conflict", "value": "true"}`
- Disagreement is highlighted to human auditors rather than artificially reconciled.

---

## 5. Information Classification Model & Invariants

ECDAT strictly forbids claiming literal "zero information loss" because security bounding and format adaptations intentionally omit or truncate specific data. Instead, ECDAT enforces **Zero Silent Information Loss**:

### The Four-Way Information Classification
1. **Preserved Without Silent Semantic Loss Under the Defined Projection:**
   - Standard cryptographic facts (algorithm, family, key size, curve, mode, padding, location, file, line) map into native CycloneDX fields where empirical evidence establishes the schema-required scheme, or are preserved without silent semantic loss under the defined projection via generic schema fields and `ecdat:` properties.
   - ECDAT analytical and provenance metadata (`confidence`, `disposition`, `correlation_basis`, `finding_ids`, `evidence_ids`, `scanners`, `raw_output_ref`, sub-line coordinates) are preserved without silent semantic loss under the defined projection in standard `properties` under the `ecdat:` namespace.
2. **Intentionally Bounded / Omitted Information (Visible in Ledger):**
   - *L-03 (Code Snippets):* Truncated to $\le 500$ chars, $\le 10$ lines by security policy (ADR-013).
   - *L-04 (Matched Text):* Truncated to $\le 200$ chars in properties.
   - *L-05 (Raw Scanner Output):* Full verbatim stdout omitted; replaced with `sha256:` content hash.
   - *L-06 (Raw AST Parse Dictionaries):* Internal scanner ASTs omitted from public CBOM.
3. **Unsupported Representations (Syntactic Format Adaptations):**
   - *L-01 / L-02 (Spans):* End coordinates moved to properties (`ecdat:line_end`, `ecdat:column_end`) because CycloneDX occurrences only accept a single integer.
   - *L-08 (Key Size):* Integer converted to string representation (`2048` $\to$ `"2048"`).
4. **ECDAT-Only Information (Internal Analysis State):**
   - *L-07 (Calculation Cache):* Intermediate normalization flags and correlation cache dictionaries are kept in memory only.

### Policy Invariants
1. **Authoritative Master:** ECDAT canonical domain models are the immutable master records.
2. **Lossless Recovery:** Every projected CBOM contains sufficient metadata (`ecdat:asset_id`, `ecdat:finding_ids`, `ecdat:raw_output_ref`) to locate the exact source evidence and raw scanner emissions within ECDAT.
3. **Audit Readiness:** External consumers of the CBOM can unambiguously distinguish between verified cryptographic implementations and unverified dynamic patterns requiring human triage.
4. **Visibility Invariant:** Zero information is dropped silently; every omission is an explicit, cataloged ledger entry.
