# ECDAT Phase 3A — CBOM Validation Strategy & Framework

**Document Identifier:** ECDAT-STRAT-PHASE-3A-VALIDATION  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/DECISIONS.md` (ADR-001, ADR-010, ADR-011, ADR-014)
- `product/docs/PHASE_3A_CBOM_ARCHITECTURE.md`
- `product/docs/PHASE_3A_CBOM_PROJECTION_MATRIX.md`
- `product/docs/PHASE_3A_INFORMATION_LOSS_POLICY.md`
- Official CycloneDX 1.7 JSON Schema (`https://cyclonedx.org/schema/bom-1.7.schema.json`)

---

## 1. The Two-Tier Validation Architecture (ADR-014)

Merely validating that an exported CBOM document conforms to a generic JSON Schema does NOT guarantee cryptographic accuracy. A document may be valid JSON according to CycloneDX 1.7 while containing fabricated algorithms, missing key sizes, or hallucinated roles.

ECDAT enforces an explicit **Two-Tier Validation Framework**:

```
                 ECDAT Canonical Domain Model
                              │
                              ▼
                   CBOM Serializer Output
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       Tier 1: Structural            Tier 2: Semantic
       Schema Validation             Preservation Validation
   (JSON Draft-07 Conformance)     (Cryptographic Fact Invariants)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                  Verified Production CBOM
```

---

## 2. Validation Tier Specifications

### Tier 1: Structural Schema Validation
- **Engine:** Standard JSON Schema Draft-07 validator (using Python standard library or offline schema runner).
- **Target Specification:** Official `bom-1.7.schema.json` published by OWASP/CycloneDX.
- **Verification Criteria:**
  1. Root fields `bomFormat == "CycloneDX"`, `specVersion == "1.7"`.
  2. `serialNumber` matches pattern `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.
  3. Every component has required fields: `type` and `name`.
  4. Every component with `cryptoProperties` specifies `assetType` from allowed enum: `['algorithm', 'certificate', 'protocol', 'related-crypto-material']`.
  5. If `assetType == "algorithm"`, all enum fields (`primitive`, `mode`, `padding`, `cryptoFunctions`, `executionEnvironment`, `implementationPlatform`) strictly conform to the allowed schema enum values.
  6. Every `bom-ref` within the CBOM document is globally unique.
  7. All dependencies in `dependencies[]` reference valid `bom-ref` targets that exist within `components[]`.

### Tier 2: Semantic Preservation Validation
- **Engine:** Programmatic comparative test harness comparing the generated CBOM components against the source `CryptoAsset` entities.
- **Verification Criteria:**
  1. **Algorithm Integrity:** If ECDAT establishes `RSA 2048`, the CBOM component MUST serialize `RSA` and `2048`. It MUST NOT serialize `1024`, `4096`, or drop the parameter.
  2. **Role & Non-Inference Integrity:** If ECDAT establishes `DIGITAL_SIGNATURE`, the CBOM primitive MUST be `"signature"` where evidenced (or omitted), and if `cryptoFunctions` is populated it MUST contain `"sign"` or `"verify"` (never synthesized operations, never `"encrypt"` or `"block-cipher"`, and never placeholder `"other"`).
  3. **Zero Hallucination:** If ECDAT establishes `UNKNOWN` algorithm, the CBOM MUST serialize `primitive: "unknown"`, omit `algorithmFamily` from standard fields (preserving `ecdat:algorithm_family = "UNKNOWN"` in properties), and tag `ecdat:confidence = "NEEDS_REVIEW"`. It MUST NOT guess `AES` or `SHA-256`.
  4. **Coordinate Accuracy:** `evidence.occurrences[0]` MUST match `LocationAnchor.file_path`, `line_start`, and `column_start` exactly.
  5. **Parameter Fidelity:** Modes (`GCM`, `CBC`), curves (`secp256r1`), and padding (`PKCS7`, `OAEP`) MUST match source parameters exactly.

---

## 3. Specialized Validation Modules

### 1. Provenance Lineage Validation
Validates that every component in `components[]` contains valid, verifiable references back to the discovery session:
- Verifies that `properties["ecdat:asset_id"]` matches the component's `bom-ref` (`"ecdat:asset:" + asset_id`).
- Verifies that `properties["ecdat:finding_ids"]` contains valid finding UUIDs.
- Verifies that `properties["ecdat:evidence_ids"]` contains valid namespaced evidence IDs.
- Verifies that `properties["ecdat:raw_output_ref"]` matches a valid `sha256:{hex}` string.
- Verifies that `metadata.tools.components` contains all scanners listed in component properties.

### 2. Information-Loss Audit Validation
Validates that the generated CBOM respects the Information Loss Ledger (ADR-010):
- Verifies that zero information is silently discarded (Zero Silent Information Loss).
- Verifies that intentional losses (L-03 snippets $\le 500$, L-04 matched text $\le 200$, L-05 raw stdout bytes, L-06 AST dict) match ledger specifications.
- Verifies that multi-line spans have their end coordinate preserved in `ecdat:line_end`.
- Verifies that verbatim raw stdout bytes are NOT embedded in the document.

### 3. Supply Chain Boundary Validation
Validates that library packages and active code assets are properly segregated (ADR-012):
- Manifest packages (from Syft) MUST be serialized as `type: "library"`.
- Cryptographic algorithms provided by a library MUST be linked via `dependency.provides`.
- Code assets invoked by application source MUST be linked via `dependency.dependsOn`.
- Verifies that library presence does not create false active code assets.

### 4. Malformed Input & Defensive Parsing Validation
Validates serializer resilience:
- Serializer MUST cleanly reject non-standard characters, dangerous control characters, or unescaped JSON delimiters.
- Missing optional parameters MUST result in clean field omission, NEVER in `null`, `undefined`, or empty string schema violations.
- Null or negative line coordinates MUST be sanitized or rejected with structured error codes.

---

## 4. Phase 3 Test Plan & Automated Test Cases

The following test suites will be implemented in Phase 3C to execute this validation strategy:

| Test Suite File | Focus Area | Target Test Cases |
| :--- | :--- | :--- |
| `product/tests/test_cbom_schema.py` | Structural JSON Schema compliance against official draft-07 schema. | Validates syntax, required fields, enum memberships, and unique `bom-ref` constraints across all seed cases (TC-01..TC-11). |
| `product/tests/test_cbom_semantic_preservation.py` | Semantic cryptographic fact preservation. | Verifies exact preservation of RSA, AES, ECC, Ed25519, SHA-1, dynamic UNKNOWN, and dependency non-inference across TC-01..TC-11. |
| `product/tests/test_cbom_provenance.py` | Multi-tier lineage and tool attribution. | Verifies unbroken provenance links from CBOM component to raw output SHA-256 and multi-scanner metadata. |
| `product/tests/test_cbom_information_loss.py` | Verification against Information Loss Ledger. | Verifies zero silent discarding, explicit intentional loss classification, and proper property extension population. |
| `product/tests/test_cbom_adversarial.py` | Adversarial edge cases and stress testing. | Verifies resilience against scanner disagreement, duplicate raw outputs, malformed fields, and extreme inputs. |

---

## 5. Acceptance Criteria for Phase 3 Validation

A generated CBOM is accepted as production-grade if and only if:
1. **Tier 1 Pass:** 100% compliant with `bom-1.7.schema.json` with zero schema validation errors.
2. **Tier 2 Pass:** 100% semantic agreement with underlying `CryptoAsset` inventory.
3. **Provenance Complete:** Every component traces deterministically to an evidence record and raw output hash.
4. **Zero Fabrication:** Zero guessed algorithms or parameters.
