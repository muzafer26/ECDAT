# ECDAT / SIH26164 — PHASE 3B FORWARD-COMPATIBILITY GATE REPORT

---

## 1. Architectural Projection Boundary

The relationship between the ECDAT Canonical Domain Model, CBOM Projection, and CycloneDX representation is strictly unidirectional:

$$\begin{matrix}
\text{Discovery Scanners} & \longrightarrow & \text{RawScannerOutput} \\
& & \downarrow \\
& & \text{EvidenceRecord} \quad (\text{Sanitized, immutable empirical facts}) \\
& & \downarrow \\
& & \text{Finding} \quad (\text{Interpreted observation}) \\
& & \downarrow \\
& & \text{CryptoAsset} \quad (\text{Correlated Canonical Domain Entity}) \\
& & \downarrow \\
& & \textbf{CBOM Projection Layer} \quad (\text{Strict non-inference translation}) \\
& & \downarrow \\
& & \text{CycloneDX 1.7 JSON Document} \quad (\textbf{Lossy Serialization Target Only})
\end{matrix}$$

### Authoritative Invariant:
* **CycloneDX output MUST NEVER become an input to canonical ECDAT interpretation.**
* Future pipeline phases (Risk Engine, PQC Migration Engine, Remediation Planner, UI/Dashboard, Compliance Policy Engine) **must consume canonical ECDAT entities** (`CryptoAsset`, `Finding`, `EvidenceRecord`) and their authoritative metadata rather than reverse-interpreting lossy CycloneDX JSON fields.
* CycloneDX 1.7 CBOM is strictly an export format for interoperability, SBOM exchange, and external reporting. It is **not** the internal domain model or the analytical source of truth for ECDAT.

---

## 2. Asset Type Forward Compatibility

The mapping from canonical `AssetType` to CycloneDX `cryptoProperties.assetType` is governed by an explicit, auditable lookup table:

```python
ECDAT_TO_CYCLONEDX_ASSET_TYPE: Dict[AssetType, str] = {
    AssetType.ALGORITHM: "algorithm",
    AssetType.PROTOCOL: "protocol",
    AssetType.CERTIFICATE: "certificate",
    AssetType.CRYPTO_KEY: "related-crypto-material",
}
```

### Forward Compatibility Invariants:
1. **Explicit Mapping Decision Only:** Every supported `AssetType` has an explicit projection decision in `ECDAT_TO_CYCLONEDX_ASSET_TYPE`.
2. **Zero Default to `"algorithm"`:** An unknown, unsupported, or newly added `AssetType` **cannot** automatically fall back or default to `"algorithm"`.
3. **No `.value` Fallback:** The projection method never executes `asset.asset_type.value` as a candidate CycloneDX `assetType`.
4. **Explicit Omission:** For any unmapped or unsupported type (including `LIBRARY_DEPENDENCY`, `UNKNOWN`, or any future enum member), `CBOMProjector.project_asset_type` returns `None`. Consequently, `component["cryptoProperties"]` is completely omitted from the CycloneDX output.
5. **Lossless Domain Preservation:** The canonical `asset_type.value` is faithfully preserved in the standardized extension property array: `{"name": "ecdat:asset_type", "value": asset.asset_type.value}`.
6. **Regression Protection:** Verified by automated regression test `test_31_unsupported_future_asset_type_no_silent_fallback`.

---

## 3. Property-Type Boundary

The CycloneDX 1.7 schema (`bom-1.7.schema.json`) defines distinct property objects under `cryptoProperties`. Phase 3B enforces strict mathematical isolation between these property objects:

| Asset Type | CycloneDX `assetType` | Permitted Property Block | Prohibited Property Block |
|:---|:---|:---|:---|
| **`ALGORITHM`** | `"algorithm"` | `algorithmProperties` (as justified by evidence) | `relatedCryptoMaterialProperties`, `certificateProperties`, `protocolProperties` |
| **`CRYPTO_KEY`** | `"related-crypto-material"` | `relatedCryptoMaterialProperties` only | `algorithmProperties`, `certificateProperties`, `protocolProperties` |
| **`CERTIFICATE`** | `"certificate"` | `certificateProperties` only | `algorithmProperties`, `relatedCryptoMaterialProperties`, `protocolProperties` |
| **`PROTOCOL`** | `"protocol"` | `protocolProperties` only | `algorithmProperties`, `relatedCryptoMaterialProperties`, `certificateProperties` |
| **`LIBRARY_DEPENDENCY`** | *None* (omitted) | *None* (`type: "library"`) | All `cryptoProperties` |
| **`UNKNOWN`** | *None* (omitted) | *None* (`type: "cryptographic-asset"`) | All `cryptoProperties` |

### Structural Enforcement:
[`CBOMValidator.validate_tier1_structure`](file:///d:/SIH/product/core/cbom/validator.py#L131-L138) actively inspects every component:
```python
algo_props = crypto_props.get("algorithmProperties")
if algo_props is not None:
    if asset_type != "algorithm":
        errors.append(
            f"Component '{ref}' has 'algorithmProperties' but assetType is '{asset_type}'; "
            f"'algorithmProperties' is permitted ONLY when assetType is 'algorithm'"
        )
```
No future code path can attach `algorithmProperties: {}` or any algorithm property field to a key, certificate, protocol, library, or unknown asset.

---

## 4. Non-Inference Invariants

The complete `product/core/cbom` package was searched for alternative code paths. All component projection operations route strictly through `CBOMProjector.project_component()`. Zero bypass paths exist.

The following non-inference boundaries are established and regression-tested:

1. **`role` $\rightarrow$ `primitive` = FORBIDDEN:**
   An operational role (e.g. `KEY_AGREEMENT`) alone must never synthesize an algorithm primitive (e.g. `"key-agree"`). Primitives require cryptographic construction evidence.
2. **`role` $\rightarrow$ `cryptoFunctions` = FORBIDDEN:**
   An operational role (e.g. `ENCRYPTION_DECRYPTION`) alone must never synthesize function arrays (e.g. `["encrypt", "decrypt"]`). Functions require source call evidence.
3. **`key_size` $\rightarrow$ `parameterSetIdentifier` = FORBIDDEN:**
   Numerical key sizes (e.g. `256`, `2048`) must never populate `parameterSetIdentifier`. Key sizes route to `ecdat:key_size_bits` and `relatedCryptoMaterialProperties.size`. `parameterSetIdentifier` is strictly reserved for formal named parameter sets (e.g. `ML-KEM-768`, `SHA-256`).
4. **Generic Family $\rightarrow$ Specific Algorithm = FORBIDDEN:**
   Generic families (bare `RSA`, bare `EC`, bare `DH`) must never be narrowed to specific schemes (`RSASSA-PSS`, `ECDSA`, `ECDH`) without explicit evidence.
5. **Dependency/Provider $\rightarrow$ Algorithm Usage = FORBIDDEN:**
   Manifest declaration of a security library (e.g. `bcprov-jdk18on`) proves library presence, **not** algorithm usage. Library capabilities are linked strictly through the `dependency.provides` graph.
6. **`UNKNOWN` $\rightarrow$ Known Algorithm = FORBIDDEN:**
   Unknown names, families, or asset types must never be replaced with guessed algorithms (e.g., guessing `AES` for dynamic calls).
7. **CycloneDX $\rightarrow$ ECDAT Truth = FORBIDDEN:**
   Downstream systems must not treat CycloneDX approximations as ground truth.

---

## 5. UNKNOWN Handling (Semantic B)

* **Semantic Contract:** In canonical ECDAT semantics, `AssetType.UNKNOWN` designates Semantic B: *"A cryptographic usage was observed, but the actual asset type is unknown."* (Distinct from an algorithm of unknown identity, which is `AssetType.ALGORITHM` with `AlgorithmFamily.UNKNOWN`).
* **Projection Rules:**
  - Component `type = "cryptographic-asset"`
  - `cryptoProperties` is **OMITTED** (CycloneDX 1.7 lacks an `unknown` assetType enum; emitting `"algorithm"` would falsely assert algorithm identity).
  - All analytical context is preserved in properties: `ecdat:asset_type = "unknown"`, `ecdat:confidence = "NEEDS_REVIEW"`, `ecdat:correlation_basis`, `ecdat:algorithm_family = "UNKNOWN"`.
* **Downstream Boundary:** Serializers, validators, risk engines, and UI dashboards must maintain `NEEDS_REVIEW` and must not reinterpret `AssetType.UNKNOWN` as a known algorithm.

---

## 6. Library Dependency Handling

* **Semantic Contract:** A library dependency (e.g. BouncyCastle, OpenSSL) is a component that *provides* cryptographic capabilities; it *is not* a cryptographic algorithm.
* **Projection Rules:**
  - Component `type = "library"`
  - PURL populated from package coordinates (`purl = "pkg:maven/..."`)
  - `cryptoProperties` is **OMITTED**.
  - Provides relationships are linked exclusively through the CycloneDX `dependencies[].provides` graph (ADR-012).
* **Downstream Boundary:** If a future AST analysis detects actual algorithm invocation within application code, that usage generates a distinct `AssetType.ALGORITHM` finding/asset linked to the library via `dependency.provides`. Manifest scanning alone never asserts algorithm usage.

---

## 7. Provenance and Traceability

Every projected CBOM component maintains deterministic traceability to its raw empirical origins:

$$\text{Component } (\texttt{bom-ref}) \longrightarrow \texttt{ecdat:asset\_id} \longrightarrow \texttt{ecdat:finding\_ids} \longrightarrow \text{Finding} \longrightarrow \text{EvidenceRecord} \longrightarrow \text{Raw Scanner Output}$$

* **Traceability Fields Projected in CBOM:**
  - `bom-ref`: Deterministic URI `ecdat:asset:{asset_id}` derived via UUIDv5 from canonical domain attributes.
  - `evidence.occurrences[]`: File path, line start, line end, offset (column), and code snippet context.
  - `properties.ecdat:finding_ids`: Comma-separated list of all contributing findings.
  - `properties.ecdat:evidence_ids`: Comma-separated list of all immutable evidence records.
  - `properties.ecdat:scanners`: Provenance list of all discovering tools and versions (`scanner:version`).
  - `properties.ecdat:raw_output_ref`: SHA-256 hash reference linking back to raw scanner JSON output.
* **Known Traceability Bounds:** Code snippets are bounded to a maximum of 500 characters during sanitization to prevent context dumping and memory exhaustion. Raw tool outputs are referenced by content hash, not embedded verbatim in the CBOM.

---

## 8. Future Scanner Compatibility

The Phase 3B projection architecture does not rely on scanner-specific structures:

```
Scanner X Raw Output 
   ↓ (Scanner Adapter)
EvidenceRecord (Generalized Discovery Location, Sanitized)
   ↓ (Finding Normalizer)
Finding (Normalized Algorithm Identity, Parameters, Role)
   ↓ (Correlation Engine)
CryptoAsset (Canonical Domain Entity)
   ↓ (CBOM Projector)
CycloneDX 1.7 CBOM Component
```

* Adding a new scanner (e.g., CodeQL, Semgrep, Trivy, custom AST visitor) requires only implementing a Phase 2A ingestion adapter to map raw scanner output into canonical `EvidenceRecord`s.
* Zero changes are required in the CBOM projection layer when new scanners are onboarded.

---

## 9. Migration and Risk Engine Compatibility

Downstream Risk Analysis (Phase 3C) and Migration Planning (Phase 4) must operate strictly according to the following architectural model:

```
                  ┌──────────────────────────────┐
                  │    Canonical CryptoAsset     │
                  │  (Exact Identity, Parameters,│
                  │   Evidence, Confidence)      │
                  └──────────────┬───────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ CycloneDX 1.7    │   │ Phase 3C         │   │ Phase 4          │
│ CBOM Projector   │   │ Risk Engine      │   │ Migration Planner│
│ (Export Target)  │   │ (Domain-Driven)  │   │ (PQC Engine)     │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

* **Prohibited Pattern:** Reading the emitted CycloneDX CBOM JSON and computing risk from `cryptoProperties.assetType` or `algorithmProperties.primitive`.
* **Required Pattern:** The Risk Engine consumes `CryptoAsset` objects directly. It evaluates raw parameters (`key_size_bits`, `curve_name`, `padding_scheme`), confidence levels (`CONFIRMED`, `NEEDS_REVIEW`), and multi-scanner correlation basis directly from canonical memory or persistent domain storage.

---

## 10. Versioning and Schema Drift Safeguards

| Failure Vector | Architectural Behavior | Fallback Risk |
|:---|:---|:---|
| **CycloneDX Spec Upgrade** (e.g. 1.8) | Schema constants and projection mapping require explicit code updates. | **None:** Unmapped fields fail schema validation or are omitted. |
| **New ECDAT `AssetType` Added** | `project_asset_type` returns `None`. Component emitted as `cryptographic-asset` with `ecdat:asset_type`; no `cryptoProperties`. | **None:** Zero silent fallback to `"algorithm"`. |
| **New Algorithm Family Discovered** | If not in CycloneDX's 93 official families, `project_algorithm_family` returns `None`. Family preserved in `ecdat:algorithm_family`. | **None:** Zero invalid family strings emitted. |
| **New Scanner Reporting New Category** | Normalizes to canonical domain model. CBOM handles standard fields; extensions preserve new attributes. | **None:** Scanner provenance cleanly isolated. |

---

## 11. Validator Boundary

* **Passive Role:** The `CBOMValidator` is strictly an inspection and verification utility. It computes `ValidationResult(is_valid, errors, warnings)`.
* **Zero Mutation:** The validator **never** mutates, enriches, infers, or synthesizes CBOM dictionary contents.
* **Two-Tier Separation:**
  - **Tier 1 (Structural):** Verifies required fields, official enumerations, UUID formats, reference integrity, and property isolation.
  - **Tier 2 (Semantic):** Verifies non-inference invariants, parameter segregation, family non-narrowing, and uncertainty preservation against source assets.

---

## 12. Automated Regression Test Suite Protection

A comprehensive test suite of **168 automated tests** directly verifies every architectural boundary:

| Test Name | Architectural Invariant Protected |
|:---|:---|
| `test_24_asset_type_mappings` | `CRYPTO_KEY` maps to `related-crypto-material`; `UNKNOWN` & `LIBRARY_DEPENDENCY` excluded from mapping; no `algorithmProperties` on keys/certs/protocols. |
| `test_25_library_dependency_not_algorithm_usage` | BouncyCastle dependency evidence alone never becomes algorithm usage; capabilities linked only via `dependency.provides`. |
| `test_26_unknown_preserves_unknown_state` | Dynamic calls with unknown algorithm preserve maximum uncertainty (`primitive="unknown"`, no family, no functions). |
| `test_27_negative_semantic_validations` | Negative validation rejecting forbidden patterns (invalid enum values, generic EC narrowing). |
| `test_28_non_inference_integration` | Role $\neq$ primitive; role $\neq$ cryptoFunctions; key size $\neq$ parameterSetIdentifier. |
| `test_29_non_algorithm_crypto_assets_no_empty_algorithm_properties` | Non-algorithm crypto assets receive strictly their respective property objects; validator rejects injected `algorithmProperties`. |
| `test_30_unknown_asset_type_semantics` | `AssetType.UNKNOWN` represents Semantic B; emits no `cryptoProperties`; preserves `ecdat:asset_type = "unknown"`. |
| `test_31_unsupported_future_asset_type_no_silent_fallback` | Artificial future/unmapped `AssetType` returns `None` and emits no `cryptoProperties` without silent fallback to `"algorithm"`. |

---

## 13. 360° Future Failure Review

| Dimension | Risk Analyzed | Disposition | Architectural Boundary / Action |
|:---|:---|:---|:---|
| **1. New Scanner Adapters** | Incompatible findings attempting to bypass canonical domain model | **KEEP** | Scanners must map strictly to `EvidenceRecord` / `Finding`. |
| **2. Multi-Scanner Correlation** | Scanner conflicts corrupting parameter signatures | **KEEP** | `check_parameter_compatibility()` separates conflicting assets with `ecdat:evidence_conflict = "true"`. |
| **3. Rescans / Temporal Runs** | Run IDs altering asset identity | **KEEP** | `CanonicalAssetKey` is deterministic and location-grounded; independent of run timestamps. |
| **4. Historical Versions** | Schema changes breaking backwards compatibility | **VERIFY LATER** | Evaluate schema migrations during Phase 3C persistence design. |
| **5. Persistence / DB Layer** | Database schema flattening canonical domain objects into CBOM JSON | **REJECT** | Database entities must store canonical `CryptoAsset` models, not CBOM JSON blobs. |
| **6. API Layer** | API endpoints returning lossy CBOM instead of canonical assets | **MODIFY** | Provide dual endpoints: `/api/v1/assets` (canonical) and `/api/v1/cbom/cyclonedx` (export). |
| **7. Risk Engine (Phase 3C)** | Risk calculations performed on lossy CycloneDX JSON | **REJECT** | Risk Engine must consume canonical `CryptoAsset` instances directly. |
| **8. Migration Engine (Phase 4)** | PQC migration paths derived from CycloneDX primitives | **REJECT** | Migration rules must evaluate canonical algorithm identities and key sizes. |
| **9. Dashboard / UI** | UI displaying guessed names instead of `UNKNOWN` / `NEEDS_REVIEW` | **KEEP** | UI must render `ecdat:confidence` and flag uncertain assets prominently. |
| **10. AI Assistance** | LLM generating synthetic parameter sets to satisfy schemas | **REJECT** | LLM suggestions must be marked `SYNTHETIC_SUGGESTION` and require human review. |
| **11. CBOM Import / Ingestion** | Ingesting external CBOMs and assuming internal ground truth | **REJECT** | External CBOMs must be ingested as external evidence, not native canonical truth. |
| **12. CycloneDX Spec Upgrades** | New CycloneDX versions breaking validator enums | **MODIFY** | Versioned validator mappings (`1.7`, `1.8`) in future phases. |
| **13. New AssetTypes** | Future types silently defaulting to `"algorithm"` | **KEEP** | Explicit mapping table returns `None` for unmapped types (verified by `test_31`). |
| **14. New Algorithm Families** | Future PQC families rejected by CycloneDX 1.7 registry | **KEEP** | Registry non-members omitted from CDX field and preserved in `ecdat:algorithm_family`. |
| **15. Tenant Isolation** | Asset UUID namespace collisions across different client workspaces | **VERIFY LATER** | Include workspace/tenant ID in root asset key hashing during Phase 5 multi-tenancy. |
| **16. Untrusted Input** | Malicious source code injecting script payloads into snippet fields | **KEEP** | [`sanitization.py`](file:///d:/SIH/product/core/evidence/sanitization.py) bounds snippets to 500 chars and sanitizes control characters. |

---

## 14. Verification Summary

* **Automated Test Suite:** 168 passing tests (100% pass rate).
* **Benchmark Integrity:** All 11 benchmark fixtures remain SHA-256 byte-identical.
* **Validation Claim:**
  > **Full CycloneDX Draft-07 JSON Schema runtime validation NOT EXECUTED.**  
  > Zero third-party dependencies installed (`jsonschema` not installed). Full runtime schema compliance is not claimed. 168/168 tests establish internal structural, functional, and semantic correctness under ECDAT's offline verification harness.

---

## 15. Final Gate Decision

> **"The current architecture contains explicit boundaries preventing the audited classes of semantic projection errors from silently propagating into downstream phases."**

* **Phase 3B Status:** **FROZEN / APPROVED FOR DOWNSTREAM DEVELOPMENT**
* **Phase 3C Status:** **READY FOR SEPARATE AUTHORIZATION**
* **Implementation Boundary:** Phase 3C implementation has **not** begun. No Phase 3B features were added or redesigned. All changes are limited strictly to forward-compatibility regression verification and gate documentation.
