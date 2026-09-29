# ECDAT / SIH26164 — PHASE 3B FINAL CBOM PROJECTION INTEGRITY REPORT

---

## 1. Defects Found

| ID | Severity | Finding | Root Cause | Status |
|:---|:---------|:--------|:-----------|:-------|
| **DEF-01** | **HIGH** | `AssetType.CRYPTO_KEY` emitted `"crypto_key"` — invalid CycloneDX enum | `asset_type.value` fallback used `.value` instead of explicit mapping | **FIXED (prior pass)** |
| **DEF-02** | **HIGH** | `AssetType.LIBRARY_DEPENDENCY` emitted `cryptoProperties.assetType: "algorithm"` — falsely asserting a library IS an algorithm | Missing semantic boundary: library provider presence ≠ algorithm usage. `LIBRARY_DEPENDENCY` was in the mapping table as `"algorithm"`. | **FIXED (this pass)** |
| **DEF-03** | **DOCUMENTED** | `AssetType.UNKNOWN` maps to `assetType: "algorithm"` — CycloneDX has no `"unknown"` assetType | Schema limitation. Not fixable without CycloneDX spec change. | **DOCUMENTED SEMANTIC APPROXIMATION** |

---

## 2. Exact Fixes Applied

### Fix 1: LIBRARY_DEPENDENCY Projection (DEF-02)
**File:** [`projection.py`](file:///d:/SIH/product/core/cbom/projection.py)

- **Removed** `AssetType.LIBRARY_DEPENDENCY` from `ECDAT_TO_CYCLONEDX_ASSET_TYPE` mapping table
- **Modified** `project_component()` to skip `cryptoProperties` entirely when `asset.asset_type == AssetType.LIBRARY_DEPENDENCY`
- Library components retain: `type: "library"`, `name`, `bom-ref`, `purl`, `evidence`, `properties` (with full ECDAT metadata)
- Library capabilities remain linked through `dependency.provides` graph (ADR-012)

### Fix 2: Regression Tests Added
**File:** [`test_cbom_projection.py`](file:///d:/SIH/product/tests/test_cbom_projection.py)

- **test_24** — Updated: LIBRARY_DEPENDENCY now asserts `assertNotIn("cryptoProperties", comp_lib)`
- **test_25** — NEW: BouncyCastle dependency evidence alone ≠ algorithm usage (full BOM + dependency graph)
- **test_26** — NEW: UNKNOWN preserves unknown state (no family, no functions, no params, primitive=unknown)
- **test_27** — NEW: Negative semantic validations (invalid enums, generic EC/DH/RSA non-narrowing, role ≠ primitive)
- **test_28** — NEW: Non-inference audit integration (role ≠ cryptoFunctions, key_size ≠ parameterSetIdentifier)

---

## 3. Complete AssetType Mapping Table

| ECDAT AssetType | CycloneDX `assetType` | Classification | Semantic Justification | Crypto Meaning Introduced? | Test Coverage |
|:----------------|:---------------------|:---------------|:-----------------------|:--------------------------|:-------------|
| `ALGORITHM` | `"algorithm"` | **Exact 1:1** | Direct schema correspondence. Algorithm is an algorithm. | No | test_01–test_22 |
| `PROTOCOL` | `"protocol"` | **Exact 1:1** | Direct schema correspondence. Protocol is a protocol. | No | test_24 |
| `CERTIFICATE` | `"certificate"` | **Exact 1:1** | Direct schema correspondence. Certificate is a certificate. | No | test_24 |
| `CRYPTO_KEY` | `"related-crypto-material"` | **Exact** | Official CycloneDX enum for keys, tokens, secrets. `relatedCryptoMaterialProperties.type = "key"` is set. `size` is populated from `key_size_bits` when present. | No — key IS crypto material | test_24 |
| `LIBRARY_DEPENDENCY` | **OMITTED** (no `cryptoProperties`) | **Omitted** | A library provider IS NOT an algorithm. Setting `assetType: "algorithm"` would falsely assert algorithm usage. Component is `type: "library"` with PURL. Capabilities linked via `dependency.provides`. | **Prevented** — omission avoids false assertion | test_24, test_25 |
| `UNKNOWN` | `"algorithm"` | **Documented Approximation** | CycloneDX has no `assetType: "unknown"`. `"algorithm"` is the closest container because the unknown finding IS from crypto API usage (e.g. `Cipher.getInstance(var)`). ALL other fields signal uncertainty: `primitive: "unknown"`, no family, no functions, no params, `ecdat:confidence = "NEEDS_REVIEW"`. | **Approximation documented** — no specific algorithm is claimed | test_12, test_26, test_27 |

---

## 4. Dependency Mapping Justification

**Invariant:** `dependency/provider presence ≠ algorithm usage`

**Previous behavior (DEFECTIVE):** BouncyCastle → `cryptoProperties.assetType: "algorithm"` — This explicitly asserted the library IS an algorithm, violating the invariant.

**Fixed behavior:** BouncyCastle → `type: "library"`, no `cryptoProperties`, PURL preserved, capabilities linked through `dependency.provides` graph only. A CBOM consumer parsing this component will correctly see it as a library, not as a discovered algorithm.

**Proof:** `test_25_library_dependency_not_algorithm_usage` creates a BouncyCastle library asset and an AES algorithm asset, links them via `dependency.provides`, and asserts:
1. Library component has `type: "library"` ✓
2. Library component has NO `cryptoProperties` ✓
3. Library component preserves PURL ✓
4. Algorithm component DOES have `cryptoProperties.assetType: "algorithm"` ✓
5. Dependency graph correctly links library → provides → algorithm ✓
6. Full two-tier validation passes ✓

---

## 5. UNKNOWN Mapping Justification

**Invariant:** `UNKNOWN must remain UNKNOWN`

**Current behavior:** `AssetType.UNKNOWN` → `cryptoProperties.assetType: "algorithm"` with ALL fields maximally uncertain.

**Justification:** CycloneDX 1.7 `cryptoProperties.assetType` enum has exactly 4 values: `["algorithm", "certificate", "protocol", "related-crypto-material"]`. There is no `"unknown"` value. Since UNKNOWN findings originate from crypto API usage (e.g. `Cipher.getInstance(algoVariable)`), the finding IS crypto-related. `"algorithm"` is the closest safe container. The semantic distortion is mitigated by:
- `component.name = "UNKNOWN"` (not a specific algorithm name)
- `algorithmProperties.primitive = "unknown"` (not a specific construction)
- `algorithmFamily` is OMITTED (not narrowed)
- `cryptoFunctions` is OMITTED (not synthesized)
- `parameterSetIdentifier` is OMITTED
- `ecdat:confidence = "NEEDS_REVIEW"` signals manual review required
- `ecdat:role = "unknown"` preserves the unknown state

**This is a DOCUMENTED SEMANTIC APPROXIMATION, not a claim of specific algorithm knowledge.**

**Proof:** `test_26_unknown_preserves_unknown_state` explicitly verifies all 10 conditions above.

---

## 6. Non-Inference Audit

### Code Paths Checked

| Forbidden Pattern | Code Path Inspected | Status |
|:------------------|:-------------------|:-------|
| role → primitive | [`projection.py:168-256`](file:///d:/SIH/product/core/cbom/projection.py#L168-L256): `project_primitive()` checks `algo_upper`, `mode_upper`, `family` — never reads `asset.role` | **SAFE** |
| role → cryptoFunctions | [`projection.py:258-304`](file:///d:/SIH/product/core/cbom/projection.py#L258-L304): `project_crypto_functions()` checks `combined_text` from evidence — never reads `asset.role` | **SAFE** |
| key_size → parameterSetIdentifier | [`projection.py:306-343`](file:///d:/SIH/product/core/cbom/projection.py#L306-L343): `project_parameter_set_identifier()` checks `algo_upper`, `variant`, `family` — never reads `asset.parameters.key_size_bits` | **SAFE** |
| family → specific algorithm without evidence | [`projection.py:82-154`](file:///d:/SIH/product/core/cbom/projection.py#L82-L154): RSA (line 119-120), EC (line 130-131), DH (line 138-139), Edwards (line 146-147) all return `None` for generic cases | **SAFE** |
| dependency → algorithm usage | [`projection.py:449-451`](file:///d:/SIH/product/core/cbom/projection.py#L449-L451): `if asset.asset_type != AssetType.LIBRARY_DEPENDENCY` — libraries skip `cryptoProperties` entirely | **SAFE** |
| UNKNOWN → known algorithm | [`projection.py:82-154`](file:///d:/SIH/product/core/cbom/projection.py#L82-L154): UNKNOWN family returns `None` for algorithmFamily; [`projection.py:252-253`](file:///d:/SIH/product/core/cbom/projection.py#L252-L253): returns `"unknown"` for primitive | **SAFE** |
| generic EC → ECDSA/ECDH/ECIES | [`projection.py:122-131`](file:///d:/SIH/product/core/cbom/projection.py#L122-L131): Only maps when "ECDSA"/"ECDH"/"ECIES" is in `algo_upper`, else returns `None` | **SAFE** |
| generic DH → ECDH | [`projection.py:133-139`](file:///d:/SIH/product/core/cbom/projection.py#L133-L139): Only maps when "FFDH"/"ECDH" is in `algo_upper`, else returns `None` | **SAFE** |
| generic RSA → scheme | [`projection.py:105-120`](file:///d:/SIH/product/core/cbom/projection.py#L105-L120): Only maps when "PSS"/"OAEP"/"PKCS1"/scheme is explicit in `algo_upper` or `padding_upper` | **SAFE** |
| operation inferred from asset type | No code path reads `asset.asset_type` to determine primitive, functions, family, or parameters | **SAFE** |
| CycloneDX → ECDAT ground truth | Projection is strictly unidirectional. No code reads CycloneDX output back into domain models | **SAFE** |

### Validator Non-Inference Guards

[`validator.py:222-268`](file:///d:/SIH/product/core/cbom/validator.py#L222-L268) — Tier 2 semantic validation enforces:
- `primitive="ae"` requires authenticated encryption evidence (line 227-231)
- `cryptoFunctions` must not contain `"other"` (line 234-238)
- `cryptoFunctions` must not be synthesized from role (line 240-244)
- `parameterSetIdentifier` must not be a curve, mode, or RSA key size (line 246-257)
- Generic RSA/EC must not be narrowed without scheme evidence (line 259-268)
- UNKNOWN algorithm name must be preserved (line 270-273)

---

## 7. Schema Reachability Analysis

### Definitions

- **A. Schema Dependency:** `bom-1.7.schema.json` references 4 external schemas via `$ref`
- **B. Reachable Schema Branch:** A subset of schema definitions that would be traversed during validation of a specific document structure
- **C. Currently Generated ECDAT Structure:** The exact JSON structures ECDAT currently emits

### Analysis

`bom-1.7.schema.json` (327,398 bytes) contains 358 `$ref` expressions. Of these, exactly 4 reference external files:

| External `$ref` | Local Status | Reachable from ECDAT output? |
|:----------------|:------------|:-----------------------------|
| `cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum` | Present locally | **YES** — algorithm family values are validated against this |
| `cryptography-defs.schema.json#/definitions/ellipticCurvesEnum` | Present locally | **YES** — curve values are checked against this |
| `jsf-0.82.schema.json#/definitions/signature` | Missing locally | **NO** — ECDAT does not emit JSON Signature Format structures |
| `spdx.schema.json` | Missing locally | **NO** — ECDAT does not emit SPDX license choice blocks |

### Proof that JSF/SPDX are unreachable from CURRENT ECDAT outputs

ECDAT currently emits these top-level structures:
1. `bomFormat`, `specVersion`, `serialNumber`, `version` — primitive strings/integers
2. `metadata` — contains `timestamp`, `lifecycles`, `tools`, `component` — none reference JSF or SPDX
3. `components[]` — each contains `type`, `name`, `bom-ref`, `cryptoProperties`, `evidence`, `properties` — `cryptoProperties` branches into `algorithmProperties`, `relatedCryptoMaterialProperties`, `protocolProperties`, or `certificateProperties`. None of these reference JSF. None emit `licenseChoice` (which would trigger SPDX).
4. `dependencies[]` — contains `ref`, `dependsOn`, `provides` — primitive string arrays

**The JSF schema branch** is reachable only through `#/definitions/signature`, used in `metadata.signature` or component-level signatures. ECDAT does NOT emit `metadata.signature` or any component signatures.

**The SPDX schema branch** is reachable only through `#/definitions/licenseChoice`, used in `component.licenses` or `metadata.licenses`. ECDAT does NOT emit license blocks.

**Claim (precisely scoped):** Of the structures ECDAT currently generates, 100% of schema branches traversed during validation resolve to `bom-1.7.schema.json` and `cryptography-defs.schema.json`. The JSF and SPDX schema branches are not exercised by any currently generated ECDAT CBOM instance.

**This is NOT the same as:** "The CycloneDX schema does not depend on JSF/SPDX." It does — but those branches are unreachable from ECDAT's current output structures.

---

## 8. Validation Results

```
Ran 165 tests in 0.067s

OK
```

- **Custom Structural Validation (Tier 1):** PASS
- **Semantic Non-Inference Validation (Tier 2):** PASS
- **Full Draft-07 JSON Schema Runtime Validation:** NOT EXECUTED
  - `jsonschema` is not installed
  - No third-party dependency was installed
  - Full CycloneDX JSON Schema runtime conformance is NOT claimed

---

## 9. Complete Test Results

| Test Range | Count | Category | Status |
|:-----------|:------|:---------|:-------|
| test_01–test_09 | 9 | Core projection (AES, RSA, ECDSA, ECDH, Ed25519, SHA) | PASS |
| test_10–test_11 | 2 | Non-inference (generic EC, generic DH) | PASS |
| test_12 | 1 | UNKNOWN preservation | PASS |
| test_13–test_16 | 4 | Parameter segregation (key size, curve, mode, padding) | PASS |
| test_17 | 1 | Formal parameter set (AES-128) | PASS |
| test_18–test_19 | 2 | cryptoFunctions evidence rules | PASS |
| test_20 | 1 | Multi-scanner provenance | PASS |
| test_21–test_22 | 2 | Identity stability + deterministic serialization | PASS |
| test_23 | 1 | Dependency supply chain graph | PASS |
| **test_24** | 1 | **AssetType mapping audit (all 6 types)** | PASS |
| **test_25** | 1 | **Library dependency ≠ algorithm usage (BouncyCastle)** | PASS |
| **test_26** | 1 | **UNKNOWN preserves unknown state** | PASS |
| **test_27** | 1 | **Negative semantic validations** | PASS |
| **test_28** | 1 | **Non-inference audit integration** | PASS |
| Other test files | 137 | Domain, ingestion, normalization, security, adapters | PASS |
| **TOTAL** | **165** | | **ALL PASS** |

---

## 10. Files Changed

| File | Change | Reason |
|:-----|:-------|:-------|
| [`projection.py`](file:///d:/SIH/product/core/cbom/projection.py) | Removed `LIBRARY_DEPENDENCY` from mapping table; wrapped `cryptoProperties` in `if asset.asset_type != AssetType.LIBRARY_DEPENDENCY` guard | Fix DEF-02: library ≠ algorithm |
| [`test_cbom_projection.py`](file:///d:/SIH/product/tests/test_cbom_projection.py) | Updated test_24; added test_25, test_26, test_27, test_28 | Regression + negative tests |
| [`PROJECT_STATE.md`](file:///d:/SIH/product/docs/PROJECT_STATE.md) | Updated test count to 165; added library/unknown invariants | Documentation accuracy |

---

## 11. Files Intentionally NOT Changed

| File / Directory | Reason |
|:----------------|:-------|
| `product/benchmark/answer_keys/*.json` | Ground truth immutability preserved (11 files SHA-256 verified) |
| `product/core/cbom/schemas/*.json` | Authoritative CycloneDX schema artifacts untouched |
| `product/core/domain/` | Phase 1D domain model preserved without modification |
| `product/core/normalization/` | Phase 1D correlation preserved |
| `product/core/ingestion/` | Phase 2A/2B ingestion preserved |
| `product/core/cbom/validator.py` | No validator changes needed (handles absent `cryptoProperties` via `comp.get(...)` defaults) |
| `product/core/cbom/serializer.py` | No serializer changes needed |
| `product/core/cbom/constants.py` | No constant changes needed |
| `product/docs/PHASE_3A_*.md` | Phase 3A architecture preserved |

---

## 12. Remaining Limitations

1. **Full CycloneDX Draft-07 JSON Schema Runtime Validation:** NOT EXECUTED. `jsonschema` is not installed. No third-party dependency was installed.
2. **UNKNOWN → `"algorithm"` semantic approximation:** CycloneDX has no `assetType: "unknown"`. Mapping to `"algorithm"` is the closest available option. All associated fields maximally signal uncertainty.
3. **`algorithmProperties` on non-algorithm crypto assets:** Empty `algorithmProperties: {}` is attached to `PROTOCOL`, `CERTIFICATE`, and `CRYPTO_KEY` components. This is structurally valid but semantically unnecessary. Not a correctness defect (empty dict asserts nothing).
4. **JSF/SPDX schemas missing locally:** `jsf-0.82.schema.json` and `spdx.schema.json` are not bundled. These branches are unreachable from current ECDAT output.

---

## 13. Unsupported / Unverified Claims

- **NOT CLAIMED:** Full CycloneDX 1.7 JSON Schema runtime conformance
- **NOT CLAIMED:** Full Draft-07 validation
- **NOT CLAIMED:** Complete formal schema validation
- **NOT CLAIMED:** 100% CycloneDX compliance
- **CLAIMED:** Custom structural validation against official CycloneDX 1.7 enumerations = PASS
- **CLAIMED:** Semantic non-inference validation = PASS
- **CLAIMED:** 165/165 internal tests = PASS (100% pass rate)

---

## 14. Final Gate Status

### PHASE 3B = PASS WITH VERIFICATION LIMITATION

**Conditions met:**
- ✅ All semantic checks pass (165/165 tests)
- ✅ No unresolved correctness defects
- ✅ CRYPTO_KEY correctly maps to `"related-crypto-material"` with proper `relatedCryptoMaterialProperties`
- ✅ LIBRARY_DEPENDENCY does NOT receive `cryptoProperties` (dependency ≠ algorithm)
- ✅ UNKNOWN preserves maximum uncertainty signals
- ✅ Non-inference invariants verified across all 11 forbidden patterns
- ✅ Schema reachability correctly scoped
- ✅ Benchmark ground truth untouched (11 answer keys SHA-256 verified)
- ✅ Zero third-party dependencies

**Verification limitation:**
- ❌ Full CycloneDX Draft-07 JSON Schema runtime validation NOT EXECUTED

### PHASE 3C = LOCKED

Phase 3C has NOT been started. Implementation has not begun. Phase 3C remains locked pending separate Project Owner authorization.
