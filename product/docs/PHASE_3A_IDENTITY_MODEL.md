# ECDAT Phase 3A — Cryptographic Identity & Anti-Collapse Model

**Document Identifier:** ECDAT-SPEC-PHASE-3A-IDENTITY  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/PROJECT_SPEC.md`
- `product/docs/ARCHITECTURE.md`
- `product/docs/DECISIONS.md` (ADR-008, ADR-009)
- `product/docs/PHASE_1D_NORMALIZATION_ARCHITECTURE.md`
- `product/docs/PRE_3A_DOMAIN_RUN_CONTRACT_GATE.md`

---

## 1. The Identity Hierarchy & Separation Principle

A foundational failure in amateur cryptographic discovery tools is **identity collapse** — conflating scanner executions with findings, or equating raw scanner outputs with cryptographic assets. 

ECDAT strictly defines ten distinct identity tiers and enforces mathematical anti-collapse invariants across all operations:

```
1. Target Identity                     (Codebase repository URI / path)
2. Target Content Identity             (Cryptographic snapshot: sha256(tree))
3. Operation / Request Identity        (External invocation transaction)
4. Analysis Run Identity               (Multi-scanner session contract: run_id)
5. Scanner Execution Identity          (Individual tool run contract: execution_id)
6. Raw-Output Content Identity         (Verbatim stdout capture: sha256(stdout))
7. Evidence Identity                   (Scan-local observation: {adapter}:{native_id})
8. Finding Identity                    (Canonical interpretation: ecdat:finding:{hash})
9. Asset Identity                      (Deterministic semantic key: ecdat:asset:{key})
10. CBOM bom-ref                       (CycloneDX inter-component link)
```

---

## 2. Formal Identity Definitions & Derivation Rules

| Tier | Identity Name | Representation / Type | Derivation Algorithm | Scope & Lifetime |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Target Identity | String (URI / Path) | Provided by caller (e.g. `d:/SIH` or `git@github.com:org/repo.git`). | Persistent across scans of the same codebase. |
| **2** | Target Content Identity | String (`sha256:{hash}`) | Merkle tree SHA-256 computed over all target source files. | Deterministic snapshot; changes upon code edits. |
| **3** | Operation / Request ID | String (UUIDv4) | Random UUID generated per API/CLI invocation transaction. | Ephemeral request lifetime. |
| **4** | Analysis Run ID | String (UUIDv5) | UUIDv5 derived from `(target_content_hash, timestamp, ecdat_version)`. | Session lifetime; distinct for every analysis execution. |
| **5** | Scanner Execution ID | String | Composite key: `{run_id}:{adapter_id}`. | Tool execution lifecycle within a run. |
| **6** | Raw-Output Content ID | String (`sha256:{hash}`) | SHA-256 computed over verbatim scanner stdout bytes. | Content-addressable; identical bytes produce identical hash. |
| **7** | Evidence ID | String | Composite: `{adapter_id}:{native_finding_id}` (or collision fallback). | Scan-local observation identity. |
| **8** | Finding ID | String (UUIDv5) | `uuid5(NAMESPACE_FINDING, sorted_evidence_ids_string)`. | Canonical interpretation identity. |
| **9** | Asset ID | String (UUIDv5) | `uuid5(NAMESPACE_ASSET, CanonicalAssetKey.canonical_string())`. | Current semantic asset key; immune to finding ordering. |
| **10** | CBOM `bom-ref` | String | Prefixed canonical key: `"ecdat:asset:" + asset_id`. (For library: `"ecdat:pkg:" + purl`). | Unique reference within the CBOM document. |

---

## 3. Strict Anti-Collapse Invariants & Rules

ECDAT enforces four explicit anti-collapse rules to prevent conflating distinct domain concepts:

### Invariant 1: `run_id != asset_id`
- **Rule:** An `AnalysisRun` represents an **execution session**; a `CryptoAsset` represents an **inventory item** in source code.
- **Violation Danger:** Conflating them implies that re-running an analysis changes the identity of the cryptographic code being scanned.
- **Enforcement:** `run_id` is derived from execution parameters; `asset_id` is derived strictly from `CanonicalAssetKey` (algorithm + coordinates + role).

### Invariant 2: `raw_output_hash != run_id`
- **Rule:** A `RawScannerOutput` hash represents the **content identity** of a tool's emission; a `run_id` represents an **analysis session**.
- **Violation Danger:** Two independent runs that happen to produce byte-identical tool output would be collapsed into the same run session.
- **Enforcement:** `run_id` includes run timestamp and session tokens; `raw_output_hash` is strictly `sha256(stdout_bytes)`.

### Invariant 3: `bom-ref != evidence_id`
- **Rule:** A CBOM component represents a **consolidated cryptographic asset**, not an individual scanner observation.
- **Violation Danger:** Conflating `bom-ref` with `evidence_id` breaks the $N \to 1$ cardinality where multiple scanner observations support a single cryptographic asset.
- **Enforcement:** `bom-ref = "ecdat:asset:" + asset_id`. Underlying evidence IDs are retained in `component.properties`.

### Invariant 4: `asset_id != physical_key_id`
- **Rule:** An `asset_id` represents a **semantic cryptographic call site** in code; it is NOT proof of physical key material or HSM memory instance (ADR-009).
- **Violation Danger:** Claiming that discovering `RSA.generate(2048)` proves the existence of a specific physical private key.
- **Enforcement:** Documented explicitly in Non-Claims Ledger; physical key properties are excluded.

---

## 4. Canonical Asset Key Specification (`CanonicalAssetKey`)

The master identity of every cryptographic asset is established by `CanonicalAssetKey` in `product/core/domain/asset.py`:

### Canonical String Structure
$$\text{canonical\_string} = \text{family} + \text{"\|"} + \text{algo} + \text{"\|"} + \text{role} + \text{"\|"} + \text{location\_anchor} + \text{"\|"} + \text{params}$$

Where:
- **`family`:** Standardized family name (e.g. `"AES"`, `"RSA"`, `"EC"`, `"SHA-2"`, `"UNKNOWN"`).
- **`algo`:** Specific normalized algorithm name (e.g. `"AES-256"`, `"UNKNOWN"`).
- **`role`:** Enum value of `CryptographicRole` (e.g. `"ENCRYPTION"`, `"SIGNATURE"`).
- **`location_anchor`:** Normalized path and line span: `"{file_path}:{line_start}-{line_end}"`. (Sub-line expressions included if multiple distinct assignments exist on the same line).
- **`params`:** Normalized canonical string of key size, curve, mode, and padding.

### Deterministic UUIDv5 Generation
$$\text{asset\_id} = \text{UUIDv5}(\text{NAMESPACE\_ASSET}, \text{canonical\_string})$$

Where `NAMESPACE_ASSET = UUID("e0a0b0c0-d0e0-50a0-b0c0-d0e0f0a0b0c0")`.

---

## 5. Summary of Identity Invariants

1. **Re-ordering Immunity:** Re-ordering scanner output findings produces the identical set of `asset_id`s and identical CBOM `bom-ref`s.
2. **Deterministic Reproducibility:** Ingesting the same scanner outputs against the same codebase snapshot produces identical UUIDv5 identifiers.
3. **Traceable Disambiguation:** In the event of scanner collisions (duplicate native IDs), disambiguated fallback IDs (`{id}:collision:{idx}`) ensure no observations are overwritten while canonical asset identities remain stable.
