# ECDAT Phase 1D Normalization, Correlation & Identity Architecture

**Document Version:** 1.2.0 (Phase 1D Correlation & Identity Redesign Applied)  
**Phase:** Phase 1D (Evidence + Normalization Layer)  
**Status:** IMPLEMENTED & VERIFIED (Conservative Statement-Level Correlation & Stable Canonical Identity)  
**Ownership Boundary:** ECDAT Core Domain  

---

## 1. Executive Architectural Summary

Phase 1D establishes the authoritative internal ECDAT data pipeline separating empirical discovery evidence from derived domain interpretation and conservative cryptographic inventory generation:

$$\begin{matrix}
\text{[Raw Discovery Output]} \\
\downarrow \\
\text{\textbf{Evidence Layer (Immutable Empirical Proof)}} \\
\text{\small (Location [Source, Dependency, Network, Container, etc.], Bounded Snippet $\le 5$ lines, Raw Scanner Category, Raw Attributes [Deeply Frozen])} \\
\downarrow \\
\text{\textbf{ECDAT Normalization Engine (Deterministic \& Conservative)}} \\
\text{\small (Sanitization, Specificity Invariant Enforcement, Non-Cryptographic Observation Classification)} \\
\downarrow \\
\text{\textbf{Canonical Finding Layer (Frozen Domain Entity)}} \\
\text{\small (Evidence IDs, Observation Type, Algorithm Identity, Role, Parameters, Confidence, Disposition Status)} \\
\downarrow \\
\text{\textbf{Conservative Asset Correlation Layer}} \\
\text{\small (Statement-Level Deduplication, Deterministic Evaluation, Explicit Correlation Basis, Rejection of Ambiguity)} \\
\downarrow \\
\text{\textbf{Cryptographic Asset Inventory (Frozen Domain Entity)}} \\
\text{\small (Deterministic Asset ID from CanonicalAssetKey, Asset Type, Algorithm Identity, Role, Parameters, Finding IDs, Primary Location, Correlation Basis)}
\end{matrix}$$

---

## 2. Core Architectural Invariants & Redesign Principles

The Phase 1D implementation enforces the following foundational invariants:

### 2.1 Non-Negotiable Safety Principle
$$\textbf{FALSE MERGING IS STRICTLY WORSE THAN FALSE SPLITTING}$$
* In cryptographic inventory management, falsely merging two independent cryptographic operations conflates distinct cryptographic keys, lifecycles, and risk profiles.
* If identity cannot be established conclusively by available evidence, observations **MUST REMAIN SEPARATE**.

### 2.2 Bounded Scope of Phase 1D Correlation
Phase 1D answers strictly:
> *"Do these scanner observations refer to the same source-level cryptographic statement?"*

Phase 1D is deliberately **NOT** responsible for:
* Determining runtime object identity.
* Tracing variable reaching definitions across statements.
* Connecting operational lifecycles (`getInstance()` $\rightarrow$ `init()` $\rightarrow$ `doFinal()`), which belongs strictly to **Phase 4 (Context & Relationships)**.
* Reconciling cryptographic asset identity across git commits and refactorings, which belongs strictly to **Phase 9 (Re-scan & Verification Engine)**.

### 2.3 Removal of Unsafe Correlation Heuristics
Correlation heuristics that led to false merging have been completely excised:
* **Spatial proximity alone:** Being within $\le 20$ lines does NOT prove object or statement identity.
* **Variable name alone:** Identical variable names across methods, reassigned variables, or distant scopes do NOT prove identity.
* **Algorithm equality alone:** Multiple usages of "AES" in the same compilation unit do NOT represent the same asset.
* **Role equality alone:** Having the same role does not merge observations.
* **Exact line equality alone:** Multiple distinct statements may reside on the exact same source line (e.g. `c1 = ...; c2 = ...;`).

### 2.4 Statement-Level Observation Equivalence Rule
Observations are correlated in Phase 1D if and only if they represent equivalent observations of the same source statement:
1. **Normalized Location Anchor:** Exact match of normalized relative file path and line range (`line_start`, `line_end`).
2. **Sub-line / Statement Disambiguation:**
   * If column coordinates are provided by both scanners, column intervals must overlap appropriately (`[col_start, col_end]`).
   * If columns are unavailable, source expressions must be compatible: distinct variable assignments on the same line (e.g. `c1 = ...` vs `c2 = ...`) are rejected, and non-overlapping distinct text snippets are marked `AMBIGUOUS` and kept separate.
3. **Algorithm Family & Identity Compatibility:** Families and specific algorithms must be compatible (identical or refinement of `UNKNOWN`).
4. **Role Compatibility:** Roles must match or refine `UNKNOWN`.
5. **Parameter Contradiction Rejection:** Parameter sets must contain zero explicit contradictions.

### 2.5 Explicit Correlation Decisions & Ambiguity Handling
Correlation evaluations produce an explicit, deterministic outcome (`CorrelationDecision`):
* `CORRELATED`: Strong, conclusive evidence of statement equivalence. May be clustered into the same `CryptoAsset`.
* `NOT_CORRELATED`: Incompatible location, algorithm, role, or parameter contradiction. Retained as separate assets.
* `AMBIGUOUS`: Insufficient evidence to prove statement identity (e.g. conflicting same-line expressions without column boundaries). **AMBIGUOUS decisions MUST NEVER merge** and are kept as separate assets.

Every `CryptoAsset` stores an explicit, human-auditable `correlation_basis` string documenting the exact rule and evidence used.

### 2.6 Parameter Contradiction & Refinement Rules
Parameter comparison strictly separates contradictions from incomplete evidence:
* **Explicit Contradictions (REJECT CORRELATION):**
  * Mode contradiction: `AES/GCM` vs `AES/CBC` $\rightarrow$ `NOT_CORRELATED`.
  * Key size contradiction: `RSA-2048` vs `RSA-3072` $\rightarrow$ `NOT_CORRELATED`.
  * Curve contradiction: `secp256r1` vs `secp384r1` $\rightarrow$ `NOT_CORRELATED`.
  * Digest contradiction: `SHA-256` vs `SHA-512` $\rightarrow$ `NOT_CORRELATED`.
* **Parameter Refinement (PERMIT CORRELATION):**
  * When one observation provides a parameter that another omitted (e.g. scanner A detected `key_size=256, mode=None` while scanner B detected `key_size=None, mode=GCM`), they correlate if statement identity holds.
  * Incomplete scanner evidence does not prevent correlation: **known parameters refine unknown parameters, and unknown values never overwrite known values**.

---

## 3. Canonical Asset Identity Model (`CanonicalAssetKey`)

Asset identity must remain stable across scans, across scanners, and across finding ordering.

### 3.1 Field Classification Taxon

| Field Name | Classification | Rationale |
| :--- | :--- | :--- |
| `asset_type` | **IDENTITY-BEARING** | Differentiates algorithms from dependencies or certificates. |
| `location_anchor` | **IDENTITY-BEARING** | Stable canonical source coordinate (`file_path:start-end:cols`). |
| `algorithm_family` | **IDENTITY-BEARING** | Standardized cryptographic family (AES, RSA, EC, etc.). |
| `algorithm_name` | **IDENTITY-BEARING** | Specific canonical primitive name. |
| `algorithm_variant` | **IDENTITY-BEARING** | Specific variant designation when known. |
| `role` | **IDENTITY-BEARING** | Operational functional role (e.g. ENCRYPTION_DECRYPTION vs KEY_GENERATION). |
| `parameter_signature` | **IDENTITY-BEARING** | Canonical string of active parameters (key size, mode, curve, digest). |
| `finding_ids` | **DESCRIPTIVE / PROVENANCE** | Scanner-specific observation tracking IDs. Excluded from key. |
| `evidence_ids` | **DESCRIPTIVE / PROVENANCE** | Raw empirical observation IDs. Excluded from key. |
| `scanner_name` / `version` | **PROVENANCE-ONLY** | Tool metadata. Excluded from key. |
| `scan_id` / `timestamp` | **SCAN-VARIABLE** | Run execution metadata. Excluded from key. |

### 3.2 Deterministic Asset ID Derivation
`asset_id` is derived deterministically from the immutable `CanonicalAssetKey`:
$$\text{canonical\_string} = \text{asset\_type}|\text{loc\_anchor}|\text{family}|\text{algo}|\text{variant}|\text{role}|\text{param\_sig}$$
$$\text{asset\_id} = \text{uuid5}(\text{NAMESPACE\_URL}, \text{"ecdat:asset:"} + \text{canonical\_string})$$

### 3.3 Provenance Reconstructability Invariant
Removing finding IDs and evidence IDs from canonical identity **does not lose provenance**:
$$\text{CryptoAsset} \longrightarrow \text{finding\_ids} \longrightarrow \text{Finding} \longrightarrow \text{evidence\_ids} \longrightarrow \text{EvidenceRecord} \longrightarrow \text{raw\_attributes}$$
Every asset retains an immutable `finding_ids` tuple. An analyst can traverse from an asset back to the exact scanner rule IDs and raw attributes.

### 3.4 Cross-Scanner & Cross-Scan Invariants
* **Cross-Scanner Equivalence:** If Scanner A (CryptoScan, finding ID `cs-01`) and Scanner B (SonarQube, finding ID `sn-02`) detect the exact same statement, ECDAT outputs **one** `CryptoAsset` with an identical `asset_id` and both `finding_ids` in its provenance tuple.
* **Cross-Scan Reproducibility:** Two independent execution runs that construct findings from equivalent code produce the **identical `asset_id`**, even with randomized or fresh finding IDs.
* **Permutation Invariance:** Passing findings to `correlate()` in reverse or arbitrary order produces identical groupings and identical asset IDs.

---

## 4. Deep Immutability & Security Invariants

1. **Deep Immutability (`freeze_value`, `FrozenIdTuple`):** `EvidenceRecord`, `Finding`, and `CryptoAsset` are frozen (`frozen=True`). Raw scanner attributes are recursively frozen into `MappingProxyType`, `tuple`, and `frozenset`.
2. **Path Sanitization (`sanitize_relative_path`):** Rejects directory traversal (`../`), percent-encoded traversal (`%2e%2e`, `%2f`), absolute paths, and drive designators.
3. **Decoy & Comment Non-Cryptographic Classification:** Misleading comments and non-cryptographic decoys are classified with `ObservationType.COMMENT_ONLY` or `NON_CRYPTOGRAPHIC_DECOY` and `DispositionStatus.FALSE_POSITIVE`. They are preserved in evidence and findings but excluded from active cryptographic assets.
4. **Specificity Invariant:** Generic scanner categories (e.g. `ECC`, `CIPHER`) never manufacture specific algorithms without explicit source evidence. `DH` code never normalizes to `ECDH` merely because a scanner category says `ECC`.

---

## 5. Verification & Test Suite Matrix

The Phase 1D test suite executed with a **100% pass rate** across 80 tests:
```
python -m unittest discover -s product/tests -p "test_*.py" -v
Ran 80 tests in 0.049s
OK (80 passed, 0 failures, 0 errors)
```

### Comprehensive 20-Point Correlation & Identity Test Matrix

| # | Test Scenario | Verified Behavior |
| :--- | :--- | :--- |
| 1 | Same statement, different finding IDs | Correlates into 1 asset; preserves all finding IDs in provenance. |
| 2 | Same statement, different scanner names | CryptoScan + SonarQube merge into 1 asset. |
| 3 | Independently constructed equivalent observations | Run 1 and Run 2 independently yield identical `asset_id`. |
| 4 | Reordered findings | Finding input permutation yields identical asset count and IDs. |
| 5 | Two AES operations, different variables | `cipherA` (line 10) vs `cipherB` (line 14) stay separate. |
| 6 | Same variable, GCM then CBC | Reassigned variable on different lines produces 2 separate assets. |
| 7 | Same variable, separate GCM instantiations | Re-instantiations on different lines produce 2 separate assets. |
| 8 | Same variable across methods | Method A vs Method B usages produce 2 separate assets. |
| 9 | Same-line distinct statements | `c1 = ...; c2 = ...;` on line 15 produce 2 separate assets. |
| 10 | Column-disambiguated same-line statements | Col 5..35 vs Col 45..75 on line 20 produce 2 separate assets. |
| 11 | Same algorithm, different roles | AES Encryption vs Key Generation produce 2 separate assets. |
| 12 | RSA-2048 vs RSA-3072 | Conflicting key sizes reject correlation; produce 2 separate assets. |
| 13 | DH vs ECDH | Conflicting families (DH vs EC) reject correlation. |
| 14 | Unknown parameter vs known parameter | Omitted parameter refined by known parameter; unknown does not overwrite known. |
| 15 | Dynamic algorithm call | `Cipher.getInstance(var)` remains UNKNOWN; does not merge with specific AES. |
| 16 | Dependency vs source usage | `build.gradle` dependency and source usage produce separate distinct assets. |
| 17 | Comment/decoy vs real usage | Comment decoy (`FALSE_POSITIVE`) does not produce an active crypto asset. |
| 18 | Deterministic asset IDs | CanonicalAssetKey derives identical UUID5; contains zero finding IDs. |
| 19 | Different location $\rightarrow$ different asset | Different files or lines produce distinct asset IDs. |
| 20 | Finding order invariance | Arbitrary permutations of findings produce identical asset IDs. |
| 21 | Provenance reconstructability | Asset $\rightarrow$ finding_ids $\rightarrow$ evidence_ids $\rightarrow$ raw attributes fully traceable. |

---

## 6. Known Limitations of Phase 1D (Bounded Scope)

1. **Intra-Procedural Scope:** Phase 1D intentionally restricts correlation to same-statement deduplication. Tracing `getInstance()` $\rightarrow$ `init()` $\rightarrow$ `doFinal()` across statements is explicitly deferred to Phase 4.
2. **Static Syntax Horizon:** Dynamically computed algorithm strings cannot be statically resolved and correctly remain `UNKNOWN` with `NEEDS_REVIEW`.
3. **Cross-Commit Re-Scans:** Deterministic asset IDs are tied to canonical source coordinates. Refactoring across commits that moves code will produce a new coordinate anchor; historical reconciliation across git commits is deferred to Phase 9.
4. **Scanner Ingestion Pipeline:** Verified using raw Phase 1C-B JSON fixtures; dedicated production scanner adapters remain gated for Phase 2.
5. **No Risk Scoring or CBOM Output:** Phase 1D strictly manages evidence, normalization, and canonical asset inventory; risk scoring (Phase 5) and CBOM emission (Phase 3) remain locked.
