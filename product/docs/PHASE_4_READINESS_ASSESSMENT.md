# PHASE 4 READINESS ASSESSMENT & DEPENDENCY GATE
## Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Problem Statement SIH26164

**Assessment ID:** ECDAT-GATE-PHASE4-002  
**Date:** 2026-09-17  
**Auditor / Roles:** Principal Software Architect, Senior Cryptography Engineer, Application-Security Specialist, QA Lead, Independent Technical Auditor  
**Scope:** Evaluation of Phase 3-to-Phase 4 Dependency Gate & Architectural Boundaries for Phase 4A (Cryptographic Agility Modeling & NIST FIPS 203/204/205 Target Mapping)  
**Baseline Test Suite:** 218 unit tests across 15 test files (218 passing, 0 failures, 0 regressions, duration: 0.229s)  
**Authoritative Defect Register:** `PHASE_3_DEFECT_REGISTER.md` (DEF-01 through DEF-07: Remediated; DEF-08 & DEF-09: Explicitly Documented Boundaries)  
**Benchmark Ground-Truth Integrity:** 11/11 answer keys byte-identical SHA-256 MATCH  

---

## 1. Executive Dependency Gate Decision

| Gate Dimension | Evaluation Status | Summary Finding |
| :--- | :---: | :--- |
| **Phase 3 Freeze Readiness** | **READY TO FREEZE** | All Phase 3 deliverables (3A, 3B, 3C-A, 3C-B, 3C-C) are complete, verified against contracts, and protected by 218 passing unit tests. All confirmed defects (DEF-01 to DEF-07) are remediated. Benchmark fixtures and answer keys remain 100% byte-identical. |
| **Phase 4A Start Readiness** | **APPROVED TO BEGIN (CONDITIONAL)** | Phase 4A can begin safely without modifying Phase 3 source code. Downstream consumption interfaces are verified against the live codebase. Execution is conditional upon adhering to documented scanner limitations, offline Draft-07 schema boundaries, and role-aware mapping rules. |
| **Blocking Code Defects** | **ZERO (0)** | There are zero blocking, critical, or unhandled high-severity code defects remaining in the Phase 3 implementation. |

---

## 2. Actual Code Dependency Verification (Interfaces 1 through 7)

Each dependency required by Phase 4A was inspected directly in the current implementation to verify actual programmatic interfaces and data structures:

### Dependency 1: Canonical Cryptographic Assets and Their Identity
* **Source Module:** `product/core/domain/asset.py` (`CryptoAsset`, `CanonicalAssetKey`, `AssetType`, `AlgorithmIdentity`)
* **Verified Interface & Data Available:**
  * `asset.asset_id`: Deterministic UUIDv5 string derived from `asset_key.canonical_string()`.
  * `asset.asset_type`: Enum `AssetType` (`ALGORITHM`, `PROTOCOL`, `CERTIFICATE`, `CRYPTO_KEY`, `LIBRARY_DEPENDENCY`, `UNKNOWN`).
  * `asset.algorithm_identity`: `AlgorithmIdentity(family: AlgorithmFamily, algorithm: str, variant: Optional[str])`.
  * `asset.asset_key`: `CanonicalAssetKey(asset_type, location_anchor, algorithm_family, algorithm_name, algorithm_variant, role, parameter_signature)`.
* **Immutability & Safety:** Class is decorated with `@dataclass(frozen=True)`. Deep immutability enforced on `finding_ids`.
* **Phase 4A Consumption:** Fully sufficient for cryptographic asset identification and deduplication.

### Dependency 2: Evidence, Provenance, Confidence, and Uncertainty
* **Source Modules:** `product/core/evidence/evidence.py` (`EvidenceRecord`, `EvidenceLocation`, `LocationType`), `product/core/domain/confidence.py` (`ConfidenceLevel`), `product/core/risk/enums.py` (`UncertaintyLevel`)
* **Verified Interface & Data Available:**
  * `asset.finding_ids`: Immutable tuple of finding IDs linking back to raw evidence records.
  * `asset.primary_location`: `EvidenceLocation` containing `location_type` (`SOURCE`, `DEPENDENCY`, `NETWORK`, `CONTAINER`, `CERTIFICATE`, `BINARY`), `file_path`, `line_start`, `line_end`, `package_coordinate`, `matched_text`, `code_snippet`.
  * `asset.confidence`: Enum `ConfidenceLevel` (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `NEEDS_REVIEW`).
* **Phase 4A Consumption:** Provides granular source file coordinates, lines, and AST snippets required to assess code isolation and parameterization for agility scoring.

### Dependency 3: Cryptographic Roles and Parameters
* **Source Modules:** `product/core/domain/role.py` (`CryptographicRole`), `product/core/domain/parameters.py` (`AlgorithmParameters`)
* **Verified Interface & Data Available:**
  * `asset.role`: Enum `CryptographicRole` (`ENCRYPTION_DECRYPTION`, `DIGITAL_SIGNATURE`, `KEY_AGREEMENT`, `KEY_GENERATION`, `MESSAGE_DIGEST`, `MAC`, `KEY_DERIVATION`, `RANDOM_GENERATION`, `CERTIFICATE_OPERATIONS`, `PROTOCOL_HANDSHAKE`, `UNKNOWN`).
  * `asset.parameters`: `AlgorithmParameters(key_size_bits, cipher_mode, padding_scheme, curve_name, digest_algorithm, tag_bits, effective_key_bits, raw_parameters)`.
* **Phase 4A Consumption:** **Critical for role-aware PQC mapping.** Allows Phase 4A to distinguish key establishment from digital signatures, preventing invalid drop-in assignments (e.g. attempting to assign ML-KEM to a digital signature role).

### Dependency 4: Classical Security and Quantum Exposure Results
* **Source Module:** `product/core/risk/posture.py` (`evaluate_crypto_posture`, `ClassicalSecurityStatus`, `QuantumExposureClass`)
* **Verified Interface & Data Available:**
  * `evaluate_crypto_posture(asset)` returns a 5-tuple: `(ClassicalSecurityStatus, QuantumExposureClass, UncertaintyLevel, rationale: str, normalized_name: str)`.
  * Classical status: `ACCEPTABLE`, `DEPRECATED`, `RESTRICTED`, `DISALLOWED`, `INDETERMINATE`.
  * Quantum exposure: `SHOR_VULNERABLE_ASYMMETRIC`, `GROVER_REDUCED_SYMMETRIC_LOW`, `GROVER_RESILIENT_SYMMETRIC_HIGH`, `GROVER_AFFECTED_HASH`, `QUANTUM_RESISTANT`, `UNCLASSIFIED_QUANTUM_POSTURE`.
* **Observed Limitation:** Classical policy rules are implemented only for DES, AES, RSA, and SHA-1. Asymmetric algorithms whose classical policies were deferred (ECDSA, ECDH, Ed25519, DH) evaluate to `INDETERMINATE`, `UNCLASSIFIED_QUANTUM_POSTURE`, and `NEEDS_REVIEW`.
* **Phase 4A Consumption Strategy:** Phase 4A target mapping must not rely solely on `QuantumExposureClass` from Phase 3 posture for deferred algorithms. Instead, Phase 4A must inspect `asset.algorithm_identity.family` (e.g. `AlgorithmFamily.EC`, `EDWARDS`, `DH`) and `asset.role` directly to assign PQC targets (ML-KEM, ML-DSA).

### Dependency 5: CBOM Projection and Its Known Validation Boundary
* **Source Modules:** `product/core/cbom/serializer.py`, `product/core/cbom/validator.py`
* **Verified Interface & Data Available:**
  * `CBOMSerializer.serialize_to_dict` produces standard CycloneDX 1.7 CBOM dictionary.
  * Verified component isolation: `ecdat:evidence_ids` and `ecdat:scanners` are isolated per component (DEF-03 fix).
  * `CBOMValidator.validate_tier1_structure` and `validate_tier2_semantics` pass cleanly.
* **Documented Validation Boundary:** Full Draft-07 JSON Schema runtime validation via `jsonschema` was **NOT EXECUTED** to uphold the zero-third-party dependencies policy (Python stdlib only). Phase 4 must not claim external JSON Schema validation engine execution.

### Dependency 6: Risk Results and Explanations
* **Source Modules:** `product/core/risk/models.py` (`MigrationPriorityRecord`, `RiskAssessment`, `RiskExplanation`), `product/core/risk/policy.py` (`RiskAnalysisEngine`)
* **Verified Interface & Data Available:**
  * `record.default_priority` and `record.effective_priority`: Enums (`P0_IMMEDIATE_ACTION`, `P1_NEAR_TERM_MIGRATION`, `P2_PLANNED_TRANSITION`, `P3_OPPORTUNISTIC_QUICK_WIN`, `P4_DEFERRED_MONITORING`, `P_REVIEW_REQUIRED`).
  * `record.risk_category`: Enum `RiskCategory` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEEDS_REVIEW`).
  * `record.explanation`: 7-part structured, deeply immutable explanation (`observed_facts`, `derived_classifications`, `context_summary`, `triggered_rules`, `assumptions`, `uncertainty_level`, `final_result`).
* **Phase 4A Consumption:** Provides deterministic risk categories and priority queues for migration roadmap sequencing.

### Dependency 7: Explicitly Deferred Policies and Unsupported Inputs
* **Source Modules:** `product/core/workflow/report.py` (`deferred_capabilities`), `product/core/discovery/ingestion.py` (`IngestionStatus.NO_FINDINGS`)
* **Verified Interface & Data Available:**
  * Ingestion results on empty scanner output (TC08 wrapper, TC11 dynamic) emit `IngestionStatus.NO_FINDINGS` and 0 canonical assets.
  * Reports attach explicit mandatory notice: `"NOTICE (ZERO CONFIRMED FINDINGS): The scanner completed execution with zero reported cryptographic findings... NOT proof that the application is cryptographically safe."`
* **Phase 4A Consumption:** Phase 4A must preserve zero-finding uncertainty and must not fabricate migration plans for undetected assets.

---

## 3. Phase 4A Boundary & Non-Inference Rules

To maintain scientific integrity and auditability, Phase 4A (Cryptographic Agility Modeling & Target Mapping) must enforce the following strict boundaries:

1. **No Parameter Invention:**
   * If an asset lacks key size evidence (e.g. raw CryptoScan TC01 output where key size is missing), Phase 4A must NOT fabricate a key size or blindly assign ML-KEM-1024.
   * Phase 4A must emit a conditional, parameterized recommendation matrix or route to `UncertaintyLevel.NEEDS_REVIEW`.
2. **No Automated Target Assignment for Unknown Algorithms:**
   * Any asset with `AssetType.UNKNOWN`, `AlgorithmFamily.UNKNOWN`, bare Rijndael, or dynamic cipher loading (TC11) must be flagged with `NEEDS_REVIEW`. Automated, blind PQC replacement recommendations are prohibited for unverified primitives.
3. **Strict Separation of Classical Security from Quantum Vulnerability:**
   * Phase 4A must not confuse classical acceptability with quantum safety. For example, RSA-2048 is classically `ACCEPTABLE` (NIST SP 800-131A) but quantum `VULNERABLE` (Shor's algorithm). AES-128 is classically `ACCEPTABLE` but Grover-reduced, where the recommendation is key expansion to AES-256 (not PQC replacement).
4. **Role-Aware, Protocol-Contextual Target Mapping (No Drop-In Fallacies):**
   * PQC algorithms cannot be treated as drop-in binary replacements.
   * **Key Encapsulation / Transport (RSA PKE, DH, ECDH):** Maps to **NIST FIPS 203 (ML-KEM)**. Security levels: Level 1 (ML-KEM-512), Level 3 (ML-KEM-768), Level 5 (ML-KEM-1024).
   * **Digital Signatures (RSA Sig, ECDSA, Ed25519):** Maps to **NIST FIPS 204 (ML-DSA)** or **NIST FIPS 205 (SLH-DSA)**.
   * Ciphertext expansion (e.g. ML-KEM-768 public key: 1,184 bytes; ciphertext: 1,088 bytes vs RSA-2048: 256 bytes) must be explicitly factored into agility scoring.
5. **Preservation of Scanner Gaps & Uncertainty:**
   * Phase 4A must not erase or paper over scanner false negatives (TC08 indirection wrapper, TC11 dynamic lookup). Undetected assets remain outside CBOM migration planning.
6. **Strict Immutability of Phase 3 Core:**
   * Phase 4A must consume Phase 3 objects as read-only. Migration strategies must be emitted as distinct analysis records (`PqcTargetMapping`, `AgilityScorecard`) without mutating `CryptoAsset` or `MigrationPriorityRecord`.

---

## 4. Dependencies Missing or Insufficiently Specified

| Dependency Area | Status in Phase 3 | Impact on Phase 4A | Mitigation / Resolution Strategy in Phase 4A |
| :--- | :---: | :--- | :--- |
| **ECC / DH Classical Posture Rules** | Deferred in 3C-C | `evaluate_crypto_posture` returns `INDETERMINATE` / `UNCLASSIFIED_QUANTUM_POSTURE` for ECDSA, ECDH, Ed25519. | Phase 4A target mapping does NOT rely on Phase 3 posture for ECC/DH. Phase 4A reads `asset.algorithm_identity.family` and `asset.role` directly to map to FIPS 203/204. |
| **NIST Security Strength Level Matrix** | Unmapped in 3C | Phase 3 categorizes algorithms into broad Grover/Shor tiers, but does not emit formal NIST Security Strength Levels (1, 2, 3, 4, 5). | Phase 4A will codify a deterministic `NistSecurityStrength` evaluator mapping key sizes / curves to NIST Levels 1–5 based on NIST SP 800-57 Part 1 Rev 5 Table 2. |
| **Agility Dimension Model** | Unmodeled in 3C | Phase 3 captures AST locations and parameters, but has no quantitative agility metric (hardcoded vs. configurable). | Phase 4A will introduce an `AgilityScorecard` evaluating parameterization, algorithm isolation, and abstraction depth. |

---

## 5. Blocking Issues & Phase 4 Transition Verdict

* **Blocking Code Defects:** **ZERO (0)**.
* **Phase 3 Source Code Changes Required:** **NONE (0 files modified)**. Phase 4A can consume Phase 3 interfaces as currently implemented.
* **Phase 4A Transition Verdict:** **APPROVED TO COMMENCE (CONDITIONAL)**.

---

## 6. Single Next Implementation Step

> [!IMPORTANT]
> **Single Next Action:** Create the Phase 4A PQC Target Mapping module in `product/core/migration/target_mapper.py`, implementing deterministic mappings from `(AlgorithmFamily, CryptographicRole, AlgorithmParameters)` to `(NistPqcTarget, NistSecurityLevel)` under NIST FIPS 203, FIPS 204, and FIPS 205, protected by dedicated unit tests in `product/tests/test_pqc_target_mapping.py`.
