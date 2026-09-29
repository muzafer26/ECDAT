# ECDAT — Phase 4A: Cryptographic Agility Modeling & PQC Target Mapping Specification & Report

**Document Version:** 1.1.0 (Standards Semantics Verification & Decoupling Update)  
**Status:** IMPLEMENTED, CORRECTED & VERIFIED  
**Module Location:** `product/core/migration/`  
**Test Suite:** `product/tests/test_migration_target_mapping.py`  
**Verification Baseline:** 244/244 automated tests passing; 11/11 benchmark answer keys 100% byte-identical  
**Date:** 2026-09-17  

---

## 1. Executive Summary & Standards Semantics Charter

Phase 4A introduces the **Cryptographic Agility Modeling & PQC Target Mapping Engine** for the Enterprise Cryptographic Discovery & Analysis Tool (ECDAT).

As specified in the system charter, ECDAT does not perform automated code rewriting, runtime migration execution, or blind algorithm substitutions. Rather, Phase 4A provides a **rigorous, deterministic decision-support foundation** that evaluates discovered cryptographic assets against published post-quantum cryptography (PQC) standards, cryptographic roles, verified parameter configurations, and observable implementation agility.

### Foundational Distinction of Five Cryptographic Dimensions
To prevent critical semantic errors in migration planning, ECDAT explicitly enforces separation across five distinct dimensions:

| Dimension | Defining Standard | Valid Metric / Range | Architectural Scope |
| :--- | :--- | :--- | :--- |
| **1. Classical Security Strength** | NIST SP 800-57 Pt 1 Rev 5 Table 2; SP 800-131A Rev 2 | Bits: `112` (legacy), `128`, `192`, `256`, `< 112` (`DISALLOWED`) | Measures resistance to cryptanalysis on classical/conventional computers. An RSA or ECC key has classical strength; it has **zero** PQC category. |
| **2. NIST PQC Security Category** | NIST FIPS 203, 204, 205 §1 Table 1; NIST PQC Call for Proposals §4.A.5 | `CATEGORY_1` through `CATEGORY_5` | Measures computational attack complexity relative to AES key search and SHA collision search. Applied **exclusively** to candidate post-quantum parameter sets. |
| **3. Quantum Exposure** | ECDAT Quantum Posture (Phase 3C-B); Shor's & Grover's algorithms | `VULNERABLE`, `TRANSITIONAL`, `RESISTANT` | Measures theoretical vulnerability to a cryptographically relevant quantum computer (CRQC). RSA-4096 is classically strong (140+ bits) yet quantum-vulnerable. |
| **4. Migration Priority** | ECDAT Prioritization Engine (Phase 3C-C); `MigrationPriorityRecord` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | Operational triage ranking combining asset posture, data retention lifetime, external exposure tier, and business context. |
| **5. Candidate Target Selection** | ECDAT Migration Decision Support (Phase 4A); `CandidateTarget` | Non-binding proposals (ML-KEM, ML-DSA, SLH-DSA) | Engineering proposals for decision support. **Never represents an approved target or compatibility guarantee.** |

### Architectural Invariants
* **Input Immutability:** Consumes Phase 3 canonical assets (`CryptoAsset`) as read-only.
* **Non-Interference:** Does not mutate `CryptoAsset`, `MigrationPriorityRecord`, evidence records, or CBOM components.
* **Role-Aware Separation:** Strictly distinguishes Key Encapsulation (FIPS 203) from Digital Signatures (FIPS 204 / FIPS 205).
* **Fail-Closed Semantics:** Ambiguous algorithms (dynamic ciphers, bare Rijndael, unknown families, unverified roles) fail closed to `NEEDS_REVIEW` or `UNSUPPORTED`.
* **Zero External Dependencies:** Implemented strictly using Python 3.12+ standard library.

---

## 2. Module Architecture & Responsibilities

The Phase 4A capability resides in `product/core/migration/`:

```
product/core/migration/
├── __init__.py          # Public interface exports
├── models.py            # Typed, immutable domain models & decoupled enums
├── strength.py          # NIST SP 800-57 Part 1 Rev. 5 classical security-strength classification
├── agility.py           # Evidence-grounded cryptographic agility assessment
└── target_mapper.py     # Deterministic PQC target mapping orchestrator
```

### Module Breakdown

| Module | Core Responsibility | Input Contract | Output Contract |
| :--- | :--- | :--- | :--- |
| `models.py` | Immutable data structures (`@dataclass(frozen=True)`) and enums representing mapping status, classical strength (`ClassicalSecurityStrength`), PQC categories (`PqcSecurityCategory`), PQC target families, and agility levels. | N/A | Immutable value objects |
| `strength.py` | Evaluates verified cryptographic parameters against NIST SP 800-57 Pt 1 Rev 5 Table 2, SP 800-131A Rev 2, FIPS 197, and FIPS 186-5. | `CryptoAsset` | `(ClassicalSecurityStrength, Optional[int], str, Tuple[str, ...])` |
| `agility.py` | Extracts observable agility indicators (hardcoded algorithms vs configurable parameters vs modular abstractions) strictly from verified AST evidence. | `CryptoAsset` | `AgilityAssessment` |
| `target_mapper.py` | Orchestrates target mapping by evaluating asset type, family, role, parameters, agility, and security strength. | `CryptoAsset` or `Sequence[CryptoAsset]` | `PqcTargetMapping` or `Tuple[PqcTargetMapping, ...]` |

---

## 3. Input and Output Contracts

### Input Contract
The engine accepts instances of `product.core.canonical.CryptoAsset`. Key fields evaluated:
* `asset_id`: Semantic SHA-256 identifier.
* `algorithm_family`: `AlgorithmFamily` enum (RSA, ECC, AES, SHA1, UNKNOWN, etc.).
* `algorithm_name`: Raw detected name (e.g. "RSA", "ECDSA", "Rijndael").
* `asset_type`: `AssetType` enum (`ALGORITHM`, `LIBRARY_DEPENDENCY`, etc.).
* `role`: `CryptoRole` enum (`KEY_EXCHANGE`, `SIGNATURE`, `ENCRYPTION`, `UNKNOWN`, etc.).
* `parameters`: Dictionary containing verified cryptographic parameters (`key_size`, `curve`, `mode`, etc.).
* `evidence`: List of `EvidenceRecord` items containing AST code snippets and file paths.

### Output Contract: `PqcTargetMapping`
An immutable, serializable record enforcing explicit semantic boundaries:
* `source_asset_id`: String identifier matching source asset.
* `source_algorithm`: String algorithm name.
* `source_family`: Source `AlgorithmFamily` value.
* `source_role`: Source `CryptoRole` value.
* `observed_parameters`: Mapping of verified parameter key-values.
* `classical_security_strength`: `ClassicalSecurityStrength` (`BITS_128`, `BITS_192`, `BITS_256`, `LEGACY_112`, `DISALLOWED_SUB_112`, `INDETERMINATE`, `OUT_OF_SCOPE`).
* `classical_bits`: `Optional[int]` indicating integer classical bits of security (e.g. 112, 128, 192, 256).
* `target_equivalence_category`: `Optional[PqcSecurityCategory]` indicating the minimum PQC category needed for security parity (e.g. Category 1 for 128-bit classical primitives).
* `selection_basis`: Detailed narrative explaining the technical basis for proposing candidate parameter sets.
* `mapping_status`: `TargetMappingStatus` (`MAPPED`, `CONDITIONAL`, `NEEDS_REVIEW`, `UNSUPPORTED`, `OUT_OF_SCOPE`).
* `candidate_targets`: Tuple of `CandidateTarget` items (family, parameter set, PQC security category, standard, use case, size metrics, rationale).
* `mapping_rationale`: Human-readable explanation of the mapping logic.
* `standards_references`: Tuple of authoritative standards citations.
* `assumptions_and_questions`: Tuple of unresolved technical questions requiring human engineering review.
* `compatibility_considerations`: Tuple of protocol, certificate, and performance constraints.
* `agility_assessment`: `AgilityAssessment` record.
* `required_human_review`: Boolean flag indicating whether human review is mandatory before proceeding.
* `unmapped_reasons`: Tuple of explicit reasons why an automatic mapping was not made.

---

## 4. Cryptographic Standards Research & Target Mapping Rules

All mapping rules are traceable to official NIST standards:

### Rule Set A: Key Encapsulation Mechanisms (NIST FIPS 203)
* **Standard:** NIST FIPS 203 (*Module-Lattice-Based Key-Encapsulation Mechanism Standard*).
* **Scope:** Asymmetric key agreement and key transport mechanisms:
  * RSA configured for encryption/key establishment (`CryptoRole.KEY_AGREEMENT` or `CryptoRole.ENCRYPTION_DECRYPTION`).
  * Diffie-Hellman / Finite Field DH (`AlgorithmFamily.DH`).
  * Elliptic Curve Diffie-Hellman (`AlgorithmFamily.EC` with `CryptoRole.KEY_AGREEMENT` or `algorithm_name="ECDH"`).
* **Candidate Targets:**
  * **ML-KEM-512** (PQC Category 1: attack resources $\ge$ AES-128 key search).
  * **ML-KEM-768** (PQC Category 3: attack resources $\ge$ AES-192 key search; primary general-purpose baseline).
  * **ML-KEM-1024** (PQC Category 5: attack resources $\ge$ AES-256 key search; CNSA 2.0 mandated).
* **Compatibility Considerations:**
  * Encapsulation/decapsulation paradigm replaces direct public-key encryption or non-interactive DH.
  * Public key expansion: 800 bytes (512), 1,184 bytes (768), 1,568 bytes (1024).
  * Ciphertext expansion: 768 bytes (512), 1,088 bytes (768), 1,568 bytes (1024).
  * Hybrid deployment (e.g. X25519 + ML-KEM-768) recommended during transition.

### Rule Set B: Lattice-Based & Hash-Based Digital Signatures (NIST FIPS 204 & FIPS 205)
* **Standards:**
  * NIST FIPS 204 (*Module-Lattice-Based Digital Signature Standard* — ML-DSA).
  * NIST FIPS 205 (*Stateless Hash-Based Digital Signature Standard* — SLH-DSA).
* **Scope:** Digital signature schemes:
  * RSA configured for signing (`CryptoRole.DIGITAL_SIGNATURE`).
  * ECDSA (`AlgorithmFamily.EC` with `CryptoRole.DIGITAL_SIGNATURE` or `algorithm_name="ECDSA"`).
  * Ed25519 / Ed448 (`AlgorithmFamily.EDWARDS`).
* **Candidate Targets:**
  * **ML-DSA** (FIPS 204):
    * ML-DSA-44 (PQC Category 2: attack resources $\ge$ SHA-256 collision search).
    * ML-DSA-65 (PQC Category 3: attack resources $\ge$ AES-192 key search; primary general-purpose baseline).
    * ML-DSA-87 (PQC Category 5: attack resources $\ge$ AES-256 key search; CNSA 2.0 mandated).
  * **SLH-DSA** (FIPS 205):
    * SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s (PQC Category 1; small signature variant; lattice hedge).
    * SLH-DSA-SHA2-192s / SLH-DSA-SHAKE-192s (PQC Category 3).
    * SLH-DSA-SHA2-256s / SLH-DSA-SHAKE-256s (PQC Category 5).
* **Compatibility Considerations:**
  * Public key and signature sizes are significantly larger than RSA-2048 (256-byte sig) or ECDSA P-256 (64-byte sig).
  * ML-DSA-65: Public key 1,952 bytes; signature 3,309 bytes (~51x expansion over Ed25519).
  * SLH-DSA-128s: Public key 32 bytes; signature 7,856 bytes (~122x expansion over Ed25519).
  * X.509 certificate chains and TLS handshake fragmentation must be evaluated.

### Rule Set C: Symmetric Ciphers & Hash Functions
* **Standards:** NIST SP 800-57 Part 1 Rev. 5, NIST SP 800-131A Rev. 2, FIPS 197.
* **Scope:** AES, DES, 3DES, SHA-1, SHA-2, SHA-3.
* **Mapping Determination:** `OUT_OF_SCOPE` (Symmetric/hash functions are not replaced by public-key PQC algorithms).
* **Recommendations:**
  * For AES-128: Grover's quantum search algorithm reduces effective key search security from 128 to 64 bits. Recommendation is symmetric key expansion to AES-256 (Category 5 equivalent margin).
  * For SHA-1: Cryptographically broken classically (SHAttered, 2017). Transition to SHA-256 or SHA-3 per NIST SP 800-131A Rev. 2.

### Rule Set D: Ambiguous & Unknown Algorithms (Fail-Closed)
* **Scope:** Dynamic algorithm names (e.g. `getattr()`), bare Rijndael, missing roles, unknown families.
* **Mapping Determination:** `NEEDS_REVIEW` or `UNSUPPORTED`.
* **Rationale:** Missing information is never permission to assume a default. Automatic mapping without verified role and parameters is rejected.

---

## 5. Classical Security Strength Classification Rules

The `classify_classical_security_strength` function maps verified parameters strictly to Classical Security Strength in bits per NIST SP 800-57 Part 1 Rev. 5 Table 2 and NIST SP 800-131A Rev. 2:

| Algorithm / Family | Verified Parameter | Classical Strength (Bits) | Classical Status (SP 800-57 / 131A) | Target Equivalence PQC Category | Standard Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RSA / FFDH** | `< 2048` bits | `< 112` bits | `DISALLOWED_SUB_112` | N/A (Disallowed) | NIST SP 800-131A Rev. 2 Table 2 |
| **RSA / FFDH** | `2048` bits | `112` bits | `LEGACY_112` (Acceptable through 2030) | `CATEGORY_1` (Minimum parity) | NIST SP 800-57 Table 2 |
| **RSA / FFDH** | `3072` bits | `128` bits | `BITS_128` (Acceptable) | `CATEGORY_1` (Parity) | NIST SP 800-57 Table 2 |
| **RSA** | `4096` bits | `~140` bits | `BITS_128` (Exceeds 128 bits) | `CATEGORY_1` (Parity) | NIST SP 800-57 Table 2 |
| **RSA / FFDH** | `7680` bits | `192` bits | `BITS_192` (Acceptable) | `CATEGORY_3` (Parity) | NIST SP 800-57 Table 2 |
| **RSA / FFDH** | `15360` bits | `256` bits | `BITS_256` (Acceptable) | `CATEGORY_5` (Parity) | NIST SP 800-57 Table 2 |
| **ECC** | Curve `P-224` | `112` bits | `LEGACY_112` (Acceptable through 2030) | `CATEGORY_1` (Minimum parity) | NIST SP 800-57 Table 2 / FIPS 186-5 |
| **ECC** | Curve `P-256`, `secp256r1`, `Curve25519`, `Ed25519` | `128` bits | `BITS_128` (Acceptable) | `CATEGORY_1` (Parity) | NIST SP 800-57 Table 2 / FIPS 186-5 |
| **ECC** | Curve `P-384`, `secp384r1` | `192` bits | `BITS_192` (Acceptable) | `CATEGORY_3` (Parity) | NIST SP 800-57 Table 2 / FIPS 186-5 |
| **ECC** | Curve `P-521`, `secp521r1` | `256` bits | `BITS_256` (Acceptable) | `CATEGORY_5` (Parity) | NIST SP 800-57 Table 2 / FIPS 186-5 |
| **AES** | Key size `128` | `128` bits | `BITS_128` (Acceptable) | N/A (Symmetric; 64-bit Grover) | FIPS 197 / SP 800-57 Table 2 |
| **AES** | Key size `192` | `192` bits | `BITS_192` (Acceptable) | N/A (Symmetric; 96-bit Grover) | FIPS 197 / SP 800-57 Table 2 |
| **AES** | Key size `256` | `256` bits | `BITS_256` (Acceptable) | N/A (Symmetric; 128-bit Grover) | FIPS 197 / SP 800-57 Table 2 |
| **Legacy (DES, 3DES, MD5, SHA-1)** | Any | `< 112` bits | `DISALLOWED_SUB_112` | N/A (Disallowed) | NIST SP 800-131A Rev. 2 |
| **Missing / Ambiguous Parameters** | Missing key size / curve | Unknown | `INDETERMINATE` | None (Indeterminate) | SP 800-57 §5.6.1 |

---

## 6. Cryptographic Agility Model

ECDAT Phase 4A rejects ungrounded pseudo-numeric agility scoring (e.g. inventing an arbitrary score like "42/100"). Agility assessment is strictly **categorical** and traceable to verified static evidence:

### Agility Levels
* `MODULAR_PROVIDER`: Discovery detected evidence of a dedicated cryptographic wrapper, interface, service, or provider module (e.g. `crypto_wrapper.py`, `crypto_service`, `Security.addProvider`).
* `CONFIGURABLE`: Algorithm selection, key size, or curve is driven by configuration, environment variables, or parameterization.
* `HARDCODED`: Algorithm name or cryptographic parameters are directly hardcoded literals in source code (e.g. `"RSA"`, `2048`, `P-256`).
* `UNEVALUATED`: Asset is a third-party dependency, lacks source code snippet evidence, or evidence is inconclusive.

---

## 7. Unsupported & Ambiguous Cases (Fail-Closed Handling)

1. **Bare Rijndael (`tc02` variant):**
   * Absent explicit evidence of 128-bit block size and AES standardization, Rijndael cannot be assumed to be AES.
   * Mapper sets status to `NEEDS_REVIEW` and classical strength to `INDETERMINATE`.
2. **Dynamic Ciphers (`tc11`):**
   * AST matches indicating dynamic resolution (`getattr()`, variable algorithm names) return `NEEDS_REVIEW` with explicit unmapped rationale.
3. **Missing Roles:**
   * An RSA asset with `CryptoRole.UNKNOWN` cannot be mapped automatically to either ML-KEM or ML-DSA. It returns `CONDITIONAL` with an unresolved question requesting role identification.
4. **Third-Party Dependencies (`tc09`):**
   * Package-level library manifests (`AssetType.LIBRARY_DEPENDENCY`) are not directly mappable to PQC algorithms. They evaluate to `OUT_OF_SCOPE`.

---

## 8. Verification & Test Suite

The test suite in `product/tests/test_migration_target_mapping.py` validates all behavior across 25 unit and adversarial test cases:

1. `test_01_rsa_key_establishment_maps_to_fips_203_ml_kem`: Role-aware mapping to FIPS 203.
2. `test_02_rsa_signature_maps_to_fips_204_and_205`: Role-aware mapping to FIPS 204 and FIPS 205.
3. `test_03_ecdh_maps_to_fips_203_ml_kem`: ECDH mapping to ML-KEM.
4. `test_04_ecdsa_maps_to_ml_dsa_and_slh_dsa`: ECDSA mapping to ML-DSA/SLH-DSA.
5. `test_05_ed25519_maps_to_ml_dsa_and_slh_dsa`: Ed25519 mapping with size considerations.
6. `test_06_symmetric_aes_is_out_of_scope_for_public_pqc`: AES-128 is `OUT_OF_SCOPE` with Grover recommendation.
7. `test_07_sha1_hash_is_out_of_scope_for_public_pqc`: SHA-1 is `OUT_OF_SCOPE` with SHA-2/SHA-3 recommendation.
8. `test_07b_library_dependency_is_out_of_scope`: Dependencies classified as `OUT_OF_SCOPE`.
9. `test_08_unknown_algorithm_evaluates_to_needs_review`: Unknown algorithm fails closed to `NEEDS_REVIEW`.
10. `test_09_bare_rijndael_evaluates_to_needs_review`: Bare Rijndael fails closed to `NEEDS_REVIEW`.
11. `test_10_missing_parameters_evaluates_to_conditional`: Missing parameters return `CONDITIONAL` with review flag.
12. `test_11_nist_classical_security_strength_boundaries`: Evaluates 14 distinct boundary combinations for RSA, ECC, AES, and DES.
13. `test_12_agility_hardcoded_literal_detected`: Detects hardcoded literals.
14. `test_13_agility_configurable_retrieval_detected`: Detects environment variable / config parameterization.
15. `test_14_agility_modular_wrapper_detected`: Detects cryptographic wrapper / helper modules.
16. `test_15_agility_non_source_location_unevaluated`: Non-source location evaluates to `UNEVALUATED`.
17. `test_16_non_mutation_of_phase3_assets`: Asserts input `CryptoAsset` is 100% unmodified.
18. `test_17_immutability_of_mapping_records`: Asserts frozen dataclasses raise on mutation attempts.
19. `test_18_batch_mapping_deterministic_sorting`: Deterministic sorting by `source_asset_id`.
20. `test_19_invalid_asset_type_raises_type_error`: Rejects invalid asset inputs with `TypeError`.
21. `test_20_unsupported_role_combination`: Unsupported role evaluates to `UNSUPPORTED`.
22. `test_21_strict_separation_of_classical_strength_and_pqc_categories`: Asserts RSA-3072 has 128-bit classical strength, Category 1 parity equivalence, and candidate targets carry their own PQC categories.
23. `test_22_candidate_versus_approved_target_semantics`: Asserts mappings produce candidate proposals with selection basis and compatibility disclosures, never claiming approved targets.
24. `test_23_quantum_exposure_distinct_from_classical_disallowance`: Verifies RSA-1024 (< 112 bits disallowed) vs RSA-4096 (140+ bits acceptable) classical distinction despite both being quantum vulnerable.
25. `test_24_ecc_curve_parameter_boundaries`: Evaluates P-224, P-256, P-384, and P-521 curve boundaries.
26. `test_25_unsupported_and_ambiguous_roles_fail_closed`: Verifies unknown roles fail closed to `CONDITIONAL`.

### Execution Command & Results
```powershell
python -m unittest discover -s product/tests -p "test_*.py"
Ran 244 tests in 0.246s
OK
```
* Existing tests (Phase 3 + Baseline): 218
* Phase 4A unit & standards tests: 26
* Total tests: 244 (100% pass, 0 regressions)

### Benchmark Ground-Truth Answer Key Integrity
All 11 benchmark answer keys were verified using SHA-256 hashing:
* `tc01_direct_rsa.json`: `ce25775e739de0b9631c2e50a0491fe2194b68862183d5910a2e8f4fc630e676` [MATCH]
* `tc02_symmetric_aes.json`: `66ea3afa0991c37aba731f8a8fb1702c1d39191307e66ca9562045ac4c2e1648` [MATCH]
* `tc03_ecc_generic.json`: `d1ac52ee5e1b92840c674b3af50456a523aa43b6344b8820ba54343a4e12d1b7` [MATCH]
* `tc04_ecdsa.json`: `b0576f80a28b4dcd1051e8b1d6803600eb8048667d4f7ea3e6dba8c4da3c5897` [MATCH]
* `tc05_ecdh.json`: `779c95c5e90f8abab5a9ec184d41eb98c302f465edc7032b62648f54e4a968e5` [MATCH]
* `tc06_ed25519.json`: `3de3a0315091015b7ef8b8017d21ec0d3fba617214a3d66425ff688091aeeb3d` [MATCH]
* `tc07_sha1_hash.json`: `b25a3c0d33cd60e94d08596c4d408ed368a4af9bafaa6e6b24d4e0615978ec1e` [MATCH]
* `tc08_crypto_wrapper.json`: `e02707f2ff7f653c4612cecac72f0430be106b6a4f9d6ecefcb4f8907b01560a` [MATCH]
* `tc09_dependency_crypto.json`: `adb59bb4f89ad7803a3ac10908521c87a2e5dffa36638bf96b48e28760478294` [MATCH]
* `tc10_misleading_comments.json`: `51be07740356783fbeca1cec00694763c5ee4af786e1a21f81eec002acdaf16d` [MATCH]
* `tc11_ambiguous_dynamic.json`: `e0f91c1eb1b080b41f39446bb4f07eb62c7cb373737a91d81eabb6cec1f068c6` [MATCH]

---

## 9. Limitations & Explicitly Deferred Scope

* **Not a Code Rewriter:** Phase 4A does not modify application source code, configuration files, or build scripts.
* **No Automated Migration Execution:** Target recommendations are decision-support inputs; they do not trigger runtime migrations.
* **Dual-Key Hybrid Schemes:** Composite hybrid transitions (e.g. X25519 + ML-KEM-768 or RSA + ML-DSA) and topological dependency scheduling are deferred to **Phase 4B**.
* **Enterprise Governance & Compliance:** Multi-standard compliance deadlines (CNSA 2.0, BSI TR-02102-1) and executive reporting dashboards are deferred to **Phase 4C**.
