# Phase 4B: Hybrid Transition Schemes & Migration Scheduling Specification & Verification Report

* **Document Version:** 1.0.0
* **Phase:** Phase 4B (Hybrid Transition Schemes & Migration Scheduling)
* **Author:** Principal Software Architect, Senior Cryptography Engineer, QA Lead
* **Date:** September 2026
* **Status:** COMPLETED & VERIFIED

---

## 1. Executive Summary

Phase 4B establishes ECDAT's deterministic, explainable, scanner-agnostic decision-support engine for:
1. **Hybrid Transition Scheme Evaluation:** Evaluating candidate hybrid and composite schemes (protocol-level KEM combiners, composite signatures, and dual-certificate PKI patterns) that bridge classical algorithms and FIPS 203/204/205 post-quantum targets.
2. **Dependency-Aware Migration Scheduling:** Constructing explicit Directed Acyclic Graphs (DAGs) of asset dependencies, detecting dependency cycles, honoring agility constraints, identifying Harvest-Now-Decrypt-Later (HNDL) priorities, and isolating unresolved assumptions behind explicit human-review gates.

The Phase 4B engine adheres strictly to the project constitution:
* Standard library only (Python 3.12+ stdlib; zero external dependencies).
* Pure decision-support: zero source code rewriting, zero automated certificate issuance, zero dynamic scanner subprocess execution.
* Full immutability: frozen domain dataclasses prevent hidden state mutations.
* 100% regression free: 278 total automated tests pass (244 baseline + 34 Phase 4B tests).
* 100% benchmark fidelity: 11 of 11 benchmark ground-truth answer keys remain byte-identical (SHA-256 verified).

---

## 2. Files Created & Modified

### Created Files:
* `product/core/migration/hybrid.py`: Hybrid scheme evaluator mapping canonical cryptographic assets and target mappings to verified candidate hybrid constructions.
* `product/core/migration/scheduler.py`: Dependency graph builder, cycle detector, topological sorter, milestone partitioner, and review-gate generator.
* `product/tests/test_migration_phase4b.py`: Comprehensive test suite containing 30 targeted unit and integration tests.
* `product/docs/ADR-016-hybrid-schemes-and-migration-scheduling.md`: Architecture Decision Record establishing hybrid taxonomy, standards statuses, combiner assumptions, and scheduling invariants.
* `product/docs/PHASE_4B_HYBRID_SCHEMES_AND_SCHEDULING.md`: This comprehensive specification, standards verification, and verification report.

### Modified Files:
* `product/core/migration/models.py`: Added `StandardsStatus`, `HybridConstructionType`, `HybridSchemeCandidate`, `MigrationPhase`, `ReviewGate`, `MigrationMilestone`, and `MigrationSchedule`. Extended `PqcTargetMapping` to include `hybrid_candidates`.
* `product/core/migration/target_mapper.py`: Connected `evaluate_hybrid_options` into `PqcTargetMapper.map_asset` to populate `PqcTargetMapping.hybrid_candidates`.
* `product/core/migration/__init__.py`: Exported all new Phase 4B models, enums, evaluator functions, and scheduler classes.

---

## 3. Architecture & Data Flow

```
[Canonical CryptoAsset] + [Phase 4A PqcTargetMapping] + [Phase 3C Context & Risk]
                                  │
                                  ▼
        ┌──────────────────────────────────────────────────┐
        │  product/core/migration/hybrid.py                │
        │  evaluate_hybrid_options(asset, target_mapping)  │
        └──────────────────────────────────────────────────┘
                                  │
                                  ▼
                     Tuple[HybridSchemeCandidate, ...]
                                  │
                                  ▼
        ┌──────────────────────────────────────────────────┐
        │  product/core/migration/scheduler.py             │
        │  MigrationScheduler.schedule_migration(...)      │
        │                                                  │
        │  1. Collect Discovered Asset Relationships       │
        │  2. Build Dependency Graph (DAG)                 │
        │  3. Detect Cycles (DFS) & Preserve If Present    │
        │  4. Topologically Sort (Kahn's in-degree)        │
        │  5. Identify Agility Blockers & Review Gates     │
        │  6. Partition into Advisory Milestone Groupings  │
        └──────────────────────────────────────────────────┘
                                  │
                                  ▼
                          MigrationSchedule
         ├── Milestones (1: Preparation, 2: Key Exchange,
         │               3: Signatures, 4: Storage, 5: Pure PQC)
         ├── Dependency Graph
         ├── Review Gates (NEEDS_REVIEW, CONDITIONAL, Cycles)
         ├── Blockers (e.g. CODE_REFACTOR_REQUIRED)
         ├── Blocked Assets
         ├── Unresolved Items
         └── Schedule Status ("FEASIBLE" or "BLOCKED_DEPENDENCY_CYCLE")
```

---

## 4. Hybrid Construction Taxonomy

Hybrid schemes are explicitly separated into distinct, non-interchangeable architectural constructions:

1. **`PROTOCOL_LEVEL_KEM` (Protocol-Level Hybrid Key Exchange / KEM Combiner):**
   * Combines classical key agreement (ECDH / DH) with post-quantum KEMs (ML-KEM-768).
   * Key combiner executes at the protocol exchange layer (e.g. TLS 1.3 ClientHello key shares or IKEv2 additional key exchanges).
   * Applicable roles: `CryptographicRole.KEY_AGREEMENT`, `PROTOCOL_HANDSHAKE`.

2. **`COMPOSITE_SIGNATURE` (Unified Composite Signature Formats):**
   * Binds classical signatures (ECDSA, RSA) with post-quantum signatures (ML-DSA, SLH-DSA) under a unified composite AlgorithmIdentifier / OID (e.g. `draft-ietf-lamps-pq-composite-sigs`).
   * Semantics require mandatory dual-verification: both component signatures must be cryptographically valid. Failure of either component causes rejection.
   * Applicable roles: `CryptographicRole.DIGITAL_SIGNATURE`.

3. **`DUAL_SIGNATURE` (Two Independent Signatures / Dual Validation Paths):**
   * Two separate, self-contained signatures produced independently (e.g. CMS dual `SignerInfo` or multi-signature document formats).
   * Verifiers validate either or both signatures according to local policy, preserving legacy compatibility.
   * Applicable roles: `CryptographicRole.DIGITAL_SIGNATURE`.

4. **`DUAL_CERTIFICATE` (PKI Deployment Pattern bound via RFC 9763):**
   * Operational deployment pattern: two distinct X.509 certificates (one classical, one PQC) issued to the same subject identity and bound via RFC 9763 `RelatedCertificate`.
   * Security is strictly partitioned: classical connections receive zero post-quantum protection.
   * Applicable roles: `CryptographicRole.CERTIFICATE_OPERATIONS`, `DIGITAL_SIGNATURE`.

5. **`PROTOCOL_AUTHENTICATION` (Protocol Handshake Authentication Arrangements):**
   * Handshake negotiation mechanisms (e.g. TLS 1.3 Certificate Request / Certificate Verify) where peer authentication is dynamically negotiated.
   * Downgrade prevention relies on transcript hash integrity and server-side policy enforcement.

6. **`APPLICATION_ENVELOPE` (Application-Layer Key Wrapping Combiner):**
   * Dual-wrapped symmetric key establishment for data-at-rest (e.g. NIST SP 800-227 Section 6 and SP 800-56B Rev. 2).

7. **`NONE`:**
   * Primitives that do not admit public-key hybrid constructions (e.g. symmetric ciphers, hashes, library dependencies). Evaluates to empty candidate tuple `()`.

---

## 5. Standards Verification Table

| Scheme Identifier | Construction Type | Classical Component | PQC Component | Reference Document | Standards Status | Combiner / Verification Semantics | Compatibility & Overhead |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `X25519MLKEM768` | `PROTOCOL_LEVEL_KEM` | X25519 (RFC 7748) | ML-KEM-768 (FIPS 203) | `draft-ietf-tls-hybrid-design` | `DRAFT` | Dual-PRF key schedule combiner in TLS 1.3. Passive confidentiality against HNDL preserved if either X25519 or ML-KEM-768 is unbroken. Does NOT provide active quantum resistance if authentication is classical. Downgrade prevention requires TLS 1.3 transcript hash integrity and server enforcement. | Requires TLS 1.3 stack with hybrid group support; +1,184 bytes ClientHello overhead. |
| `SecP256r1MLKEM768` | `PROTOCOL_LEVEL_KEM` | ECDH P-256 (SEC 1) | ML-KEM-768 (FIPS 203) | `draft-ietf-tls-hybrid-design` | `DRAFT` | Dual-PRF key schedule combiner in TLS 1.3. Preserves FIPS 140 classical anchor + post-quantum passive confidentiality. Does not provide active quantum security if authentication is classical. | Requires TLS 1.3 stack; +1,184 bytes ClientHello overhead. |
| `IKEV2_MULTIPLE_KE_MLKEM768` | `PROTOCOL_LEVEL_KEM` | Classical DH / ECDH | ML-KEM-768 (FIPS 203) | `RFC 9370` | `STANDARDIZED` | Multiple Key Exchange rounds (IKE_INTERMEDIATE) combined into IKEv2 SKEYSEED. Passive confidentiality against retro-decryption holds if ML-KEM is secure; classical peer authentication remains vulnerable to active quantum impersonation. | Supported by modern IPsec daemons (strongSwan); extra negotiation round trips. |
| `RSA_OAEP_MLKEM768_DUAL_WRAP` | `APPLICATION_ENVELOPE` | RSA-OAEP 2048+ | ML-KEM-768 (FIPS 203) | `NIST SP 800-56B Rev. 2 / NIST SP 800-227 (Final Sept 2025)` | `PROFILE_DEPLOYMENT_PATTERN` | Dual key-wrapping combiner per NIST SP 800-227 Section 6: symmetric DEK encapsulated using both RSA-OAEP and ML-KEM-768, with DEK derived via KDF(K_rsa \|\| K_kem). Confidentiality preserved if either wrapper is unbroken and KDF enforces strict domain separation. | Application key-management architecture with composite wrapping logic. |
| `MLDSA65-ECDSA-P256-SHA512` | `COMPOSITE_SIGNATURE` | ECDSA P-256 (FIPS 186-5) | ML-DSA-65 (FIPS 204) | `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification: both signatures must be valid under specified hash. Unforgeable if at least one component is secure against EUF-CMA. Signature failure of either component causes rejection. Requires verifier composite OID support. | Requires verifier composite OID support; message size expansion (~3.3 KB). |
| `MLDSA65-RSA3072-PKCS15` | `COMPOSITE_SIGNATURE` | RSA-3072 (FIPS 186-5) | ML-DSA-65 (FIPS 204) | `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification: both RSA-3072 and ML-DSA-65 signatures must verify. Does not provide backward compatibility with legacy single-algorithm verifiers. | Requires verifier composite OID support; message size expansion (~3.7 KB). |
| `SLHDSA128s-ECDSA-P256` | `COMPOSITE_SIGNATURE` | ECDSA P-256 (FIPS 186-5) | SLH-DSA-128s (FIPS 205) | `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification: stateless hash-based signature + ECDSA. High verification overhead. Hedge against structured lattice cryptanalysis. | Requires verifier composite OID support; signature size expansion (~7.8 KB). |
| `DUAL_CERT_ECDSA_MLDSA65` | `DUAL_CERTIFICATE` | ECDSA P-256 Cert | ML-DSA-65 Cert | `RFC 9763 / NIST SP 800-57 Pt 1` | `PROFILE_DEPLOYMENT_PATTERN` | Parallel PKI deployment bound via RFC 9763 RelatedCertificate. Security is strictly partitioned: classical connections receive zero quantum protection. | Dual cert management overhead; client dual-trust anchor support. |
| `DUAL_CERT_RSA_MLDSA65` | `DUAL_CERTIFICATE` | RSA-3072 Cert | ML-DSA-65 Cert | `RFC 9763 / NIST SP 800-57 Pt 1` | `PROFILE_DEPLOYMENT_PATTERN` | Parallel PKI deployment bound via RFC 9763 RelatedCertificate. Security is strictly partitioned: classical connections receive zero quantum protection. | Dual cert management overhead; client dual-trust anchor support. |

---

## 6. Security-Semantic Assumptions & Boundaries

1. **No Universal Mathematical Claims:**
   * Claims of "Security $\ge \max(\text{classical}, \text{PQC})$" or universal unbreakable confidentiality are rejected.
   * Every security property is conditional on specific combiner constructions (e.g. dual-PRF in TLS 1.3), protocol negotiation semantics, and absence of downgrade vulnerabilities.
   * Passive confidentiality against HNDL does NOT provide active quantum resistance if peer authentication remains classical.
   * Downgrade protection relies on transcript hash integrity and server enforcement of hybrid groups.

2. **Standards Status Preservation:**
   * Internet-Drafts (`draft-ietf-tls-hybrid-design`, `draft-ietf-lamps-pq-composite-sigs`) are strictly marked `StandardsStatus.DRAFT`.
   * Ratified RFCs (`RFC 9370`, `RFC 7748`, `RFC 9763`) are marked `STANDARDIZED` or cited as authoritative references for deployment patterns.
   * NIST Special Publications: NIST SP 800-227 is recognized in its Final Publication status (September 18, 2025).

3. **Candidate Target Separation:**
   * All hybrid options are non-binding proposals (`HybridSchemeCandidate`). They do not represent approved organizational targets, compliance authorizations, or binding directives.

4. **Data-at-Rest Architecture Separation:**
   * Symmetric ciphers (e.g., AES-256) are NEVER mapped to hybrid KEMs.
   * AES-256 belongs in `MigrationPhase.DATA_AT_REST` with 256-bit Grover key-expansion recommendations. Key-wrapping dependencies are evaluated as distinct key-management assets.

---

## 7. Migration Scheduling & Dependency Graph Modeling

### Graph Construction & Topological Sequencing
* **Node Definition:** Each canonical cryptographic asset is a discrete node in the dependency graph.
* **Edge Semantics:** A directed edge $A \to B$ indicates that $A$ is a prerequisite for $B$ (e.g., library dependency $A$ must be upgraded before application cryptographic usage $B$ can transition).
* **Cycle Handling:** DFS cycle detection scans the graph. If a cycle is detected, the scheduler:
  1. Preserves the cycle intact without deleting edges.
  2. Sets `schedule_status = "BLOCKED_DEPENDENCY_CYCLE"`.
  3. Marks all participating assets as blocked.
  4. Generates a formal `ReviewGate` describing the cycle for human intervention.
* **Independent Asset Isolation:** Assets without prerequisite relationships are never artificially serialized; they remain parallel.

### Advisory Milestone Groupings
Milestones serve as advisory categorical phases, not rigid chronological mandates:
1. **Milestone 1: `PREPARATION`** — Discovery dependencies, libraries, cryptographic providers, and cryptographic inventory validation.
2. **Milestone 2: `KEY_EXCHANGE_HNDL`** — Session key negotiation, protocol handshakes, and assets exposed to Harvest-Now-Decrypt-Later (HNDL) threats.
3. **Milestone 3: `AUTHENTICATION_SIGNATURES`** — Digital signatures, code signing, PKI certificates, and identity verification.
4. **Milestone 4: `DATA_AT_REST`** — Bulk storage encryption, key-management architectures, and envelope encryption.
5. **Milestone 5: `PURE_PQC`** — Long-term decommissioning of classical hybrid components to achieve pure FIPS 203/204/205 post-quantum posture.

---

## 8. Agility Handling & Review Gates

### Agility Constraints
* Assets with `AgilityLevel.HARDCODED` produce a formal blocker:
  `CODE_REFACTOR_REQUIRED: Hardcoded cryptographic primitive requires structural refactoring to achieve agility.`
* This blocker prevents migration until application code is refactored into a configurable provider/factory.

### Review Gate Triggers
Formal `ReviewGate` records are generated whenever:
1. `mapping_status == TargetMappingStatus.NEEDS_REVIEW`: Ambiguous algorithm family or unmapped primitive.
2. `mapping_status == TargetMappingStatus.CONDITIONAL`: Missing explicit key sizes or unannotated parameters.
3. `confidence != ConfidenceLevel.CONFIRMED`: Unverified detection confidence.
4. Dependency cycles or missing operational architecture context.

---

## 9. Verification & Test Evidence

### Test Execution Summary
* **Command:** `python -m unittest discover -s product/tests -p "test_*.py"`
* **Total Tests Executed:** 278
* **Passing:** 278 (100%)
* **Failures:** 0
* **Errors:** 0
* **Execution Duration:** 0.14s

### Benchmark Ground-Truth Answer Key Integrity
All 11 benchmark answer keys were verified using SHA-256 hashing against established baseline:
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

## 10. Boundaries & Accounting

* **Implemented:** Hybrid construction taxonomy, standards verification model, hybrid candidate evaluator, DAG dependency graph builder, DFS cycle detector, agility blocker generator, review-gate constructor, and advisory milestone partitioner.
* **Tested:** 30 comprehensive unit and integration tests verifying all hybrid combinations, draft status tracking, cycle preservation, immutability, determinism, and data-at-rest isolation.
* **Standards Actually Verified:**
  * NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  * RFC 7748 (X25519 / X448)
  * RFC 9370 (Multiple Key Exchanges in IKEv2)
  * draft-ietf-tls-hybrid-design (TLS 1.3 Hybrid Key Exchange) [Strictly DRAFT]
  * draft-ietf-lamps-pq-composite-sigs (Composite Signatures for PKI) [Strictly DRAFT]
* **Not Implemented:** Automated source code refactoring, runtime certificate generation/deployment, live scanner subprocess invocation, or dynamic network protocol negotiation.
* **Not Independently Verified:** Full Draft-07 runtime CycloneDX schema validation (due to zero external dependency policy).
* **Known Limitations:**
  1. Draft IETF specifications may evolve wire formats or OIDs before final RFC publication.
  2. Static AST analysis cannot verify whether a server or client TLS stack actually supports hybrid groups at runtime.
* **Open Risks:** Operational environments with hardcoded crypto require manual engineering refactoring before PQC hybrid migration can begin.
* **Single Recommended Next Action:** Authorize Phase 4C (Enterprise Governance, Executive Reporting & Remediation Planning).
