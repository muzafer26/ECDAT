# Phase 4B: Cryptographic Standards Correction & Release Gate Report

* **Document Version:** 1.0.0
* **Phase:** Phase 4B Standards Correction & Release Gate
* **Author:** Principal Software Architect, Senior Cryptography Engineer, Standards Auditor
* **Date:** September 2026
* **Repository Baseline Version:** 1.30.0
* **Repository Final Version:** 1.31.0
* **Release Gate Outcome:** **READY FOR REVIEW**

---

## 1. Executive Summary

This report delivers the standards review, semantic corrections, and verification results for ECDAT Phase 4B (*Hybrid Transition Schemes & Migration Scheduling*).

Prior to this review, Phase 4B had implemented preliminary models and tests, but contained several critical standards-semantic inaccuracies and heuristic assumptions:
1. **NIST SP 800-227 Publication Status:** Previously cited as a draft; verified as finalized in September 2025 (*Recommendations for Key-Encapsulation Mechanisms*).
2. **Dual-Certificate PKI Reference:** Previously cited as an Internet-Draft (`draft-ietf-lamps-cert-binding-for-multi-auth`); verified as published as **IETF RFC 9763** (*Related Certificates for Use in Multiple Authentications within a Protocol*).
3. **Overly Broad Hybrid Security Semantics:** Presumed passive confidentiality without explicitly documenting that hybrid key exchange does **not** protect against an active quantum adversary during handshake negotiation if authentication remains classical (RSA/ECDSA), and without detailing downgrade protection dependencies on TLS 1.3 transcript hash integrity and server enforcement.
4. **Signature Taxonomy Conflation:** Combined multi-signature approaches into a generic composite bucket. The taxonomy is now formally refined into four distinct signature/authentication concepts:
   - Unified Composite Signatures (`COMPOSITE_SIGNATURE`)
   - Two Independent Signatures / Validation Paths (`DUAL_SIGNATURE`)
   - Dual Certificates bound via RFC 9763 (`DUAL_CERTIFICATE`)
   - Protocol-Level Handshake Authentication Arrangements (`PROTOCOL_AUTHENTICATION`)
5. **Unevidenced Heuristic in Scheduler:** The scheduler's dependency linker contained a blanket substring check (`"bouncy" in lib_name`) that linked unrelated assets; this was removed in favor of strict, evidenced file-path/code-snippet attribution.

All corrections have been implemented in-place, tested with 34 focused unit tests (278 total automated tests across the repository), and benchmark answer keys were verified 100% byte-identical.

---

## 2. Scope Inspected & Repository Version

* **Repository Version Before:** 1.30.0
* **Repository Version After:** 1.31.0
* **Code Inspected & Modified:**
  - `product/core/migration/models.py`: Enum models, hybrid scheme candidate contracts, and scheduling structures.
  - `product/core/migration/hybrid.py`: Hybrid evaluation logic, standards citations, combiner descriptions, and security properties.
  - `product/core/migration/scheduler.py`: Dependency graph builder, cycle safety, agility blocker generation, and milestone partitioner.
  - `product/core/migration/target_mapper.py`: Phase 4A target mapper integration with hybrid evaluation.
  - `product/core/migration/strength.py`: Classical strength definitions and NIST SP 800-57 Table 2 alignment.
  - `product/tests/test_migration_phase4b.py`: Unit and integration test suite.
  - `product/docs/ADR-016-hybrid-schemes-and-migration-scheduling.md`: Architecture Decision Record.
  - `product/docs/PHASE_4B_HYBRID_SCHEMES_AND_SCHEDULING.md`: Technical specification document.
  - `product/benchmark/answer_keys/tc*.json`: 11 ground-truth oracle answer keys.

---

## 3. Standards Reviewed & Authoritative Status Registry

| Document Identifier | Full Title | Organization / Working Group | Status | Key Normative Clauses / Scope | ECDAT Application & Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NIST FIPS 203** | *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)* | NIST CSRC | Final Standard (Aug 2024) | Parameter sets ML-KEM-512, ML-KEM-768, ML-KEM-1024; IND-CCA2 security. | Primary PQC KEM component in hybrid KEM candidates. `STANDARDIZED`. |
| **NIST FIPS 204** | *Module-Lattice-Based Digital Signature Standard (ML-DSA)* | NIST CSRC | Final Standard (Aug 2024) | Parameter sets ML-DSA-44, ML-DSA-65, ML-DSA-87; EUF-CMA security. | Primary PQC signature component in composite candidates. `STANDARDIZED`. |
| **NIST FIPS 205** | *Stateless Hash-Based Digital Signature Standard (SLH-DSA)* | NIST CSRC | Final Standard (Aug 2024) | SLH-DSA-128s, SLH-DSA-128f, etc.; hedge against structured lattices. | Hedge signature component in composite candidates. `STANDARDIZED`. |
| **NIST SP 800-227** | *Recommendations for Key-Encapsulation Mechanisms* | NIST CSRC | Final Publication (Sept 18, 2025) | Companion to FIPS 203. Section 6 specifies KEM combiners (dual-wrap, concatenation + HKDF). | Authoritative baseline for KEM combiners and envelope encryption. `STANDARDIZED`. |
| **IETF RFC 7748** | *Elliptic Curves for Security* | IETF CFRG | Final RFC (Jan 2016) | Curve25519 (X25519) and Curve448 (X448) Diffie-Hellman functions. | Classical key exchange component for ECDH hybrid candidates. `STANDARDIZED`. |
| **IETF RFC 9370** | *Multiple Key Exchanges in the Internet Key Exchange Protocol Version 2 (IKEv2)* | IETF IPsecME WG | Final Proposed Standard (May 2023) | `IKE_INTERMEDIATE` exchange for up to 7 additional key exchanges combined into SKEYSEED. | Network IPsec/VPN hybrid key exchange. `STANDARDIZED`. |
| **IETF RFC 9763** | *Related Certificates for Use in Multiple Authentications within a Protocol* | IETF LAMPS WG | Final RFC (Oct 2024) | Defines `relatedCertRequest` CSR attribute and `RelatedCertificate` X.509 extension. | Authoritative standard for dual-certificate PKI binding. `STANDARDIZED`. |
| **`draft-ietf-tls-hybrid-design`** | *Hybrid key exchange in TLS 1.3* | IETF TLS WG | Internet-Draft (Work-in-Progress, Informational) | Codepoints `0x11ec` (X25519MLKEM768) and `0x11ed` (SecP256r1MLKEM768); dual-PRF key schedule. | TLS 1.3 draft hybrid groups. Strictly marked `DRAFT`. |
| **`draft-ietf-lamps-pq-composite-sigs`** | *Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for use in X.509 PKI* | IETF LAMPS WG | Internet-Draft (Work-in-Progress, Standards Track) | ASN.1 structures, OIDs, and dual-verification semantics for ML-DSA + RSA/ECDSA. | Composite digital signatures. Strictly marked `DRAFT`. |

---

## 4. Claims Verified, Corrected, or Left Unresolved

### Verified Claims
* **No Universal Max-Security Formulations:** Verified that zero unconditional "$\ge \max(\text{classical}, \text{PQC})$" claims exist in the codebase or models.
* **Separation of Candidates from Approved Targets:** Verified that all hybrid suggestions are modeled as non-binding `HybridSchemeCandidate` structures.
* **Draft vs Standard Demarcation:** Verified that all draft specifications are strictly typed with `StandardsStatus.DRAFT`.
* **Cycle Preservation:** Verified that circular dependencies in the asset graph are preserved intact, marked `BLOCKED_DEPENDENCY_CYCLE`, and added to review gates rather than broken by heuristics.

### Corrected Claims
1. **NIST SP 800-227 Status:** Corrected from `(Draft)` to `(Final Sept 2025)` across `hybrid.py`, `ADR-016`, and documentation.
2. **Dual-Certificate PKI Standard Citation:** Corrected citation from expired/old draft `draft-ietf-lamps-cert-binding-for-multi-auth` to ratified **RFC 9763** (*Related Certificates for Use in Multiple Authentications within a Protocol*).
3. **Passive vs Active Security Semantics:** Updated security descriptions for `X25519MLKEM768`, `SecP256r1MLKEM768`, and `IKEV2_MULTIPLE_KE_MLKEM768` to explicitly state:
   - Secrecy against passive retroactive cryptanalysis (HNDL) is preserved if either component remains unbroken.
   - Active quantum security during handshake negotiation is **not** provided if peer authentication remains classical (RSA or ECDSA).
   - Downgrade prevention strictly requires TLS 1.3 transcript hash integrity and server enforcement of hybrid named groups.
4. **Library Dependency Heuristic Elimination:** Removed `or "bouncy" in lib_name` from `scheduler.py`, preventing unevidenced linkages of unrelated code assets to BouncyCastle dependencies.
5. **Taxonomy Expansion:** Expanded `HybridConstructionType` to formally separate `COMPOSITE_SIGNATURE`, `DUAL_SIGNATURE`, `DUAL_CERTIFICATE`, and `PROTOCOL_AUTHENTICATION`.

### Unresolved Items (Preserved by Policy)
* **Runtime TLS Hybrid Support:** Static AST discovery cannot determine whether a deployed TLS termination endpoint or client browser actually negotiates hybrid named groups at runtime. This remains documented as an unresolved operational prerequisite in `compatibility_assumptions`.
* **Private Key Lifetime & Retention Data:** Retention periods ($X$) remain `UNRESOLVED_INPUT` when absent from source evidence, avoiding fabricated Mosca urgency calculations.

---

## 5. Hybrid KEM Findings

1. **Protocol-Level Hybrid Key Exchange vs Hybrid KEM Construction:**
   - In TLS 1.3 (`draft-ietf-tls-hybrid-design`), the hybrid mechanism is a **protocol-level key exchange combiner**, where an ECDHE shared secret ($SS_{ecdh}$) and an ML-KEM shared secret ($SS_{kem}$) are concatenated into the TLS 1.3 key schedule:
     $$IKM = SS_{ecdh} \parallel SS_{kem}$$
     $$Handshake\_Secret = \text{HKDF-Extract}(\text{Derived\_Secret}, IKM)$$
   - This relies on the **dual-PRF assumption** of HKDF-Extract.
   - In contrast, a standalone **hybrid KEM** (per NIST SP 800-227 Section 6) encapsulates a symmetric key via two independent encapsulations with domain-separated KDF binding.
2. **Downgrade Attack Resistance:**
   - In TLS 1.3, downgrade protection is guaranteed by the `transcript_hash` covering `ClientHello` through `Finished`. An attacker modifying the `ClientHello` to strip hybrid named groups causes a handshake failure during `CertificateVerify` / `Finished` verification.
   - However, if the server's configuration permits classical groups, a legacy client will negotiate classical algorithms without error. Thus, post-quantum confidentiality is only achieved when both client and server enforce hybrid groups.
3. **Active Quantum Attacker Boundary:**
   - A hybrid KEM prevents Harvest-Now-Decrypt-Later (passive eavesdropping).
   - If an active adversary has a Cryptanalytically Relevant Quantum Computer (CRQC) at the time of the handshake, and the server's authentication key is classical RSA or ECDSA, the adversary can forge the signature in `CertificateVerify`, impersonate the server, and mount an active man-in-the-middle attack, completely subverting the hybrid key exchange.
   - This distinction is now explicitly stated in every hybrid KEM candidate's `security_property`.

---

## 6. Composite Signature & Dual Certificate Findings

Four distinct concepts are now formally separated in ECDAT's data model:

1. **Composite Signature Schemes (`COMPOSITE_SIGNATURE`):**
   - Single unified AlgorithmIdentifier and OID (e.g. `draft-ietf-lamps-pq-composite-sigs`).
   - Private key contains $(sk_{classical}, sk_{pqc})$; signature contains $(sig_{classical}, sig_{pqc})$.
   - **Verification semantics:** Dual-verification is mandatory. Both signatures must verify; if either fails, verification fails.
   - **Limitation:** Incompatible with legacy verifiers. Verifiers without composite OID parsers reject the certificate or signature.
2. **Two Independent Signatures / Validation Paths (`DUAL_SIGNATURE`):**
   - Two separate, independent signature objects (e.g. parallel `SignerInfo` in CMS/PKCS#7 or multi-signature document envelopes).
   - Verifiers validate either or both signatures based on local policy.
   - Enables backward compatibility: legacy verifiers check only the classical signature; upgraded verifiers check the PQC signature.
3. **Dual Certificates (`DUAL_CERTIFICATE`):**
   - Two independent X.509 certificates issued to the same end entity (one classical, one PQC), bound via RFC 9763 (`RelatedCertificate` extension and `relatedCertRequest` attribute).
   - **Security is strictly partitioned:** Connections negotiating the classical certificate receive **zero** quantum authentication protection. It is an operational deployment pattern for backward-compatible server migration, not a cryptographic combiner.
4. **Protocol-Level Authentication Arrangements (`PROTOCOL_AUTHENTICATION`):**
   - Dynamic handshake negotiation (e.g. TLS 1.3 `signature_algorithms` and `signature_algorithms_cert`).
   - Security depends on strict server configuration preventing negotiation of insecure or classical-only signature algorithms.

---

## 7. Phase 4A Semantic Consistency Findings

The review verified that Phase 4A's foundational boundaries remain 100% intact:
* **Classical Security Strength $\ne$ PQC Security Category:** RSA-2048 is 112 bits of classical security; it is never labeled PQC Category 1. PQC Category 1 is the minimum parity replacement target.
* **Quantum Exposure $\ne$ Migration Priority:** Shor vulnerability is an intrinsic mathematical property; operational priority incorporates context, external exposure, and agility.
* **Role-Aware Mapping:** AES-256 is evaluated strictly under `CryptographicRole.ENCRYPTION_DECRYPTION` in `MigrationPhase.DATA_AT_REST` with Grover 256-bit recommendations. It is never mapped to a public-key hybrid KEM.
* **Candidate Target $\ne$ Approved Directive:** Target mappings remain advisory proposals for human review.

---

## 8. Migration Scheduler Findings

1. **Topological DAG Sequencing:**
   - Discovered dependencies (library packages providing crypto functions) form directed prerequisite edges in `dependency_graph`.
   - Topological ordering via in-degree traversal dictates scheduling.
2. **Cycle Safety:**
   - Circular dependencies are detected using DFS.
   - Cycles are preserved intact, marked `BLOCKED_DEPENDENCY_CYCLE`, and added to Review Gates. Cycles are never silently deleted.
3. **Independent Asset Isolation:**
   - Independent assets without prerequisite edges remain unchained and parallel.
4. **Agility Blocker Generation:**
   - `AgilityLevel.HARDCODED` produces a formal `CODE_REFACTOR_REQUIRED` blocker.
5. **No Fabricated Dates or Deadlines:**
   - Missing operational information evaluates to `UNRESOLVED_INPUT` instead of guessing compliance dates or business deadlines.

---

## 9. Exact Implementation Changes

1. [`product/core/migration/models.py`](file:///d:/SIH/product/core/migration/models.py):
   - Expanded `HybridConstructionType` to include `DUAL_SIGNATURE` and `PROTOCOL_AUTHENTICATION`.
   - Added string aliases for flexible parsing (`PROTOCOL_HYBRID_KEM`, `COMPOSITE`, `DUAL_CERT`).
2. [`product/core/migration/hybrid.py`](file:///d:/SIH/product/core/migration/hybrid.py):
   - Updated NIST SP 800-227 status from draft to Final Publication (Sept 2025).
   - Updated Dual-Certificate reference from draft to RFC 9763.
   - Revised `security_property` strings across all 9 candidate schemes to articulate passive vs active security and downgrade protection requirements.
3. [`product/core/migration/scheduler.py`](file:///d:/SIH/product/core/migration/scheduler.py):
   - Removed heuristic `"bouncy" in lib_name` from library dependency extraction, ensuring library prerequisites are established strictly from evidenced file paths or code snippets.
4. [`product/tests/test_migration_phase4b.py`](file:///d:/SIH/product/tests/test_migration_phase4b.py):
   - Added 4 new focused tests (tests 31–34) verifying SP 800-227 Final citation, RFC 9763 citation, passive/active/downgrade security properties, refined taxonomy separation, and graceful fallback on invalid scheme inputs.
5. Documentation & State:
   - Updated [`product/docs/ADR-016-hybrid-schemes-and-migration-scheduling.md`](file:///d:/SIH/product/docs/ADR-016-hybrid-schemes-and-migration-scheduling.md).
   - Updated [`product/docs/PHASE_4B_HYBRID_SCHEMES_AND_SCHEDULING.md`](file:///d:/SIH/product/docs/PHASE_4B_HYBRID_SCHEMES_AND_SCHEDULING.md).
   - Updated [`product/docs/PROJECT_STATE.md`](file:///d:/SIH/product/docs/PROJECT_STATE.md).

---

## 10. Tests and Actual Results

### Full Test Suite Execution
* **Command:** `python -m unittest discover -s product/tests -p "test_*.py"`
* **Total Tests Ran:** **278** (244 baseline + 34 Phase 4B tests)
* **Results:** **278 passed, 0 failed, 0 errors**
* **Duration:** 0.142s

### Benchmark Ground-Truth Answer Key Hashes (SHA-256)
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

11/11 benchmark answer keys are 100% byte-identical.

---

## 11. Remaining Limitations & Open Risks

1. **Draft IETF Standards:**
   - `draft-ietf-tls-hybrid-design` and `draft-ietf-lamps-pq-composite-sigs` remain active Internet-Drafts. While widely implemented in pre-standard form, wire formats, OIDs, and named group codepoints may shift upon final RFC publication.
2. **Static AST Visibility vs Runtime Protocol Capability:**
   - ECDAT static discovery observes source code invocations and dependencies. It cannot independently verify whether a runtime network endpoint actually supports or negotiates post-quantum hybrid extensions.
3. **No Automatic Code Modification:**
   - ECDAT provides decision support only; automated refactoring of `AgilityLevel.HARDCODED` assets into agile crypto providers requires human software engineering.
4. **Git Absence in Workspace:**
   - Version control state lacks `.git` repository in the local evaluation environment (`fatal: not a git repository`). Strict change verification is preserved via content-addressable SHA-256 hashes.

---

## 12. Release Decision

**Release Outcome:** **READY FOR REVIEW**

### Rationale
All required cryptographic standards corrections, taxonomy distinctions, security-semantic caveats, and scheduler DAG enhancements have been implemented and verified. The 278-test automated suite passes with 0 regressions, and 11/11 benchmark answer keys remain byte-identical. In accordance with the release gate governance, Phase 4B is now submitted as **READY FOR REVIEW** for owner inspection and authorization before freezing.
