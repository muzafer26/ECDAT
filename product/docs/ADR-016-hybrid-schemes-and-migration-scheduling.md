# ADR-016: Hybrid Transition Schemes & Migration Scheduling Architecture

* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** Following the establishment of the Phase 4A target mapping foundation (mapping classical algorithms to FIPS 203/204/205 targets), enterprise post-quantum cryptographic transitions require hybrid mechanisms (combining classical and post-quantum algorithms) to protect against harvest-now-decrypt-later (HNDL) attacks while preserving classical compliance, FIPS 140-3 validations, and existing PKI trust anchors. Furthermore, enterprise migration cannot be deployed instantaneously; assets must be sequenced in a dependency-aware, explainable schedule that accounts for libraries, protocol endpoints, agility constraints, and review gates.
* **Scope Boundary:** Decision-support only. Zero automated code rewriting, zero automated certificate issuance, zero dynamic scanner execution, and zero unverified mathematical security claims.

---

### 1. Hybrid Construction Taxonomy & Boundary Separation

Hybrid schemes must NEVER be treated as a single monolithic or interchangeable category. ECDAT models distinct architectural constructions:

1. **`PROTOCOL_LEVEL_KEM` (Protocol-Level Hybrid Key Exchange / KEM Combiner):**
   - Combines a classical key agreement primitive (e.g., X25519, secp256r1) with a post-quantum KEM (e.g., ML-KEM-768).
   - Occurs at the protocol layer (e.g., TLS 1.3 key share negotiation or IKEv2 multiple key exchanges).
   - Applicable roles: `CryptographicRole.KEY_AGREEMENT`, `PROTOCOL_HANDSHAKE`.

2. **`COMPOSITE_SIGNATURE` (Unified Composite Signature Formats):**
   - Cryptographic composite signature under a single unified OID (e.g. `draft-ietf-lamps-pq-composite-sigs`).
   - Verification semantics require mandatory dual-verification (both component signatures must verify).
   - Applicable roles: `CryptographicRole.DIGITAL_SIGNATURE`.

3. **`DUAL_SIGNATURE` (Two Independent Signatures / Validation Paths):**
   - Two distinct, self-contained signatures produced independently (e.g. CMS dual SignerInfo).
   - Verifiers validate either or both signatures according to local policy, enabling backward compatibility.
   - Applicable roles: `CryptographicRole.DIGITAL_SIGNATURE`.

4. **`DUAL_CERTIFICATE` (PKI Deployment Pattern bound via RFC 9763):**
   - Independent operational deployment pattern where an entity maintains two distinct X.509 certificates (one classical, one PQC) bound via RFC 9763 `RelatedCertificate`.
   - Security is partitioned: legacy clients negotiating classical certificates receive zero PQC protection.
   - Applicable roles: `CryptographicRole.CERTIFICATE_OPERATIONS`, `CryptographicRole.DIGITAL_SIGNATURE`.

5. **`PROTOCOL_AUTHENTICATION` (Protocol Handshake Authentication Arrangements):**
   - Negotiation protocols (such as TLS 1.3 Certificate Request / Certificate Verify) where peer authentication is dynamically negotiated.
   - Downgrade protection relies on transcript hash integrity and server enforcement.

6. **`APPLICATION_ENVELOPE` (Application-Layer Key Wrapping Combiner):**
   - Dual-wrapped key establishment for data-at-rest (e.g. NIST SP 800-227 Section 6 and SP 800-56B Rev. 2).

7. **`NONE` (Inapplicable Primitives):**
   - Symmetric ciphers (`AES`, `3DES`, `ChaCha20`), secure hash functions (`SHA-256`, `SHA-3`), and library dependencies have no public-key hybrid candidate. Evaluates to an empty candidate list (`()`).

---

## 2. Standards Verification Gate & Strict Status Classification

Every candidate hybrid scheme must be classified with an authoritative standards status:

| Scheme Identifier | Construction Type | Classical Component | PQC Component | Authoritative Reference | Standards Status | Security Property & Combiner Semantics | Compatibility Assumptions |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `X25519MLKEM768` | `PROTOCOL_LEVEL_KEM` | X25519 (RFC 7748) | ML-KEM-768 (FIPS 203) | `draft-ietf-tls-hybrid-design` | `DRAFT` | Dual-PRF combiner in TLS 1.3 key schedule. Passive confidentiality against HNDL preserved if either component primitive is unbroken under CDH/IND-CCA2. Does NOT provide active security if handshake authentication is classical. Downgrade prevention requires TLS 1.3 transcript hash integrity and server enforcement. | TLS 1.3 stack with hybrid named group support (0x11ec). Additional ~1,184 bytes ClientHello overhead. |
| `SecP256r1MLKEM768` | `PROTOCOL_LEVEL_KEM` | ECDH P-256 (SEC 1) | ML-KEM-768 (FIPS 203) | `draft-ietf-tls-hybrid-design` | `DRAFT` | Dual-PRF combiner in TLS 1.3 key schedule. Preserves FIPS 140 classical anchor + post-quantum passive confidentiality. Does not provide active quantum security if authentication is classical. | TLS 1.3 stack supporting draft hybrid named group (0x11ed). |
| `IKEV2_MULTIPLE_KE_MLKEM768`| `PROTOCOL_LEVEL_KEM` | Classical DH / ECDH | ML-KEM-768 (FIPS 203) | `RFC 9370` | `STANDARDIZED` | Additional Key Exchange rounds (IKE_INTERMEDIATE) combined in IKEv2 SKEYSEED derivation. Passive confidentiality holds if ML-KEM is secure; classical peer authentication remains vulnerable to active quantum impersonation. | IPsec/IKEv2 daemon supporting RFC 9370 extension. |
| `RSA_OAEP_MLKEM768_DUAL_WRAP`| `APPLICATION_ENVELOPE`| RSA-OAEP 2048+ | ML-KEM-768 (FIPS 203) | `NIST SP 800-56B Rev. 2 / NIST SP 800-227 (Final Sept 2025)` | `PROFILE_DEPLOYMENT_PATTERN` | Dual key-wrapping combiner: symmetric DEK encapsulated using both RSA-OAEP and ML-KEM-768, with DEK derived via KDF(K_rsa \|\| K_kem). Confidentiality preserved if either wrapper is unbroken and KDF enforces strict domain separation. | Application key-management architecture with composite wrapping logic. |
| `MLDSA65-ECDSA-P256-SHA512` | `COMPOSITE_SIGNATURE`| ECDSA P-256 (FIPS 186-5) | ML-DSA-65 (FIPS 204) | `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification semantics: both signatures must be valid under specified hash. Unforgeable if at least one component remains secure against EUF-CMA. Signature failure of either component causes rejection. Requires verifier composite OID support. | PKI and verifier support for composite signature OIDs; message size expansion (~3.3 KB). |
| `MLDSA65-RSA3072-PKCS15` | `COMPOSITE_SIGNATURE`| RSA-3072 (FIPS 186-5) | ML-DSA-65 (FIPS 204) | `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification semantics: both RSA-3072 and ML-DSA-65 signatures must verify. Does not provide backward compatibility with legacy single-algorithm verifiers. | Verifier support for composite signature OIDs; signature size expansion (~3.7 KB). |
| `SLHDSA128s-ECDSA-P256` | `COMPOSITE_SIGNATURE`| ECDSA P-256 (FIPS 186-5) | SLH-DSA-128s (FIPS 205)| `draft-ietf-lamps-pq-composite-sigs` | `DRAFT` | Dual verification semantics: stateless hash-based signature + ECDSA. High verification overhead. Hedge against structured lattice cryptanalysis. | Verifier composite OID support; signature size expansion (~7.8 KB). |
| `DUAL_CERT_ECDSA_MLDSA65` | `DUAL_CERTIFICATE` | ECDSA P-256 X.509 Cert | ML-DSA-65 X.509 Cert | `RFC 9763 / NIST SP 800-57 Pt 1` | `PROFILE_DEPLOYMENT_PATTERN`| Parallel PKI deployment bound via RFC 9763 RelatedCertificate. Security is strictly partitioned: classical connections receive zero quantum protection. | Dual certificate management and client trust store configuration. |
| `DUAL_CERT_RSA_MLDSA65` | `DUAL_CERTIFICATE` | RSA-3072 X.509 Cert | ML-DSA-65 X.509 Cert | `RFC 9763 / NIST SP 800-57 Pt 1` | `PROFILE_DEPLOYMENT_PATTERN`| Parallel PKI deployment bound via RFC 9763 RelatedCertificate. Security is strictly partitioned: classical connections receive zero quantum protection. | Dual certificate management and client trust store configuration. |

---

## 3. Strict Security Semantic Rules

1. **Rejection of Universal Max-Security Formulations:**
   - ECDAT rejects unconditioned claims such as "Security $\ge \max(\text{classical}, \text{PQC})$" or "confidentiality is guaranteed if one algorithm is broken".
   - Hybrid security properties are strictly construction-specific, combiner-dependent, and conditional on protocol negotiation and verification semantics.
   - Passive confidentiality against HNDL does NOT provide active quantum resistance if peer authentication remains classical.
   - Downgrade protection relies on transcript integrity and explicit server-side policy enforcement.

2. **Separation of Candidates from Approved Targets:**
   - All hybrid mappings are candidate transition proposals (`HybridSchemeCandidate`), not binding engineering directives or compliance approvals.

3. **Separation of Symmetric Data-at-Rest from Hybrid KEMs:**
   - AES-256 is never mapped to a hybrid KEM. It belongs in `DATA_AT_REST` with 256-bit Grover resilience recommendations. Key encapsulation or envelope encryption architectures are evaluated as separate key-management dependencies when evidence exists.

---

## 4. Dependency-Aware Migration Scheduling Engine

1. **Directed Acyclic Graph (DAG) Modeling:**
   - The scheduler builds a directed dependency graph where nodes are canonical assets and edges represent prerequisite relationships (e.g. library package must precede application cryptographic usage; transport layer precedes payload operations).
   - Topological sorting (`collections.deque` in-degree traversal) produces deterministic ordering.

2. **Cycle Preservation & Safety Halting:**
   - If a dependency cycle is detected via Depth-First Search (DFS), the scheduler NEVER silently breaks the cycle or invents arbitrary edges.
   - The affected assets are flagged as `BLOCKED_DEPENDENCY_CYCLE`, assigned to a blocking review gate, and the schedule status is marked `BLOCKED_DEPENDENCY_CYCLE`.

3. **Independence Preservation:**
   - Unrelated assets are never artificially serialized. Independent assets remain in parallel milestone groupings without fabricated inter-dependencies.

4. **Agility Blocker Generation:**
   - Assets with `AgilityLevel.HARDCODED` generate an explicit blocker: `CODE_REFACTOR_REQUIRED: Hardcoded cryptographic primitive requires structural refactoring to achieve agility.`

5. **Formal Review Gates:**
   - Any asset with `NEEDS_REVIEW` or `CONDITIONAL` mapping, missing parameters, ambiguous family, or dependency cycles produces a formal `ReviewGate` specifying reason, evidence, missing information, and consequence if unresolved.
