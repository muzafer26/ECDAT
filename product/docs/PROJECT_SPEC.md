# ECDAT Project Specification

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Problem Statement ID:** SIH26164  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | **Category:** Software  

---

## 1. Problem Statement & Background

### 1.1 SIH Problem Statement Context
Under Problem Statement SIH26164, the National Technical Research Organisation (NTRO) requires an **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**. The objective is to identify, catalogue, assess, and prioritize cryptographic usage across software repositories, dependencies, containers, configurations, and network endpoints to prepare enterprise digital infrastructure for the Post-Quantum Cryptography (PQC) transition.

### 1.2 The Actual Enterprise Problem Being Solved
Modern enterprise ecosystems run thousands of distributed services, microservices, and applications spanning multiple programming languages and runtime frameworks. Cryptography is rarely centralized:
* Developers embed hardcoded legacy ciphers (e.g., DES, 3DES, MD5, SHA-1).
* Asymmetric algorithms vulnerable to Shor's algorithm (RSA, ECC, ECDSA, Diffie-Hellman) are pervasive in digital signatures, TLS handshakes, session encryption, and token generation.
* Cryptographic libraries are pulled in transitively through deep dependency trees.
* Cryptographic keys and certificates are configured via external environment variables, hardcoded secrets, or legacy keystores.
* Organizations lack an accurate, machine-readable cryptographic inventory. Consequently, they cannot answer fundamental risk questions:
  1. *Where is quantum-vulnerable cryptography located?*
  2. *What data does it protect, and what is the exposure lifetime of that data?*
  3. *Which components must be migrated first to mitigate "Harvest Now, Decrypt Later" (HNDL) attacks?*
  4. *How can an enterprise formally prove that a vulnerable algorithm was actually replaced following a migration sprint?*

ECDAT serves as an enterprise **"Cryptographic X-Ray"** that provides continuous, evidence-grounded visibility and migration verification.

---

## 2. Goals and Non-Goals

### 2.1 Explicit Goals
* **G-01 (Multi-Source Discovery):** Discover cryptographic primitives, algorithms, protocols, certificates, and keys across source code, build dependencies, and configuration artifacts.
* **G-02 (Scanner Agnosticism):** Abstract all discovery engines behind an adapter boundary so tools can be added, benchmarked, or swapped without refactoring the core.
* **G-03 (Verifiable Evidence Chain):** Associate every finding with concrete empirical evidence: file path, line numbers, code snippets, scanner origin, detection method, and raw payload.
* **G-04 (CycloneDX 1.7 CBOM Compliance):** Generate standardized, machine-readable Cryptographic Bill of Materials (CBOM) compliant with CycloneDX 1.7 schema specifications.
* **G-05 (Contextual & Quantum Risk Modeling):** Calculate multi-factor, deterministic risk scores considering algorithm type, key length, quantum vulnerability class, operational role, data sensitivity, and business criticality.
* **G-06 (Role-Aware PQC Migration Decision Support):** Provide role-aware, explainable migration roadmaps aligned with NIST post-quantum standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). ECDAT explicitly rejects universal algorithm-to-PQC replacement:
  * Key establishment / key agreement $\longrightarrow$ ML-KEM or hybrid approaches (e.g. X25519 + ML-KEM-768).
  * Digital signatures $\longrightarrow$ ML-DSA or SLH-DSA.
  * Bulk encryption / decryption $\longrightarrow$ Context-dependent symmetric review (e.g. ensuring AES-256 with authenticated modes).
  * Certificate / PKI signatures $\longrightarrow$ Signature migration path (ML-DSA / SLH-DSA / hybrid X.509 certs).
* **G-07 (Re-scan Verification):** Provide automated diffing between historical scans to empirically verify the removal of legacy algorithms and introduction of PQC primitives.
* **G-08 (Zero-Trust Deployment Architecture):** Support four deployment models (Upload, Local CLI, CI/CD Agent, and On-Premises) using a unified core engine with strict data boundary requirements.

### 2.2 Explicit Non-Goals
* **NG-01 (Not a Quantum Simulator):** ECDAT does not simulate quantum circuits or run quantum attack algorithms (e.g., Grover or Shor simulators).
* **NG-02 (Not an Encryption Product):** ECDAT does not provide runtime encryption services, key management (KMS), or Hardware Security Module (HSM) emulation.
* **NG-03 (Not a Generic SAST/DAST/CVE Scanner):** ECDAT is not a general-purpose security scanner for SQLi, XSS, or generic OWASP Top 10 flaws, except where they intersect with cryptographic vulnerabilities.
* **NG-04 (Not an Automated Code Rewriter):** ECDAT will not blindly rewrite production source code or attempt automated one-click PQC refactoring.
* **NG-05 (Not an Authoritative Black-Box AI):** ECDAT will not delegate risk assessment or migration decisions to an opaque LLM. AI is strictly limited to advisory explanation.
* **NG-06 (Not a Claim of Absolute Coverage):** ECDAT will never assert that zero findings equals zero cryptography; it will explicitly state: *"No detected finding under current discovery coverage"*.
* **NG-07 (Not an Absolute Quantum Security Guarantee):** ECDAT does not treat symmetric primitives (e.g. AES-256) as "absolutely quantum safe", but evaluates them as generally resilient to Grover-style quadratic speedup, subject to the operational security model and implementation correctness.
* **NG-08 (Not a CRQC Emergence Predictor):** ECDAT does not claim to predict the exact date when a Cryptographically Relevant Quantum Computer (CRQC) will emerge. The Mosca model is applied strictly as a migration-planning and prioritization framework.

---

## 3. Target Users & Personas

1. **Enterprise Security Architect / CISO:**
   * Needs high-level executive visibility into enterprise quantum readiness, exposure planning models (Mosca-style lifetime analysis), and compliance posture.
2. **Cryptographic / Security Engineer:**
   * Needs granular evidence, parameter inspection (key length, padding mode, curve name), and verification that deprecated algorithms are fully retired.
3. **Application Developer / Lead:**
   * Needs actionable remediation guidance, exact code locations, and role-appropriate NIST PQC replacement recommendations with minimal architectural disruption.
4. **Compliance & Audit Officer:**
   * Needs exportable, standardized CycloneDX 1.7 CBOM reports with immutable provenance for regulatory compliance.

---

## 4. Core Workflow Lifecycle

ECDAT guides an enterprise through an 8-stage lifecycle:

$$\text{Discover} \longrightarrow \text{Prove} \longrightarrow \text{Inventory} \longrightarrow \text{Understand} \longrightarrow \text{Assess} \longrightarrow \text{Prioritize} \longrightarrow \text{Prepare Migration} \longrightarrow \text{Verify}$$

1. **Discover:** Multi-engine scanning across source files, package manifests, and configuration files.
2. **Prove:** Extraction of raw code evidence, file locations, line ranges, and scanner provenance.
3. **Inventory:** Normalization into a unified Cryptographic Asset Catalog and CycloneDX 1.7 CBOM.
4. **Understand:** Contextual mapping of the cryptographic asset's operational role (e.g., TLS key exchange vs password hashing vs digital signature vs bulk data encryption).
5. **Assess:** Multi-factor deterministic risk calculation combining quantum susceptibility, parameter strength, and exposure.
6. **Prioritize:** Generation of a PQC migration priority queue based on data shelf-life ($X$), estimated migration time ($Y$), and assumed quantum threat horizon ($Z$).
7. **Prepare Migration:** Provision of role-specific, NIST-compliant replacement paths and hybrid transition guidance.
8. **Verify:** Commit-by-commit or release-by-release re-scanning and automated diffing to verify migration completion.

---

## 5. Functional Requirements

* **FR-01 (Multi-Format Ingestion):** Ingest git repositories, archive bundles (ZIP, tar.gz), local filesystem directories, and dependency lockfiles.
* **FR-02 (Pluggable Scanner Harness):** Interface with multiple discovery engines (static AST matchers, semantic regex, dependency analyzers) via standard adapter contracts.
* **FR-03 (Canonical Normalization):** Map heterogeneous scanner outputs into a normalized domain model (`CryptoAsset`, `EvidenceRecord`, `AlgorithmParameters`).
* **FR-04 (CBOM 1.7 Serialization):** Generate, validate, and export CycloneDX 1.7 CBOM documents in JSON format.
* **FR-05 (Deterministic Risk Scoring):** Calculate risk using transparent scoring matrices incorporating algorithm type, key size, cipher mode, and quantum vulnerability class.
* **FR-06 (Role-Aware PQC Transition Advisor):** Map identified legacy algorithms to their NIST FIPS 203/204/205 equivalents and transitional hybrid modes based strictly on operational role.
* **FR-07 (Cryptographic Diff Engine):** Compare Scan $N$ with Scan $N+1$ to identify:
  * Resolved assets (successfully retired)
  * New assets (introduced in code change)
  * Regressive assets (re-introduction of deprecated algorithms)
* **FR-08 (Human Review Annotations):** Enable analysts to tag findings (`CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) while strictly preserving original empirical evidence.

---

## 6. Non-Functional Requirements

* **NFR-01 (Explainability):** Every score, rating, and recommendation must be traceably backed by deterministic logic and inspectable evidence.
* **NFR-02 (Performance & Scalability):** Capable of scanning a repository of 50,000 files in under 3 minutes in local CLI mode without memory exhaustion.
* **NFR-03 (Zero-Trust Input Isolation):** Treat all ingested repositories as potentially hostile. Prevent path traversal, zip bombs, symlink loops, and shell injection.
* **NFR-04 (Maintainability & Modularity):** Decouple discovery adapters from the core analysis engine to ensure third-party scanner churn does not break the system.
* **NFR-05 (Auditability & Provenance):** Maintain immutable cryptographic hashes of scanned files and scan runs to support compliance audits.

---

## 7. Evidence Requirements vs. Derived Interpretation

ECDAT enforces a strict architectural distinction between raw empirical evidence and derived domain interpretation:

### 7.1 Empirical Evidence (Immutable Ground Truth)
Every finding must link to verifiable evidence extracted from the scanned target:
* **Target Relative File Path:** Sanitized repository-relative path.
* **Line Number Range:** Exact start and end line coordinates.
* **Code Context Snippet:** Sanitized excerpt (maximum 5 lines) showing the invocation.
* **Scanner Origin & Version:** Pinned identifier and semantic version of the discovery tool.
* **Detection Method:** Mechanism (`ast_analysis`, `regex_heuristic`, `lockfile_parse`).
* **Raw Scanner Finding:** Unmodified raw payload emitted by the adapter.

### 7.2 Derived Interpretation (Domain Analysis)
* **Normalized Cryptographic Asset:** Canonical name and algorithm family.
* **Cryptographic Parameters:** Extracted key size, cipher mode, padding, or elliptic curve.
* **Operational Role:** Functional role (e.g. key exchange, digital signature, bulk encryption).
* **Detection Confidence:** Explicit multi-tier rating:
  * `CONFIRMED`: Definitive syntactic proof (direct AST instantiation with literal parameters).
  * `LIKELY`: Strong contextual or dependency indicators (standard crypto wrapper invocation or direct manifest package import).
  * `POSSIBLE`: Heuristic or string literal match without confirmed call hierarchy (configuration string mentioning `"RSA"` or ambiguous wrapper).
  * `NEEDS_REVIEW`: Detected anomaly or dynamic pattern where static analysis cannot confirm the underlying primitive.
* **Authoritative Boundary:** Raw scanner outputs are NOT authoritative interpretations. External discovery engines frequently report noisy keywords or proprietary labels; ECDAT's normalization rules derive authoritative classifications from raw evidence.

---

## 8. Trust & Enterprise Data Boundary Requirements

The following statements represent **strict engineering requirements** that must be validated by automated implementation and network-level tests before making enterprise-readiness claims:

1. **Source Code Confidentiality (Requirement):**
   * Local Scanner and CI/CD Agent modes are **REQUIRED** to process source code entirely within the customer perimeter. Zero bytes of source code may be transmitted to external servers. This requirement must be validated by network packet inspection tests during verification.
2. **Ephemeral Sandbox & Deletion (Requirement):**
   * In Upload Mode, archives are **REQUIRED** to be extracted into ephemeral, sandboxed scratch directories and cryptographically purged immediately upon scan completion or failure. This requirement must be verified by filesystem lifecycle tests.
3. **Audit Trail Non-Destructiveness (Requirement):**
   * Human analyst triage reviews (`CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) are **REQUIRED** to create immutable, timestamped review records without overwriting or deleting raw scanner evidence.

---

## 9. Deployment Modes

ECDAT supports four execution models via a unified core:
1. **Upload Mode:** Web-based upload of repository archive for rapid demonstration or ad-hoc evaluation.
2. **Local Scanner Mode:** Standalone zero-network CLI binary executing on the developer's workstation.
3. **Agent Mode:** Lightweight container/runner executing within enterprise CI/CD pipelines (GitHub Actions, GitLab CI).
4. **On-Premises Enterprise Platform:** Multi-tenant cluster deployed in air-gapped or private cloud environments.

---

## 10. AI Boundary Specification

* **Advisory Only:** Generative AI is strictly an optional auxiliary service for explaining complex findings or suggesting code refactoring patterns.
* **Zero Security Authority:** AI models are forbidden from assigning, overriding, or suppressing risk scores or detection confidence.
* **Prompt Injection Defense:** Scanned source code, variable names, and code comments are treated as untrusted input and must never be injected directly into LLM prompt templates without strict escaping and boundary delimiters.
* **Air-Gapped Operation:** All core features of ECDAT must function with 100% fidelity without requiring external LLM API access.

---

## 11. Human-in-the-Loop Review Boundaries

* Automated scans provide baseline evidence and calculated risk.
* Security analysts can update the review state of a finding (`PENDING` $\rightarrow$ `CONFIRMED`, `FALSE_POSITIVE`, `SUPPRESSED`).
* **Non-Destructive Guarantee:** When an analyst marks a finding as `FALSE_POSITIVE`, the original code snippet, scanner output, and risk calculation remain stored in the audit log for provenance.
