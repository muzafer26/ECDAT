# ECDAT MVP Scope Specification

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Governance Goal:** Strict scope containment and anti-feature-creep controls.  

---

## 1. Scope Containment Principles

To prevent feature creep and ensure engineering correctness, the ECDAT project categorizes all capabilities using the MoSCoW methodology (Must have, Should have, Later, Explicitly Out of Scope). 

Under no circumstances will development jump to "Later" or "Out of Scope" items before "Must Have" baseline capabilities pass formal testing and acceptance gating.

---

## 2. Capability Categorization

### 2.1 MUST HAVE (Phase 1 – Phase 6 MVP Baseline)
These features are non-negotiable for the SIH core evaluation:

* **M-01 (Pluggable Scanner Adapter Interface):** A cleanly decoupled abstraction boundary for discovery engines capable of processing local source directories and archives.
* **M-02 (Canonical Normalization Engine):** Transformation of heterogeneous scanner findings into normalized internal representations (`CryptoAsset`, `EvidenceRecord`, `AlgorithmParameters`) distinguishing empirical evidence from derived interpretation.
* **M-03 (Unbroken Evidence Chain):** Precise extraction of file path, line numbers, surrounding code snippet (capped at 5 lines), detection method, and raw payload for every finding.
* **M-04 (CycloneDX 1.7 CBOM Generation):** Export of valid CycloneDX 1.7 JSON CBOM documents containing standard `cryptoProperties`.
* **M-05 (Deterministic Multi-Factor Risk Engine):** Rule-based scoring reflecting algorithm type, key length, quantum vulnerability class (Shor vs Grover), operational role, and detection confidence.
* **M-06 (Role-Aware PQC Migration Mapping):** Deterministic, role-aware mapping of detected quantum-vulnerable primitives to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) replacements (key establishment vs digital signatures vs bulk encryption).
* **M-07 (Local CLI Execution Mode):** A standalone CLI runner capable of scanning directories and producing terminal summaries and CBOM exports without external network calls.
* **M-08 (Phase 1 Seed Corpus & Benchmark Harness):** An initial reproducible test suite of known cryptographic samples (direct RSA, AES, ECC, wrappers, misleading comments) validating precision, recall, and false positive rates.

### 2.2 SHOULD HAVE (Phase 7 – Phase 9 Enhanced MVP)
These features will be implemented only after the "Must Have" baseline passes verification:

* **S-01 (Analyst Web Dashboard):** Interactive UI for visualizing cryptographic inventories, risk breakdown graphs, and evidence snippets.
* **S-02 (Human Review & Triage Workflow):** Ability for analysts to mark findings as `CONFIRMED`, `FALSE_POSITIVE`, or `ACCEPTED_RISK` without overwriting raw evidence.
* **S-03 (Re-scan Diff Engine):** Automated comparison of Scan $N$ vs Scan $N+1$ highlighting retired algorithms, newly introduced primitives, and regressions.
* **S-04 (Upload Mode with Ephemeral Sandbox):** Web-based archive upload with strict sandbox isolation requirements and automatic post-scan data purging.
* **S-05 (CI/CD Agent Runner):** Lightweight runner packaging for integration into automated build pipelines.

### 2.3 LATER (Post-MVP / Future Phases)
Items deferred to post-competition enterprise scaling:

* **L-01 (Active TLS/Network Probing):** Active discovery of runtime cryptographic certificates and cipher suites over live enterprise network interfaces.
* **L-02 (Container Image Extraction):** Deep layer-by-layer inspection of compiled binary shared libraries (`.so`, `.dll`) inside Docker images.
* **L-03 (Automated Pull Request Code Annotations):** GitHub App / GitLab bot commenting cryptographic risk directly onto developer pull requests.
* **L-04 (Advisory Generative AI Summarization):** Optional LLM integration for generating human-readable architectural migration summaries.
* **L-05 (HSM / Cloud KMS Integration):** Direct telemetry ingestion from AWS KMS, Azure Key Vault, or PKCS#11 hardware security modules.

### 2.4 EXPLICITLY OUT OF SCOPE (Forbidden / Rejected)
These items are strictly prohibited to prevent architectural distortion:

* ❌ **Automated One-Click Source Rewriting:** Blindly rewriting developer source code to replace RSA with ML-KEM via AST transforms (high risk of breaking production software).
* ❌ **Universal Algorithm-to-PQC Mapping:** Blindly mapping an algorithm to a single PQC primitive without inspecting operational role (e.g. mapping RSA to ML-KEM when it is used for digital signatures).
* ❌ **Quantum Computer Emulation:** Attempting to simulate quantum key distribution (QKD) or execute Shor's algorithm on quantum circuit emulators.
* ❌ **General SAST/Vulnerability Scanning:** Expanding into generic OWASP top-10 scanning (SQL injection, XSS, CSRF).
* ❌ **Black-Box AI Security Governance:** Permitting an LLM to override deterministic risk scores, suppress findings, or assign compliance status.
* ❌ **Proprietary Encryption Development:** Developing custom ciphers, key generation tools, or runtime cryptographic wrappers.
