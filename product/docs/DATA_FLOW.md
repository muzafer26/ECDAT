# ECDAT End-to-End Data Flow Specification

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Objective:** Complete traceability of data transformation from untrusted source to verified cryptographic report.  

---

## 1. End-to-End Data Progression Map

Data flows through ECDAT across eight distinct pipeline stages. Every transformation preserves provenance and enforces strict boundaries:

$$\begin{matrix}
\text{[Target Input]} & \xrightarrow{\text{Stage 1}} & \text{[Discovery Ingestion]} & \xrightarrow{\text{Stage 2}} & \text{[Raw Evidence Capture]} \\
& & & & \downarrow \text{Stage 3} \\
\text{[Crypto Asset Inventory]} & \xleftarrow{\text{Stage 4}} & \text{[Canonical Normalization]} & & \text{[CycloneDX 1.7 CBOM]} \\
\downarrow \text{Stage 5} & & & & \\
\text{[Contextual Analysis]} & \xrightarrow{\text{Stage 6}} & \text{[Deterministic Risk]} & \xrightarrow{\text{Stage 7}} & \text{[Role-Aware PQC Roadmap]} \\
& & & & \downarrow \text{Stage 8} \\
& & & & \text{[Verification & Audit Report]}
\end{matrix}$$

---

## 2. Stage-by-Stage Specifications

### Stage 1: Target Ingestion & Extraction
* **Input:** Raw source repository, Git URL, archive file (ZIP, TAR.GZ), or directory path.
* **Output:** Extracted filesystem hierarchy in an isolated ephemeral directory (`/tmp/ecdat_run_<id>`).
* **Trust Level:** **Hostile / Untrusted.**
* **Persistence:** Ephemeral scratch volume. **Requirement:** Extraction engine is REQUIRED to cryptographically purge and shred the scratch directory immediately upon scan completion or failure.
* **Provenance:** Cryptographic hash (SHA-256) of the raw archive bundle recorded in the scan audit log.

### Stage 2: Discovery Execution
* **Input:** Read-only access to the sandboxed filesystem directory.
* **Output:** Raw scanner-specific outputs (AST event streams, JSON dumps, regex capture sets).
* **Trust Level:** **Untrusted.** (Scanner output may contain unescaped content extracted from attacker-controlled comments or variable names).
* **Persistence:** Temporary in-memory or ephemeral intermediate JSON.
* **Provenance:** Pinned Scanner ID, Scanner Semantic Version, and execution timestamp.

### Stage 3: Normalization & Evidence vs. Interpretation Boundary
* **Input:** Raw scanner findings and target source files.
* **Processing Boundary:** Strict separation of immutable empirical proof from derived analysis:
  * **Empirical Evidence:** Relative file path, start/end line coordinates, sanitized code snippet (maximum 5 lines), scanner ID/version, detection method, and unmodified raw payload.
  * **Derived Interpretation:** Normalized algorithm family, parameter extraction (key size, padding, curve), operational cryptographic role, and detection confidence level (`CONFIRMED`, `LIKELY`, `POSSIBLE`, `NEEDS_REVIEW`).
* **Authoritative Rule:** Raw scanner outputs are NOT authoritative interpretations. External tools frequently report noisy or non-standard keyword hits; ECDAT's normalization engine derives authoritative domain interpretations from raw evidence.
* **Trust Level:** **Semi-Trusted** (Sanitized, bounded text strings; absolute host paths stripped to relative repository paths).
* **Persistence:** In-memory during pipeline execution; committed to pipeline bus.
* **Provenance:** Unbroken link from normalized record to raw evidence and source coordinates.

### Stage 4: Canonical Domain Modeling & CBOM Serialization
* **Input:** Normalized evidence and derived interpretation records.
* **Output:** Canonical `CryptoAsset` entities (Algorithms, Protocols, Certificates, Keys) and standard CycloneDX 1.7 CBOM JSON document.
* **Trust Level:** **Trusted Internal Model.**
* **Persistence:** Persisted in PostgreSQL/SQLite findings database; CBOM exported as file artifact.
* **Provenance:** Globally unique finding UUID (`finding_id`) linked to parent `scan_id` and normalized schema version.

### Stage 5: Context & Relationship Resolution
* **Input:** Canonical `CryptoAsset` inventory, AST call-graph metadata, application manifest data, and environment configurations.
* **Output:** Contextual metadata attributes:
  * **Operational Role:** Key establishment/agreement, digital signature, bulk data encryption, password hashing, certificate signing.
  * **Exposure:** Public-facing network endpoint vs internal microservice.
  * **Data Classification:** PII, credentials, financial records, internal telemetry.
* **Trust Level:** **Trusted Internal Model.**
* **Persistence:** Associated with `CryptoAsset` database records.
* **Provenance:** Resolution rule ID and heuristic confidence tag.

### Stage 6: Deterministic Risk Calculation
* **Input:** Contextualized `CryptoAsset` records and static Cryptographic Knowledge Base (NIST SP 800-131A, FIPS 203/204/205 quantum parameters).
* **Risk Evaluation:**
  * Evaluates quantum susceptibility (Shor's algorithm impact on asymmetric cryptography; Grover's quadratic search reduction on symmetric primitives).
  * Symmetric ciphers (e.g. AES-256) are evaluated as generally resilient to Grover search reduction subject to security model and implementation (not an absolute guarantee).
  * Applies the Mosca-style planning model ($X + Y > Z$) distinguishing data confidentiality lifetime ($X$), estimated migration time ($Y$), and assumed quantum threat horizon ($Z$). ECDAT does not claim to predict the exact date of CRQC emergence.
* **Output:** Numerical risk score ($0.0 - 10.0$), Risk Severity Tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and explicit mathematical explanation string.
* **Trust Level:** **Trusted Internal Model.**
* **Persistence:** Persisted alongside finding records.
* **Provenance:** Deterministic Risk Formula Version (`risk_engine_v1.0`).

### Stage 7: Role-Aware PQC Migration Decision Mapping
* **Input:** Risk-scored assets categorized by quantum vulnerability class and operational role.
* **Output:** Prioritized migration queue with role-aware replacement mappings:
  * **Key Establishment / Key Agreement:** Targeted for **ML-KEM (NIST FIPS 203)** or approved hybrid schemes (e.g. X25519 + ML-KEM-768).
  * **Digital Signatures:** Targeted for **ML-DSA (NIST FIPS 204)** or **SLH-DSA (NIST FIPS 205)**.
  * **Bulk Encryption / Decryption:** Context-dependent symmetric review (e.g. ensuring AES-256 with authenticated modes).
  * **Certificate & PKI Chains:** Targeted for signature migration paths (ML-DSA / SLH-DSA / hybrid X.509 certs).
  * *Negative Rule:* Universal algorithm-to-PQC replacement (e.g. blindly mapping RSA to ML-KEM without role inspection) is strictly forbidden.
* **Trust Level:** **Trusted Internal Model.**
* **Persistence:** Exportable migration roadmap report.
* **Provenance:** NIST Post-Quantum Cryptography Standard Reference (FIPS 203, FIPS 204, FIPS 205).

### Stage 8: Verification & Audit Reporting
* **Input:** Current scan results, baseline/historical scan results (Scan $N-1$), and human analyst triage annotations.
* **Output:** Verification Delta Report ($\Delta(\text{Scan}_{t_0}, \text{Scan}_{t_1})$), Compliance Audit Ledger, and CycloneDX 1.7 CBOM Export.
* **Trust Level:** **Trusted Certified Output.**
* **Persistence:** Permanent historical audit log in enterprise storage.
* **Provenance:** Cryptographically signed report bundle linking Git commit SHA, scan timestamp, analyst signatures, and immutable evidence records.
