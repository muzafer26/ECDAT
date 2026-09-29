# ECDAT System Architecture

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Status:** Architectural Baseline  

---

## 1. Architectural Principles & Status Classifications

In compliance with Phase 0 governance, all architectural components and design decisions are explicitly categorized using the following status designations:
* `[VALIDATED]`: Validated against external authoritative specifications (e.g. CycloneDX 1.7 JSON-Schema, NIST FIPS) or empirical project verification.
* `[APPROVED / ARCHITECTURAL DECISION]`: Formally chosen and specified by the project architecture, pending empirical implementation verification.
* `[PROVISIONAL]`: Requires implementation, experimental verification, or benchmark validation during upcoming phases.

---

## 2. High-Level Architecture Overview

ECDAT is designed as a decoupled, multi-tier pipeline prioritizing scanner agnosticism, deterministic evaluation, and strict security isolation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TARGET INGESTION LAYER                            │
│  [Source Repo / Git]     [Archive ZIP/tar]     [Local Dir]    [CI/CD Agent] │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│          SCANNER-AGNOSTIC ADAPTER BOUNDARY [PROVISIONAL]                    │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────┐  │
│  │ AST Discovery Engine │  │ Semantic Regex Engine│  │ Dependency Parser │  │
│  │ (e.g. CryptoScan/AST)│  │ (Heuristic Rule Base)│  │ (Lockfile Scan)   │  │
│  └──────────┬───────────┘  └──────────┬───────────┘  └─────────┬─────────┘  │
└─────────────┼─────────────────────────┼────────────────────────┼────────────┘
              │                         │                        │
              ▼                         ▼                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│         EVIDENCE CAPTURE & CANONICAL NORMALIZATION [PROVISIONAL]             │
│  ┌─────────────────────────────────┐   ┌─────────────────────────────────┐  │
│  │ RAW EVIDENCE (Immutable Proof)  │   │ DERIVED INTERPRETATION (ECDAT)  │  │
│  │ • File path & line range        │──►│ • Normalized algorithm & variant│  │
│  │ • Bounded code snippet (<=5 ln) │   │ • Extracted parameters & curve  │  │
│  │ • Scanner identity & version    │   │ • Operational cryptographic role│  │
│  │ • Detection method & raw payload│   │ • Confidence classification     │  │
│  └─────────────────────────────────┘   └─────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│        CANONICAL CRYPTO DOMAIN MODEL [APPROVED ARCHITECTURAL DECISION]      │
│  • CryptoAsset (Algorithm, Protocol, Certificate, Key, Token)               │
│  • Cryptographic Role & Parameter Attributes (Key Length, Padding, Curve)   │
└───────────────────┬─────────────────────────────────────┬───────────────────┘
                    │                                     │
                    ▼                                     ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────────┐
│     CYCLONEDX 1.7 CBOM ENGINE        │  │     CONTEXT & RELATIONSHIP ENGINE │
│             [VALIDATED]              │  │             [PROVISIONAL]         │
│  • CycloneDX 1.7 Schema Mapping      │  │  • Asset Call-Graph Traversal     │
│  • Standard JSON Serialization       │  │  • Data Sensitivity Mapping       │
│  • Official Schema Validation        │  │  • Exposure (Internal vs External)│
└───────────────────┬──────────────────┘  └───────────────────┬───────────────┘
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│   DETERMINISTIC EXPLAINABLE RISK ENGINE [PROVISIONAL / APPROVED DIRECTION]   │
│  • Multi-Factor Algorithmic Scoring (Quantum Susceptibility, Key Size)      │
│  • Mosca Planning Model (Lifetime vs Migration vs Threat Horizon)           │
│  • Rule-Based Explanations (Zero Black-Box AI Dependency)                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                ROLE-AWARE PQC MIGRATION ENGINE [PROVISIONAL]                │
│  • Role-Specific Transitions (Key Exchange vs Signature vs Encryption)      │
│  • NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA) Mapping  │
│  • Hybrid Migration Schemes & Priority Queuing                              │
└───────────────────┬─────────────────────────────────────┬───────────────────┘
                    │                                     │
                    ▼                                     ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────────┐
│     RE-SCAN & VERIFICATION ENGINE    │  │       ANALYST CONTROL PLANE       │
│             [PROVISIONAL]            │  │          & UI [PROVISIONAL]       │
│  • Delta / Diffing (Scan N vs N+1)   │  │  • Cryptographic Inventory Views  │
│  • Retirement & Regressive Detection │  │  • Human Review Audit Trail       │
│  • Verification Audit Proofs         │  │  • Optional AI Explainer [Advisory│
└──────────────────────────────────────┘  └───────────────────────────────────┘
```

---

## 3. Detailed Component Architecture

### 3.1 Scanner-Agnostic Adapter Boundary `[PROVISIONAL]`
* **Problem Solved:** External tools (CryptoScan, IBM CBOMkit, pqaudit) have divergent CLI formats, data structures, and lifecycle maintenance. Tightly coupling the core to any single tool creates fragility.
* **Design:** An explicit interface (`IScannerAdapter`) abstracts execution and data parsing. The core platform never imports scanner internals directly.
* **Status:** `[PROVISIONAL]`. Subject to benchmark validation in Phase 1.

### 3.2 Evidence Capture vs. Derived Interpretation Layer `[PROVISIONAL]`
A critical architectural boundary separates **immutable empirical evidence** from **derived domain interpretation**:

1. **Evidence (Empirical Proof):**
   * Target relative file path
   * Start and end line numbers
   * Bounded code context snippet (maximum 5 lines)
   * Discovered scanner identifier and semantic version
   * Detection method (`ast_analysis`, `regex_heuristic`, `manifest_lockfile`)
   * Raw scanner payload / event string
2. **Interpretation (Derived Domain Analysis):**
   * Normalized cryptographic algorithm name and family
   * Algorithm variant and parameters (key length, mode, padding, elliptic curve)
   * Operational cryptographic role (e.g., key exchange vs digital signature vs bulk encryption)
   * Detection confidence (`CONFIRMED`, `LIKELY`, `POSSIBLE`, `NEEDS_REVIEW`)
   * Contextual risk and classification tags
* **Authoritative Rule:** **Raw scanner outputs are NOT authoritative interpretations.** External scanners frequently report raw keywords or vendor-specific labels. ECDAT's normalization engine applies deterministic validation rules to convert raw evidence into authoritative domain interpretations.

### 3.3 Canonical Cryptographic Domain Model `[APPROVED / ARCHITECTURAL DECISION]`
* The internal domain representation is decoupled from serialization formats:
  * `CryptoAsset`: Abstract entity representing a discovered cryptographic element.
  * `Algorithm`: Type, name, family, variant, key size, mode of operation, padding scheme.
  * `Protocol`: TLS, SSH, IPsec, IKE, handshake parameters, cipher suites.
  * `Certificate`: X.509 metadata, subject, issuer, signature algorithm, expiry, key usage.
  * `CryptoKey`: Key type, length, curve, generation parameters, hardcoded/configured flag.

### 3.4 CycloneDX 1.7 CBOM Layer `[VALIDATED]`
* **Specification Alignment:** Aligns strictly with the official CycloneDX 1.7 standard schema for cryptographic assets (`cryptoProperties`).
* **Distinction:**
  $$\text{Internal ECDAT Domain Model} \neq \text{CycloneDX 1.7 Schema}$$
  The internal model is optimized for analysis and risk computation; the CBOM serializer converts internal entities into valid CycloneDX 1.7 JSON format.
* **Status:** `[VALIDATED]`. Validated against the published, authoritative CycloneDX 1.7 schema specifications.

### 3.5 Context & Relationship Layer `[PROVISIONAL]`
* Cryptographic primitives do not exist in isolation. This layer establishes:
  * **Role Mapping:** Distinguishes whether an asymmetric primitive is used for key exchange, signature verification, or certificate signing.
  * **Data Sensitivity:** Correlates the asset with data classifications (e.g., PII, financial, credentials, internal telemetry).
  * **Exposure:** Distinguishes public-facing network endpoints from air-gapped internal microservices.

### 3.6 Deterministic Explainable Risk Engine `[PROVISIONAL / APPROVED ARCHITECTURAL DIRECTION]`
* **Philosophy:** Deterministic rule trees—never black-box machine learning.
* **Quantum Susceptibility Matrix:**
  * Asymmetric (RSA, ECC, ECDSA, DH, DSA) $\rightarrow$ **Vulnerable to Shor's Algorithm** (Critical Quantum Risk).
  * Symmetric (AES-128, 3DES, Blowfish) $\rightarrow$ **Weakened by Grover's Algorithm** (AES-128 search space halved to 64-bit security).
  * Symmetric (AES-256) $\rightarrow$ **Generally considered resilient to Grover-style quadratic search reduction**, subject to the security model and implementation (quantum resistance is not treated as an absolute guarantee).
  * Hash Functions (MD5, SHA-1) $\rightarrow$ Broken classically; SHA-256/SHA-384/SHA-512 remain resilient under current Grover bounds.
* **Mosca-Style Migration Planning Model:**
  * Uses the classical inequality as a migration-planning and risk-prioritization heuristic:
    $$X + Y > Z$$
  * Where parameters are explicitly distinguished:
    * $X$ = **Data Confidentiality Lifetime:** Duration the protected data must remain confidential (e.g. 5, 10, or 30 years).
    * $Y$ = **Estimated Migration Time:** Time required for the enterprise to re-engineer, test, and deploy PQC replacements.
    * $Z$ = **Assumed/Estimated Quantum Threat Horizon:** Working planning assumption for when a Cryptographically Relevant Quantum Computer (CRQC) might emerge.
  * **Explicit Non-Claim:** ECDAT does **NOT** claim to predict the exact date of CRQC realization; the tool provides planning heuristics based on configurable enterprise threat horizon assumptions.

### 3.7 Role-Aware PQC Migration Decision Engine `[PROVISIONAL]`
Migration recommendations are strictly **role-aware**. ECDAT rejects simplistic, universal "RSA $\rightarrow$ ML-KEM" mappings. Migrations are mapped based on operational role:

1. **Key Establishment / Key Agreement Role:**
   * Detected: RSA Key Transport, Diffie-Hellman (DH), ECDH.
   * Target: **ML-KEM (NIST FIPS 203 / Kyber)** or approved hybrid schemes (e.g., X25519 + ML-KEM-768).
2. **Digital Signature Role:**
   * Detected: RSA-PSS, RSA PKCS#1 v1.5 signatures, ECDSA, Ed25519.
   * Target: **ML-DSA (NIST FIPS 204 / Dilithium)** for general signatures, or **SLH-DSA (NIST FIPS 205 / SPHINCS+)** for hash-based state-isolated verification.
3. **Bulk Encryption / Decryption Role:**
   * Detected: Symmetric ciphers (DES, 3DES, AES-128, AES-256).
   * Target: Context-dependent migration decision (e.g., migrate legacy ciphers to AES-256-GCM / ChaCha20-Poly1305; ensure proper key derivation and quantum-resilient key lengths).
4. **Certificate & PKI Signature Role:**
   * Detected: X.509 certificate validation chains using RSA or ECDSA.
   * Target: Structured PKI migration path (Composite/Hybrid X.509 certificates with dual signatures or ML-DSA roots).

### 3.8 Re-scan & Verification Engine `[PROVISIONAL]`
* Enables cryptographic change verification across software releases:
  $$\Delta(\text{Scan}_{t_0}, \text{Scan}_{t_1}) = \{\text{RetiredAssets}, \text{IntroducedAssets}, \text{UnchangedAssets}, \text{Regressions}\}$$
* Proves whether legacy algorithms were completely retired or merely relocated.

---

## 4. Architectural Boundaries and Status Review

| Architecture Layer | Proposed Approach | Status | Verification & Testing Requirement |
| :--- | :--- | :--- | :--- |
| **Ingestion Pipeline** | Ephemeral sandbox extractor with path sanitizer | `[PROVISIONAL]` | **Requirement:** Strict path traversal rejection (`Zip Slip`), symlink blocking, and archive size quotas. Must be verified by adversarial zip tests in Phase 10. |
| **Adapter Interface** | Standardized pluggable Python/CLI abstraction | `[PROVISIONAL]` | **Requirement:** Clean subprocess isolation and fault handling. Must be benchmarked on Phase 1 Seed Corpus. |
| **CycloneDX CBOM** | Direct serialization to CycloneDX 1.7 JSON | `[VALIDATED]` | **Verified:** Validated against official CycloneDX 1.7 JSON-schema specification. |
| **Risk Calculation** | Deterministic multi-factor scoring formula | `[PROVISIONAL / APPROVED DIRECTION]` | **Requirement:** 100% reproducible scoring without AI dependencies. Must be verified against ground truth test cases. |
| **Data Boundary** | Local/Agent zero-source transmission | `[PROVISIONAL]` | **Requirement:** Local and Agent modes are REQUIRED to prevent source code transmission. Must be verified by network-level packet capture tests before enterprise claims. |
| **External Scanners** | Candidate tools (CryptoScan, CBOMkit, pqaudit) | `[PROVISIONAL]` | **Requirement:** Benchmark evaluation against Phase 1 Seed Corpus before adapter selection. |
