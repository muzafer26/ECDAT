# ECDAT — Phase 0–4 Capability Projection Matrix (Phase D5)

**Status:** AUTHORITATIVE SPECIFICATION  
**Scope:** Complete Traceability from Frozen Product Core (`product/`) to Demo Presentation Layer (`demo/`)  
**Product Core Freeze SHA-256:** `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2`  

---

## 1. Capability Classification Framework

In accordance with Phase D0 Section 18 and Phase D5 Section 12, every capability exposed or documented in the demo is classified into exactly one of three operational states:

1. **Implemented / Core-Integrated:**  
   The capability exists as verified, tested Python code in the frozen `product/core/` engine and is actively executed during demo runs.
2. **Controlled Demo Execution:**  
   The demo executes real core analytical pipelines against curated, ground-truth benchmark fixtures from `product/benchmark/` (rather than an active enterprise CI/CD hook).
3. **Architectural / Future:**  
   The capability is documented or visually represented to establish product roadmap completeness (e.g., Phase 9 verification), but is explicitly disclosed as not executed in the current working demo.

---

## 2. Phase 0–4 Capability Projection Matrix

| Phase | Capability | Actual Core Status | Demo Projection Status | Core Source File | UI Representation & Location |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Phase 0** | Terminology & Trust Model | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/domain/` | Top Navigation subtitle, Tab 1 Overview narrative, and Tab 5 Uncertainty policy. |
| **Phase 1** | Raw Evidence Ingestion | Implemented / Core-Integrated | Controlled Demo Execution | `product/core/evidence/evidence.py` | Tab 4 (Evidence Explorer): raw scanner evidence table, line numbers, and detection method. |
| **Phase 1** | CryptoScan AST Parsing | Implemented / Core-Integrated | Controlled Demo Execution | `product/core/ingestion/adapters/cryptoscan.py` | Tab 2 (Adapters Registry): status `IMPLEMENTED_CORE_INTEGRATED`; Tab 4: syntax-highlighted code snippet. |
| **Phase 1** | Syft SBOM Package Parsing | Implemented / Core-Integrated | Controlled Demo Execution | `product/core/ingestion/adapters/syft.py` | Tab 2 (Adapters Registry): status `IMPLEMENTED_CORE_INTEGRATED`; cataloging package-level dependencies. |
| **Phase 1D**| Finding Normalization | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/normalization/` | Tab 4 (Evidence Explorer): Step 3 in 7-stage Provenance Stepper (`finding` node). |
| **Phase 1D**| Confidence Derivation | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/domain/confidence.py` | Tab 3 (Inventory): Confidence chip (`CONFIRMED`, `INFERRED`, `HEURISTIC`). |
| **Phase 2** | Discovery Adapter Registry | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/ingestion/registry.py` | Tab 2 (Discovery): Adapters Table with capability classifications and limitations. |
| **Phase 2** | Future Scanner Boundaries | Architectural / Future | Architectural / Future | `demo/adapters/registry.py` | Tab 2 (Adapters Table): `sonar`, `codeql`, `sslscan` badged as `ARCHITECTURAL`. |
| **Phase 3** | Canonical Asset Model | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/domain/asset.py` | Tab 3 (Inventory): Canonical assets table with unique deterministic asset IDs. |
| **Phase 3** | CycloneDX 1.7 CBOM | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/cbom/serializer.py` | Tab 3 (Inventory): CBOM component count metric card (`CycloneDX 1.7`). |
| **Phase 3C**| Categorical Risk Derivation | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/risk/evaluator.py` | Tab 5 (Risk): 5 Risk dimension cards (`Priority Tier`, `Risk Category`, `Primary Cause`). |
| **Phase 3C**| Classical Security Assessment| Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/risk/evaluator.py` | Tab 5 (Risk): Classical status card (`INDETERMINATE` for unevidenced key length). |
| **Phase 3C**| Quantum Exposure Classification| Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/risk/evaluator.py` | Tab 5 (Risk): Quantum exposure card (`SHOR_VULNERABLE_ASYMMETRIC` vs `GROVER_REDUCED`). |
| **Phase 3C**| Uncertainty & Gap Analysis | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/risk/explainer.py` | Tab 5 (Risk): Known vs Not Established banner (`observed_facts` vs `missing_facts`). |
| **Phase 3C**| Authoritative Rule Tracing | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/risk/rules/` | Tab 5 (Risk): Triggered rules cards with exact rule ID citations (`R-RISK-06`). |
| **Phase 4A**| Role-Aware PQC Target Mapping| Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/target_mapper.py` | Tab 6 (Migration): Target Primitive card (FIPS 203 ML-KEM for KEM; FIPS 204/205 for Signatures). |
| **Phase 4A**| Symmetric Cipher Exemption | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/target_mapper.py` | Tab 6 (Migration): Evaluates `AES` to `OUT_OF_SCOPE` with Grover rationale. |
| **Phase 4A**| Standardized Parameter Sets | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/models.py` | Tab 6 (Migration): Target Details Table (NIST security categories, public key/ciphertext overhead). |
| **Phase 4B**| Candidate Hybrid Schemes | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/hybrid.py` | Tab 6 (Migration): Evaluated hybrid combiner cards (`RSA_OAEP_MLKEM768_DUAL_WRAP`, composite sigs). |
| **Phase 4B**| Cryptographic Agility Rating | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/agility.py` | Tab 6 (Migration): Agility Card (`HARDCODED` with evidenced code factors). |
| **Phase 4B**| Dependency-Aware Scheduling | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/scheduler.py` | Tab 7 (Plan): Milestone cards (`M2-KEY-EXCHANGE-HNDL`), prerequisites, and agility blockers. |
| **Phase 4B**| Human Review Decision Gates | Implemented / Core-Integrated | Implemented / Core-Integrated | `product/core/migration/scheduler.py` | Tab 8 (Review Gates): Formal review gate card (`GATE-REVIEW-26700200`) and triage actions. |
| **Phase 9** | Post-Migration Verification | Architectural / Future | Architectural / Future | `demo/frontend/index.html` | Tab 9 (Verification): 5-step lifecycle & diff schema badged `CONTROLLED / FUTURE (PHASE 9)`. |

---

## 3. Provenance of Scenario Benchmarks

| Benchmark Scenario | Core Ground Truth | Evaluated Primitive | Target Source File | Demo Scenario Classification |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | `product/benchmark/corpus/seed/tc01_direct_rsa/` | RSA Key Generation | `DirectRSAKeyGen.java:16` | `CONTROLLED_DEMO` (Grounded in benchmark output) |
| **TC-02** | `product/benchmark/corpus/seed/tc02_symmetric_aes/`| AES-GCM Cipher | `DirectAESCipher.java:20` | `CONTROLLED_DEMO` (Grounded in benchmark output) |
| **TC-06** | `product/benchmark/corpus/seed/tc06_ed25519/` | Ed25519 Digital Signature | `DirectEd25519Signature.java:18` | `CONTROLLED_DEMO` (Grounded in benchmark output) |
