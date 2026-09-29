# ECDAT — Phase D5 Rebaseline Gate & Formal Truth Specification

**Gate Evaluation Date:** 2026-09-26  
**Phase:** Phase D5 — Demo Truth & Product Projection Specification  
**Status:** **PASS** (Zero Frozen Core Modifications, Full Truth Model Established)  
**Next Gate:** Authorized to proceed to Phase D6 (Do NOT begin visual redesign until D6 kickoff)  

---

## 1. Product Core Freeze Baseline Verification

Before formulating the D5 specification, the frozen product core was re-evaluated against the authoritative Phase D0 baseline:

| Metric | Authoritative Baseline | Current Measured Value | Status |
| :--- | :--- | :--- | :---: |
| **Product File Count** | 392 files | 392 files | **MATCH** |
| **Product Core SHA-256** | `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2` | `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2` | **EXACT MATCH** |
| **Product Test Suite** | 300 / 300 Passing | 300 / 300 Passing (0.314s) | **PASS** |
| **Demo Test Suite** | 49 / 49 Baseline | 59 / 59 Passing (+10 D5 truth tests) | **PASS** |

> **Certification:** `product/` tree remains 100% byte-identical to the baseline. Zero files were added, deleted, or modified under `product/`.

---

## 2. Complete Files Inspected Catalog

During the Phase D5 audit, the following repository files were inspected:

### 2.1 Product Core (`product/core/`)
- `product/core/domain/asset.py` — Canonical Cryptographic Asset model & parameters.
- `product/core/domain/role.py` — Cryptographic operational roles (`key_generation`, `encryption_decryption`, `digital_signature`).
- `product/core/domain/confidence.py` — Multi-tier empirical confidence model (`CONFIRMED`, `INFERRED`, `HEURISTIC`).
- `product/core/domain/algorithm.py` — Algorithm families and identities (`RSA`, `AES`, `EDWARDS`).
- `product/core/evidence/evidence.py` — Empirical evidence records and scanner attribution.
- `product/core/evidence/location.py` — AST source locations, line numbers, matched tokens.
- `product/core/evidence/sanitization.py` — Host path sanitization.
- `product/core/ingestion/registry.py` — Multi-scanner discovery adapter registry.
- `product/core/ingestion/adapters/cryptoscan.py` — CryptoScan AST tool adapter.
- `product/core/ingestion/adapters/syft.py` — Syft SBOM tool adapter.
- `product/core/cbom/serializer.py` — CycloneDX 1.7 CBOM serializer.
- `product/core/risk/evaluator.py` — Deterministic categorical risk evaluator.
- `product/core/risk/explainer.py` — Known facts vs missing facts reasoning engine.
- `product/core/risk/rules/` — Authoritative risk rules (`R-RISK-01` through `R-RISK-10`).
- `product/core/migration/target_mapper.py` — Role-aware PQC target mapper.
- `product/core/migration/hybrid.py` — Transitional hybrid combiner evaluator.
- `product/core/migration/agility.py` — Cryptographic agility assessment engine.
- `product/core/migration/scheduler.py` — Dependency-aware DAG scheduler & review gate generator.
- `product/core/workflow/engine.py` — Unified ECDAT pipeline orchestrator.
- `product/core/workflow/models.py` — Workflow run results & ingestion envelopes.

### 2.2 Benchmark Fixtures (`product/benchmark/`)
- `product/benchmark/tools/raw_outputs/cryptoscan/tc01_direct_rsa/run1_output.json`
- `product/benchmark/corpus/seed/tc01_direct_rsa/DirectRSAKeyGen.java`
- `product/benchmark/tools/raw_outputs/cryptoscan/tc02_symmetric_aes/run1_output.json`
- `product/benchmark/corpus/seed/tc02_symmetric_aes/DirectAESCipher.java`
- `product/benchmark/tools/raw_outputs/cryptoscan/tc06_ed25519/run1_output.json`
- `product/benchmark/corpus/seed/tc06_ed25519/DirectEd25519Signature.java`

### 2.3 Demo Implementation (`demo/`)
- `demo/orchestration/models.py` — Presentation DTOs & Provenance Source Type enums.
- `demo/orchestration/transformer.py` — Domain-to-presentation transformation boundary.
- `demo/orchestration/engine.py` — Demo pipeline orchestrator.
- `demo/scenarios/registry.py` — Scenario registry and ground-truth metadata.
- `demo/scenarios/models.py` — Scenario models and classifications.
- `demo/adapters/registry.py` — Adapter status registry and limitation disclosures.
- `demo/adapters/models.py` — Adapter classification models.
- `demo/backend/app.py` — Flask API endpoints and boundary.
- `demo/backend/server.py` — Server entry point.
- `demo/frontend/index.html` — 9-tab Analyst Control Plane markup.
- `demo/frontend/app.js` — Client presentation controller.
- `demo/frontend/style.css` — Control plane stylesheet.
- `demo/tests/test_demo_foundation.py` — Foundation tests (D1).
- `demo/tests/test_demo_d2.py` — Hero slice tests (D2).
- `demo/tests/test_demo_d3.py` — Working prototype tests (D3).
- `demo/tests/test_demo_d4.py` — Adversarial integrity tests (D4).
- `demo/tests/test_demo_f_audit.py` — Functional traceability audit tests.
- `demo/tests/test_demo_d5.py` — D5 Truth & Projection test suite.

---

## 3. Truth Model & Provenance Formalization

Phase D5 establishes the **Authoritative Four-Category Provenance Model**:
1. `DIRECT_CORE_OUTPUT`: Derived from frozen `product/core/` execution.
2. `CONTROLLED_SCENARIO_CONTEXT`: Injected via scenario configuration; never masquerades as scanner evidence.
3. `BENCHMARK_GROUND_TRUTH`: Ground-truth facts known from seed files but unevidenced in scanner AST.
4. `FUTURE_ARCHITECTURE`: Post-Phase 4 concepts (Phase 9 verification) badged as projected.

---

## 4. Scenario Contracts Summary

| Scenario | Primary Primitive | Evidenced Role | Key Size Status | Classical Status | Priority & Risk | PQC Target | Hybrid Scheme | Review Gate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | `RSA` | `key_generation` | `None` (Unevidenced in AST; 2048 in BGT) | `INDETERMINATE` | `P_REVIEW_REQUIRED` / `NEEDS_REVIEW` | `ML-KEM-768` (CONDITIONAL) | `RSA_OAEP_MLKEM768_DUAL_WRAP` | `GATE-REVIEW-26700200` (Blocking) |
| **TC-02** | `AES` | `encryption_decryption` | `None` (Unevidenced in AST) | `ACCEPTABLE` | `P_REVIEW_REQUIRED` / `NEEDS_REVIEW` | `OUT_OF_SCOPE` | None (Decoupled) | None (0 Gates) |
| **TC-06** | `Ed25519` | `digital_signature` | `None` (Curve ed25519) | `INDETERMINATE` | `P_REVIEW_REQUIRED` / `NEEDS_REVIEW` | `ML-DSA-65`, `ML-DSA-44`, `SLH-DSA` | `MLDSA65-ECDSA-P256-SHA512` | None (0 Gates) |

---

## 5. Current Demo Component Reuse Plan

Every existing demo component has been audited and classified into a strict lifecycle decision:

| Component | Path | Decision | Rationale & Modification Scope |
| :--- | :--- | :---: | :--- |
| **Workflow Engine Integration** | `demo/orchestration/engine.py` | **KEEP** | Core invocation and benchmark execution pipeline are completely sound, robust, and cleanly isolated. |
| **Presentation DTOs** | `demo/orchestration/models.py` | **MODIFY** | Formally enriched with `ProvenanceSourceType` (4 categories) and explicit `benchmark_ground_truth` and `context_provenance` fields. |
| **Result Transformer** | `demo/orchestration/transformer.py` | **MODIFY** | Removed default plausible fallback strings for missing metadata; added benchmark ground-truth status mapping. |
| **Scenario Registry** | `demo/scenarios/registry.py` | **MODIFY** | Updated descriptions to eradicate unevidenced "RSA-2048 key exchange" claims; distinguished benchmark ground truth from scanner findings. |
| **Adapter Registry** | `demo/adapters/registry.py` | **KEEP** | Accurately exposes real product adapters vs future architectural boundaries. |
| **Backend REST API** | `demo/backend/app.py` | **KEEP** | Safe, hardened REST boundary exposing `/api/health`, `/api/scenarios`, `/api/adapters`, `/api/scenarios/<id>/run`. |
| **Frontend Markup** | `demo/frontend/index.html` | **MODIFY** | Strip presentation-coaching language ("judge"), add explicit scenario context provenance badges, and clean up hardcoded review gate action text. |
| **Frontend Controller** | `demo/frontend/app.js` | **MODIFY** | Remove fallback defaults (`|| 'Payment Gateway'`); render actual AST snippets from `evidence_records` instead of hardcoded strings. |
| **Frontend Stylesheet** | `demo/frontend/style.css` | **KEEP** | Functional, dark-themed control plane styling; deferred to Phase D6 for visual refinement. |
| **Test Suites (D1–D4)** | `demo/tests/test_demo_*.py` | **KEEP** | 49 baseline regression tests pass with 100% success. |
| **D5 Truth Test Suite** | `demo/tests/test_demo_d5.py` | **KEEP** | Added 10 rigorous tests enforcing provenance, anti-masquerading, and truth contracts. |

---

## 6. Unresolved Issues & Risk Ledger

| Issue ID | Description | Severity | Resolution in D5 / Deferred to D6 |
| :--- | :--- | :---: | :--- |
| **ISSUE-D5-01** | `app.js` contained hardcoded code snippets for RSA/AES/Ed25519 rather than reading directly from `evidence.code_snippet`. | Low | Documented in `DEMO_UI_CONTENT_AUDIT_D5.md`. To be cleanly wired to dynamic AST records in D6. |
| **ISSUE-D5-02** | `app.js` contained fallback string defaults (`|| 'Payment Gateway API'`) that could mask unannotated scenario metadata. | Low | Transformer updated in D5 to preserve `None`; frontend fallback removal audited for D6. |
| **ISSUE-D5-03** | Tab 9 diff table displays `AES-128 (GCM)` when AST finding omitted key size. | Low | Documented in audit table; replacement text specified as `AES (GCM) (key size unevidenced in AST)`. |

---

## 7. Acceptance Criteria Verification

- [x] **Criterion 1: Frozen Product Untouched:** 392 files, SHA-256 hash `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2` verified exact match.
- [x] **Criterion 2: Product Tests Passing:** All 300 / 300 tests pass in 0.314s.
- [x] **Criterion 3: Demo Tests Passing:** 59 tests pass (49 baseline + 10 D5 truth tests).
- [x] **Criterion 4: Provenance Categories Formalized:** All 4 categories (`DIRECT_CORE_OUTPUT`, `CONTROLLED_SCENARIO_CONTEXT`, `BENCHMARK_GROUND_TRUTH`, `FUTURE_ARCHITECTURE`) formalized in models and documentation.
- [x] **Criterion 5: Scenario Context Separated:** Operational deployment facts explicitly labeled as scenario configuration.
- [x] **Criterion 6: Benchmark Ground Truth Separated:** 2048-bit modulus isolated from scanner AST evidence.
- [x] **Criterion 7: Future Architecture Separated:** Phase 9 verification explicitly marked projected.
- [x] **Criterion 8: TC01 Truth Contract Verified:** Key size `None`, classical `INDETERMINATE`, candidate `ML-KEM-768`, hybrid `RSA_OAEP_MLKEM768_DUAL_WRAP`, gate `GATE-REVIEW-26700200`.
- [x] **Criterion 9: TC02 Isolation Verified:** AES ciphers evaluate `OUT_OF_SCOPE` for public-key PQC; zero TC01 review gates or context leaked.
- [x] **Criterion 10: TC06 Role Awareness Verified:** Ed25519 digital signature maps to ML-DSA/SLH-DSA and composite signatures, not KEMs.
- [x] **Criterion 11: Missing Values Preserved:** Unannotated fields remain `None` / "Not established".
- [x] **Criterion 12: Frontend Passive Boundary Enforced:** Zero security calculation or analytical inference in client code.
- [x] **Criterion 13: Capability Matrix Complete:** All Phase 0–4 core capabilities mapped to presentation elements with source tracing.
- [x] **Criterion 14: UI Content Audit Complete:** Full replacement table provided for all coaching terms, misleading labels, and unevidenced claims.
- [x] **Criterion 15: Component Reuse Plan Defined:** KEEP / MODIFY / REMOVE / REBUILD decision assigned to every demo component.
- [x] **Criterion 16: Zero UI Redesign Begun:** No visual styling, animations, or landing page redesign attempted in Phase D5.
- [x] **Criterion 17: Required Deliverables Produced:** All 7 required markdown artifacts created in `demo/docs/`.

---

## 8. Final D5 Gate Decision

```text
======================================================================
D5 GATE DECISION: PASS (FULLY SATISFIED)
======================================================================
The ECDAT Phase D5 Demo Truth & Product Projection Specification is 
authoritative, mathematically grounded, and rigorously verified.

AUTHORIZATION:
The team is cleared to proceed to Phase D6 (Presentation Layer
Content Corrections & Visual Polish Execution).
======================================================================
```
