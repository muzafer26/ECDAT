# ECDAT — Phase D2 Verification Report

**Phase:** D2 — Hero Scenario + Evidence / Risk / Migration Flow  
**Status:** PASS  
**Implementation Agent:** Antigravity  
**Product Core:** `product/` FROZEN (392 files, SHA-256: `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2`)  
**Demo Code:** `demo/`  
**Test Pass Rate:** 17/17 demo tests (100%), 300/300 product tests (100%)  

---

## 1. D2 Status
**PASS.** All 18 Phase D2 acceptance criteria (D2-01 through D2-18) have been implemented, tested, and verified via automated test suites and end-to-end browser walkthrough.

---

## 2. Files Changed

| File Path | Purpose |
| :--- | :--- |
| `demo/orchestration/models.py` | Enriched `DemoAssetSummary` and `DemoMigrationSummary` with D2 analytical fields (`observed_facts`, `triggered_rules`, `assumptions`, `missing_facts`, `target_details`, `mapping_rationale`, `standards_references`, `agility_factors`, `review_reasons`, `milestones`, `review_gates`). |
| `demo/orchestration/transformer.py` | Mapped Phase 3C risk explanations, uncertainty flags, Phase 4 target records, and Phase 4B milestones into presentation-safe D2 models. Sanitized file paths and labeled all provenance nodes with `source_type=DIRECT_CORE_OUTPUT`. |
| `demo/frontend/index.html` | Restructured UI into a high-credibility 4-tab analyst layout: (1) Overview & Pipeline, (2) Discovery & Scenarios, (3) Cryptographic Inventory, (4) Hero Asset Intelligence (Screens D, E, F, G). |
| `demo/frontend/style.css` | Implemented high-contrast, technical dark cyber-analyst styling with responsive grids, stepper flows, code inspection cards, and distinct alert hierarchies. |
| `demo/frontend/app.js` | Built client-side controller managing tab transitions, scenario switching (TC01 vs TC02), asset selection, provenance node inspection, and rendering of all backend data without frontend analytical calculation. |
| `demo/backend/app.py` | Updated service version to `0.2.0-d2` and phase descriptor to Phase D2. |
| `demo/tests/test_demo_d2.py` | Added comprehensive test suite covering Tests A through H (evidence chain, key-size uncertainty, conditional mapping, out-of-scope symmetric, API contract, zero analytical logic in frontend, honest missing values, safe failure states). |
| `demo/README.md` | Updated architecture documentation, walkthrough instructions, test commands, and known limitations. |
| `demo/docs/PHASE_D2_VERIFICATION_REPORT.md` | This formal engineering report. |

---

## 3. Architecture & Actual Data Flow

```text
Controlled Benchmark Fixture (e.g. TC01 Direct RSA)
       │
       ▼
DemoOrchestrator.run_scenario()
       │
       ▼
ECDATWorkflowEngine.run() [FROZEN PRODUCT CORE]
  ├── Ingestion: CryptoScanAdapter.parse() -> EvidenceRecord
  ├── Normalization: FindingNormalizer -> Canonical CryptoAsset
  ├── CBOM: CycloneDXSerializer.serialize() -> CycloneDX 1.7 CBOM
  ├── Risk Analysis: RiskAnalysisEngine.evaluate_asset()
  │     ├── Uncertainty Policy -> ClassicalSecurityStatus.INDETERMINATE
  │     └── Priority Evaluator -> PriorityTier.P_REVIEW_REQUIRED, NEEDS_REVIEW
  ├── Phase 4A Mapping: PqcTargetMapper.map_asset() -> CONDITIONAL ML-KEM-768
  └── Phase 4B Scheduling: MigrationScheduler.schedule() -> Milestones & Review Gates
       │
       ▼
WorkflowExecutionResult
       │
       ▼
DemoResultTransformer.transform()
       │
       ▼
DemoRunResult (Presentation-Safe JSON Models)
       │
       ▼
Flask Demo API (/api/scenarios/<id>/run)
       │
       ▼
Analyst Web Client (Vanilla HTML/CSS/JS)
```

---

## 4. Hero Journey Walkthrough

The interface guides a first-time technical judge through the canonical 5-step journey:
1. **DISCOVER (Tab 1 & 2):** Judge selects controlled scenario `TC-01: Direct RSA Keypair Generation` and executes real core analysis in ~6 ms.
2. **UNDERSTAND (Tab 3 & 4 / Screen D):** Judge selects the RSA asset in Cryptographic Inventory and views the Evidence Explorer. A 7-stage interactive provenance chain visualizes every transformation from AST token match to migration schedule.
3. **PRIORITIZE (Tab 4 / Screen E):** The judge sees the critical **"What ECDAT Knows vs What is Not Established"** banner. Because CryptoScan omitted key size, ECDAT refuses to invent a 2048-bit value, evaluating classical security to `INDETERMINATE` and routing to `P_REVIEW_REQUIRED`. Authoritative rule citations (`R-RISK-06`) are displayed.
4. **MIGRATE (Tab 4 / Screen F):** ECDAT transitions from "What is wrong?" to "What can be done?", displaying candidate target `ML-KEM-768 (NIST FIPS 203)` with exact byte sizes, NIST Category 3 classification, and `HARDCODED` agility assessment.
5. **REVIEW (Tab 4 / Screen G):** The migration is blocked by formal human review gate `GATE-REVIEW-26700200`, requiring analyst confirmation of key parameters before scheduling code refactoring for milestone `M2-KEY-EXCHANGE-HNDL`.
6. **CONTRAST:** Judge switches to `TC-02: Symmetric AES` and verifies that ECDAT evaluates symmetric block ciphers as `OUT_OF_SCOPE` rather than incorrectly mapping them to public-key PQC.

---

## 5. Real ECDAT Components Used

The demo invokes the frozen product core without mock or synthetic analytical logic:
- `product.core.workflow.engine.ECDATWorkflowEngine`: Master pipeline coordinator.
- `product.core.ingestion.adapters.cryptoscan.CryptoScanAdapter`: Raw tool output parser.
- `product.core.normalization.normalizer`: Derives canonical `CryptoAsset`.
- `product.core.cbom.serializer.CycloneDXSerializer`: CycloneDX 1.7 CBOM projection.
- `product.core.risk.engine.RiskAnalysisEngine`: Contextual risk reasoning engine.
- `product.core.risk.rules.ruleset.RuleSet`: Uncertainty and prioritization rules (`R-RISK-06`, `R-PRIORITY-P-REVIEW-REQUIRED`).
- `product.core.migration.target_mapper.PqcTargetMapper`: Deterministic NIST FIPS 203/204/205 mapper.
- `product.core.migration.scheduler.MigrationScheduler`: Dependency DAG milestone and review gate generator.

---

## 6. API Contracts

### `GET /api/health`
- Returns health status, core freeze indicator (`CONNECTED_FROZEN`), and capability classifications (`LIVE`, `CONTROLLED_DEMO`, `ARCHITECTURAL`).

### `GET /api/scenarios`
- Returns list of registered controlled scenarios with adapter, classification, and target identifiers.

### `POST /api/scenarios/<scenario_id>/run`
- Returns full `DemoRunResult` JSON containing:
  - `status`: `"SUCCESS"` | `"FAILED"` | `"UNAVAILABLE"`
  - `assets`: List of enriched `DemoAssetSummary` objects.
  - `evidence_records`: List of `DemoEvidenceRecord` objects.
  - `findings`: List of `DemoFindingRecord` objects.
  - `risk_summary`: Total assets, priority distribution, and mandatory review counts.
  - `migration_summary`: Phase 4 status, target counts, milestones, and review gates.
  - `provenance_chain`: 7-stage transformation nodes with `DIRECT_CORE_OUTPUT` attribution.
  - `cbom_summary`: Component counts and metadata.

---

## 7. Scenario Behavior: TC01 vs TC02

| Metric / Attribute | TC-01: Direct RSA Keypair Generation | TC-02: Symmetric AES Block Cipher |
| :--- | :--- | :--- |
| **Input Source** | `product/benchmark/tools/raw_outputs/cryptoscan/tc01_direct_rsa/` | `product/benchmark/tools/raw_outputs/cryptoscan/tc02_symmetric_aes/` |
| **Discovered Family** | `RSA` (Asymmetric) | `AES` (Symmetric) |
| **Key Size Capture** | `None` (Omitted by scanner) | `None` (Omitted by scanner) |
| **Classical Status** | `INDETERMINATE` (Refuses to guess) | `INDETERMINATE` (Refuses to guess) |
| **Quantum Exposure** | `SHOR_VULNERABLE_ASYMMETRIC` | `GROVER_REDUCED_SYMMETRIC_LOW` |
| **Priority Tier** | `P_REVIEW_REQUIRED` | `P_REVIEW_REQUIRED` |
| **PQC Target Mapping** | `CONDITIONAL` &rarr; `ML-KEM-768` | `OUT_OF_SCOPE` (No public-key PQC) |
| **Standards Standard** | NIST FIPS 203 (Category 3) | NIST SP 800-131A (Retain symmetric) |
| **Review Gate** | `GATE-REVIEW-26700200` (Blocking) | Advisory review |

---

## 8. Evidence & Provenance Verification

Every node in the provenance chain is tagged with `source_type="DIRECT_CORE_OUTPUT"`.
- Stage 1: `scanner`: Name and version (`CryptoScan v1.4.0`) extracted from raw run output.
- Stage 2: `raw_evidence`: Direct attributes from `EvidenceRecord` (`cryptoscan:RSA-001-16-64`, line 16, token "RSA").
- Stage 3: `finding`: Direct attributes from `Finding` (`f618a82b-...`, confidence `CONFIRMED`).
- Stage 4: `crypto_asset`: Canonical domain object `CryptoAsset` (`26700200-...`, `key_size=None`).
- Stage 5: `risk`: Priority record from `RiskAnalysisEngine` (`P_REVIEW_REQUIRED`, `NEEDS_REVIEW`).
- Stage 6: `migration`: Target record from `PqcTargetMapper` (`CONDITIONAL`, `ML-KEM-768`).
- Stage 7: `schedule`: Milestone record from `MigrationScheduler` (`M2-KEY-EXCHANGE-HNDL`).

---

## 9. Risk Verification

Zero synthetic risk scores (such as "87/100") are fabricated. The interface surfaces only the actual categorical dimensions derived by the core engine:
- `priority_tier`: `P_REVIEW_REQUIRED`
- `risk_category`: `NEEDS_REVIEW`
- `primary_risk_cause`: `UNRESOLVED_UNCERTAINTY`
- `classical_status`: `INDETERMINATE`
- `quantum_exposure_class`: `SHOR_VULNERABLE_ASYMMETRIC`
- `triggered_rules`: `R-RISK-06`, `R-PRIORITY-P-REVIEW-REQUIRED`
- `assumptions`: NIST SP 800-131A Rev 2 Section 5.1 citation regarding unevidenced key length.

---

## 10. Migration Verification

Phase 4 migration intelligence is populated directly from `PqcTargetMapper` and `MigrationScheduler`:
- Candidate target: `ML-KEM-768` (NIST FIPS 203)
- NIST Security Category: `CATEGORY_3` (AES-192 equivalent)
- Public key size: `1184 bytes`
- Ciphertext size: `1088 bytes`
- Mapping status: `CONDITIONAL`
- Milestone: `M2-KEY-EXCHANGE-HNDL`
- Schedule status: `ADVISORY_PENDING_REVIEW`
- Blocker: `CODE_REFACTOR_REQUIRED: Hardcoded algorithm literal in tc01_direct_rsa/DirectRSAKeyGen.java:16 requires code refactoring.`
- Blocking gate: `GATE-REVIEW-26700200`

---

## 11. Test Results

### Demo Test Suite (`demo/tests/`):
```text
Ran 17 tests in 0.359s
OK (All 17 passed)
```
- Tests 01–09: D1 foundation, core freeze verification, dynamic processing, API boundary safety.
- Tests A–H: D2 evidence chain, key-size uncertainty preservation, conditional mapping, out-of-scope symmetric handling, API schema contract, zero analytical logic in frontend, missing data honesty, traceback-free error handling.

### Product Test Suite (`product/tests/`):
```text
Ran 300 tests in 0.154s
OK (All 300 passed)
```

### Product Freeze Verification:
- Source files: Exactly 392 files.
- SHA-256 hash: `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2` (100% byte-identical to baseline).

---

## 12. UI Walkthrough Result
An automated browser subagent performed the complete 15-step human walkthrough:
- Overview & Pipeline verified.
- TC01 executed; RSA asset inspected.
- Evidence Explorer, Provenance Stepper, and Code snippet verified.
- Known vs Not Established banner and `INDETERMINATE` classical security verified.
- ML-KEM-768 migration candidate and `HARDCODED` agility verified.
- Milestone `M2-KEY-EXCHANGE-HNDL` and `GATE-REVIEW-26700200` review gate verified.
- TC02 executed; verified AES evaluates to `OUT_OF_SCOPE` without public-key PQC mapping.
- Browser session recording: `d2_judge_journey_1790333888853.webp`.

---

## 13. Security Review
- **Controlled Fixtures Only:** Scenario execution only consumes controlled local benchmark fixtures; no arbitrary file access or user-provided paths accepted.
- **Path Sanitization:** File paths are normalized and relative to benchmark fixtures; no absolute system paths are exposed to the browser.
- **Safe Error Propagation:** Invalid scenario IDs or malformed inputs return structured JSON error envelopes with zero stack trace or traceback disclosure.
- **No Client-Side Authority:** Frontend is strictly read-only presentation; zero security decisions or classifications are computed in JavaScript.

---

## 14. Remaining Limitations
- Live CLI scanning is intentionally disabled; analysis is performed on recorded scanner outputs.
- Automated code patching/refactoring is out of scope; output is an engineering migration plan.
- D3 (multi-asset inventory / graph filtering) and D4 (adversarial hardening) are deferred to future phases.

---

## 15. D2 Acceptance Matrix

| Criterion | Description | Status | Evidence |
| :---: | :--- | :---: | :--- |
| **D2-01** | Judge can select controlled scenario and execute real ECDAT analysis | **PASS** | TC01/TC02 execution in UI and `test_a_tc01_evidence_chain` |
| **D2-02** | Real cryptographic asset can be selected | **PASS** | RSA asset `26700200-...` selectable in inventory table |
| **D2-03** | Evidence Explorer shows actual source/provenance info | **PASS** | `CryptoScan v1.4.0`, `DirectRSAKeyGen.java:16`, token "RSA" |
| **D2-04** | Provenance chain is visually understandable | **PASS** | 7-stage interactive stepper with node inspector |
| **D2-05** | Known vs unknown information is visible | **PASS** | Dedicated "Known vs Not Established" banner with gap list |
| **D2-06** | Risk displayed using actual core results | **PASS** | `P_REVIEW_REQUIRED`, `NEEDS_REVIEW`, `UNRESOLVED_UNCERTAINTY` |
| **D2-07** | Risk reasoning understandable without invented scores | **PASS** | Rules `R-RISK-06` and `R-PRIORITY-P-REVIEW-REQUIRED` cited |
| **D2-08** | Quantum exposure displayed from actual core info | **PASS** | `SHOR_VULNERABLE_ASYMMETRIC` from domain classifier |
| **D2-09** | Migration mapping displayed from actual Phase 4 output | **PASS** | `ML-KEM-768 (NIST FIPS 203)` from `PqcTargetMapper` |
| **D2-10** | Review requirements are visible | **PASS** | `GATE-REVIEW-26700200` displayed with gating cause |
| **D2-11** | Migration scheduling info visible where available | **PASS** | `M2-KEY-EXCHANGE-HNDL` with `CODE_REFACTOR_REQUIRED` blocker |
| **D2-12** | TC02 demonstrates correct out-of-scope handling | **PASS** | AES evaluated as `OUT_OF_SCOPE` in `test_d_tc02_out_of_scope_symmetric` |
| **D2-13** | No analytical logic duplicated in frontend code | **PASS** | Verified via regex inspection in `test_f_no_analytical_logic_in_frontend` |
| **D2-14** | Failure, empty, partial and review states behave honestly | **PASS** | Verified in `test_h_failure_state_renders_without_stack_traces` |
| **D2-15** | All D1 tests continue passing | **PASS** | 9/9 D1 tests pass |
| **D2-16** | All product tests continue passing | **PASS** | 300/300 product tests pass |
| **D2-17** | No unsupported capability represented as LIVE | **PASS** | Strict classification badges maintained on all views |
| **D2-18** | Complete judge journey executable without editing source | **PASS** | Completed and recorded via automated browser agent |

---

## 16. Deviations
**None.** Implementation strictly adhered to the Phase D2 specification without architectural compromises or modifications to `product/`.

---

## 17. Semantic Verification (Provenance & Role-Aware Mapping)

### Provenance Terminology Audit:
- **Prior wording:** Occasionally referred to the 7-stage chain as the "authoritative complete trace".
- **Corrected wording:** Formally designated as the **"Runtime Evidence-to-Migration Trace"** and **"Runtime Provenance Chain"**.
- **Lifecycle boundary clarification:** Explicitly documented that environmental context is evaluated within the Asset & Risk stages rather than as a disconnected node, and post-migration verification is a future controlled lifecycle phase (Phase 9) not claimed as active runtime output.

### RSA `KEY_GENERATION` &rarr; ML-KEM-768 Mapping Verification:
- **Source Family:** `AlgorithmFamily.RSA`
- **Observed Role:** `CryptographicRole.KEY_GENERATION` (derived from AST visitor capturing `KeyPairGenerator.getInstance("RSA")`).
- **Core Mapping Rule:** `PqcTargetMapper.map_asset()`, Section 6 ("Key Establishment / Key Encapsulation (FIPS 203 — ML-KEM)"), lines 242–254 of `product/core/migration/target_mapper.py`.
- **Target Equivalence Category:** `None` (classical strength is `INDETERMINATE` due to missing key length; ECDAT refuses to guess).
- **Proposed Candidate:** `ML-KEM-768 (NIST FIPS 203)` as a provisional Category 3 general-purpose baseline subject to parameter verification.
- **Mapping Status:** `TargetMappingStatus.CONDITIONAL` (lines 378–382).
- **Human Review Requirement:** `required_human_review = True`, enforced via blocking review gate `GATE-REVIEW-26700200` in `MigrationScheduler`.
- **Role Specificity:** The UI now explicitly notes that ML-KEM is proposed specifically because the role is asymmetric key establishment/generation. If the role were `DIGITAL_SIGNATURE`, the core maps to `ML-DSA` (FIPS 204) or `SLH-DSA` (FIPS 205).
- **Standards Claims:** References to NIST FIPS 203 are contextualized as "Candidate target proposed based on ECDAT role-aware mapping", not a universal standards mandate for all RSA uses.

---

## 18. Gate Decision
**D2 VERIFIED AND FROZEN.**  
All semantic and functional requirements are verified. Zero modifications were made to `product/`. The product core remains 100% byte-identical to the baseline. Antigravity stops at the D2 gate; no D3 work has been initiated.
