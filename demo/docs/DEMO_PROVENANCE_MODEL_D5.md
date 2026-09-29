# ECDAT — Demo Provenance Model (Phase D5)

**Status:** AUTHORITATIVE SPECIFICATION  
**Standard:** Strict Provenance Integrity & Anti-Masquerading Protocol  
**Core Reference:** `demo/orchestration/models.py` (`ProvenanceSourceType`, `ProvenanceNode`, `DemoAssetSummary`)  

---

## 1. The Four Formal Provenance Classes

Every data point, label, score, table row, and text snippet rendered across the ECDAT demonstration plane must be explicitly traceable to one of four authoritative provenance classifications:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ 1. DIRECT_CORE_OUTPUT                                                  │
│    Data produced directly by the frozen ECDAT core during execution.   │
├────────────────────────────────────────────────────────────────────────┤
│ 2. CONTROLLED_SCENARIO_CONTEXT                                         │
│    Environmental, organizational, or threat context injected via       │
│    scenario metadata. Must be declared as scenario context.            │
├────────────────────────────────────────────────────────────────────────┤
│ 3. BENCHMARK_GROUND_TRUTH                                              │
│    Facts known from the benchmark seed fixtures that were not captured │
│    or established by the evaluated discovery tool.                     │
├────────────────────────────────────────────────────────────────────────┤
│ 4. FUTURE_ARCHITECTURE                                                 │
│    Conceptual data structures, schemas, and lifecycle workflows        │
│    describing post-Phase 4 roadmap (e.g. Phase 9 verification).        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Complete Attribute-Level Provenance Mapping

The following table maps every significant field displayed across the 9 demo tabs to its authoritative provenance classification:

| Tab / Screen | UI Element / Field | Internal Field | Provenance Category | Authoritative Source |
| :--- | :--- | :--- | :--- | :--- |
| **Tab 2: Discovery** | Scenario Selection | `scenario_id`, `name`, `description` | `CONTROLLED_SCENARIO_CONTEXT` | `demo/scenarios/registry.py` |
| **Tab 2: Discovery** | Adapter Status | `adapter_id`, `status`, `limitations` | `DIRECT_CORE_OUTPUT` / `FUTURE_ARCHITECTURE` | `demo/adapters/registry.py` |
| **Tab 3: Inventory** | Asset ID | `asset.asset_id` | `DIRECT_CORE_OUTPUT` | `product/core/domain/asset.py` |
| **Tab 3: Inventory** | Family & Algorithm | `asset.family`, `asset.algorithm` | `DIRECT_CORE_OUTPUT` | `product/core/normalization/` |
| **Tab 3: Inventory** | Cryptographic Role | `asset.role` | `DIRECT_CORE_OUTPUT` | `product/core/domain/role.py` |
| **Tab 3: Inventory** | Source Location | `asset.location_display` | `DIRECT_CORE_OUTPUT` | `product/core/evidence/location.py` |
| **Tab 3: Inventory** | Observation Confidence| `asset.confidence` | `DIRECT_CORE_OUTPUT` | `product/core/domain/confidence.py` |
| **Tab 3: Inventory** | Priority Tier | `asset.priority_tier` | `DIRECT_CORE_OUTPUT` | `product/core/risk/evaluator.py` |
| **Tab 3: Inventory** | PQC Mapping Status | `asset.pqc_mapping_status` | `DIRECT_CORE_OUTPUT` | `product/core/migration/target_mapper.py` |
| **Tab 3: Inventory** | System / Component | `asset.system`, `asset.component` | `CONTROLLED_SCENARIO_CONTEXT` | Scenario metadata (`metadata`) |
| **Tab 4: Evidence** | Scanner Name & Version| `ev.scanner_name`, `ev.scanner_version` | `DIRECT_CORE_OUTPUT` | `product/core/evidence/evidence.py` |
| **Tab 4: Evidence** | Matched AST Token | `ev.matched_text` | `DIRECT_CORE_OUTPUT` | Raw tool finding parser |
| **Tab 4: Evidence** | Code Snippet | `ev.code_snippet` | `DIRECT_CORE_OUTPUT` | Evidence AST extraction |
| **Tab 4: Evidence** | Provenance Chain Nodes | `provenance_chain[*]` | `DIRECT_CORE_OUTPUT` | Trace generated in `transformer.py` |
| **Tab 5: Risk** | What ECDAT Knows | `asset.observed_facts` | `DIRECT_CORE_OUTPUT` | `product/core/risk/explainer.py` |
| **Tab 5: Risk** | What is Not Established| `asset.missing_facts` | `DIRECT_CORE_OUTPUT` | `product/core/risk/explainer.py` |
| **Tab 5: Risk** | Technical Risk Category| `asset.risk_category` | `DIRECT_CORE_OUTPUT` | `product/core/risk/engine.py` |
| **Tab 5: Risk** | Primary Risk Cause | `asset.primary_risk_cause` | `DIRECT_CORE_OUTPUT` | `product/core/risk/engine.py` |
| **Tab 5: Risk** | Classical Status | `asset.classical_status` | `DIRECT_CORE_OUTPUT` | `product/core/risk/evaluator.py` |
| **Tab 5: Risk** | Quantum Exposure Class | `asset.quantum_exposure_class` | `DIRECT_CORE_OUTPUT` | `product/core/risk/evaluator.py` |
| **Tab 5: Risk** | Authoritative Rule ID | `rule.rule_id`, `rule.authority` | `DIRECT_CORE_OUTPUT` | `product/core/risk/rules/` (`R-RISK-06`) |
| **Tab 5: Risk** | Business Criticality | `asset.business_criticality` | `CONTROLLED_SCENARIO_CONTEXT` | Scenario metadata (`metadata`) |
| **Tab 5: Risk** | Data Lifetime Horizon | `asset.data_lifetime` | `CONTROLLED_SCENARIO_CONTEXT` | Scenario metadata (`metadata`) |
| **Tab 5: Risk** | Network Exposure | `asset.network_exposure` | `CONTROLLED_SCENARIO_CONTEXT` | Scenario metadata (`metadata`) |
| **Tab 5: Risk** | Benchmark Modulus Size | `benchmark_ground_truth.key_size_bits` | `BENCHMARK_GROUND_TRUTH` | `DirectRSAKeyGen.java:19` |
| **Tab 6: Migration**| Candidate Targets | `asset.candidate_targets` | `DIRECT_CORE_OUTPUT` | `product/core/migration/target_mapper.py` |
| **Tab 6: Migration**| Target Overhead (Bytes)| `target_details[*].*_bytes` | `DIRECT_CORE_OUTPUT` | Standardized parameter definitions |
| **Tab 6: Migration**| Agility Assessment | `asset.agility_factors` | `DIRECT_CORE_OUTPUT` | `product/core/migration/agility.py` |
| **Tab 6: Migration**| Hybrid Combiner Scheme | `asset.hybrid_candidates[*]` | `DIRECT_CORE_OUTPUT` | `product/core/migration/hybrid.py` |
| **Tab 7: Plan** | Milestone ID & Title | `milestone.milestone_id`, `title` | `DIRECT_CORE_OUTPUT` | `product/core/migration/scheduler.py` |
| **Tab 7: Plan** | Agility Blockers | `milestone.blockers` | `DIRECT_CORE_OUTPUT` | `product/core/migration/scheduler.py` |
| **Tab 7: Plan** | Advisory Schedule Note | `migration_summary.advisory_notice` | `DIRECT_CORE_OUTPUT` | `product/core/migration/scheduler.py` |
| **Tab 8: Review** | Review Gate ID | `gate.gate_id` | `DIRECT_CORE_OUTPUT` | `product/core/migration/scheduler.py` |
| **Tab 8: Review** | Gating Reason & Missing| `gate.reason`, `gate.missing_information` | `DIRECT_CORE_OUTPUT` | `product/core/migration/scheduler.py` |
| **Tab 9: Verification**| 5-Stage Lifecycle | Lifecycle Steps | `FUTURE_ARCHITECTURE` | `demo/frontend/index.html` (Phase 9) |
| **Tab 9: Verification**| Diff Schema Model | Projected Delta Table | `FUTURE_ARCHITECTURE` | `demo/frontend/index.html` (Phase 9) |

---

## 3. Anti-Masquerading Rules

To maintain strict truth integrity, the demo enforces four anti-masquerading rules:

### Rule 1: Scenario Context Cannot Masquerade as Core Evidence
- Scenario configuration fields (`organization`, `system`, `component`, `business_criticality`, `network_exposure`) must NEVER be injected into `evidence_records`, AST snippets, or scanner output tables.
- The UI must render an explicit provenance header:  
  `Source: Controlled Scenario Configuration (Enterprise Context Lineage)`

### Rule 2: Benchmark Ground Truth Cannot Masquerade as Discovered Facts
- If a benchmark fixture contains details that the discovery tool failed to capture (e.g., `keyGen.initialize(2048)` omitted by CryptoScan's AST visitor), the demo must NOT backfill `asset.key_size_bits = 2048`.
- The missing parameter must be rendered as `Not established in AST`, while ground truth is explicitly distinguished in the Uncertainty reasoning box.

### Rule 3: Future Architecture Cannot Masquerade as Completed Actions
- Phase 9 post-migration verification must be badged `CONTROLLED / FUTURE (PHASE 9)`.
- Projected delta table rows must be labeled `PROJECTED: QUANTUM-RESILIENT (PHASE 9)`.
- No checkmark or "PASS" badge indicating that code has been patched or verified in the live system may be shown.

### Rule 4: Synthetic Scenarios Cannot Masquerade as Live Production Scans
- Even though the execution pipeline consumes the live frozen core, the input data derives from static benchmark files in `product/benchmark/`.
- Scenarios must be badged `CONTROLLED BENCHMARK FIXTURES`, never simply `LIVE REPOSITORY SCAN`.
