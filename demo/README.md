# ECDAT Demo — F1–F6 Functional Traceability Audit & Gate

**Status:** F1–F6 Functional Traceability Audit Complete & Verified (All 6 Objectives Passed)  
**Gate Decision:** FUNCTIONALLY READY FOR D5 (Do NOT begin Phase D5 visual polish; await authorization)  
**Boundary:** Consumes frozen `product/core/` via clean orchestration and API boundaries.  
**Product Core Freeze:** Verified 392 files, SHA-256 `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2`.  
**Zero Code Duplication:** No core domain models, risk rules, or migration engines copied into `demo/`.  
**Architecture:** 9-stage Analyst Control Plane with enterprise organizational context, role-aware PQC mapping, and dynamic Phase 4B hybrid candidate evaluation.  

---

## 1. D3 Mission & Analyst Workflow

Phase D3 extends the D2 hero vertical slice into a **complete, working Analyst Control Plane prototype**. A technical judge can navigate the complete lifecycle:

```text
SCENARIO & ADAPTERS
       ↓
DISCOVERY
       ↓
CRYPTO INVENTORY
       ↓
EVIDENCE EXPLORER
       ↓
CONTEXT + RISK REASONING
       ↓
MIGRATION INTELLIGENCE
       ↓
MIGRATION PLAN & SCHEDULING
       ↓
FORMAL REVIEW GATES
       ↓
VERIFICATION BOUNDARY (PHASE 9)
```

---

## 2. 9 Discrete Workflow Tabs

| Tab | Name | Purpose & Contents |
| :---: | :--- | :--- |
| **1** | **Overview & Pipeline** | Orient the judge: 5-step analyst journey, runtime evidence-to-migration trace, and intellectual foundation. |
| **2** | **Discovery & Adapters** | Select and execute controlled scenarios (`TC-01 Direct RSA`, `TC-02 Symmetric AES`, `TC-06 Ed25519 Signature`). Displays live Ingestion Adapters registry with capability classifications. |
| **3** | **Crypto Inventory** | Discovered cryptographic assets table with operational role, location, confidence, priority tier, PQC mapping, and review gate status. |
| **4** | **Evidence Explorer** | 7-stage interactive runtime provenance chain (`Scanner → Raw Evidence → Finding → Crypto Asset → Risk → Migration Target → Schedule`) with node inspector and source code snippet. |
| **5** | **Context & Risk** | What ECDAT Empirically Knows vs What is Not Established; 5 risk dimensions (Priority, Risk category, Cause, Classical status, Quantum exposure); authoritative rule citations (`R-RISK-06`). |
| **6** | **Migration Intelligence** | Role-aware PQC mapping (KEM vs Signatures vs Symmetric), standardized target parameter sets (FIPS 203/204/205), agility assessment (`HARDCODED`), and candidate hybrid schemes. |
| **7** | **Migration Plan** | Dependency-ordered migration milestones (`M2-KEY-EXCHANGE-HNDL`, `M3-AUTHENTICATION-SIGNATURES`), agility blockers (`CODE_REFACTOR_REQUIRED`), and advisory status notices. |
| **8** | **Review Gates** | Human Review Gate Protocol visualizer, active review gates (`GATE-REVIEW-26700200`), missing information, and required analyst triage actions. |
| **9** | **Verification [Future]** | Post-migration verification boundary tagged `CONTROLLED / FUTURE (PHASE 9)`, 5-step lifecycle architecture, and architectural projection of cryptographic diff delta schema. |

---

## 3. Capability Classification (D0 Section 18)

| Capability / Adapter | Classification | Status & Description |
|:---|:---:|:---|
| **ECDAT Core Engine** | **LIVE** | Real implementation in `product/core/workflow/engine.py` executed dynamically. |
| **CryptoScan Adapter** | **LIVE** | Real adapter in `product/core/ingestion/adapters/cryptoscan.py` parsing raw tool outputs. |
| **Syft Adapter** | **LIVE** | Real adapter in `product/core/ingestion/adapters/syft.py` cataloging package-level dependencies. |
| **CycloneDX 1.7 CBOM** | **LIVE** | Real projection serializer in `product/core/cbom/serializer.py`. |
| **Phase 4A PQC Mapping** | **LIVE** | Real deterministic target mapper in `product/core/migration/target_mapper.py`. |
| **Phase 4B Scheduling** | **LIVE** | Real dependency-aware scheduler in `product/core/migration/scheduler.py`. |
| **TC01, TC02, TC06 Scenarios** | **CONTROLLED DEMO** | Curated benchmark fixtures from `product/benchmark/` used for deterministic demonstration. |
| **Sonar Adapter** | **ARCHITECTURAL / FUTURE** | Architectural boundary documented in `demo/adapters/registry.py`; parser deferred. |
| **CodeQL Adapter** | **ARCHITECTURAL / FUTURE** | External SARIF ingestion pipeline deferred; requires proprietary license. |
| **sslscan2 Adapter** | **ARCHITECTURAL / FUTURE** | Network TLS discovery deferred; GPLv3 isolation required. |
| **Rescan Verification** | **ARCHITECTURAL / FUTURE** | Rescan diff engine planned for Phase 9; not claimed as production capability. |

---

## 4. How to Run the Demo

### Launch the Development Server:
```bash
python -m demo.backend.server --port 8080
```
Open `http://127.0.0.1:8080` in your web browser.

---

## 5. Test Commands

### Run Complete Demo Test Suite (34 tests: D1 + D2 + D3):
```bash
python -m unittest discover -s demo/tests
```

### Run Full Frozen Product Test Suite (300 tests):
```bash
python -m unittest discover -s product/tests
```

---

## 6. Known D3 Limitations

- Controlled benchmark fixtures (`tc01_direct_rsa`, `tc02_symmetric_aes`, `tc06_ed25519`) drive the demo; live repository scanning is intentionally out of scope.
- No live code refactoring or automated source patching is performed; remediation is advisory and plan-oriented.
- Enterprise RBAC, multi-tenant databases, and cloud infrastructure are deferred non-goals.
