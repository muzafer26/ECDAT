# ECDAT — Demo Information Architecture (Phase D5)

**Status:** AUTHORITATIVE SPECIFICATION  
**Workflow Paradigm:** Analyst Control Plane (9 Continuous Stages)  
**Story Foundation:** Scanner-Agnostic Cryptographic Intelligence & Migration Decision Plane  

---

## 1. Executive Product Narrative

> **"Organizations already possess cryptographic discovery tools. ECDAT sits above them, turning raw scanner evidence into normalized cryptographic assets, contextual risk reasoning, migration intelligence, dependency-aware planning, and human review."**

The demo does not need lengthy paragraphs explaining itself. The relationships between **evidence**, **canonical assets**, **risk rules**, **standards mappings**, and **dependency schedules** do the explanation through their own observable behavior.

---

## 2. Canonical Product Journey

The demo is structured around one coherent, unbroken analytical lifecycle:

```text
DISCOVERY (Input Selection & Adapters)
   ↓
EVIDENCE (Empirical AST Tokens & Scanner Findings)
   ↓
CRYPTOGRAPHIC ASSET (Normalized Inventory & CycloneDX CBOM)
   ↓
CONTEXT (Enterprise Deployment & Environmental Lineage)
   ↓
RISK (Categorical Derivation & Uncertainty Policy)
   ↓
MIGRATION INTELLIGENCE (Role-Aware FIPS Standards Mapping & Hybrids)
   ↓
MIGRATION PLAN (Dependency DAG Milestones & Agility Blockers)
   ↓
HUMAN REVIEW (Formal Decision Gates & Actionable Triage)
   ↓
VERIFICATION BOUNDARY (Phase 9 Post-Migration Rescan Projection)
```

---

## 3. Screen-by-Screen Information Architecture

### Tab 1: Overview & Pipeline Architecture
- **Product Question Answered:** *What problem does ECDAT solve, and what is the analytical pipeline?*
- **Primary Elements:**
  - High-level value proposition: scanner-agnostic intelligence above raw tools.
  - 5-step analyst journey visualization (`Discover → Understand → Prioritize → Migrate → Review`).
  - Active runtime evidence-to-migration trace.
- **Truth Constraints:**
  - Zero presentation-coaching language (no "Orient the judge", "Why trust this").
  - Clear statement that environmental context is evaluated within Asset & Risk stages and post-migration verification is a future controlled lifecycle phase.

### Tab 2: Discovery & Adapters Control
- **Product Question Answered:** *What evidence sources are being evaluated, and what tools are integrated?*
- **Primary Elements:**
  - Controlled Scenarios Selector (`TC-01 Direct RSA`, `TC-02 Symmetric AES`, `TC-06 Ed25519 Signature`).
  - Pipeline Execution Controller (triggers real core execution).
  - Discovery Engine Ingestion Adapters Registry Table (status, formats, known limitations).
- **Truth Constraints:**
  - Explicit badge: `CONTROLLED BENCHMARK FIXTURES`.
  - TC01 description states RSA key generation without fabricated 2048-bit claims as AST evidence.
  - Ingestion adapters accurately classified: `CryptoScan` (Implemented / Core-Integrated), `Syft` (Implemented / Core-Integrated), `Sonar` (Architectural / Future), `CodeQL` (Architectural / Future), `sslscan2` (Architectural / Future).

### Tab 3: Canonical Cryptographic Inventory
- **Product Question Answered:** *What normalized cryptographic assets exist across the evaluated codebase?*
- **Primary Elements:**
  - Summary metric cards (Target, Latency ms, CycloneDX CBOM components, Priority, Review status).
  - Discovered Assets Table with columns: Asset ID, Enterprise System/Component, Family/Algorithm, Role, Location, Confidence, Risk Tier, PQC Target Mapping, Human Review Gate Status.
- **Truth Constraints:**
  - Data populated 100% from `DemoAssetSummary`.
  - Absence of detections does NOT certify safety (explicit disclaimer on empty states).

### Tab 4: Evidence Explorer
- **Product Question Answered:** *What empirical scanner observations substantiate this cryptographic asset?*
- **Primary Elements:**
  - Active Asset Context Banner (Family, Role, Quantum Posture).
  - 7-Stage Interactive Runtime Provenance Chain (`Scanner → Raw Evidence → Finding → Crypto Asset → Risk → Migration Target → Schedule`).
  - Interactive Node Inspector displaying exact JSON provenance attributes on click.
  - Raw Scanner Output key-value table.
  - Code Location & Syntax-Highlighted Source Code Snippet.
- **Truth Constraints:**
  - Eradicate "Answers the judge's fundamental question".
  - Code snippet and location must derive from actual scanner evidence in `currentRunResult.evidence_records`.

### Tab 5: Context, Risk & Uncertainty Reasoning
- **Product Question Answered:** *Why is this asset risky, and what information remains unestablished?*
- **Primary Elements:**
  - **Hero Uncertainty Moment:** "What ECDAT Empirically Knows" vs "What is Not Established (Gaps)".
  - 5 Risk Dimensions: Priority Tier, Technical Risk Category, Primary Risk Cause, Classical Status, Quantum Exposure Class.
  - Enterprise Operational Deployment Context (System, Component, Criticality, Data Sensitivity & Lifetime, Network Exposure, Environment).
  - Authoritative Rule Tracing & Formal Policy Citations (e.g., `R-RISK-06`).
- **Truth Constraints:**
  - Operational Context box must declare provenance: `Source: Controlled Scenario Configuration`.
  - Missing facts (e.g. unknown network isolation, unevidenced key size) must remain uninvented.
  - No numerical risk scores or fabricated probabilistic algorithms.

### Tab 6: Migration Intelligence
- **Product Question Answered:** *What standardized post-quantum algorithms and transitional schemes are viable?*
- **Primary Elements:**
  - Role-Aware Migration Semantics explanation.
  - Visual Primitive Mapping Box (`Current Observed Primitive → Status Pill → Candidate PQC Target`).
  - Standardized Target Parameter Set Details Table (FIPS standard reference, NIST security category, key overhead bytes, ciphertext/sig overhead bytes).
  - Cryptographic Agility Assessment (`Agility Level`, evidenced agility blockers).
  - Candidate Hybrid Transition Strategy (Phase 4B evaluated hybrid schemes).
- **Truth Constraints:**
  - Target must match operational role (KEM for key exchange/generation; ML-DSA/SLH-DSA for signature; OUT_OF_SCOPE for symmetric).
  - Hybrid candidate must be the exact scheme evaluated by Phase 4B (e.g., `RSA_OAEP_MLKEM768_DUAL_WRAP`).
  - Agility must display actual evidenced factors from core mapping.

### Tab 7: Migration Plan & Scheduling
- **Product Question Answered:** *In what sequence should migration occur, and what engineering blockers exist?*
- **Primary Elements:**
  - Advisory Planning Notice (milestones are decision-support groupings, not guaranteed deadlines).
  - Primary Milestone Card for Selected Asset (Milestone ID, status, rationale, agility blockers).
  - All Scheduled Milestones in Current Analysis Run list.
- **Truth Constraints:**
  - Milestones derive from real topological sorting of cryptographic dependencies in `MigrationScheduler`.
  - Agility blockers reflect true code inspection (e.g., `CODE_REFACTOR_REQUIRED`).

### Tab 8: Human Review Decision Gates
- **Product Question Answered:** *Where is automated analysis insufficient, and what human decisions are required?*
- **Primary Elements:**
  - Responsible Security Automation Protocol (5-stage protocol from Discovery to Release Approval).
  - Deep-Dive Card on Selected Asset Review Gate (Gate ID, Gating Trigger Reason, Missing Information, Consequence if Unresolved, Required Human Action).
  - All Active Review Gates Table.
- **Truth Constraints:**
  - Surfaced only when `requires_human_review = True`.
  - TC02 must show zero review gates.

### Tab 9: Verification Boundary [Future Architecture]
- **Product Question Answered:** *How will organizations verify migration in future phases without trusting self-attestation?*
- **Primary Elements:**
  - Architectural Disclosure Banner (clearly stating that Phase 4 does not perform code refactoring or live rescan).
  - 5-Stage Post-Migration Verification Lifecycle Architecture (`Baseline CBOM → Code Migration → Source Re-Scan → Diff Comparison → Quantum Assurance`).
  - Architectural Projection: Cryptographic Diff Schema Model (pre-migration vs post-migration CBOM component comparison).
- **Truth Constraints:**
  - Explicitly badged `CONTROLLED / FUTURE (PHASE 9)`.
  - All verdicts badged `PROJECTED (PHASE 9)`.
  - Zero claims of completed verification or live patching.
