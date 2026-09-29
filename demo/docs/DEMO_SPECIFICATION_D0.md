# ECDAT Demo Product Specification

## Phase D0 — Demo Product Definition & Architecture Gate

**Project:** ECDAT — Enterprise Cryptographic Discovery & Analysis Tool  
**Demo purpose:** Interactive SIH judge-facing prototype  
**Implementation agent:** Antigravity  
**Product core:** Existing `product/` implementation (FROZEN)  
**Demo location:** `demo/`  
**Status:** D0 — Specification / Architecture Gate (PASSED / ADOPTED)  

---

# 1. Demo Mission

Build an interactive web-based prototype that allows a first-time technical judge to understand, in a short guided interaction:

1. What ECDAT is.
2. Why it exists above existing cryptographic discovery/scanning tools.
3. How evidence becomes a cryptographic asset.
4. How ECDAT adds context and risk reasoning.
5. How cryptographic assets are mapped toward migration/PQC strategies.
6. How dependencies and review gates affect migration.
7. Why ECDAT's results are evidence-driven rather than unexplained security verdicts.
8. Where the current implementation ends and future enterprise capabilities begin.

The demo must communicate the product concept through interaction rather than through a collection of disconnected marketing screens.

---

# 2. Core Product Story

The demo's central narrative is:

**Discover → Understand → Prioritize → Migrate → Verify**

Internally, the deeper trace is:

**Source / Scanner**  
→ **Raw Evidence**  
→ **Normalized Evidence**  
→ **Finding**  
→ **Crypto Asset**  
→ **Context**  
→ **Risk**  
→ **Migration Candidate**  
→ **Dependency / Schedule**  
→ **Review**  
→ **Verification**  

The second chain is the actual intellectual differentiator of the demo.

The judge should be able to follow one cryptographic asset through this chain.

---

# 3. Product Positioning

ECDAT is presented as:

> A scanner-agnostic cryptographic intelligence and migration decision framework that unifies evidence from existing discovery tools, preserves provenance and uncertainty, analyzes cryptographic risk and quantum/PQC exposure, and produces explainable migration decisions and verification paths.

ECDAT is NOT presented as:

* a replacement for every scanner;
* a cryptographic algorithm generator;
* a quantum computer;
* a chatbot;
* an automatic code-rewriting system;
* a magic AI security verdict engine;
* a claim of complete cryptographic discovery coverage.

Existing organizational tools may include:

* CryptoScan
* CodeQL
* Sonar
* Syft
* internal/proprietary scanners
* CI/CD tooling
* organization-specific collectors

ECDAT provides the intelligence/normalization/analysis layer above those sources.

---

# 4. Fundamental Architecture Rule

The existing:

`product/`

directory is the authoritative ECDAT product implementation and must be treated as FROZEN during demo development.

The demo must NOT:

* copy the ECDAT core into `demo/`;
* fork core logic;
* recreate risk logic;
* recreate migration mappings;
* recreate asset models unnecessarily;
* modify production code merely to make the demo easier;
* silently implement functionality that the real product does not possess.

Preferred relationship:

`demo/`  
→ consumes/imports  
→ `product/`  

Not:

`product/`  
→ copied into  
→ `demo/`  

If the demo exposes a limitation in the product core, report it instead of silently changing the core.

---

# 5. Demo Architecture

Target conceptual architecture:

```text
┌──────────────────────────────────────────────┐
│              ECDAT DEMO UI                   │
│                                              │
│ Overview · Discovery · Evidence · Risk       │
│ Migration · Schedule · Verification          │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│               DEMO API / BFF                 │
│                                              │
│ UI-safe response models                      │
│ Scenario control                             │
│ Error handling                               │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│          DEMO ORCHESTRATION LAYER            │
│                                              │
│ Scenario → ingestion → analysis → result     │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│           REAL ECDAT PRODUCT CORE            │
│                                              │
│ ingestion                                    │
│ normalization                                │
│ evidence                                     │
│ assets                                       │
│ CBOM                                         │
│ risk                                         │
│ migration                                    │
│ scheduling                                   │
└──────────────────────────────────────────────┘
```

The demo layer is responsible for presentation and controlled orchestration.

The product core remains responsible for actual ECDAT analytical behavior wherever functionality already exists.

---

# 6. Demo Directory Boundary

The target structure should be approximately:

```text
ECDAT/
├── product/              # FROZEN
├── learning/             # existing project knowledge
└── demo/
    ├── frontend/
    ├── backend/
    ├── scenarios/
    ├── adapters/
    ├── orchestration/
    ├── tests/
    ├── docs/
    └── README.md
```

Antigravity may refine the structure if there is a strong engineering reason.

Any deviation must be reported.

Do not create unnecessary framework complexity.

---

# 7. Primary Judge Journey

The demo must support one canonical walkthrough.

### Step 1 — Overview

Judge sees:

**Your cryptographic environment**

with a clear pipeline:

`Discover → Understand → Prioritize → Migrate → Verify`

The overview should immediately communicate that ECDAT works with existing discovery sources rather than requiring the organization to abandon them.

---

### Step 2 — Discovery

Show sources/adapters conceptually and/or through actual supported demo integration.

Important distinction:

* actually implemented/live functionality must be labeled as such;
* available architectural adapters must not be presented as live integrations;
* future integrations must be visibly distinguished.

Existing repository evidence should determine exactly what can honestly be shown as live.

---

### Step 3 — Crypto Inventory

Show discovered cryptographic assets.

Example asset classes may include:

* RSA
* AES
* ECDSA
* ECDH
* Ed25519
* DES
* SHA-1
* dependency-only cryptographic indicators
* unknown/dynamic cases

The demo should preserve the distinction between:

**direct evidence**

and

**dependency/presence evidence**.

A dependency containing a cryptographic library must not automatically be represented as proof that a particular algorithm is used.

---

### Step 4 — Evidence Explorer

This is the HERO feature.

Select a cryptographic asset such as RSA-2048.

The interface should expose:

* source/scanner;
* source type;
* file/module/location where available;
* detection method;
* raw/normalized evidence;
* evidence identifiers;
* provenance;
* confidence/evidence quality;
* finding;
* associated asset;
* relevant context;
* resulting analysis.

The central question the screen must answer:

> "Why does ECDAT believe this cryptographic asset exists?"

The user should be able to trace the answer.

---

# 8. Context & Risk

Risk must not be presented as merely:

`RSA → HIGH`

Instead the interface should expose reasoning.

Conceptually:

```text
Observed Asset
      ↓
Usage / Context
      ↓
Security Characteristics
      ↓
Exposure / Uncertainty
      ↓
Risk Dimensions
      ↓
Priority
      ↓
Reasoning
```

Where available from the actual core, expose:

* risk;
* priority;
* uncertainty;
* context;
* explainability;
* evidence quality;
* relevant mitigation/isolation information.

Do not invent values merely to make the UI impressive.

---

# 9. Migration Intelligence

The migration screen should answer:

> "What could the organization do about this?"

For an eligible cryptographic asset, show:

```text
Current Algorithm
       ↓
Cryptographic Role
       ↓
Candidate PQC Target
       ↓
Possible Hybrid Strategy
       ↓
Constraints
       ↓
Dependencies
       ↓
Review Required
```

Migration candidates are advisory.

The UI must not imply that a mapping is an unconditional deployment recommendation.

Security semantics must remain faithful to the existing Phase 4 implementation.

Do not simplify hybrid cryptography into claims such as:

> "Hybrid = maximum security."

The demo must preserve the product's distinction between construction, combiner semantics, threat model, passive HNDL exposure and active quantum threats.

---

# 10. Migration Plan / Scheduler

Show that migration is not simply:

`RSA → ML-DSA`

Instead:

```text
Asset
 ↓
Dependency
 ↓
Migration milestone
 ↓
Ordering constraints
 ↓
Blockers
 ↓
Review gates
 ↓
Migration sequence
```

The demo should visibly surface:

* dependencies;
* cycles;
* blocked assets;
* review gates;
* missing parameters;
* ambiguous/unknown cases;
* code-refactor requirements where represented by the actual core.

Do not fabricate organizational deadlines, ownership, criticality or dependency edges.

---

# 11. Verification

The current ECDAT implementation does NOT establish a fully implemented production rescan/diff verification system.

Therefore the demo must NOT pretend that it does.

The verification section may present:

* the intended verification workflow;
* what would be rescanned;
* what evidence would be compared;
* how migration verification would work;
* what is currently implemented;
* what is future/deferred.

Any prototype-only verification interaction must be explicitly represented as a demo workflow rather than silently presented as an existing production capability.

---

# 12. Trust Model

The demo should communicate:

> ECDAT does not ask an organization to blindly trust another security tool.

Instead:

```text
Evidence
   ↓
Reasoning
   ↓
Decision
   ↓
Verification
```

Every important actionable conclusion should be traceable to evidence and an identifiable source where the underlying implementation supports that trace.

The demo should distinguish:

1. Observed fact.
2. ECDAT-derived analysis.
3. External standards/knowledge.
4. Human/organizational decision.

These categories must not be visually conflated.

---

# 13. Privacy / Deployment Messaging

Do NOT claim:

* "ECDAT never reads your source code."
* "ECDAT guarantees zero source retention."
* "Everything runs locally."
* "Enterprise on-prem deployment is already production-ready."

The existing project has architectural/privacy goals and boundaries, but not all of those guarantees are fully enforced.

The demo should instead communicate the architectural direction:

```text
Organization-controlled environment

Repositories
Binaries
Containers
CI/CD
Internal scanners
        ↓
Organization-controlled collectors/adapters
        ↓
ECDAT
```

If a capability is future architecture rather than current implementation, label it accordingly.

---

# 14. Scanner-Agnostic Story

The demo must make the scanner-agnostic architecture understandable.

Concept:

```text
             ┌─ CryptoScan
             ├─ CodeQL
             ├─ Sonar
             ├─ Syft
             ├─ Internal Scanner
             └─ Custom Adapter
                    │
                    ▼
             ECDAT Adapter Boundary
                    │
                    ▼
             Common Evidence Model
                    │
                    ▼
              ECDAT Intelligence
```

However:

**Do not show an integration as "live" unless it actually exists in the current implementation.**

The current repository evidence must determine the actual status of each adapter.

---

# 15. Known Limitations That Must Remain Visible

The demo must not hide known limitations when they materially affect interpretation.

Important examples include:

* scanner false negatives such as benchmark TC08 and TC11;
* no-finding does not mean cryptographically safe;
* discovery coverage is not equivalent to pipeline fidelity;
* live subprocess execution/security isolation capabilities are incomplete;
* zero-source-retention enforcement is incomplete;
* full CycloneDX Draft-07 runtime validation has not been executed;
* several cryptographic/PQC families and policies remain deferred;
* migration override expiry/reversion is not implemented;
* Phase 4C is not commissioned.

The exact presentation can be concise, but these limitations must not be contradicted by the UI.

---

# 16. Visual/Product Principles

The UI should feel like an enterprise security analyst/control-plane product.

It should NOT feel like:

* a generic admin dashboard;
* a student CRUD project;
* a collection of cards;
* an AI chatbot;
* a marketing landing page;
* a fake SOC dashboard filled with meaningless numbers.

Prioritize:

* strong information hierarchy;
* evidence visibility;
* traceability;
* technical credibility;
* readable graphs;
* clear status semantics;
* restrained visual design;
* purposeful interaction;
* consistent terminology.

Every major visual element should answer a user question.

---

# 17. Data Philosophy

The demo may use controlled scenarios, but controlled data must remain distinguishable from actual engine output.

Preferred structure:

```text
Scenario
   ↓
Real / controlled input
   ↓
Real ECDAT processing where available
   ↓
Presentation adapter
   ↓
UI
```

Avoid hardcoding the final answer directly into UI components.

If a demo-only fixture is necessary, document it.

The UI must not contain duplicated copies of analytical rules.

---

# 18. Live / Controlled / Future Classification

Every demonstrated capability should belong to one of these states:

### LIVE

Implemented in the existing ECDAT core and actually used by the demo.

### CONTROLLED DEMO

A deterministic demonstration wrapper/scenario used because the complete production capability does not yet exist.

### ARCHITECTURAL / FUTURE

A future capability shown only to explain product direction.

The UI and documentation must not blur these categories.

---

# 19. Demo Scenario

The first canonical scenario should use a realistic mixed cryptographic environment rather than a trivial single-algorithm toy.

The scenario should ideally demonstrate several different analytical outcomes, for example:

* an actionable RSA asset;
* a symmetric AES asset that should not be incorrectly routed through public-key PQC mapping;
* a weak/legacy algorithm such as DES;
* a hash finding such as SHA-1 where appropriate;
* dependency-only evidence;
* an unknown/dynamic cryptographic case;
* at least one asset requiring review.

The exact scenario composition must be derived from the existing benchmark fixtures and actual ECDAT behavior rather than invented arbitrarily.

The existing TC01–TC11 benchmark set should be considered the primary source for realistic demo cases.

---

# 20. What the Demo Must Prove

By the end of the walkthrough, a judge should understand these five claims:

### Claim 1

ECDAT can consume cryptographic discovery evidence instead of requiring one proprietary scanner.

### Claim 2

ECDAT preserves evidence and provenance instead of hiding the origin of findings.

### Claim 3

ECDAT converts findings into a contextual cryptographic asset model.

### Claim 4

ECDAT adds explainable risk and migration intelligence.

### Claim 5

ECDAT treats migration as a dependency/review/verification problem rather than simply replacing algorithms.

These are product claims and must be supported by actual implementation or clearly labeled prototype behavior.

---

# 21. Explicit Non-Goals

The demo will NOT attempt to:

* rebuild the ECDAT core;
* implement a new scanner;
* support every scanner;
* implement every cryptographic family;
* implement complete enterprise authentication/RBAC;
* implement full production source-code sandboxing;
* implement complete CI/CD integration;
* implement automatic source-code rewriting;
* implement a production migration deployment engine;
* claim complete cryptographic discovery;
* claim production readiness;
* invent unsupported AI functionality.

---

# 22. Engineering Constraints

1. `product/` is frozen.
2. Demo changes stay inside `demo/` unless a genuine product defect is discovered.
3. Existing tests must continue passing.
4. No benchmark answer keys may be modified to force success.
5. No unsupported security claims.
6. No fabricated standards compliance.
7. No fabricated scanner integrations.
8. No duplicated analytical logic where the existing core can be consumed.
9. Prefer simple architecture over unnecessary infrastructure.
10. Every phase must have explicit acceptance criteria.
11. Every phase must stop at its defined boundary.
12. Antigravity must report evidence, not merely state that the task is complete.

---

# 23. Engineering Verification

At every phase:

```text
Implement
   ↓
Build
   ↓
Run focused tests
   ↓
Run relevant existing tests
   ↓
Inspect changed files
   ↓
Verify architectural boundaries
   ↓
Verify claims
   ↓
Report
   ↓
Human/technical review gate
```

The final demo should additionally undergo:

* functional testing;
* UI/UX review;
* integration testing;
* failure-state testing;
* adversarial/hardening review;
* claim audit;
* demo rehearsal.

---

# 24. Demo Phase Structure

## D0

Product specification and architecture gate.

## D1

Demo foundation + real-core integration.

## D2

Hero scenario + evidence/risk/migration flow.

## D3

Complete analyst control plane + judge walkthrough.

## D4

Hardening + adversarial review + claim audit.

## D5

Visual polish + performance + final rehearsal.

No phase is considered complete merely because Antigravity reports completion.

---

# 25. D0 Acceptance Criteria

D0 is complete when:

* demo purpose is defined;
* target judge experience is defined;
* product positioning is defined;
* `product/` freeze boundary is explicit;
* demo architecture is defined;
* live/controlled/future distinction is defined;
* hero scenario is defined;
* evidence-first UX is defined;
* migration/scheduling UX is defined;
* verification limitations are defined;
* privacy/security claims are constrained;
* known limitations are captured;
* non-goals are explicit;
* phase structure is defined;
* D1 implementation can proceed without major product ambiguity.

---

# 26. Decision Gate

D0 output is the specification above.

The next implementation task is **D1 only**.

Antigravity must NOT begin implementing D2/D3 functionality during D1.

D1's mission will be:

> Establish the demo application boundary and prove that the demo can safely consume the real frozen ECDAT core.

The first D1 implementation should therefore prioritize architectural correctness over visual completeness.
