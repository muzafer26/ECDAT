# ECDAT — Demo Truth Contract (Phase D5)

**Status:** AUTHORITATIVE SPECIFICATION  
**Scope:** Demo Presentation Layer vs Frozen Product Core (`product/core/`)  
**Product Freeze SHA-256:** `b748942df467803008be85b10f093d87c3f7fa6e9705382ecab62165a44e35b2` (392 files, 300 tests passing)  

---

## 1. Governing Principle

The ECDAT Demo is a **truthful presentation layer of the existing ECDAT Phase 0–4 product**, not an independently invented security scanner, compliance certification platform, or marketing simulator.

The demo **may**:
- Simplify complex data models for executive and analyst comprehension.
- Select representative slices and canonical scenarios (`TC-01`, `TC-02`, `TC-06`).
- Visualize relationships, dependencies, and transformation flows.
- Aggregate metrics and category counts across discovered assets.
- Reorder presentation elements into an intuitive analyst journey.
- Animate transitions between evidence, risk, and scheduling views.
- Explain reasoning, policy citations, and standards foundations.

The demo **must NOT invent**:
- Cryptographic findings or AST matches not present in raw scanner inputs.
- Unobserved facts (e.g., parameter sizes, padding schemes, protocol usages).
- Numerical risk scores, probabilities, or quantitative security ratings.
- Operational deployment facts (unless explicitly classified as scenario context).
- Scanner capabilities beyond implemented adapter ingestion parsers.
- Migration targets incompatible with evidenced cryptographic roles.
- Standards compliance claims (e.g., claiming FIPS certification when only candidate mapping exists).
- Performance claims or false latency comparisons.
- Post-migration verification verdicts (e.g., claiming code has been migrated or verified).

> **Core Rule on Missing Information:**  
> **Render the missing state. Do not fill it with a plausible value.**

---

## 2. Source-of-Truth Hierarchy

When resolving any conflict between presentation text, documentation, and system behavior, the following strict hierarchy governs:

```text
1. Actual product source code (product/core/)
      ↓
2. Actual product tests (product/tests/)
      ↓
3. Actual demo orchestration source code (demo/orchestration/, demo/backend/)
      ↓
4. Actual runtime behavior (execution outputs)
      ↓
5. Benchmark fixtures / ground truth (product/benchmark/)
      ↓
6. Documentation (specifications, ADRs, matrices)
      ↓
7. Previous Antigravity / agent conversation reports
```

*Notes:* Reports and narrative summaries are claims to verify, never self-authenticating truth. No modification to `product/core/` is permitted under any circumstance.

---

## 3. Prohibited Presentation Patterns

The following patterns, phrases, and assertions are strictly prohibited across all screens, documentation, tooltips, and code comments in the demo:

| Prohibited Pattern / Claim | Reason for Prohibition | Enforced Replacement Standard |
| :--- | :--- | :--- |
| **"Answers the judge..." / "Why the judge should trust..."** | Coaching language breaks professional software credibility. | Describe actual product behavior and evidence trace directly. |
| **"Guarantees scientific reproducibility / security"** | Security is probabilistic and scoped; nothing is unconditionally "guaranteed". | "Executes deterministic pipeline on verified benchmark inputs." |
| **"Air-gapped security" as broad claim** | Misleads the audience regarding runtime infrastructure. | Reference local offline fixture execution without network egress. |
| **"RSA-2048" without ground-truth label** | Scanner AST finding only captured "RSA" token; key length was omitted. | State: `RSA (key size unevidenced in AST; 2048-bit benchmark ground truth)`. |
| **"Session Key Exchange" for TC01** | AST evidence only reveals `KeyPairGenerator.getInstance("RSA")`. | State: `Asymmetric Key Generation (key_generation role)`. |
| **"100% Quantum-Safe" / "Verified PQC"** | ECDAT does not perform code refactoring or binary verification in Phase 4. | State: `Advisory Candidate Target (FIPS 203 ML-KEM-768)`. |
| **"Migration Complete" / "Successfully Replaced"** | Implies execution of changes that have not occurred. | State: `Migration Target Identified — Pending Engineering Implementation`. |
| **Fake AI Confidence / Machine Learning Scores** | ECDAT uses deterministic formal rule deduction, not opaque ML classifiers. | State: `Deterministic Rule Derivation (R-RISK-06)`. |
| **Generic Drop-In Binary Replacement Claims** | PQC primitives have differing key/ciphertext sizes and API contracts. | Disclose agility blockers: `CODE_REFACTOR_REQUIRED`. |
| **Plausible Fallback Defaults for Missing Context** | Fabricates enterprise system names if metadata is missing. | Display: `Not Specified / Unannotated`. |

---

## 4. Scenario Truth Contract: TC01 (Hero Scenario)

**Scenario Identifier:** `tc01_direct_rsa`  
**Purpose:** Demonstrates evidence-driven uncertainty handling, fail-closed risk evaluation, conditional PQC mapping, hybrid transition modeling, dependency scheduling, and blocking human review gates.

### 4.1 Required Runtime Trace
```text
RSA (Token at Line 16)
       ↓
KEY_GENERATION (Inferred Operational Role)
       ↓
Actual Evidence (AST instantiation without parameters)
       ↓
Key Size Not Established (Unevidenced in scanner output)
       ↓
Classical Strength Indeterminate (Refuses to invent 2048-bit value)
       ↓
Review Required (Priority P_REVIEW_REQUIRED / Risk NEEDS_REVIEW)
       ↓
ML-KEM-768 Candidate Target (FIPS 203 / Category 3)
       ↓
Conditional Mapping (mapping_status = CONDITIONAL)
       ↓
RSA_OAEP_MLKEM768_DUAL_WRAP (Evaluated Hybrid Combiner Scheme)
       ↓
Dependency-Aware Scheduling (Milestone M2-KEY-EXCHANGE-HNDL)
       ↓
Human Review Gate (GATE-REVIEW-26700200 Blocking Ticket)
```

### 4.2 Non-Negotiable Representation Rules for TC01
1. **Key Size Distinction:**  
   - Scanner Evidence: `key_size_bits = None` (AST token only).
   - Benchmark Ground Truth: `2048-bit modulus` in source seed file `DirectRSAKeyGen.java:19`.
   - The UI must explicitly present this distinction: *"Benchmark ground truth: 2048 bits; Unevidenced in scanner AST."*
2. **Operational Role:**  
   - The role is `key_generation` based on `KeyPairGenerator`.
   - The demo must NOT claim it observed a live TLS session-key exchange on the wire; network transmission is an unobserved operational assumption.
3. **Classical Security Status:**  
   - Must be displayed as `INDETERMINATE`. It is NOT `ACCEPTABLE` or `DEPRECATED` because without evidenced bit length, security cannot be computed.
4. **Hybrid Combiner Semantics:**  
   - The hybrid candidate must use the exact construction produced by Phase 4B: `RSA_OAEP_MLKEM768_DUAL_WRAP` with draft-ietf-lamps-pq-composite-kem semantics.

---

## 5. Scenario Truth Contract: TC02 (Symmetric Contrast)

**Scenario Identifier:** `tc02_symmetric_aes`  
**Purpose:** Demonstrates that ECDAT does not blindly map every cryptographic primitive to public-key PQC. Proves truthful non-inference.

### 5.1 Required Runtime Trace
```text
AES (Token at Line 20)
       ↓
ENCRYPTION_DECRYPTION (Symmetric Cipher Role)
       ↓
Symmetric Cryptography (Grover's Algorithm Threat Model)
       ↓
Public-Key KEM Mapping OUT OF SCOPE (Zero PQC KEM Candidates)
       ↓
Advisory Symmetric Recommendation (Retain AES-256 / NIST SP 800-131A)
       ↓
Milestone M1-DATA-AT-REST-SYMMETRIC (Non-PQC Roadmap Grouping)
       ↓
Zero Blocking Review Gates (No human gate inherited from TC01)
```

### 5.2 Non-Negotiable Representation Rules for TC02
1. **Symmetric Exemption:**  
   - `pqc_mapping_status` must evaluate strictly to `OUT_OF_SCOPE`.
   - Candidate targets list must be empty (`[]`).
   - Hybrid schemes list must be empty (`[]`).
2. **Scenario State Isolation:**  
   - TC02 must NOT inherit review gate `GATE-REVIEW-26700200` from TC01.
   - TC02 must NOT inherit milestone `M2-KEY-EXCHANGE-HNDL`.
   - TC02 must NOT display Payment Gateway / FinTech API operational context from TC01. Context is strictly bound to `Core Ledger & Storage Service`.

---

## 6. Scenario Truth Contract: TC06 (Role Awareness)

**Scenario Identifier:** `tc06_ed25519`  
**Purpose:** Demonstrates role-aware migration intelligence. Proves that cryptographic primitives map according to their operational role, not simply their mathematical family.

### 6.1 Required Runtime Trace
```text
Ed25519 (Token at Line 18)
       ↓
DIGITAL_SIGNATURE (Inferred Operational Role)
       ↓
Asymmetric Signature Family (Shor's Discrete Logarithm Threat)
       ↓
Signature Migration Family (NIST FIPS 204 & FIPS 205)
       ↓
Candidate Targets: ML-DSA-65, ML-DSA-44, SLH-DSA-SHA2-128s
       ↓
Candidate Hybrids: MLDSA65-ECDSA-P256-SHA512 (Composite Signature)
       ↓
Agility Factor: Hardcoded Algorithm Instantiation
```

### 6.2 Non-Negotiable Representation Rules for TC06
1. **Signature Role Preservation:**  
   - Ed25519 must map to post-quantum **digital signature** standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
   - Ed25519 must NEVER map to ML-KEM-768 or any key encapsulation mechanism.
2. **Hybrid Construction:**  
   - Hybrid schemes must be composite signatures (`draft-ietf-lamps-pq-composite-sigs`) or dual certificates (`RFC 9763`), never dual-KEM wrappers.

---

## 7. Verification Boundary Truth Contract

The demo must never imply or state that post-quantum migration has actually been performed.

### 7.1 Five-Stage Lifecycle Model
```text
[STAGE 1: CURRENT STATE]
Discovered cryptographic asset & empirical evidence
        ↓
[STAGE 2: MIGRATION TARGET]
Standardized PQC candidate parameter set (advisory)
        ↓
[STAGE 3: IMPLEMENTATION BOUNDARY]
Code refactoring by engineering teams (NOT performed by demo)
        ↓
[STAGE 4: VERIFICATION BOUNDARY]
Post-migration rescan & CBOM delta (NOT executed in demo)
        ↓
[STAGE 5: FUTURE ARCHITECTURE (PHASE 9)]
Cryptographic diff schema projection & assurance verification
```

### 7.2 Strict Display Rules
- Tab 9 must be explicitly badged: `CONTROLLED / FUTURE (PHASE 9)`.
- Diff tables must be titled: `Architectural Projection: Cryptographic Diff Schema Model`.
- Delta cells must display: `PROJECTED: QUANTUM-RESILIENT (PHASE 9)`.
- The interface must never display checkboxes indicating completed migration.
