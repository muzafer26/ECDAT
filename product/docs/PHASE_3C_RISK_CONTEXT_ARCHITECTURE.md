# PHASE 3C — RISK, CONTEXT & PRIORITIZATION ARCHITECTURE (REVISED)

---

## 1. Executive Summary & Architectural Separation

Phase 3C establishes the **Contextual Risk Analysis and Prioritization Engine** for ECDAT.

$$\begin{matrix}
\text{Evidence} & \longrightarrow & \text{Canonical Domain Interpretation} & \longrightarrow & \text{CryptoAsset} \\
& & & & \downarrow \\
\text{Context Layers} & \longrightarrow & \text{Deterministic Threat Classification} & \longrightarrow & \mathbf{Technical Risk Vector} \\
& & & & \downarrow \\
\text{Enterprise Policy Overrides} & \longrightarrow & \text{Default Priority Assignment} & \longrightarrow & \mathbf{Final Actionable Priority} \\
& & & & \downarrow \\
& & & & \text{Structured Explainability}
\end{matrix}$$

### Authoritative Separation of Core Concepts:

The engine strictly separates five distinct analytical concepts that must never be collapsed:

1. **Cryptographic Posture:** The intrinsic technical characteristics of the algorithm instantiation: classical algorithm status, key length, mode of operation, padding scheme, and implementation parameters.
2. **Quantum Exposure Class:** The mathematical susceptibility of the underlying mathematical primitive to quantum cryptanalysis (Shor's polynomial speedup vs Grover's quadratic speedup vs PQC design).
3. **Classical Security Status:** Adherence to authoritative classical cryptographic baselines (e.g. NIST SP 800-131A Rev 2 disallowed, deprecated, or acceptable).
4. **Contextual Impact:** The operational environment, data sensitivity, external accessibility, and system criticality where the asset is deployed.
5. **Overall Risk:** The multi-dimensional synthesis of technical posture and contextual impact. An algorithm classification alone **never** automatically dictates overall risk.
6. **Actionable Priority:** The organizational urgency and scheduling sequence for remediation, incorporating data lifetime ($X$), migration complexity ($Y$), and enterprise policy. **Risk $\neq$ Priority.**

---

## 2. Component Decoupling & Invariants

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CANONICAL DOMAIN LAYER                          │
│   • CryptoAsset (Deterministic Identity, Family, Parameters, Role)    │
│   • EvidenceRecord (File Path, Line Range, Code Snippet, Scanner)      │
│   • Finding (Confidence, Detection Method, Correlation Basis)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────┴────────────────────────────────────┐
│                       CONTEXT INGESTION LAYER                          │
│   • AssetContext (Data Lifetime, Sensitivity, Exposure, Criticality)   │
│   • ContextProvenance (Source, Author, Confidence, Timestamp)          │
│   • Configurable Enterprise Thresholds (e.g. HNDL Horizon Policy)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────┴────────────────────────────────────┐
│                    DETERMINISTIC RISK ENGINE                           │
│   • Classical Security Evaluation (Disallowed / Deprecated / Acceptable)│
│   • Primitive-Level Quantum Classification (Shor / Grover / PQC)       │
│   • Operational Role Contextualization (Impact on Confidentiality/Auth)│
│   • Configurable HNDL Exposure Assessment                              │
│   • Categorical Uncertainty Assessment (Confirmed / Partial / Review)  │
│   • Output: RiskAssessment Vector (Separated Dimensions, No Fake Float)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────┴────────────────────────────────────┐
│                   CONTEXTUAL PRIORITIZATION ENGINE                     │
│   • Technical Default Priority Derivation                              │
│   • Mosca Planning Heuristic Evaluation (X + Y > Z with Provenance)    │
│   • Explicit, Auditable Enterprise Policy Overrides                    │
│   • Output: MigrationPriorityRecord (Tier P0-P4 / Review, Lineage)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────┴────────────────────────────────────┐
│                     EXPLAINABILITY & REASONING LAYER                   │
│   • Fact / Classification / Context / Rule / Assumption Breakdown      │
│   • Verified Standards Citations (NIST SP 800-131A, FIPS 203/204/205)  │
│   • Transparent Uncertainty and Gaps Disclosure                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Strict Role Semantics and Non-Inference Invariants

In strict adherence to Phase 3B forward-compatibility invariants:

* **Primitive & Algorithm** determine the mathematical cryptographic and quantum threat class (e.g., RSA is Shor-vulnerable; AES is Grover-affected).
* **Role** provides **operational consequence only** (e.g., `KEY_AGREEMENT` impacts session confidentiality; `DIGITAL_SIGNATURE` impacts authenticity; `AUTHENTICATION` does not expose historical traffic to retroactive decryption).
* **Role MUST NOT manufacture or infer:**
  - Algorithm family
  - Quantum vulnerability class
  - Algorithm primitive
  - Cryptographic function array
  - Formal parameter set identifier

---

## 4. Boundary Protection Against CycloneDX CBOM and AI

1. **CycloneDX CBOM Output Isolation:**
   - The Risk Engine takes canonical `CryptoAsset` instances as input.
   - It **never** reads, parses, or queries CycloneDX CBOM files.
   - CBOM remains strictly an export artifact for interoperability and compliance exchange.
2. **Zero Authoritative AI:**
   - Risk and priority calculations are 100% deterministic and written in Python standard library.
   - No Large Language Model is permitted in the decision or scoring path.
   - Advisory explanations in downstream UIs (Phase 5) must format structured `RiskExplanation` records without altering facts or categories.
