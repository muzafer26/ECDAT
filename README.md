# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

**SIH Problem Statement ID:** SIH26164  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software  
**Current Phase:** Phase 0 (Foundation, Architecture & Project Constitution)  
**Project Gate Status:** Gated — Awaiting Phase 1 Authorization  

---

## 1. Executive Summary

**ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)** is an evidence-first, scanner-agnostic cryptographic intelligence platform designed to discover, inventory, analyze, and prioritize cryptographic assets across enterprise software repositories, dependencies, configurations, and artifacts.

Modern organizations lack a comprehensive, verifiable cryptographic inventory. Cryptographic implementations—ranging from legacy symmetric ciphers and vulnerable asymmetric public-key infrastructure (PKI) to quantum-vulnerable algorithms—are scattered across codebases, configuration files, containers, and third-party dependencies.

ECDAT functions as an organization's **"Cryptographic X-Ray"**, navigating the complete lifecycle:
$$\text{Discover} \longrightarrow \text{Prove} \longrightarrow \text{Inventory} \longrightarrow \text{Understand} \longrightarrow \text{Assess} \longrightarrow \text{Prioritize} \longrightarrow \text{Prepare Migration} \longrightarrow \text{Verify}$$

### What ECDAT Is
* A **scanner-agnostic discovery and analysis framework** that decouples external detection engines from core normalization and risk logic.
* An **evidence-first inventory system** that maintains a strict boundary between empirical evidence (file, line, code snippet, scanner origin) and derived domain interpretation.
* A **CycloneDX 1.7 CBOM (Cryptographic Bill of Materials)** compliant platform.
* A **deterministic, explainable risk and role-aware Post-Quantum Cryptography (PQC) migration decision support engine**.
* A **verification system** capable of diffing scans across commits to verify cryptographic retirement and replacement.

### What ECDAT Is NOT
* ❌ Not a quantum computer simulator.
* ❌ Not an encryption/decryption product or key manager.
* ❌ Not an opaque AI chatbot making unverified security decisions.
* ❌ Not a generic vulnerability/SAST scanner or dependency CVE checker.
* ❌ Not merely an "RSA detector" or universal algorithm replacer.
* ❌ Not a claim that all cryptography can always be detected statically.
* ❌ Not a one-click magical PQC code-rewriting tool.

---

## 2. Core Development Philosophy

1. **Evidence Over Claims:** A finding is meaningless without unambiguous evidence. Raw scanner outputs are empirical leads, not authoritative interpretations.
2. **Role-Aware Migration:** Migration recommendations are strictly role-aware (key establishment $\rightarrow$ ML-KEM/hybrid; digital signatures $\rightarrow$ ML-DSA/SLH-DSA; bulk encryption $\rightarrow$ symmetric review). Universal algorithm replacement is rejected.
3. **Deterministic Risk Logic:** Security decisions and risk rankings are computed by transparent, verifiable rule sets—never delegated to non-deterministic black-box models.
4. **Explicit Uncertainty:** The platform explicitly distinguishes between `CONFIRMED`, `LIKELY`, `POSSIBLE`, and `NEEDS_REVIEW`. It never equates *"no detected finding under current discovery coverage"* with *"no cryptography exists"*.
5. **Standardization Over Reinvention:** Aligns with international open standards (CycloneDX 1.7 CBOM, NIST PQC Standards FIPS 203, 204, 205).
6. **Scanner Agnosticism:** External discovery tools are pluggable adapters. If a scanner is added, updated, or removed, the core domain model and risk engine remain unaffected.
7. **Requirement-Based Security Posture:** Security guarantees (sandbox isolation, zero-source transmission, ephemeral shredding) are treated as strict engineering requirements to be verified by automated implementation and network tests before operational readiness claims.
8. **Two-Layer Repository Architecture:** Strict separation between the operational production engineering codebase (`product/`) and the human owner learning curriculum (`learning/`).

---

## 3. Repository Structure

```
d:\SIH\
├── product/                         # Authoritative Engineering Core
│   ├── docs/                        # Specifications, Models, Decisions, and Registers
│   │   ├── PROJECT_SPEC.md          # Comprehensive functional & non-functional spec
│   │   ├── ARCHITECTURE.md          # Multi-layer scanner-agnostic architecture
│   │   ├── MVP_SCOPE.md             # Strict boundary controls (Must/Should/Later/Out)
│   │   ├── SECURITY_MODEL.md        # Sandbox, untrusted input handling, trust boundaries
│   │   ├── DATA_FLOW.md             # End-to-end data progression and persistence rules
│   │   ├── THREAT_MODEL.md          # STRIDE-based vulnerability & adversary analysis
│   │   ├── INTEGRATION_STRATEGY.md  # Adapter contracts and third-party isolation
│   │   ├── EVALUATION_PLAN.md       # Phase 1 Seed Corpus and accuracy benchmarks
│   │   ├── JUDGE_DEFENSE_MATRIX.md  # Viva/defense questions with live demonstration paths
│   │   ├── OPEN_SOURCE_REGISTER.md  # Evaluated candidate tools and licensing registry
│   │   ├── DECISIONS.md             # Architecture Decision Records (ADRs) with validation state
│   │   ├── KNOWN_LIMITATIONS.md     # Explicit catalog of technical boundaries & unknowns
│   │   └── PROJECT_STATE.md         # Current execution gate and historical roadmap
│   └── README.md                    # Product layout and build documentation
│
├── learning/                        # Human Owner Educational Support
│   ├── concepts/                    # Fundamentals of Cryptography, CBOM, and PQC
│   ├── rationale/                   # Architectural trade-off explanations
│   ├── interview_prep/              # Defense preparation and technical viva Q&A
│   └── README.md                    # Learning curriculum navigation
│
└── README.md                        # Root Project Constitution (This file)
```

---

## 4. Phase-Gated Engineering Workflow

To ensure production rigor and eliminate unsupported assumptions, ECDAT follows a gated 13-phase implementation roadmap. **No phase may begin until the prior phase passes formal human review and acceptance criteria.**

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 0** | **Foundation, Architecture & Project Constitution** | **COMPLETED (Current)** |
| **Phase 1** | Core Discovery Integration & Adapter Harness | *Gated — Awaiting Authorization* |
| **Phase 2** | Evidence Model & Normalization Pipeline | *Pending* |
| **Phase 3** | Cryptographic Inventory & CycloneDX 1.7 CBOM Engine | *Pending* |
| **Phase 4** | Contextual Analysis & Cryptographic Relationships | *Pending* |
| **Phase 5** | Deterministic Explainable Risk Engine | *Pending* |
| **Phase 6** | PQC Migration Decision Support | *Pending* |
| **Phase 7** | Analyst Dashboard & Human Review Workflow | *Pending* |
| **Phase 8** | Multi-Mode Deployment (Upload, Local, Agent, On-Prem) | *Pending* |
| **Phase 9** | Re-scan, Verification & Cryptographic Diff Engine | *Pending* |
| **Phase 10** | Security Hardening & Adversarial Penetration Testing | *Pending* |
| **Phase 11** | Ground-Truth Evaluation & Benchmark Verification | *Pending* |
| **Phase 12** | SIH Presentation, Live Demonstration & Defense | *Pending* |

---

## 5. Security Notice

This repository will process arbitrary, untrusted source code and archive files during scan execution. Sandboxing, resource quotas, and path traversal protections defined in `product/docs/SECURITY_MODEL.md` must be enforced before executing discovery pipelines on external targets.
