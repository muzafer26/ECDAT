# ECDAT Controlled Benchmark Infrastructure

**Document Version:** 1.0.0  
**Phase:** Phase 1B (Controlled Benchmark Environment & Seed Corpus)  
**Governance Directive:** Test Infrastructure Only. Zero production code, zero external scanner installations.  
**Download Gate Status:** LOCKED (No external tools may be installed).

---

## 1. Purpose & Architectural Isolation

The `product/benchmark/` directory contains the controlled, reproducible benchmark test suite authored for objective evaluation of candidate cryptographic discovery tools (e.g. IBM CBOMkit, CryptoScan, pqaudit, CodeQL).

### Critical Boundaries:
* **Test Infrastructure Only:** This directory does **NOT** contain production application code, production discovery engines, or backend services.
* **Separation of Concerns:** Benchmark fixtures and seed test cases are completely isolated from future `product/core/` and `product/engine/` implementations.
* **Ground Truth Authority:** The answer keys in this directory represent manually derived, human-verified ground truth against synthetic test cases (formally verified and signed off on 2026-09-12 in `HUMAN_REVIEW_CHECKLIST.md`). No external scanner or AI is assumed to represent ground truth.

---

## 2. Benchmark Directory Structure

```
product/benchmark/
├── README.md                 # Benchmark architecture & execution overview (This file)
├── schemas/                  # Formal JSON schemas defining answer keys & report formats
│   └── answer_key.schema.json
├── corpus/                   # Curated cryptographic test cases
│   └── seed/                 # Phase 1 Seed Corpus (TC-01 through TC-11)
│       ├── MANIFEST.md       # Master seed corpus index and test case specifications
│       ├── tc01_direct_rsa/
│       ├── tc02_symmetric_aes/
│       ├── tc03_ecc_generic/
│       ├── tc04_ecdsa/
│       ├── tc05_ecdh/
│       ├── tc06_ed25519/
│       ├── tc07_sha1_hash/
│       ├── tc08_crypto_wrapper/
│       ├── tc09_dependency_crypto/
│       ├── tc10_misleading_comments/
│       └── tc11_ambiguous_dynamic/
├── answer_keys/              # Human-verified ground truth for each test case (signed off in HUMAN_REVIEW_CHECKLIST.md)
│   ├── README.md             # Ground-truth methodology, schemas, and verification guide
│   ├── tc01_direct_rsa.json
│   ├── tc02_symmetric_aes.json
│   ├── tc03_ecc_generic.json
│   ├── tc04_ecdsa.json
│   ├── tc05_ecdh.json
│   ├── tc06_ed25519.json
│   ├── tc07_sha1_hash.json
│   ├── tc08_crypto_wrapper.json
│   ├── tc09_dependency_crypto.json
│   ├── tc10_misleading_comments.json
│   └── tc11_ambiguous_dynamic.json
├── fixtures/                 # Common non-cryptographic templates, mock manifests, and mocks
│   └── README.md
├── environment/              # Proposed runtime environment, sandboxing & isolation specs
│   └── README.md
└── reports/                  # Future comparative benchmark scorecards (Phase 1C/1D)
    └── README.md
```

---

## 3. Seed Corpus Philosophy

Every test case in `corpus/seed/` is:
1. **Small & Self-Contained:** Focused strictly on answering one specific cryptographic discovery question.
2. **Deterministic:** Formatted to ensure stable line numbers and reproducible parsing.
3. **Synthetic & Safe:** Strictly free of real private keys, passwords, production certs, or malicious payloads.
4. **Manually Auditable:** Easy for a human auditor to open the source code and immediately verify why an answer key expects a specific finding.
