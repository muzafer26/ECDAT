# ECDAT Product Core

This directory contains the authoritative engineering implementation of the **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**.

---

## Architecture Layout

The product is organized into distinct, modular functional layers designed to enforce scanner agnosticism, deterministic evaluation, and strict security isolation:

```
product/
├── docs/                        # Authoritative Specifications & Architecture Records
├── core/                        # Domain entities, normalized schemas, CBOM serializers
│   ├── domain/                  # Cryptographic asset models (algorithms, certificates, keys)
│   ├── evidence/                # Evidence chain and provenance tracking
│   └── cbom/                    # CycloneDX 1.7 CBOM mapping and validation
├── integration/                 # Scanner-agnostic adapter boundary
│   ├── interfaces/              # Standard discovery contracts and engine specifications
│   └── adapters/                # Dedicated scanner adapters (CryptoScan, CBOMkit, static regex)
├── engine/                      # Deterministic risk and migration prioritization
│   ├── risk/                    # Deterministic multi-factor scoring engine
│   └── migration/               # PQC migration priority, compatibility, and verification
├── api/                         # Pipeline orchestration, control plane, and API endpoints
├── agent/                       # Lightweight local CLI / remote audit runner
├── web/                         # Analyst interface and interactive verification UI
└── tests/                       # Unit tests, integration tests, adversarial corpus
```

---

## Current Status: Phase 0

* **Codebase State:** Architectural constitution established. No production code, API endpoints, or database tables have been instantiated yet.
* **External Scanners:** Zero external scanners are installed. Scanner integrations will occur through adapter harnesses starting in Phase 1 following benchmark validation.
* **Primary Reference:** All engineering specifications and constraints are documented in [`product/docs/`](./docs/).
