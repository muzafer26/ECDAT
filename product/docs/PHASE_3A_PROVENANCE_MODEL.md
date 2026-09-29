# ECDAT Phase 3A — Cryptographic Provenance Model

**Document Identifier:** ECDAT-SPEC-PHASE-3A-PROVENANCE  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:** 
- `product/docs/PROJECT_SPEC.md`
- `product/docs/ARCHITECTURE.md`
- `product/docs/DECISIONS.md` (ADR-007, ADR-008, ADR-010, ADR-013, ADR-015)
- `product/docs/PHASE_3A_CBOM_ARCHITECTURE.md`
- `product/docs/PHASE_3A_CBOM_PROJECTION_MATRIX.md`
- `product/docs/PRE_3A_DOMAIN_RUN_CONTRACT_GATE.md`

---

## 1. Provenance Architecture & Objective

In enterprise cryptographic auditing, a Bill of Materials is untrustworthy if an auditor cannot verify:
1. Which scanner observed the cryptography.
2. The exact line, file, and statement in source code where the call occurred.
3. The verbatim raw scanner output that produced the finding.
4. The specific tool version, ruleset, and analysis session that generated the data.

This specification designs the **unbroken end-to-end provenance chain** linking every external CBOM component back to its empirical discovery origin, while enforcing strict boundaries so that the public CBOM does not claim to embed the entire internal raw evidence repository.

---

## 2. Complete End-to-End Lineage Chain

```
Target Codebase / Repository Snapshot (target_id, target_content_hash)
                         │
                         ▼
        Analysis Run (run_id, timestamp, ecdat_version)
                         │
                         ├─────────────────────────────────────────┐
                         ▼                                         ▼
            Scanner Execution A                       Scanner Execution B
          (CryptoScan v1.4.0)                         (Syft v1.51.1)
                         │                                         │
                         ▼                                         ▼
        Raw Scanner Output (stdout)               Raw Scanner Output (stdout)
          (sha256:7f83b165...)                      (sha256:a4b2c1d3...)
                         │                                         │
                         ▼                                         ▼
                 EvidenceRecords                           EvidenceRecords
             (cryptoscan:rule-01)                          (syft:pkg-02)
                         └──────────────────┬──────────────────────┘
                                            ▼
                                         Findings
                                (ecdat:finding:{sha256})
                                            │
                                            ▼
                                      CryptoAssets
                                  (ecdat:asset:{key})
                                            │
                                            ▼
                                  CBOM Components
                        (bom-ref: "ecdat:asset:{asset_id}")
```

---

## 3. Tier-by-Tier Provenance Links & Invariants

### Tier 1: CBOM Component $\to$ ECDAT CryptoAsset
- **CBOM Field:** `component.bom-ref` and `component.properties.name = "ecdat:asset_id"`.
- **Target Entity:** `CryptoAsset.asset_id`.
- **Derivation:** Deterministic string: `"ecdat:asset:" + asset_id`.
- **Invariant:** $1 \to 1$ mapping between a `CryptoAsset` and its primary exported CBOM component.

### Tier 2: CryptoAsset $\to$ Findings
- **CBOM Field:** `component.properties.name = "ecdat:finding_ids"`.
- **Target Entity:** `Sequence[Finding.finding_id]`.
- **Value:** Comma-separated list of UUIDv5 finding identifiers.
- **Invariant:** A `CryptoAsset` references one or more `Finding` IDs merged via same-source-statement deduplication.

### Tier 3: Finding $\to$ EvidenceRecords
- **CBOM Field:** `component.properties.name = "ecdat:evidence_ids"`.
- **Target Entity:** `Sequence[EvidenceRecord.evidence_id]`.
- **Value:** Comma-separated list of namespaced evidence records (e.g. `cryptoscan:rule-01,syft:pkg-02`).
- **Invariant:** Unbroken lineage from canonical interpretation to raw scanner observation.

### Tier 4: EvidenceRecord $\to$ Scanner Execution & Tool Version
- **CBOM Field:** `component.properties.name = "ecdat:scanners"` and `metadata.tools.components`.
- **Target Entity:** `EvidenceRecord.scanner_id`, `EvidenceRecord.scanner_version`, `EvidenceRecord.adapter_id`.
- **Value:** Formal tool strings (e.g. `"cryptoscan:1.4.0"`).
- **Invariant:** Multiple scanners contributing to a single asset are all explicitly credited.

### Tier 5: EvidenceRecord $\to$ Raw Scanner Output Capture
- **CBOM Field:** `component.properties.name = "ecdat:raw_output_ref"`.
- **Target Entity:** `RawScannerOutput.sha256_hash`.
- **Value:** Content-addressable hash string: `"sha256:" + hex_digest`.
- **Security Boundary:** The verbatim raw scanner bytes are NEVER embedded in the CBOM; they reside in quarantined storage and are referenced solely by cryptographic digest (ADR-013).

### Tier 6: Scanner Execution $\to$ Analysis Run
- **CBOM Field:** `serialNumber` (BOM Root) and `metadata.properties.name = "ecdat:run_id"`.
- **Target Entity:** `AnalysisRun.run_id`.
- **Value:** Formatted as RFC 4122 UUID URN: `"urn:uuid:" + run_id`.
- **Invariant:** Links the entire CBOM document to a specific discovery session.

### Tier 7: Analysis Run $\to$ Target Codebase Snapshot
- **CBOM Field:** `metadata.component.hashes` and `metadata.properties.name = "ecdat:target_content_hash"`.
- **Target Entity:** Content hash of scanned codebase directory / archive.
- **Value:** SHA-256 hash of codebase tree.
- **Invariant:** Binds the analysis run to an exact snapshot of source files.

---

## 4. CBOM Representation of Provenance Without Schema Pollution

CycloneDX 1.7 provides specific standard containers for provenance that ECDAT leverages:

### 1. Root Tool Metadata (`metadata.tools`)
Every scanner that executed during the `AnalysisRun` is declared in `metadata.tools.components`:

```json
{
  "metadata": {
    "timestamp": "2026-09-14T18:38:24Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "ECDAT",
          "version": "1.0.0",
          "vendor": { "name": "ECDAT Engineering Team" }
        },
        {
          "type": "application",
          "name": "CryptoScan",
          "version": "1.4.0",
          "vendor": { "name": "CryptoScan Authors" }
        },
        {
          "type": "application",
          "name": "Syft",
          "version": "1.51.1",
          "vendor": { "name": "Anchore" }
        }
      ]
    }
  }
}
```

### 2. Component Occurrence Evidence (`component.evidence.occurrences`)
Physical location coordinates are serialized in standard CycloneDX evidence occurrences:

```json
{
  "evidence": {
    "occurrences": [
      {
        "location": "src/main/java/com/example/CryptoService.java",
        "line": 45,
        "offset": 12,
        "symbol": "Cipher.getInstance",
        "additionalContext": "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");"
      }
    ]
  }
}
```

### 3. Deep Lineage via Standard Property Taxonomy (`component.properties`)
Detailed multi-tier IDs are serialized as structured name-value pairs:

```json
{
  "properties": [
    { "name": "ecdat:asset_id", "value": "a1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d" },
    { "name": "ecdat:finding_ids", "value": "f001-uuid,f002-uuid" },
    { "name": "ecdat:evidence_ids", "value": "cryptoscan:rule-01,syft:pkg-02" },
    { "name": "ecdat:native_finding_ids", "value": "find-101,art-55" },
    { "name": "ecdat:native_rule_ids", "value": "java/crypto/weak-cipher,java/crypto/ecb-mode" },
    { "name": "ecdat:scanner_category", "value": "CIPHER" },
    { "name": "ecdat:scanners", "value": "cryptoscan:1.4.0,syft:1.51.1" },
    { "name": "ecdat:raw_output_ref", "value": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069" }
  ]
}
```

---

## 5. Bidirectional Auditability Protocol

An auditor or security analyst holding an exported ECDAT CBOM can perform complete forensic tracing:

1. **Forward Trace (CBOM $\to$ Source):**  
   Read `component.evidence.occurrences[0]` to locate the file, line, and code snippet in the target codebase.
2. **Backward Trace (CBOM $\to$ Raw Scanner Output):**  
   Read `component.properties["ecdat:raw_output_ref"]` to retrieve the exact SHA-256 hash. Query the ECDAT offline archive for the raw scanner stdout file matching this hash.
3. **Reproducibility Verification (CBOM $\to$ Run):**  
   Read `serialNumber` and `metadata.component.hashes` to verify that re-running ECDAT against the same codebase snapshot with the specified tool versions reproduces the identical asset inventory and `asset_id`s.

This provides cryptographically verifiable provenance across the entire discovery pipeline.
