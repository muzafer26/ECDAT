# ECDAT Phase 3A — CBOM Architecture & Projection Specification

**Document Identifier:** ECDAT-SPEC-PHASE-3A-CBOM  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary References:**
- `product/docs/PROJECT_SPEC.md`
- `product/docs/ARCHITECTURE.md`
- `product/docs/DECISIONS.md` (ADR-001, ADR-002, ADR-007 through ADR-015)
- `product/docs/PHASE_1D_NORMALIZATION_ARCHITECTURE.md`
- `product/docs/PHASE_2A_SCANNER_ADAPTER_INGESTION_ARCHITECTURE.md`
- `product/docs/PHASE_2B_SCANNER_ADAPTER_IMPLEMENTATION.md`
- `product/docs/PRE_3A_DOMAIN_RUN_CONTRACT_GATE.md`
- Authoritative CycloneDX 1.7 JSON Schema: `https://cyclonedx.org/schema/bom-1.7.schema.json`

---

## 1. Executive Summary & Core Architectural Question

### The Core Architectural Question
> **What is the canonical ECDAT domain model, and how can it be represented in a Cryptographic Bill of Materials (CBOM) without losing information or creating misleading semantics?**

ECDAT decouples internal analytical models from external serialization formats (ADR-002, ADR-007). ECDAT is an **authoritative cryptographic discovery, risk calculation, and migration management system**, whereas CycloneDX 1.7 CBOM is a standardized, interoperable software supply chain exchange format.

This specification defines the authoritative one-way projection architecture from ECDAT's rich canonical domain model into CycloneDX 1.7 CBOM JSON. It guarantees:
1. **Zero Silent Information Loss:** Analytical metadata that lacks a native CycloneDX field is preserved using structured, standardized `properties` extensions under the `ecdat:` namespace.
2. **Zero Fabricated Certainty:** Dynamic or ambiguous cryptography is serialized as `unknown` / `NEEDS_REVIEW` without guessing algorithms or key lengths.
3. **Unbroken Multi-Tier Provenance:** Every CBOM component traces deterministically back to canonical assets, findings, scanner evidence, raw scanner stdout captures, and scanner execution runs.
4. **Separation of Supply Chain Capability from Active Code Usage:** Library dependencies (e.g. Bouncy Castle) are cataloged via `dependency.provides` rather than falsely asserting active code execution.

---

## 2. Authoritative ECDAT Canonical Domain Model

ECDAT enforces an immutable, layered domain hierarchy. Under no circumstances may these tiers be collapsed:

```
Operation / Request ID          (API/CLI transaction boundary)
        ↓
Analysis Run ID                 (Multi-scanner discovery session contract)
        ↓
Scanner Execution ID            (Specific scanner tool invocation contract)
        ↓
Raw Scanner Output Ref / Hash   (Content-addressable stdout capture: sha256:...)
        ↓
Evidence Record ID              (Scan-local empirical observation: {adapter}:{native_id})
        ↓
Finding ID                      (Canonical interpretation of evidence: ecdat:finding:{hash})
        ↓
CryptoAsset ID                  (Deterministic semantic key: ecdat:asset:{canonical_key})
```

### Domain Tier Definitions & Cardinality

| Tier | Entity Class | Cardinality | Immutability & Lifecycle | Identity Definition |
| :--- | :--- | :--- | :--- | :--- |
| **Operation / Request** | Client Request | $1 \to N$ Runs | Ephemeral transaction lifetime | External HTTP request UUID or CLI session token. |
| **Analysis Run** | `AnalysisRun` (Contract) | $1 \to N$ Executions | Persistent session contract | Deterministic UUID derived from run metadata (`ecdat:run:{timestamp}:{target_hash}`). |
| **Scanner Execution** | `ScannerExecution` (Contract) | $1 \to 0..1$ Raw Output | Tool execution lifecycle | `{run_id}:{adapter_id}`. |
| **Raw Scanner Output** | `RawScannerOutput` | $1 \to N$ Evidence | Immutable content-addressable capture | `sha256:{hex_digest}` computed over verbatim stdout bytes. |
| **Evidence Record** | `EvidenceRecord` | $N \to M$ Findings | Immutable scan-local observation | `{adapter_id}:{native_finding_id}` (or collision disambiguation `{id}:collision:{idx}`). |
| **Finding** | `Finding` | $N \to M$ Assets | Immutable interpretation of evidence | `ecdat:finding:{sha256(sorted(evidence_ids))}`. |
| **CryptoAsset** | `CryptoAsset` | $1 \to N$ CBOM Components | Immutable semantic asset entity | `ecdat:asset:{sha256(CanonicalAssetKey.canonical_string())}`. |

---

## 3. Canonical CryptoAsset Model

A `CryptoAsset` represents an authoritative, normalized, statement-level cryptographic inventory entity established by ECDAT.

### Domain Entity Separation Invariant
$$\text{Observation (EvidenceRecord)} \neq \text{Interpretation (Finding)} \neq \text{Semantic Inventory (CryptoAsset)} \neq \text{Exchange Format (CBOM)}$$

1. **`EvidenceRecord`:** Represents raw scanner emissions (e.g. line numbers, raw rule categories, extracted text). Owned by the adapter.
2. **`Finding`:** Represents ECDAT's normalized cryptographic interpretation of one or more evidence records (e.g. resolving `Cipher.getInstance("AES/GCM")` into `SymmetricFamily.AES`, role `ENCRYPTION_DECRYPTION`, confidence `CONFIRMED`).
3. **`CryptoAsset`:** Represents the consolidated, deduplicated cryptographic asset at a specific source code location. Created strictly via conservative same-source-statement deduplication (`AssetCorrelationEngine`).
4. **`CBOM Component`:** A CycloneDX 1.7 JSON object (`type: "cryptographic-asset"`) projected from a `CryptoAsset`.

### CryptoAsset Attribute Schema

```python
@dataclass(frozen=True)
class CryptoAsset:
    asset_id: str                          # Deterministic UUIDv5 from CanonicalAssetKey
    asset_type: AssetType                  # ALGORITHM, PROTOCOL, CERTIFICATE, KEY, TOKEN, LIBRARY_DEPENDENCY
    algorithm_identity: AlgorithmIdentity  # family, specific algorithm name, variant
    role: CryptographicRole                # ENCRYPTION, SIGNATURE, KEY_EXCHANGE, DIGEST, etc.
    parameters: AlgorithmParameters        # key_size_bits, curve_name, mode, padding
    primary_location: LocationAnchor       # file_path, line_start, line_end, column_start, column_end
    finding_ids: Sequence[str]             # FrozenIdTuple of contributing finding IDs
    confidence: ConfidenceLevel            # CONFIRMED, LIKELY, POSSIBLE, NEEDS_REVIEW
    disposition: DispositionStatus         # UNREVIEWED, CONFIRMED, FALSE_POSITIVE, SUPPRESSED
    correlation_basis: str                 # "same_statement_deduplication(...)"
    raw_attributes: Dict[str, Any]         # Internal-only attributes (never exposed to public CBOM)
```

---

## 4. Authoritative CycloneDX 1.7 Standard Verification

**Authoritative Source:** CycloneDX Specification Repository & Published JSON Schema (`https://cyclonedx.org/schema/bom-1.7.schema.json`, Apache License 2.0). Verified directly against the official draft-07 JSON Schema.

### 1. Component Representation
- In CycloneDX 1.7, cryptographic assets MUST be serialized as components with:
  ```json
  "type": "cryptographic-asset"
  ```
- Dependency components (e.g. libraries discovered in manifests) MUST be serialized as:
  ```json
  "type": "library"
  ```

### 2. `cryptoProperties` Schema Structure
The `cryptoProperties` object is the standard CBOM metadata container:
- **`assetType` (Required Enum):**
  - `"algorithm"`
  - `"certificate"`
  - `"protocol"`
  - `"related-crypto-material"`

### 3. `algorithmProperties` (When `assetType == "algorithm"`)
- **`primitive` (Enum):**
  `["drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap", "other", "unknown"]`. Optional in schema. Mapped from evidenced mathematical construction (e.g. AES-GCM $\to$ `"ae"`, AES-CBC $\to$ `"block-cipher"`, ChaCha20 $\to$ `"stream-cipher"`), **NOT** from high-level role alone. Role `ENCRYPTION_DECRYPTION` does not automatically become `"ae"`. If construction is unevidenced or generic, omitted or set to `"unknown"`.
- **`algorithmFamily` (String / Enum):** Refers to official `cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum` (93 standardized values). Note: `algorithmFamily` is an *optional* schema property. Where scheme-specific information is available, maps to exact enum values (e.g. `AES`, `SHA-2`, `RSASSA-PKCS1`, `ECDSA`). Where only generic families are evidenced (e.g. generic `RSA`, generic `EC`, `UNKNOWN`), `algorithmFamily` is omitted from the standard field to preserve strict schema validity, and the authoritative family is preserved in `ecdat:algorithm_family` property.
- **`parameterSetIdentifier` (String):** Standard parameter set identifier (e.g. `"128"` for AES-128, `"SHA2-128s"` for SLH-DSA, `"ML-KEM-768"`). Optional in schema. Populated **ONLY** when a formal recognized parameter set is established. Curve, mode, padding, and general asymmetric key sizes (e.g. RSA-2048) are **NEVER** collapsed into this field.
- **`curve` (String):** Elliptic curve name (e.g. `"secp256r1"`, `"curve25519"`). Kept distinct from parameter set.
- **`mode` (Enum):** `["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"]`. Kept distinct from algorithm variant or parameter set.
- **`padding` (Enum):** `["pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"]`.
- **`cryptoFunctions` (Array of Enums):** `["generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"]`. Optional in schema. Populated **ONLY** when specific code invocation establishes the operation (e.g. call to `sign()`, call to `generateKey()`). **NEVER** synthesized from role alone (e.g. `KEY_AGREEMENT` never emits `["keyderive", "other"]`). Omitted entirely if operation is unevidenced. `"other"` is NEVER used as a placeholder.
- **`executionEnvironment` (Enum):** `["software-plain-ram", "software-encrypted-ram", "software-tee", "hardware", "other", "unknown"]`.
- **`implementationPlatform` (Enum):** `["generic", "x86_32", "x86_64", "armv7-a", "armv8-a", ... "other", "unknown"]`.
- **`classicalSecurityLevel` (Integer):** Equivalent symmetric security bits.
- **`nistQuantumSecurityLevel` (Integer):** NIST Category 1 through 5.

### 4. `certificateProperties` (When `assetType == "certificate"`)
Captures X.509 metadata: `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat`.

### 5. `protocolProperties` (When `assetType == "protocol"`)
Captures communication protocols: `type` (enum: `tls`, `ssh`, `ipsec`, `ike`, `sstp`, `wpa`, `dtls`, `quic`, `other`, `unknown`), `version`, `cipherSuites`, `relatedCryptographicAssets`.

### 6. `relatedCryptoMaterialProperties` (When `assetType == "related-crypto-material"`)
Captures keys and secrets: `type` (enum: `private-key`, `public-key`, `secret-key`, `shared-secret`, `seed`), `size` (bits), `format` (`PEM`, `DER`, `JWK`), `algorithmRef`, `securedBy`.

### 7. Component Evidence Structure (`component.evidence`)
- **`occurrences` (Array of Objects):**
  - `location`: File path (string).
  - `line`: Line number (integer $\ge 0$).
  - `offset`: Column offset (integer $\ge 0$).
  - `symbol`: Extracted symbol name (string).
  - `additionalContext`: Bounded code snippet ($\le 500$ chars, $\le 10$ lines).

### 8. Dependency Graph Representation (`dependencies`)
CycloneDX 1.7 provides explicit support for cryptographic supply chain linking:
- `ref`: The `bom-ref` of the declaring component (e.g. library).
- `dependsOn`: Array of `bom-ref`s that this component depends upon at runtime.
- `provides`: Array of `bom-ref`s of components/specifications implemented or provided by this component (e.g. linking `bcprov-jdk18on` to `RSA`, `AES`, etc.).

---

## 5. Projection Architecture & Zero Silent Information Loss Strategy

```
ECDAT Canonical Domain Models (product/core/)
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│             Phase 3B CBOM Serializer                   │
│                                                        │
│  1. Map CryptoAsset to component (type=crypto-asset)   │
│  2. Map AlgorithmIdentity to algorithmProperties       │
│  3. Map Parameters to key size, curve, mode, padding   │
│  4. Map primary_location to evidence.occurrences       │
│  5. Map Library Dependencies to type=library           │
│  6. Map Library Provided Crypto to dependency.provides │
│  7. Project ECDAT metadata into ecdat:* properties     │
│  8. Populate metadata.tools with multi-scanner info    │
└────────────────────────────────────────────────────────┘
                 │
                 ▼
     CycloneDX 1.7 CBOM JSON Document
```

### Property Extension Taxonomy (`ecdat:*`)
To satisfy ADR-010 (Zero Silent Information Loss), attributes lacking direct schema fields are mapped into `component.properties`:

```json
[
  { "name": "ecdat:asset_id", "value": "a1b2c3d4-..." },
  { "name": "ecdat:confidence", "value": "CONFIRMED" },
  { "name": "ecdat:disposition", "value": "UNREVIEWED" },
  { "name": "ecdat:correlation_basis", "value": "same_statement_deduplication(loc='src/Crypto.java:45', algo='AES')" },
  { "name": "ecdat:finding_ids", "value": "finding-001,finding-002" },
  { "name": "ecdat:evidence_ids", "value": "cryptoscan:rule-01,syft:pkg-02" },
  { "name": "ecdat:scanners", "value": "cryptoscan:1.4.0,syft:1.51.1" },
  { "name": "ecdat:raw_output_ref", "value": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069" },
  { "name": "ecdat:column_span", "value": "12-48" }
]
```

---

## 6. Multi-Scanner Model & Disagreement Preservation

ECDAT ingests outputs from heterogeneous discovery tools:
1. **CryptoScan (AST Misuse Scanner):** Detects code invocations and parameters.
2. **Syft (SBOM/Manifest Scanner):** Detects library packages and declared dependencies.
3. **Future Scanners (Network, Binary, Static):** Ingested via standard `IScannerAdapter`.

### Multi-Scanner Ingestion & Projection Flow
```
CryptoScan Execution          Syft Execution           Future Scanner Execution
  [RawScannerOutput]        [RawScannerOutput]            [RawScannerOutput]
          │                         │                             │
  EvidenceRecords           EvidenceRecords               EvidenceRecords
  (cryptoscan:...)            (syft:...)                  (scanner:... )
          └─────────────────────────┼─────────────────────────────┘
                                    ▼
                         AssetCorrelationEngine
                 (Conservative Statement Deduplication)
                                    ▼
                               CryptoAssets
                                    │
                         CBOM Projection Layer
                                    ▼
            CycloneDX 1.7 CBOM with Full Tool Attribution
```

### Scanner Disagreement Preservation Policy
If two scanners inspect the same source line but emit conflicting evidence (e.g. Scanner A claims AES-128 while Scanner B claims AES-256):
- `AssetCorrelationEngine.evaluate_correlation()` detects the contradiction and returns `CorrelationDecision.NOT_CORRELATED`.
- Two distinct `CryptoAsset` instances are preserved.
- The exported CBOM serializes **both assets** with distinct `bom-ref`s, attaching an explicit property:
  `ecdat:evidence_conflict = "true"` and recording each scanner's native finding ID.
- Scanner disagreement is **never silently resolved or merged**.

---

## 7. Unknown & Ambiguous States Policy

In static cryptographic discovery, ambiguity is an empirical reality:
- **Dynamic Ciphers (e.g. `Cipher.getInstance(var)`):** Cannot be resolved to a concrete algorithm without runtime execution.
- **Generic Key Agreements:** `KeyAgreement.getInstance("DH")` may not specify the curve or key size statically.

1. **Algorithm:** If `AlgorithmIdentity.algorithm == "UNKNOWN"`, set `algorithmProperties.primitive = "unknown"`, omit the optional `algorithmProperties.algorithmFamily` field (since `"UNKNOWN"` is not in `algorithmFamiliesEnum`), and preserve `name: "ecdat:algorithm_family", value: "UNKNOWN"` in `component.properties`.
2. **Parameters:** If key size or mode is unknown, the field is **strictly omitted** from `algorithmProperties`. It is NEVER filled with assumed defaults (e.g. 2048 or GCM).
3. **Non-Inference of Schemes:** An ECDAT `role` MUST NOT by itself determine a more specific CycloneDX algorithm family (e.g. `EC + ENCRYPTION` does not become `ECIES`, `EC + KEY_AGREEMENT` does not become `ECDH`, `RSA + SIGNATURE` does not become `RSASSA-PKCS1` or `RSASSA-PSS`) unless empirical evidence explicitly establishes that scheme. If unevidenced, `algorithmFamily` is omitted and preserved in `ecdat:algorithm_family`.
4. **Confidence:** Tagged with `properties.name = "ecdat:confidence" value = "NEEDS_REVIEW"`.
5. **Compliance Assurance:** Consumers parsing the CBOM are immediately alerted that manual triage is required, preventing false compliance passes.

---

## 8. Security & Privacy Boundary for CBOM Exports

Exported CBOM files may be shared across organizations, vendors, and external auditors. To avoid premature or misleading security claims, all controls are explicitly classified:

### 1. IMPLEMENTED & VERIFIED (Existing Tested Controls)
- **Code Snippet Bounding:** `bound_code_snippet()` caps code snippets at $\le 500$ characters and $\le 10$ lines in `component.evidence.occurrences.additionalContext`. Verified in `test_security.py`.
- **String Sanitization:** `sanitize_scanner_string()` strips dangerous control characters, null bytes, and ANSI escape sequences. Verified in `test_security.py`.
- **Content-Addressable Hashing:** `RawScannerOutput.sha256_hash` computes verbatim SHA-256 over captured stdout bytes. Verified in `test_ingestion_framework.py`.
- **Path Traversal Rejection:** Defensive path normalizers reject relative and absolute directory traversal sequences. Verified in `test_security.py`.

### 2. DESIGN REQUIREMENT (Architectural Policies for CBOM Generation)
- **No Secret/Key Material Leakage:** Exported CBOM components MUST NOT expose private key bytes, seed material, or plaintext passwords.
- **Raw Output Quarantine:** Verbatim scanner outputs (`RawScannerOutput`) contain raw terminal dumps and ASTs; they MUST remain in quarantined internal storage and NEVER be embedded as base64 attachments in public CBOMs (referenced solely by `ecdat:raw_output_ref = "sha256:..."`).
- **Internal State Omission:** Intermediate AST parser dictionaries (`EvidenceRecord.raw_payload`) and correlation cache dictionaries (`CryptoAsset.raw_attributes`) MUST be omitted from public CBOM exports.

### 3. FUTURE VERIFICATION (Phase 3B / 3C Requirements)
- **Serializer Output Verification:** The actual serializer implementation in Phase 3B must be tested against sensitive benchmark fixtures in Phase 3C to prove that private keys and credentials are not accidentally serialized.
- **Automated Secret Redaction:** Automated credential/private key detection is formally classified as **NOT IMPLEMENTED in Phase 2B/3A** (scheduled as a design requirement for Phase 8 sandboxing). No claim of automated secret redaction is made in Phase 3A.

---

## 9. Explicit Non-Claims & Future-Phase Boundaries

To maintain rigorous governance, Phase 3A establishes the following non-claims:
1. **No Production Implementation in Phase 3A:** This document is an architectural specification. Zero Python code is added to `product/core/`.
2. **Phase 3B Scope:** CycloneDX 1.7 JSON serialization implementation will occur strictly in Phase 3B using standard library Python 3.12 only.
3. **Phase 4 Boundary:** Caller context, interprocedural dataflow, and call graph analysis belong to Phase 4.
4. **Phase 5 Boundary:** Risk scoring algorithms (Shor vs Grover, quantum vulnerability calculations) belong to Phase 5.
5. **Phase 6 Boundary:** PQC migration mappings (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) belong to Phase 6.
6. **Phase 9 Boundary:** Historical cross-commit refactoring tracking and diff engines belong to Phase 9.
