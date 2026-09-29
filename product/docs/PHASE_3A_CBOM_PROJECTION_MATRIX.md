# ECDAT Phase 3A — CBOM Projection Matrix

**Document Identifier:** ECDAT-SPEC-PHASE-3A-MATRIX  
**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT / SIH26164)  
**Phase:** Phase 3A — CBOM Architecture & Projection Specification  
**Mode:** Design-Only Architectural Specification  
**Status:** DRAFT SPECIFICATION (Pending Project Owner Review)  
**Date:** 2026-09-14  
**Primary Standards Reference:** Official CycloneDX 1.7 JSON Schema (`https://cyclonedx.org/schema/bom-1.7.schema.json`)

---

## 1. Classification Taxonomy for Projections & Core Projection Principle

### 1.1 The Core Non-Inferential Projection Principle
ECDAT enforces a strict pipeline for projecting discovered facts into standard CBOM fields:

$$\text{EVIDENCE} \longrightarrow \text{CANONICAL INTERPRETATION} \longrightarrow \text{CYCLONEDX FIELD}$$
$$\text{NOT: } \text{ROLE} \longrightarrow \text{ASSUMED CYCLONEDX SEMANTIC}$$

Every mapping from an ECDAT canonical domain entity to a CycloneDX schema field must possess an explicit, non-inferential justification rooted in empirical scanner evidence. An operational role (e.g. `ENCRYPTION_DECRYPTION` or `KEY_AGREEMENT`) describes how code interacts with cryptography; it MUST NOT be treated as a substitute for algorithm identity, primitive construction, or parameter set semantics.

### 1.2 Classification Taxonomy

| Category | Definition | Projection & Serialization Behavior |
| :--- | :--- | :--- |
| **DIRECT / EVIDENCE-SUPPORTED MAPPING** | Direct 1:1 semantic and structural correspondence with a native CycloneDX 1.7 field or schema enum, where underlying empirical evidence explicitly establishes the concept without inference. | Populated directly in official CycloneDX 1.7 schema field (e.g. `AES` $\to$ `"AES"`, `curve_name` $\to$ `curve`, `file_path` $\to$ `location`, explicit call `sign()` $\to$ `["sign"]`). |
| **DERIVED MAPPING** | Deterministically computed or normalized representation derived from explicit evidence via non-inferential transformations (e.g. lowercase enum translation, UUID formatting). | Transformed via standard deterministic functions (e.g. mode `GCM` $\to$ `"gcm"`, `run_id` $\to$ `"urn:uuid:" + run_id`). Speculative semantic leaps are strictly forbidden. |
| **AMBIGUOUS / INSUFFICIENT EVIDENCE (Non-Inference Rule)** | The domain model possesses broad or generic knowledge (e.g. `RSA`, `EC`, `DH`, `EDWARDS`, `UNKNOWN`), but underlying evidence does NOT explicitly establish a narrower, scheme-specific CycloneDX enum or construction (e.g. whether RSA is `RSASSA-PKCS1` vs `RSASSA-PSS`, whether encryption is authenticated encryption (`"ae"`) vs block cipher (`"block-cipher"`), or whether an operation is evidenced). | **Do Not Guess:** Omit the optional standard CycloneDX field (`algorithmProperties.algorithmFamily`, `algorithmProperties.primitive`, `algorithmProperties.cryptoFunctions`, `parameterSetIdentifier`). Populate generic schema fields where evidenced. Preserve authoritative facts in `ecdat:*` properties. Mark `ecdat:confidence = "NEEDS_REVIEW"` where the unresolved distinction materially affects interpretation. |
| **ECDAT-ONLY REPRESENTATION** | Authoritative ECDAT analytical, correlation, and multi-scanner provenance metadata lacking a direct native CycloneDX field, or internal calculation state. | - *Extension Properties:* Serialized into `component.properties` or `metadata.properties` using the `ecdat:` namespace (e.g. `confidence`, `disposition`, `correlation_basis`, `finding_ids`, `evidence_ids`, `scanners`, `raw_output_ref`, `role`, `key_size_bits`).<br>- *Internal State:* Parser AST state, intermediate caches, and raw scanner stdout bytes retained in internal storage and omitted from export by policy (ADR-013). |
| **Provenance-Only** | Operational execution metadata recording discovery tool runs, timestamps, and target identity. | Serialized in `metadata.tools`, `metadata.properties`, or `externalReferences`. |
| **Intentionally Bounded / Omitted** | Sensitive raw data (e.g. full raw scanner stdout bytes, private keys) excluded for security, or string snippets bounded to prevent denial of service. | Excluded or bounded by policy (ADR-013); replaced with content-addressable SHA-256 references. |

---

## 2. Root BOM & Metadata Projection Matrix

| ECDAT Source Entity & Field | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| *Fixed Value* | `bomFormat` | DIRECT / EVIDENCE-SUPPORTED | Always `"CycloneDX"`. | Preserved without silent semantic loss under the defined projection. | None | None | Exact string match. |
| *Fixed Value* | `specVersion` | DIRECT / EVIDENCE-SUPPORTED | Always `"1.7"`. | Preserved without silent semantic loss under the defined projection. | None | None | Exact string match. |
| `AnalysisRun.run_id` | `serialNumber` | DERIVED MAPPING | Formatted as RFC 4122 UUID URN: `"urn:uuid:" + run_id`. | Preserved without silent semantic loss under the defined projection. | None | None | Regex: `^urn:uuid:[0-9a-f]{8}-...$` |
| `AnalysisRun.timestamp` | `metadata.timestamp` | DIRECT / EVIDENCE-SUPPORTED | ISO 8601 UTC timestamp string (`YYYY-MM-DDTHH:MM:SSZ`). | Preserved without silent semantic loss under the defined projection. | None | None | ISO 8601 date-time validator. |
| `AnalysisRun.target_id` / Path | `metadata.component.name` | DIRECT / EVIDENCE-SUPPORTED | Root scanned codebase / application name. | Preserved without silent semantic loss under the defined projection. | None | None | Non-empty string. |
| `AnalysisRun.target_hash` | `metadata.component.hashes` | DERIVED MAPPING | SHA-256 hash array of root target archive/directory snapshot. | Preserved without silent semantic loss under the defined projection. | None | None | Valid SHA-256 hex string. |
| `AnalysisRun.scanner_executions` | `metadata.tools.components` | DERIVED MAPPING | Array of scanner components (`type: "application"`, name, version, vendor). | Preserved without silent semantic loss under the defined projection. | None | None | Unique components; valid semver. |
| `ECDAT Version` | `metadata.tools.components` | DERIVED MAPPING | ECDAT core engine component with version `1.0.0`. | Preserved without silent semantic loss under the defined projection. | None | None | Tool name == `"ECDAT"`. |
| *Lifecycle Stage* | `metadata.lifecycles` | DIRECT / EVIDENCE-SUPPORTED | Pre-defined phase: `[{"phase": "discovery"}]` (or `"pre-build"`). | Preserved without silent semantic loss under the defined projection. | None | None | Enum check against allowed lifecycles. |
| `AnalysisRun.ingestion_status` | `metadata.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:ingestion_status"`, `value: status.name`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid `IngestionStatus` enum name. |

---

## 3. `CryptoAsset` Projection Matrix

| `CryptoAsset` Field | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `asset_id` | `component.bom-ref` | DERIVED MAPPING | Prefixed canonical reference: `"ecdat:asset:" + asset_id`. | Preserved without silent semantic loss under the defined projection. | None | None | Unique string within BOM. |
| `asset_id` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:asset_id"`, `value: asset_id`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | UUIDv5 format validation. |
| `asset_type` | `component.type` | DERIVED MAPPING | If `ALGORITHM`, `PROTOCOL`, `CERTIFICATE`, `KEY` $\to$ `"cryptographic-asset"`. If `LIBRARY_DEPENDENCY` $\to$ `"library"`. | Preserved without silent semantic loss under the defined projection. | None | None | Enum check: must be `"cryptographic-asset"` or `"library"`. |
| `asset_type` | `component.cryptoProperties.assetType` | DERIVED MAPPING | `ALGORITHM` $\to$ `"algorithm"`, `PROTOCOL` $\to$ `"protocol"`, `CERTIFICATE` $\to$ `"certificate"`, `KEY` $\to$ `"related-crypto-material"`. | Preserved without silent semantic loss under the defined projection. | None | None | Required enum check against schema. |
| `algorithm_identity.algorithm` | `component.name` | DIRECT / EVIDENCE-SUPPORTED | Full canonical algorithm name (e.g. `"AES-256-GCM"`, `"RSA-2048"`, `"UNKNOWN"`). | Preserved without silent semantic loss under the defined projection. | None | None | Non-empty string. |
| `algorithm_identity.family` | `cryptoProperties.algorithmProperties.algorithmFamily` | DIRECT / EVIDENCE-SUPPORTED or AMBIGUOUS / INSUFFICIENT EVIDENCE | Mapped to exact `cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum` value **ONLY** when underlying evidence explicitly establishes the specific scheme (see Section 3.1). If generic, broad, or unresolved, field is **strictly omitted** and canonical family is preserved in `ecdat:algorithm_family`. | Preserved without silent semantic loss under the defined projection. | None | None | Strict enum check against official 93-value enum when present. |
| `algorithm_identity.variant` | `cryptoProperties.algorithmProperties.parameterSetIdentifier` | DIRECT / EVIDENCE-SUPPORTED or OMITTED | Populated **ONLY** if the variant constitutes a recognized cryptographic parameter set identifier (e.g. `"128"` in AES-128, `"SHA2-128s"` in SLH-DSA). Mode, curve, and padding are **NEVER** placed here. If informal or absent, omitted and preserved in `ecdat:algorithm_variant`. | Preserved without silent semantic loss under the defined projection. | None | None | Standard string representation when present. |
| `algorithm_identity.variant` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:algorithm_variant"`, `value: variant`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional string. |
| *Evidenced Primitive Construction* | `cryptoProperties.algorithmProperties.primitive` | DIRECT / EVIDENCE-SUPPORTED or AMBIGUOUS / INSUFFICIENT EVIDENCE | Mapped from the **evidenced cryptographic construction** (see Section 3.2), NOT from high-level role alone. E.g. AES-GCM $\to$ `"ae"`; AES-CBC $\to$ `"block-cipher"`; ChaCha20 $\to$ `"stream-cipher"`; ECDSA $\to$ `"signature"`; ECDH $\to$ `"key-agree"`; SHA-256 $\to$ `"hash"`; HMAC $\to$ `"mac"`; RSAES-OAEP $\to$ `"pke"`. If construction is not evidenced or generic, **omitted** from standard field (optional in schema) or set to `"unknown"`. | Preserved without silent semantic loss under the defined projection. | None | None | Enum check against allowed primitives when present. |
| *Evidenced Operation* | `cryptoProperties.algorithmProperties.cryptoFunctions` | DIRECT / EVIDENCE-SUPPORTED or OMITTED | Populated **ONLY** when specific code invocation or operational context establishes the operation (see Section 3.2). E.g. `init(ENCRYPT_MODE)` $\to$ `["encrypt"]`; `sign()` $\to$ `["sign"]`; `generateKeyPair()` $\to$ `["keygen"]`; `generateSecret()` $\to$ `["keyderive"]`. **Omitted entirely** if operation is not evidenced. `"other"` is NEVER used as a placeholder. | Preserved without silent semantic loss under the defined projection. | None | None | Array of allowed `cryptoFunctions` enums when present. |
| `role` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:role"`, `value: role.value` (preserves authoritative ECDAT typed role independently without inferential distortion). | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Exact `CryptographicRole` enum match. |
| `confidence` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:confidence"`, `value: confidence.value` (`CONFIRMED`, `LIKELY`, `POSSIBLE`, `NEEDS_REVIEW`). | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid `ConfidenceLevel` enum string. |
| `disposition` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:disposition"`, `value: disposition.value` (`UNREVIEWED`, `CONFIRMED`, `FALSE_POSITIVE`, `SUPPRESSED`). | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid `DispositionStatus` enum string. |
| `correlation_basis` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:correlation_basis"`, `value: correlation_basis`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | String representation of deduplication predicate. |
| `finding_ids` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:finding_ids"`, `value: ",".join(finding_ids)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Comma-delimited list of valid finding UUIDs. |
| `raw_attributes` | *None* | ECDAT-ONLY REPRESENTATION | Kept in internal ECDAT repository only. Never exported to public CBOM. | Preserved in internal storage; omitted from export by policy (ADR-013). | Omitted from CBOM by policy | None | Verified absent from JSON output. |

---

### 3.1 Verified Algorithm Family Mapping & Non-Inference Rules (UQ-02 Resolution)

#### 3.1.1 The ECDAT Non-Inference Invariant for Algorithm Families
**Critical Rule:** An ECDAT `role` MUST NOT by itself determine a more specific CycloneDX algorithm family unless the underlying evidence actually establishes that cryptographic scheme.

In CycloneDX 1.7 (`cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum`), broad cryptographic families such as bare `"RSA"` and bare `"EC"` do **not** exist. The official registry only defines narrower, scheme-specific families:
- For RSA: `RSAES-OAEP`, `RSAES-PKCS1`, `RSASSA-PKCS1`, `RSASSA-PSS`.
- For EC: `ECDSA`, `ECDH`, `ECIES`, `EdDSA`.
- For DH: `FFDH`, `ECDH`.
- For Edwards: `EdDSA`.

Under the ECDAT Non-Inference Invariant:
```
IF canonical algorithm, parameters, or scanner evidence explicitly establish the CycloneDX-specific scheme:
    map to the specific CycloneDX algorithm family (DIRECT / EVIDENCE-SUPPORTED or DERIVED).
ELSE:
    DO NOT GUESS OR INFER A SCHEME FROM ROLE ALONE.
    Omit the optional CycloneDX algorithmProperties.algorithmFamily field.
    Preserve the canonical family in component.properties ("ecdat:algorithm_family").
    Preserve the evidenced primitive and cryptoFunctions where supported.
    Preserve confidence and disposition.
    Mark ecdat:confidence = "NEEDS_REVIEW" where the unresolved distinction materially affects interpretation.
```

#### 3.1.2 Family-by-Family Mapping & Non-Inference Specification

##### 1. RSA Family (`AlgorithmFamily.RSA`)
- **CycloneDX Registry Values:** `RSAES-OAEP` (enum[60]), `RSAES-PKCS1` (enum[61]), `RSASSA-PKCS1` (enum[62]), `RSASSA-PSS` (enum[63]).
- **Bare `"RSA"` in Registry:** NO. (Schema validation will fail if bare `"RSA"` is passed).
- **CycloneDX `algorithmFamily` is Optional:** YES (in `bom-1.7.schema.json`, `algorithmFamily` is an optional schema property under `algorithmProperties`).
- **Direct / Evidence-Supported Mappings:**
  - `RSASSA-PSS`: Mapped ONLY if evidence explicitly establishes PSS padding/signature scheme (e.g. algorithm contains `"PSS"`, `"SHA256withRSA/PSS"`, or `padding == "PSS"`).
  - `RSASSA-PKCS1`: Mapped ONLY if evidence explicitly establishes PKCS#1 v1.5 signature scheme (e.g. algorithm contains `"SHA256withRSA"`, `"NONEwithRSA"`, or explicit PKCS#1 v1.5 signature padding).
  - `RSAES-OAEP`: Mapped ONLY if evidence explicitly establishes OAEP encryption scheme (e.g. algorithm contains `"OAEP"`, `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"`, or `padding == "OAEP"`).
  - `RSAES-PKCS1`: Mapped ONLY if evidence explicitly establishes PKCS#1 v1.5 encryption scheme (e.g. algorithm contains `"RSA/ECB/PKCS1Padding"`, or `padding == "PKCS1"` with encryption role).
- **Ambiguous / Insufficient Evidence (Non-Inference Rule):**
  - If evidence only indicates `KeyPairGenerator.getInstance("RSA")`, `KeyFactory.getInstance("RSA")`, or generic RSA key size (e.g. 2048) without explicit padding or scheme:
    - **DO NOT** default `role=SIGNATURE` to `RSASSA-PKCS1` or `RSASSA-PSS`.
    - **DO NOT** default `role=ENCRYPTION` to `RSAES-OAEP` or `RSAES-PKCS1`.
    - **Action:** Omit `algorithmProperties.algorithmFamily`. Set `primitive` according to evidenced operation (`"pke"`, `"signature"`, or omit if unevidenced). Preserve `name: "ecdat:algorithm_family", value: "RSA"` in properties. Mark `ecdat:confidence = "NEEDS_REVIEW"` if the scheme ambiguity affects compliance interpretation.

##### 2. EC Family (`AlgorithmFamily.EC`)
- **CycloneDX Registry Values:** `ECDSA` (enum[23]), `ECDH` (enum[22]), `ECIES` (enum[24]), `EdDSA` (enum[25]).
- **Bare `"EC"` or `"ECC"` in Registry:** NO.
- **Direct / Evidence-Supported Mappings:**
  - `ECDSA`: Mapped ONLY if algorithm or API explicitly names ECDSA (e.g. `"ECDSA"`, `"SHA256withECDSA"`, `Signature.getInstance("...ECDSA")`).
  - `ECDH`: Mapped ONLY if algorithm or API explicitly names ECDH (e.g. `"ECDH"`, `KeyAgreement.getInstance("ECDH")`).
  - `ECIES`: Mapped ONLY if algorithm or API explicitly names ECIES (e.g. `"ECIES"`, `Cipher.getInstance("ECIES")`).
- **Ambiguous / Insufficient Evidence (Non-Inference Rule):**
  - If evidence only indicates `KeyPairGenerator.getInstance("EC")` or an EC named curve (e.g. `secp256r1`, `prime256v1`) without explicit operational scheme:
    - `family=EC + role=ENCRYPTION` MUST NOT automatically become `ECIES`.
    - `family=EC + role=KEY_AGREEMENT` MUST NOT automatically become `ECDH`.
    - `family=EC + role=SIGNATURE` MUST NOT automatically become `ECDSA`.
    - **Action:** Omit `algorithmProperties.algorithmFamily`. Populate `algorithmProperties.curve` with the evidenced curve name. Set `primitive` based on evidenced operation (`"signature"`, `"key-agree"`, or omit if unevidenced). Preserve `name: "ecdat:algorithm_family", value: "EC"` in properties. Set `ecdat:confidence = "NEEDS_REVIEW"`.

##### 3. DH Family (`AlgorithmFamily.DH`)
- **CycloneDX Registry Values:** `FFDH` (enum[27]), `ECDH` (enum[22]).
- **Bare `"DH"` or `"Diffie-Hellman"` in Registry:** NO.
- **Direct / Evidence-Supported Mappings:**
  - `FFDH`: Mapped ONLY if evidence explicitly establishes finite-field Diffie-Hellman parameters (e.g. RFC 7919 groups, prime modulus $p$ / generator $g$, or explicit `"FFDH"` algorithm name).
  - `ECDH`: Mapped ONLY if evidence explicitly establishes elliptic-curve Diffie-Hellman (e.g. EC curve parameters or explicit `"ECDH"` algorithm name).
- **Ambiguous / Insufficient Evidence (Non-Inference Rule):**
  - If evidence only indicates generic `KeyAgreement.getInstance("DH")` or `KeyPairGenerator.getInstance("DH")` without finite-field group or curve parameters:
    - **DO NOT** guess `FFDH` merely because DH historically meant finite-field.
    - **DO NOT** guess `ECDH`.
    - **Action:** Omit `algorithmProperties.algorithmFamily`. Set `primitive = "key-agree"`. Preserve `name: "ecdat:algorithm_family", value: "DH"` in properties. Set `ecdat:confidence = "NEEDS_REVIEW"`.

##### 4. EDWARDS Family (`AlgorithmFamily.EDWARDS`)
- **CycloneDX Registry Values:** `EdDSA` (enum[25]), `ECDH` (enum[22]).
- **Bare `"EDWARDS"` or `"Curve25519"` in Registry:** NO.
- **Direct / Evidence-Supported Mappings:**
  - `EdDSA`: Mapped ONLY if evidence establishes Edwards-curve Digital Signature Algorithm (e.g. algorithm `"Ed25519"`, `"Ed448"`, `"EdDSA"`).
  - `ECDH`: Mapped if the algorithm is Montgomery curve key agreement (`"X25519"`, `"X448"`), because X25519 key agreement maps to CycloneDX family `"ECDH"`, NOT `"EdDSA"`.
- **Ambiguous / Insufficient Evidence (Non-Inference Rule):**
  - If evidence only indicates generic Edwards curve material without establishing signature vs key agreement:
    - **DO NOT** automatically infer `EdDSA`.
    - **Action:** Omit `algorithmProperties.algorithmFamily`. Populate `curve = "Ed25519"` (or evidenced curve). Set `primitive` if evidenced. Preserve `name: "ecdat:algorithm_family", value: "EDWARDS"` in properties.

##### 5. Symmetric Ciphers & Hashes (`AES`, `DES`, `SHA-1`, `SHA-2`, `SHA-3`)
- `AES`: DIRECT / EVIDENCE-SUPPORTED MAPPING to `"AES"` (`algorithmFamiliesEnum[4]`). Verbatim match.
- `DES`: DIRECT / EVIDENCE-SUPPORTED MAPPING to `"DES"` (`algorithmFamiliesEnum[20]`). Verbatim match.
- `3DES`: DIRECT / EVIDENCE-SUPPORTED MAPPING to `"3DES"` (`algorithmFamiliesEnum[0]`) ONLY when evidence establishes Triple-DES / 3DES (e.g. algorithm `"DESede"`, `"3DES"`). Single DES is never converted to 3DES.
- `SHA1`: DERIVED MAPPING to `"SHA-1"` (`algorithmFamiliesEnum[65]`). Deterministic hyphenation.
- `SHA2`: DERIVED MAPPING to `"SHA-2"` (`algorithmFamiliesEnum[66]`). Deterministic hyphenation.
- `SHA3`: DERIVED MAPPING to `"SHA-3"` (`algorithmFamiliesEnum[67]`). Deterministic hyphenation.
- `UNKNOWN`: AMBIGUOUS / INSUFFICIENT EVIDENCE. `"UNKNOWN"` is NOT in `algorithmFamiliesEnum`. `algorithmFamily` is omitted from standard field. Set `primitive = "unknown"`. Preserve `name: "ecdat:algorithm_family", value: "UNKNOWN"` in properties.

---

### 3.2 Non-Inference Rules for Cryptographic Primitives & Functions

#### 3.2.1 Role Must NOT Automatically Determine Cryptographic Primitive
In CycloneDX 1.7, `algorithmProperties.primitive` defines the mathematical building block (`"ae"`, `"block-cipher"`, `"stream-cipher"`, `"pke"`, `"signature"`, `"hash"`, `"mac"`, `"kdf"`, `"key-agree"`, `"kem"`, etc.).

An ECDAT `role` describes operational intent, NOT the mathematical primitive construction:
1. **No Automatic AE Upgrade:** `role = ENCRYPTION_DECRYPTION` MUST NOT automatically become `primitive = "ae"`.
   - `primitive = "ae"` is permitted **ONLY** when authenticated encryption is evidenced (e.g. mode is GCM, CCM, or algorithm is ChaCha20-Poly1305).
   - If mode is CBC, ECB, CTR, CFB, OFB $\to$ `primitive = "block-cipher"`.
   - If algorithm is Salsa20 or plain ChaCha20 $\to$ `primitive = "stream-cipher"`.
   - If algorithm is RSA encryption $\to$ `primitive = "pke"`.
   - If mode or cipher construction is unevidenced or generic (e.g. `Cipher.getInstance("AES")` without mode or dynamic variable) $\to$ **omit `primitive`** (it is optional in schema), or set to `"unknown"` if dynamic/unresolved.
2. **Public-Key Encryption vs Signature:** A generic asymmetric keypair must NOT be assigned `primitive = "pke"` or `"signature"` unless the operational construction is evidenced.
3. **Preservation Invariant:** The authoritative ECDAT role is always preserved independently via `ecdat:role` without loss or distortion.

#### 3.2.2 Non-Fabrication of Cryptographic Functions (`cryptoFunctions`)
In CycloneDX 1.7, `algorithmProperties.cryptoFunctions` is an array of operations: `['generate', 'keygen', 'encrypt', 'decrypt', 'digest', 'tag', 'keyderive', 'sign', 'verify', 'encapsulate', 'decapsulate', 'other', 'unknown']`.

**Critical Governance Rules:**
1. **No Role-Based Synthesis:** Functions MUST NOT be synthesized merely because a role exists.
   - `KEY_AGREEMENT` MUST NOT automatically emit `["keyderive", "other"]`.
   - `ENCRYPTION_DECRYPTION` MUST NOT automatically emit `["encrypt", "decrypt"]`.
   - `DIGITAL_SIGNATURE` MUST NOT automatically emit `["sign", "verify"]`.
2. **No Placeholder `"other"`:** The value `"other"` MUST NOT be used as a convenient placeholder for unknown or broad semantics.
3. **Evidence-Driven Population:** `cryptoFunctions` is populated **ONLY** when the underlying call site or scanner evidence establishes that specific invocation:
   - Call site invokes encryption (`init(ENCRYPT_MODE)`, `encrypt`) $\to$ `["encrypt"]`.
   - Call site invokes decryption (`init(DECRYPT_MODE)`, `decrypt`) $\to$ `["decrypt"]`.
   - Call site generates key material (`generateKey()`, `generateKeyPair()`) $\to$ `["keygen"]`.
   - Call site signs (`sign()`) $\to$ `["sign"]`.
   - Call site verifies (`verify()`) $\to$ `["verify"]`.
   - Call site computes digest (`digest()`) $\to$ `["digest"]`.
   - Call site tags MAC (`doFinal()`) $\to$ `["tag"]`.
   - Call site derives secret via agreement (`generateSecret()`) $\to$ `["keyderive"]`.
4. **Omission Rule:** If the specific operation is NOT established by evidence at the discovery site (e.g. a static manifest declaration, generic class import, or uncalled key agreement object), **`cryptoFunctions` is omitted entirely**.

---

### 3.3 Parameter Set Semantics & Anti-Collapsing Rules

To prevent semantic conflation in the string field `parameterSetIdentifier`, ECDAT strictly segregates parameter types:

| Cryptographic Attribute | Native CycloneDX 1.7 Field | ECDAT Extension Property | Mapping Rule & Anti-Collapsing Constraint |
| :--- | :--- | :--- | :--- |
| **Formal Parameter Set** (e.g. `"128"` in AES-128, `"SHA2-128s"` in SLH-DSA, `"ML-KEM-768"`) | `algorithmProperties.parameterSetIdentifier` | `ecdat:parameter_set` | Populated **ONLY** when the value represents a recognized, formal cryptographic parameter set name. |
| **Key Size** (e.g. 2048, 256, 4096) | *None* (or `parameterSetIdentifier` only if key size defines the formal parameter set name) | `ecdat:key_size_bits = "2048"`, `ecdat:key_size = "2048"` | Raw bit length is preserved via `ecdat:key_size_bits`. It MUST NOT be collapsed into `parameterSetIdentifier` for general asymmetric keys (e.g. RSA-2048). |
| **Elliptic Curve** (e.g. `"secp256r1"`, `"Ed25519"`) | `algorithmProperties.curve` (and `ellipticCurve`) | `ecdat:curve = "secp256r1"` | Elliptic curves MUST be serialized in `algorithmProperties.curve`. They MUST NOT be dumped into `parameterSetIdentifier`. |
| **Cipher Mode** (e.g. `"gcm"`, `"cbc"`, `"ecb"`) | `algorithmProperties.mode` | `ecdat:mode = "gcm"` | Modes MUST be serialized in `algorithmProperties.mode`. Encoding `"GCM"` or `"CBC"` into `parameterSetIdentifier` or treating it as an algorithm variant is strictly forbidden. |
| **Padding Scheme** (e.g. `"pkcs7"`, `"oaep"`) | `algorithmProperties.padding` | `ecdat:padding = "oaep"` | Padding schemes MUST be serialized in `algorithmProperties.padding`. Never placed in `parameterSetIdentifier`. |
| **Scanner Algorithm Variant** (Informal label) | *None* (Omitted from standard fields) | `ecdat:algorithm_variant = variant` | Informal scanner labels that do not match formal parameter sets are preserved in `ecdat:algorithm_variant`. |

---

### 3.4 Examples of Mappings Intentionally NOT Performed Due to Insufficient Evidence

The table below catalogs real-world static discovery scenarios illustrating mappings that an inferential system might guess, but which ECDAT **strictly forbids**:

| Discovery Scenario & Source Evidence | What an Inferential Mapper Might Guess | ECDAT Non-Inference Behavior | Rationale & Protection |
| :--- | :--- | :--- | :--- |
| `Cipher.getInstance("AES")`<br>Role = `ENCRYPTION_DECRYPTION`, mode unevidenced. | Infer `primitive = "ae"` or default to `"block-cipher"`; infer `cryptoFunctions = ["encrypt", "decrypt"]`. | `primitive` **omitted**.<br>`cryptoFunctions` **omitted**.<br>`ecdat:role = "ENCRYPTION_DECRYPTION"`.<br>`ecdat:confidence = "NEEDS_REVIEW"`. | AES without mode is ambiguous (could be ECB default in Java, or configured via parameters). Upgrading to `"ae"` or fabricating operations violates empirical discovery. |
| `Cipher.getInstance("AES/GCM/NoPadding")`<br>Call site invokes `cipher.init(ENCRYPT_MODE)`. | Infer `cryptoFunctions = ["encrypt", "decrypt"]`. | `primitive = "ae"`.<br>`mode = "gcm"`.<br>`cryptoFunctions = ["encrypt"]`. | Mode GCM explicitly establishes `"ae"`. Only `"encrypt"` is evidenced at call site; `"decrypt"` is not fabricated. |
| `KeyAgreement.getInstance("ECDH")`<br>Declared in helper class, no call to `generateSecret()`. | Infer `cryptoFunctions = ["keyderive", "other"]`. | `algorithmFamily = "ECDH"`.<br>`primitive = "key-agree"`.<br>`cryptoFunctions` **omitted**.<br>`ecdat:role = "KEY_AGREEMENT"`. | Role is key agreement, but specific operation is not evidenced at call site. `"other"` is NEVER used as a placeholder. |
| `KeyPairGenerator.getInstance("RSA")`<br>Key size = 2048, no padding/role evidenced. | Infer `algorithmFamily = "RSASSA-PKCS1"`, `parameterSetIdentifier = "2048"`, `primitive = "signature"`. | `algorithmFamily` **omitted**.<br>`parameterSetIdentifier` **omitted**.<br>`primitive` **omitted**.<br>`ecdat:key_size_bits = "2048"`.<br>`ecdat:algorithm_family = "RSA"`.<br>`ecdat:confidence = "NEEDS_REVIEW"`. | Avoids asserting a signature scheme when key may be used for RSAES encryption; preserves key size in typed property without polluting parameter set. |
| `Cipher.getInstance("EC")`<br>Role = `ENCRYPTION`. | Infer `algorithmFamily = "ECIES"`, `primitive = "ae"`. | `algorithmFamily` **omitted**.<br>`primitive` **omitted**.<br>`ecdat:algorithm_family = "EC"`.<br>`ecdat:role = "ENCRYPTION_DECRYPTION"`.<br>`ecdat:confidence = "NEEDS_REVIEW"`. | Role `ENCRYPTION` with family `EC` does not prove standard ECIES is implemented; prevents false compliance claims. |
| `KeyAgreement.getInstance("DH")`<br>Role = `KEY_AGREEMENT`, no parameters. | Infer `algorithmFamily = "FFDH"`, `cryptoFunctions = ["keyderive", "other"]`. | `algorithmFamily` **omitted**.<br>`primitive = "key-agree"`.<br>`cryptoFunctions` **omitted**.<br>`ecdat:algorithm_family = "DH"`.<br>`ecdat:confidence = "NEEDS_REVIEW"`. | DH without parameters may be finite-field or curve-based; guessing FFDH or synthesizing operations violates non-inference. |
| `KeyPairGenerator.getInstance("X25519")`<br>Role = `KEY_AGREEMENT`. | Infer `algorithmFamily = "EdDSA"` because curve is 25519. | Map to `algorithmFamily = "ECDH"`.<br>`primitive = "key-agree"`.<br>`curve = "curve25519"`. | RFC 7748 X25519 is a Montgomery curve for Diffie-Hellman key agreement, not EdDSA. Inferring EdDSA would be cryptographically false. |
| `Cipher.getInstance(algorithmVariable)`<br>Role = `ENCRYPTION`, algorithm dynamic. | Guess `"AES"`, `primitive = "block-cipher"`. | `algorithmFamily` **omitted**.<br>`primitive = "unknown"`.<br>`cryptoFunctions` **omitted**.<br>`ecdat:algorithm_family = "UNKNOWN"`.<br>`ecdat:confidence = "NEEDS_REVIEW"`. | Prevents fabricating cryptographic facts in audit CBOM. |

---

## 4. `AlgorithmParameters` Projection Matrix

| `AlgorithmParameters` Field | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `key_size_bits` | `algorithmProperties.parameterSetIdentifier` | DIRECT / EVIDENCE-SUPPORTED or OMITTED | Serialized as string representation (e.g. `"128"`, `"256"`) **ONLY** where the key size constitutes a formal parameter set identifier (e.g. AES-128/256). For general asymmetric keys (e.g. RSA 2048), omitted to prevent parameter set conflation. | Preserved without silent semantic loss under the defined projection. | Converted int to string when present | None | Numeric string validator when present. |
| `key_size_bits` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:key_size_bits"`, `value: str(key_size_bits)`. Also populated as `ecdat:key_size = str(key_size_bits)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Integer string. |
| `curve_name` | `algorithmProperties.curve` | DIRECT / EVIDENCE-SUPPORTED | Elliptic curve name string (e.g. `"secp256r1"`, `"curve25519"`). Serialized in `curve` (and `ellipticCurve` where enum matches). NEVER placed in `parameterSetIdentifier`. | Preserved without silent semantic loss under the defined projection. | None | None | Valid curve string. |
| `curve_name` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:curve"`, `value: curve_name`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Sanitized string. |
| `mode` | `algorithmProperties.mode` | DERIVED MAPPING | Lowercase enum translation: `GCM` $\to$ `"gcm"`, `CBC` $\to$ `"cbc"`, `ECB` $\to$ `"ecb"`, `CTR` $\to$ `"ctr"`, etc. NEVER placed in `parameterSetIdentifier`. | Preserved without silent semantic loss under the defined projection. | None | None | Allowed enum check: `['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown']`. |
| `mode` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:mode"`, `value: mode.value.lower()`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Sanitized string. |
| `padding` | `algorithmProperties.padding` | DERIVED MAPPING | Lowercase enum translation: `PKCS7` $\to$ `"pkcs7"`, `PKCS1` $\to$ `"pkcs1v15"`, `OAEP` $\to$ `"oaep"`, `RAW` $\to$ `"raw"`, `NONE` $\to$ `"raw"`. NEVER placed in `parameterSetIdentifier`. | Preserved without silent semantic loss under the defined projection. | None | None | Allowed enum check: `['pkcs5', 'pkcs7', 'pkcs1v15', 'oaep', 'raw', 'other', 'unknown']`. |
| `padding` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:padding"`, `value: padding.value.lower()`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Sanitized string. |
| `iv_length_bits` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:iv_length_bits"`, `value: str(iv_length_bits)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional integer string. |
| `salt_length_bytes` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:salt_length_bytes"`, `value: str(salt_length_bytes)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional integer string. |
| `iteration_count` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:iteration_count"`, `value: str(iteration_count)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional integer string. |
| `digest_algorithm` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:digest_algorithm"`, `value: digest_algorithm`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional string. |
| `tag_length_bits` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:tag_length_bits"`, `value: str(tag_length_bits)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Optional integer string. |

---

## 5. `LocationAnchor` Projection Matrix

| `LocationAnchor` Field | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `file_path` | `evidence.occurrences[].location` | DIRECT / EVIDENCE-SUPPORTED | Relative normalized file path (e.g. `"src/main/Crypto.java"`). | Preserved without silent semantic loss under the defined projection. | None | None | Valid relative path without traversal. |
| `line_start` | `evidence.occurrences[].line` | DIRECT / EVIDENCE-SUPPORTED | Starting line number (integer $\ge 1$). | Preserved without silent semantic loss under the defined projection. | None | None | Positive integer validator. |
| `column_start` | `evidence.occurrences[].offset` | DIRECT / EVIDENCE-SUPPORTED | Starting column offset (integer $\ge 0$). | Preserved without silent semantic loss under the defined projection. | None | None | Integer $\ge 0$. |
| `line_end` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:line_end"`, `value: str(line_end)`. (CycloneDX `line` is a single integer; span end preserved via property). | Preserved without silent semantic loss under the defined projection (Property Extension). | Multi-line span split between native `line` and property | None | Integer $\ge line\_start$. |
| `column_end` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:column_end"`, `value: str(column_end)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Integer $\ge column\_start$. |
| `symbol` | `evidence.occurrences[].symbol` | DIRECT / EVIDENCE-SUPPORTED | Extracted API symbol or variable name (e.g. `"Cipher.getInstance"`). | Preserved without silent semantic loss under the defined projection. | None | None | Sanitized string. |
| `code_snippet` | `evidence.occurrences[].additionalContext` | DERIVED MAPPING | Bounded code snippet ($\le 500$ chars, $\le 10$ lines) sanitized of control chars. | Preserved within defined security bounds (ADR-013). | Chars beyond 500 truncated by policy (ADR-013) | None | Max length 500, max lines 10. |
| `package_coordinate` | `component.purl` | DERIVED MAPPING | Valid Package URL (e.g. `"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"`). Populated when `location_type == PACKAGE`. | Preserved without silent semantic loss under the defined projection. | None | None | RFC purl-spec syntax validator. |
| `matched_text` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:matched_text"`, `value: matched_text[:200]`. | Preserved within defined security bounds (ADR-013). | Length bounded to 200 chars | None | Sanitized string. |
| `scope_status` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:scope_status"`, `value: scope_status.value`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid `ScopeStatus` enum string. |

---

## 6. `EvidenceRecord` & Multi-Scanner Provenance Projection

| `EvidenceRecord` Field | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `evidence_id` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:evidence_ids"`, `value: ",".join(...)`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid namespaced IDs. |
| `adapter_id` / `scanner_id` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:scanners"`, `value: "cryptoscan:1.4.0"`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Tool identifier string. |
| `native_finding_id` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:native_finding_ids"`, `value: native_id`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Scanner native string. |
| `native_rule_id` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:native_rule_ids"`, `value: native_rule_id`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Scanner native string. |
| `raw_category` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:scanner_category"`, `value: raw_category`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Scanner native string. |
| `raw_output_ref` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:raw_output_ref"`, `value: raw_output_ref` (`"sha256:..."`). | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | Valid SHA-256 hash reference. |
| `collision_flag` | `component.properties` | ECDAT-ONLY REPRESENTATION | `name: "ecdat:native_id_collision"`, `value: str(collision_flag).lower()`. | Preserved without silent semantic loss under the defined projection (Property Extension). | None | None | `"true"` or `"false"`. |
| `raw_payload` | *None* | ECDAT-ONLY REPRESENTATION | Verbatim JSON/XML parse tree kept in internal storage. Omitted from CBOM to prevent data bloat and leak. | Preserved in internal storage; omitted from export by policy (ADR-013). | Omitted from CBOM by policy (ADR-013) | None | Verified absent from JSON output. |

---

## 7. Dependency & Supply Chain Projection Matrix

| ECDAT Supply Chain Entity | CycloneDX 1.7 Target Field | Classification | Transformation & Value Specification | Preservation Status | Information Lost? | Ambiguity Introduced? | Validation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Discovered Package (Syft) | `components[]` (`type: "library"`) | DIRECT / EVIDENCE-SUPPORTED | Library component with `name`, `version`, `purl`, and `bom-ref: "ecdat:pkg:" + purl`. | Preserved without silent semantic loss under the defined projection. | None | None | Schema library component validator. |
| Library Cryptographic Capability | `dependencies[].provides` | DERIVED MAPPING | The library's `dependency` object lists `provides: [bom_ref_algo1, bom_ref_algo2]`. Represents supply chain capability. | Preserved without silent semantic loss under the defined projection. | None | None | Valid `bom-ref`s in `provides` array. |
| Active Code Cryptographic Usage | `dependencies[].dependsOn` | DERIVED MAPPING | Root component or calling module lists `dependsOn: [bom_ref_asset]` representing active code usage. | Preserved without silent semantic loss under the defined projection. | None | None | Valid `bom-ref`s in `dependsOn` array. |

---

## 8. Summary of Zero Silent Information Loss Guarantees

ECDAT enforces a strict **Zero Silent Information Loss** policy, explicitly distinguishing the fate of every domain attribute under the defined projection:

1. **Preserved Without Silent Semantic Loss Under the Defined Projection:**
   - Standard cryptographic facts (algorithm, family, key size, curve, mode, padding, location, file, line) map into native CycloneDX 1.7 fields where empirical evidence establishes the schema-required scheme, or are preserved without silent semantic loss under the defined projection via generic schema fields and `ecdat:` property extensions.
   - ECDAT-specific analytical, operational, and provenance attributes (`role`, `confidence`, `disposition`, `correlation_basis`, `finding_ids`, `evidence_ids`, `scanners`, `raw_output_ref`, sub-line coordinates) are preserved without silent semantic loss under the defined projection in standard `properties` under the `ecdat:` namespace without violating schema validation.
2. **Intentionally Bounded / Omitted Information (Security & Privacy Isolation):**
   - *Code Snippets (L-03):* Bounded strictly to $\le 500$ characters and $\le 10$ lines by security policy (ADR-013).
   - *Matched Text (L-04):* Bounded to $\le 200$ characters in properties.
   - *Raw Scanner Output Bytes (L-05):* Verbatim stdout bytes are omitted from public CBOMs to prevent IP/secret leakage; replaced with content-addressable `sha256:` digest references.
   - *Raw Scanner AST Dictionaries (L-06):* Internal parser trees are omitted from external CBOMs.
3. **Unsupported Representations (Syntactic Type Adaptations):**
   - *Key Size Type (L-08):* Preserved primarily in `ecdat:key_size_bits` property; mapped to `parameterSetIdentifier` only when key length formally designates the algorithm parameter set (e.g. AES-128/256).
4. **ECDAT-Only Information (Internal Lifecycle Data):**
   - *Calculation Cache (L-07):* Intermediate correlation flags and raw attribute caches are retained in internal memory and omitted from export.

*Every intentional loss is cataloged in the Information Loss Ledger (L-01..L-10); zero information is dropped silently, and no numerical preservation claim is made without an explicit equivalence test.*
