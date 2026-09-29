# ECDAT Benchmark Corpus — Human Verification Checklist

**Document Version:** 1.2.0  
**Phase:** Phase 1B (Benchmark Environment & Seed Corpus Foundation)  
**Phase 1B Technical Foundation:** COMPLETE  
**Human Verification:** COMPLETE  
**Phase 1B Status:** CLOSED  
**Phase 1C Status:** READY TO START  
**Reviewer / Verifier:** Human Project Owner (SK)  
**Verification Date:** 2026-09-12  

---

## 1. Review Governance & Verification Record

> [!NOTE]
> **Human Verification Complete Notice:** All 11 test cases (TC-01 through TC-11) in the Phase 1 Seed Corpus have been manually inspected, cross-checked against source code fixtures, and verified by the Human Project Owner on 2026-09-12. All assertions, line coordinates, parameters, operational roles, and confidence tiers are formally approved.

### Verification Criteria Completed:
1. **Source Code Inspection:** Each fixture in `product/benchmark/corpus/seed/<tc_id>/` opened and inspected.
2. **Line Boundary Validation:** Line numbers in `observed_fact` confirmed against exact syntax statements.
3. **Algorithm & Parameter Fidelity:** No unobserved algorithms or key sizes inferred; curve field sizes kept distinct from key sizes.
4. **Role Conservatism:** Roles asserted only when established by code (`unknown` preserved for unspecialized key generation).
5. **Preservation of Uncertainty:** Dynamic calls in TC-11 verified as `UNKNOWN` and `NEEDS_REVIEW`; decoy keywords in TC-10 verified as zero expected findings.

---

## 2. Master Verification Checklist

| Test Case ID | Test Case Title | Source File(s) | Verification Checkpoints (Completed by Human Reviewer) | Reviewer Initials / Date |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Direct RSA Key Pair Generation | `tc01_direct_rsa/DirectRSAKeyGen.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`RSA`)<br>- [x] Parameters verified (`key_size_bits: 2048`)<br>- [x] Role verified (`unknown`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L16-19)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-02** | Symmetric AES Authenticated Cipher | `tc02_symmetric_aes/AesGcmCipher.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`AES`)<br>- [x] Parameters verified (`GCM`, `NoPadding`; 128-bit tag noted in evaluation notes)<br>- [x] Role verified (`encryption_decryption`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L21-28)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-03** | Generic ECC Key Pair Generation | `tc03_ecc_generic/EccKeyGen.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`EC`)<br>- [x] Parameters verified (`curve_name: secp256r1`, `key_size_bits: null`)<br>- [x] Role verified (`unknown`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L19-23)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-04** | Explicit ECDSA Digital Signature | `tc04_ecdsa/EcdsaSignature.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`ECDSA`)<br>- [x] Parameters verified (`variant: SHA256withECDSA`; SHA-256 digest noted)<br>- [x] Role verified (`digital_signature`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L19-22)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-05** | Explicit ECDH Key Agreement | `tc05_ecdh/EcdhKeyAgreement.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`ECDH`)<br>- [x] Parameters verified (`KeyAgreement`)<br>- [x] Role verified (`key_establishment`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L20-23)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-06** | Ed25519 Modern Digital Signature | `tc06_ed25519/Ed25519Signature.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`Ed25519`)<br>- [x] Parameters verified (`curve_name: null`, `variant: null`; distinct from Curve25519)<br>- [x] Role verified (`digital_signature`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L19-22)<br>- [x] Negative/ambiguous behavior verified (N/A — Positive) | `[ SK / 2026-09-12 ]` |
| **TC-07** | SHA-1 Hash Digest (Python) | `tc07_sha1_hash/sha1_hash.py` | - [x] Source inspected<br>- [x] Expected algorithm verified (`SHA-1`)<br>- [x] Parameters verified (`key_size_bits: null`; 160-bit digest output noted)<br>- [x] Role verified (`message_digest`)<br>- [x] Confidence verified (`CONFIRMED`)<br>- [x] Evidence location verified (L11-14)<br>- [x] Negative/ambiguous behavior verified (Classically broken) | `[ SK / 2026-09-12 ]` |
| **TC-08** | Crypto Behind Internal Helper | `tc08_crypto_wrapper/LegacyCryptoHelper.java`<br>`tc08_crypto_wrapper/DataEncryptor.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`DES`)<br>- [x] Parameters verified (`key_size_bits: 56` effective strength, `CBC`, `PKCS5Padding`)<br>- [x] Role verified (`encryption_decryption`)<br>- [x] Confidence verified (`CONFIRMED` / `LIKELY`)<br>- [x] Evidence location verified (Helper L20-26, Caller L15)<br>- [x] Negative/ambiguous behavior verified (Wrapper invocation) | `[ SK / 2026-09-12 ]` |
| **TC-09** | Dependency Manifest Presence | `tc09_dependency_crypto/pom.xml`<br>`tc09_dependency_crypto/DirectService.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`UNKNOWN` / `NOT_OBSERVED` in code)<br>- [x] Parameters verified (Component `org.bouncycastle:bcprov-jdk18on:1.78.1`)<br>- [x] Role verified (`unknown` — 0 code calls)<br>- [x] Confidence verified (`LIKELY`)<br>- [x] Evidence location verified (`pom.xml` L22-26, `DirectService.java` negative)<br>- [x] Negative/ambiguous behavior verified (Dependency presence only) | `[ SK / 2026-09-12 ]` |
| **TC-10** | Misleading Decoy Comments & Strings | `tc10_misleading_comments/NonCryptoProcessor.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (None / Zero assets)<br>- [x] Parameters verified (None)<br>- [x] Role verified (`none_decoy`)<br>- [x] Confidence verified (`FALSE_POSITIVE_IF_DETECTED`)<br>- [x] Evidence location verified (L16, L19, L22, L26, L32)<br>- [x] Negative/ambiguous behavior verified (Pure Negative Decoy) | `[ SK / 2026-09-12 ]` |
| **TC-11** | Ambiguous Dynamic Cipher String | `tc11_ambiguous_dynamic/DynamicCipherService.java` | - [x] Source inspected<br>- [x] Expected algorithm verified (`UNKNOWN` — variable transformation)<br>- [x] Parameters verified (`null` — dynamic)<br>- [x] Role verified (`encryption_decryption`)<br>- [x] Confidence verified (`NEEDS_REVIEW`)<br>- [x] Evidence location verified (L23-26)<br>- [x] Negative/ambiguous behavior verified (Dynamic Uncertainty Preserved) | `[ SK / 2026-09-12 ]` |

---

## 3. Detailed Review Cards (TC-01 through TC-11)

### TC-01: Direct RSA Key Pair Generation
* **Fixture Path:** [`corpus/seed/tc01_direct_rsa/DirectRSAKeyGen.java`](corpus/seed/tc01_direct_rsa/DirectRSAKeyGen.java)
* **Answer Key:** [`answer_keys/tc01_direct_rsa.json`](answer_keys/tc01_direct_rsa.json)
* **Exact Evidence Lines:** Lines 16–19:
  ```java
  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
  keyGen.initialize(2048);
  ```
* **Demonstrated Behavior:** Direct JCA key pair generation for RSA with 2048-bit key length.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `RSA`
  * Parameters: `{"key_size_bits": 2048, "cipher_mode": null, "padding_scheme": null, "curve_name": null}`
  * Operational Role: `unknown` (KeyPairGenerator alone does not establish digital signature vs key encapsulation)
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-02: Symmetric AES Authenticated Cipher (AES-GCM)
* **Fixture Path:** [`corpus/seed/tc02_symmetric_aes/AesGcmCipher.java`](corpus/seed/tc02_symmetric_aes/AesGcmCipher.java)
* **Answer Key:** [`answer_keys/tc02_symmetric_aes.json`](answer_keys/tc02_symmetric_aes.json)
* **Exact Evidence Lines:** Lines 21–28:
  ```java
  SecretKey key = new SecretKeySpec(keyBytes, "AES");
  Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
  GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
  cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
  ```
* **Demonstrated Behavior:** Symmetric block cipher instantiation with explicit GCM authenticated mode, no padding, and a 128-bit authentication tag (`TAG_LENGTH_BITS = 128`).
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `AES`
  * Parameters: `{"key_size_bits": null, "cipher_mode": "GCM", "padding_scheme": "NoPadding", "curve_name": null}`
  * Tag Length Note: Fixture specifies 128-bit authentication tag. Schema limitation: `answer_key.schema.json` does not define `tag_length_bits` in `parameters.properties`, so this is documented in evaluation notes.
  * Operational Role: `encryption_decryption`
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-03: Generic Elliptic Curve Key Pair Generation
* **Fixture Path:** [`corpus/seed/tc03_ecc_generic/EccKeyGen.java`](corpus/seed/tc03_ecc_generic/EccKeyGen.java)
* **Answer Key:** [`answer_keys/tc03_ecc_generic.json`](answer_keys/tc03_ecc_generic.json)
* **Exact Evidence Lines:** Lines 19–23:
  ```java
  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
  ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
  keyGen.initialize(ecSpec);
  ```
* **Demonstrated Behavior:** Elliptic curve key generation bound to named curve `secp256r1` (NIST P-256).
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `EC`
  * Parameters: `{"key_size_bits": null, "cipher_mode": null, "padding_scheme": null, "curve_name": "secp256r1"}`
  * Parameter Note: `key_size_bits` is set to `null` to avoid conflating curve field/group order size (256 bits) with an explicit key size parameter.
  * Operational Role: `unknown` (Does not determine ECDSA vs ECDH usage)
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-04: Explicit ECDSA Digital Signature
* **Fixture Path:** [`corpus/seed/tc04_ecdsa/EcdsaSignature.java`](corpus/seed/tc04_ecdsa/EcdsaSignature.java)
* **Answer Key:** [`answer_keys/tc04_ecdsa.json`](answer_keys/tc04_ecdsa.json)
* **Exact Evidence Lines:** Lines 19–22:
  ```java
  Signature signature = Signature.getInstance("SHA256withECDSA");
  signature.initSign(privateKey);
  ```
* **Demonstrated Behavior:** Explicit digital signature signing operation combining ECDSA with SHA-256 digest.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `ECDSA`
  * Variant: `SHA256withECDSA` (Explicitly represents associated digest SHA-256; schema limitation noted regarding lack of separate `digest_algorithm` property)
  * Parameters: `{"key_size_bits": null, "cipher_mode": null, "padding_scheme": null, "curve_name": null}`
  * Operational Role: `digital_signature`
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-05: Explicit ECDH Key Agreement
* **Fixture Path:** [`corpus/seed/tc05_ecdh/EcdhKeyAgreement.java`](corpus/seed/tc05_ecdh/EcdhKeyAgreement.java)
* **Answer Key:** [`answer_keys/tc05_ecdh.json`](answer_keys/tc05_ecdh.json)
* **Exact Evidence Lines:** Lines 20–23:
  ```java
  KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
  keyAgreement.init(privateKey);
  ```
* **Demonstrated Behavior:** Explicit Diffie-Hellman key agreement protocol invocation deriving a shared secret.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `ECDH`
  * Parameters: `{"key_size_bits": null, "cipher_mode": null, "padding_scheme": null, "curve_name": null}`
  * Operational Role: `key_establishment`
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-06: Modern Edwards-Curve Digital Signature (Ed25519)
* **Fixture Path:** [`corpus/seed/tc06_ed25519/Ed25519Signature.java`](corpus/seed/tc06_ed25519/Ed25519Signature.java)
* **Answer Key:** [`answer_keys/tc06_ed25519.json`](answer_keys/tc06_ed25519.json)
* **Exact Evidence Lines:** Lines 19–22:
  ```java
  Signature signature = Signature.getInstance("Ed25519");
  signature.initSign(privateKey);
  ```
* **Demonstrated Behavior:** Modern RFC 8032 Edwards-curve digital signature instantiation.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `Ed25519`
  * Variant: `null` (Must NOT be confused with or labeled Curve25519/X25519 key agreement)
  * Parameters: `{"key_size_bits": 256, "cipher_mode": null, "padding_scheme": null, "curve_name": null}`
  * Curve Name Note: `curve_name` is set to `null` because the source specifies only algorithm string `"Ed25519"` without an explicit curve parameter.
  * Operational Role: `digital_signature`
  * Confidence: `CONFIRMED`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-07: Legacy Cryptographic Hash Function (SHA-1 in Python)
* **Fixture Path:** [`corpus/seed/tc07_sha1_hash/sha1_hash.py`](corpus/seed/tc07_sha1_hash/sha1_hash.py)
* **Answer Key:** [`answer_keys/tc07_sha1_hash.json`](answer_keys/tc07_sha1_hash.json)
* **Exact Evidence Lines:** Lines 11–14:
  ```python
  hasher = hashlib.sha1()
  hasher.update(data)
  ```
* **Demonstrated Behavior:** Python standard library `hashlib` SHA-1 digest calculation.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `SHA-1`
  * Parameters: `{"key_size_bits": null, "cipher_mode": null, "padding_scheme": null, "curve_name": null}`
  * Digest Size Note: SHA-1 produces a 160-bit message digest output. `key_size_bits` is strictly `null` because hash functions do not take cryptographic keys. Schema limitation noted regarding lack of separate `digest_size_bits` parameter.
  * Operational Role: `message_digest`
  * Confidence: `CONFIRMED`
  * Vulnerability Class: `broken_classically`
  * Classification: Positive Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-08: Cryptographic Call Behind Internal Helper / Wrapper
* **Fixture Paths:**
  * Application Caller: [`corpus/seed/tc08_crypto_wrapper/DataEncryptor.java`](corpus/seed/tc08_crypto_wrapper/DataEncryptor.java)
  * Internal Helper: [`corpus/seed/tc08_crypto_wrapper/LegacyCryptoHelper.java`](corpus/seed/tc08_crypto_wrapper/LegacyCryptoHelper.java)
* **Answer Key:** [`answer_keys/tc08_crypto_wrapper.json`](answer_keys/tc08_crypto_wrapper.json)
* **Exact Evidence Lines:**
  * Helper (Direct): Lines 20–26 in `LegacyCryptoHelper.java`:
    ```java
    SecretKey key = new SecretKeySpec(keyBytes, "DES");
    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
    ```
  * Caller (Indirect): Line 15 in `DataEncryptor.java`:
    ```java
    return LegacyCryptoHelper.performLegacyEncryption(customerData, keyBytes, ivBytes);
    ```
* **Demonstrated Behavior:** Layered encapsulation of legacy DES cipher behind an internal utility class.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Direct Finding (Helper): Algorithm `DES`, Mode `CBC`, Padding `PKCS5Padding`, Confidence `CONFIRMED`, Role `encryption_decryption`
  * Indirect Finding (Caller): Algorithm `DES`, Mode `CBC`, Padding `PKCS5Padding`, Confidence `LIKELY`, Role `encryption_decryption`
  * Key Size Note: `key_size_bits: 56` represents the effective cryptographic security strength of DES (derived from the 64-bit encoded key which includes 8 parity bits).
  * Classification: Wrapper / Indirect Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-09: Dependency Manifest Presence Without Source Invocations
* **Fixture Paths:**
  * Build Manifest: [`corpus/seed/tc09_dependency_crypto/pom.xml`](corpus/seed/tc09_dependency_crypto/pom.xml)
  * Clean Source File: [`corpus/seed/tc09_dependency_crypto/DirectService.java`](corpus/seed/tc09_dependency_crypto/DirectService.java)
* **Answer Key:** [`answer_keys/tc09_dependency_crypto.json`](answer_keys/tc09_dependency_crypto.json)
* **Exact Evidence Lines:**
  * Manifest Declaration: Lines 22–26 in `pom.xml`:
    ```xml
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78.1</version>
    </dependency>
    ```
  * Source Service: Zero calls to Bouncy Castle or JCA in `DirectService.java`.
* **Demonstrated Behavior:** Manifest dependency inclusion without any active application code utilization.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `UNKNOWN` (Algorithm usage `NOT_OBSERVED` in code; Bouncy Castle is modeled as provider/library evidence, NOT an algorithm)
  * Variant / Coordinates: `org.bouncycastle:bcprov-jdk18on:1.78.1`
  * Parameters: All `null`
  * Operational Role: `unknown` (Package manifest declaration only)
  * Confidence: `LIKELY`
  * Usage Type: `dependency`
  * Classification: Dependency Test (Must NOT report active RSA/AES usage in source code)
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-10: Misleading Decoy Comments, Variables & Strings (Negative Test)
* **Fixture Path:** [`corpus/seed/tc10_misleading_comments/NonCryptoProcessor.java`](corpus/seed/tc10_misleading_comments/NonCryptoProcessor.java)
* **Answer Key:** [`answer_keys/tc10_misleading_comments.json`](answer_keys/tc10_misleading_comments.json)
* **Exact Evidence Lines:**
  * Line 16: `// TODO: Deprecate RSA-2048 and migrate our authentication system to PQC ML-KEM`
  * Line 19: `private String rsaServerEndpoint = "https://gateway.internal.network/rsa-token-service";`
  * Line 22: `private String aesConfigKey = "AES_DISABLED_FOR_BATCH_PROCESSING";`
  * Line 26: `logger.info("Initializing RSA secure handshake simulation for test harness...");`
  * Line 32: `/* Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); */`
* **Demonstrated Behavior:** High density of cryptographic terminology in non-functional syntactic positions.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Expected Findings: `[]` (Strictly empty array)
  * Operational Role: `none_decoy`
  * Confidence: `FALSE_POSITIVE_IF_DETECTED` (Any detection by a tool is a false positive)
  * Classification: Pure Negative Decoy Test
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

### TC-11: Ambiguous & Dynamic Runtime Cryptographic Invocation
* **Fixture Path:** [`corpus/seed/tc11_ambiguous_dynamic/DynamicCipherService.java`](corpus/seed/tc11_ambiguous_dynamic/DynamicCipherService.java)
* **Answer Key:** [`answer_keys/tc11_ambiguous_dynamic.json`](answer_keys/tc11_ambiguous_dynamic.json)
* **Exact Evidence Lines:** Lines 23–26:
  ```java
  Cipher cipher = Cipher.getInstance(configuredTransformation);
  cipher.init(Cipher.ENCRYPT_MODE, key);
  ```
  *(Where `configuredTransformation` is loaded from `System.getenv("DYNAMIC_CIPHER_TRANSFORMATION")` at line 16).*
* **Demonstrated Behavior:** Dynamic algorithm specification unresolved at compile/scan time.
* **Human-Reviewed Benchmark Ground Truth / Expected Result:**
  * Algorithm: `UNKNOWN` (Tools must NOT invent or guess an algorithm name)
  * Parameters: All `null`
  * Operational Role: `encryption_decryption` (Evidenced by `Cipher.init(Cipher.ENCRYPT_MODE, ...)`)
  * Confidence: `NEEDS_REVIEW`
  * Usage Type: `ambiguous`
  * Classification: Ambiguous Dynamic Test (Preserves Uncertainty)
* **Reviewer Verification:** Verified by SK on 2026-09-12.

---

## 4. Human Verification Sign-Off Block

| Verification Gate | Required Reviewer | Approval Status | Signature / Timestamp |
| :--- | :--- | :--- | :--- |
| **All 11 Test Cases Verified** | Project Technical Lead / Human Owner | `APPROVED / COMPLETE` | `SK (Human Project Owner) / 2026-09-12` |
| **Answer Key Ground Truth Approved** | Human Cybersecurity Reviewer | `APPROVED / COMPLETE` | `SK (Human Project Owner) / 2026-09-12` |
| **Authorization to Unlock Phase 1C Download Gate** | Human Project Authority | `AUTHORIZED FOR PHASE 1C` | `SK (Human Project Owner) / 2026-09-12` |
