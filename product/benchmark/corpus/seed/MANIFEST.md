# Phase 1 Seed Corpus Manifest

**Document Version:** 1.2.0  
**Phase:** Phase 1B (Benchmark Environment & Seed Corpus)  
**Corpus Classification:** Calibration Baseline (TC-01 through TC-11) — Human Verification COMPLETE  
**Strict Safety Notice:** All fixtures in this corpus use synthetic, safe test constructs. Zero real private keys, zero passwords, zero production certificates, and zero malicious payloads are present.

---

## 1. Master Seed Corpus Index

| Test Case ID | Language | Primary Purpose | Expected Crypto Primitive / Algorithm | Expected Operational Role | Test Case Classification | Primary Files | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Java | Direct RSA key pair generation. | Algorithm: **RSA** (2048-bit key) | `unknown` (KeyGen does not define role) | **Positive Test** | `tc01_direct_rsa/DirectRSAKeyGen.java` | **Human-Verified** |
| **TC-02** | Java | Symmetric authenticated block cipher (AES-GCM). | Algorithm: **AES** (Mode: GCM, Padding: None) | `encryption_decryption` | **Positive Test** | `tc02_symmetric_aes/AesGcmCipher.java` | **Human-Verified** |
| **TC-03** | Java | Generic Elliptic Curve key pair generation. | Algorithm: **EC** (Curve: secp256r1) | `unknown` (KeyGen does not define role) | **Positive Test** | `tc03_ecc_generic/EccKeyGen.java` | **Human-Verified** |
| **TC-04** | Java | Explicit ECDSA digital signature generation. | Algorithm: **ECDSA** (Digest: SHA-256) | `digital_signature` | **Positive Test** | `tc04_ecdsa/EcdsaSignature.java` | **Human-Verified** |
| **TC-05** | Java | Explicit Elliptic Curve Diffie-Hellman key agreement. | Algorithm: **ECDH** (KeyAgreement) | `key_establishment` | **Positive Test** | `tc05_ecdh/EcdhKeyAgreement.java` | **Human-Verified** |
| **TC-06** | Java | Modern Edwards-curve digital signature (Ed25519). | Algorithm: **Ed25519** (Signature) | `digital_signature` | **Positive Test** | `tc06_ed25519/Ed25519Signature.java` | **Human-Verified** |
| **TC-07** | Python | Legacy cryptographic hash digest (SHA-1). | Algorithm: **SHA-1** (hashlib) | `message_digest` | **Positive Test** | `tc07_sha1_hash/sha1_hash.py` | **Human-Verified** |
| **TC-08** | Java | Cryptographic call hidden behind internal wrapper class. | Algorithm: **DES** (Mode: CBC, Padding: PKCS5) | `encryption_decryption` | **Indirect / Wrapper Test** | `tc08_crypto_wrapper/DataEncryptor.java`<br>`tc08_crypto_wrapper/LegacyCryptoHelper.java` | **Human-Verified** |
| **TC-09** | Java / XML | Manifest declaration of crypto library without code usage. | Component: **org.bouncycastle:bcprov-jdk18on:1.78.1** | `unknown` (Zero code calls) | **Dependency Test** | `tc09_dependency_crypto/pom.xml`<br>`tc09_dependency_crypto/DirectService.java` | **Human-Verified** |
| **TC-10** | Java | Misleading comments, decoy variable names, and log strings. | None (Zero cryptographic assets) | `none_decoy` | **Negative Decoy Test** | `tc10_misleading_comments/NonCryptoProcessor.java` | **Human-Verified** |
| **TC-11** | Java | Dynamic runtime cipher string resolution via environment variable. | Algorithm: **UNKNOWN** (Variable transformation) | `encryption_decryption` | **Ambiguous Dynamic Test** | `tc11_ambiguous_dynamic/DynamicCipherService.java` | **Human-Verified** |

---

## 2. Test Case Classification Taxonomy

1. **Positive Direct Tests (TC-01..TC-07):** Verify baseline detection of standard algorithms, parameter extraction, and role differentiation where syntactically evident.
2. **Indirect / Wrapper Tests (TC-08):** Measure whether tools can trace cryptographic invocations across internal method/class boundaries or only detect direct calls.
3. **Dependency vs. Usage Tests (TC-09):** Verify that discovery tools do not equate declaring a library dependency in `pom.xml` with active cryptographic execution in source code.
4. **Negative Decoy Tests (TC-10):** Measure false-positive rates when cryptographic keywords appear in non-functional contexts (comments, string literals, logging messages).
5. **Ambiguous Dynamic Tests (TC-11):** Measure whether discovery tools safely preserve uncertainty (`NEEDS_REVIEW` / `UNKNOWN`) or hallucinate arbitrary algorithms when input is dynamically resolved.
