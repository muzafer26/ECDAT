# ECDAT Controlled Evaluation & Benchmark Plan

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Core Directive:** No claims without empirical measurement against controlled ground truth.  

---

## 1. Evaluation Philosophy

ECDAT does not rely on marketing claims or README assertions from third-party tools. Existing tools (IBM CBOMkit, CryptoScan, pqaudit) are treated strictly as **benchmark candidates**, not ground truth.

To scientifically evaluate both external engines and ECDAT's own detection pipelines, we establish an initial **Phase 1 Seed Corpus** with known, verified expected outputs.

* **Corpus Evolution Policy:** The Phase 1 Seed Corpus serves as an initial calibration and verification baseline rather than a final comprehensive benchmark. Additional test cases (including complex enterprise wrappers, macro expansions, dynamic reflection, and multi-language polyglot repos) will be iteratively added based on benchmark findings and discovered coverage gaps in subsequent phases.

---

## 2. Phase 1 Seed Corpus Design

The Phase 1 Seed Corpus consists of synthetic and real-world curated micro-projects covering 11 specific cryptographic usage patterns:

| Test Case ID | Test Category | Implementation Scenario | Expected Detection | Ground-Truth Classification |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | **Direct RSA** | Java: `Cipher.getInstance("RSA/ECB/PKCS1Padding")`, 2048-bit key. | RSA (Asymmetric), 2048-bit, PKCS1. | `CONFIRMED` / Quantum Vulnerable (Shor) |
| **TC-02** | **Direct AES** | Python: `AES.new(key, AES.MODE_GCM, nonce=nonce)`, 256-bit key. | AES (Symmetric), 256-bit, GCM mode. | `CONFIRMED` / Generally resilient to Grover search reduction |
| **TC-03** | **Direct ECC** | Go: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`. | ECDSA (Asymmetric Signature), P-256 curve. | `CONFIRMED` / Quantum Vulnerable (Shor) |
| **TC-04** | **Diffie-Hellman** | C/OpenSSL: `DH_generate_key(dh)`. | Diffie-Hellman Key Exchange. | `CONFIRMED` / Quantum Vulnerable (Shor) |
| **TC-05** | **Wrapper Pattern** | Custom internal enterprise class `EnterpriseSecurityHelper.encrypt(data)` wrapping DES. | DES (Symmetric Legacy) inside wrapper. | `LIKELY` or `CONFIRMED` (wrapper resolved) |
| **TC-06** | **Dependency Usage** | Maven `pom.xml` importing `org.bouncycastle:bcprov-jdk18on:1.78` without direct call in main code. | Cryptographic library dependency. | `LIKELY` (Dependency Evidence, not Static Call) |
| **TC-07** | **Configuration Crypto**| YAML/Env: `SSL_CIPHER_SUITE: "TLS_RSA_WITH_AES_128_CBC_SHA"`. | RSA Key Exchange + AES-128-CBC + SHA-1. | `CONFIRMED` (Configuration Evidence) |
| **TC-08** | **Misleading Comments**| Java: `// TODO: Refactor RSA out of this module` in code that only uses AES. | No RSA detected; only AES detected. | Detection of RSA here is a **FALSE POSITIVE**. |
| **TC-09** | **Decoy String Literals**| Python: `log.info("Connecting to RSATerminal...")`. | No cryptographic algorithm detected. | Detection of RSA here is a **FALSE POSITIVE**. |
| **TC-10** | **Ambiguous Dynamic Usage**| Java: `Cipher.getInstance(System.getProperty("cipher.algo"))`. | Dynamic Cipher Call with variable parameter. | `NEEDS_REVIEW` (Must NOT report false certainty) |
| **TC-11** | **Multi-Asset Pipeline**| Combined service using RSA for TLS, AES-256 for DB encryption, and SHA-256 for hashing. | 3 distinct assets identified with correct operational roles. | 3 `CONFIRMED` assets with role mapping |

---

## 3. Benchmark Evaluation Metrics

Every discovery engine and adapter will be evaluated across ten rigorous dimensions:

1. **Precision ($P$):**
   $$P = \frac{TP}{TP + FP}$$
   *Proportion of detected cryptographic findings that are genuine cryptographic assets.*
2. **Recall ($R$):**
   $$R = \frac{TP}{TP + FN}$$
   *Proportion of actual cryptographic assets in the codebase successfully detected.*
3. **F1-Score ($F_1$):**
   $$F_1 = 2 \cdot \frac{P \cdot R}{P + R}$$
   *Harmonic mean of precision and recall.*
4. **False Positive Rate ($FPR$):**
   $$FPR = \frac{FP}{FP + TN}$$
   *Rate at which non-cryptographic code, comments, or decoys are erroneously flagged as crypto.*
5. **False Negative Rate ($FNR$):**
   $$FNR = \frac{FN}{TP + FN}$$
   *Rate at which genuine cryptographic implementations escape detection.*
6. **Discovery Coverage:**
   *Percentage of target programming languages, file types, and configuration formats parsed.*
7. **Scan Latency:**
   *Wall-clock execution time per 10,000 lines of code (LOC).*
8. **Resource Utilization:**
   *Peak memory consumption (RAM MB) and CPU core utilization during scan execution.*
9. **Evidence Quality Score:**
   *Completeness of metadata: accurate line numbers, intact code snippets, parameter extraction.*
10. **Reproducibility:**
    *Consistency of findings across 10 identical consecutive scan runs on the same repository.*

---

## 4. Benchmark Execution Protocol (Phase 1 Gate)

1. Automated test runner executes each candidate adapter against the Phase 1 Seed Corpus.
2. Raw outputs are collected and normalized through ECDAT's adapter boundary.
3. Automated assertions verify $TP$, $FP$, and $FN$ counts against the ground-truth answer key.
4. Comparative benchmark scorecard published in `product/docs/BENCHMARK_RESULTS.md` prior to Phase 2 entry.
5. New test cases addressing identified coverage gaps will be committed to expand the corpus for Phase 2+.
