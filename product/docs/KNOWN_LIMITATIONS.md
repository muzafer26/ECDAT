# ECDAT Known Limitations & Technical Boundaries

**Document Version:** 1.0.0  
**Phase:** Phase 0 (Foundation & Constitution)  
**Core Directive:** Explicitly state what the tool cannot do. Never hide uncertainty or make deceptive claims of total coverage.  

---

## 1. Fundamental Philosophy on Limitations

In cybersecurity engineering, claiming 100% detection coverage is a dangerous fallacy. ECDAT adopts a strict principle of **Honest Transparency**:

$$\text{"No detected finding under current discovery coverage"} \neq \text{"No cryptography exists"}$$

Every report, CBOM export, and UI view produced by ECDAT must convey its detection boundaries and coverage limits.

---

## 2. Technical Limitations Register

### 2.1 Static Analysis vs. Runtime Reality
* **Limitation:** A static source finding (e.g., `Cipher.getInstance("RSA")`) proves that cryptographic code exists in the repository, but **cannot prove it is actively executed in production**.
* **Impact:** The code could be dead code, test harness scaffolding, or an inactive legacy branch.
* **Mitigation:** Findings are tagged with `StaticSourceEvidence` rather than `RuntimeEvidence`. Production verification requires active runtime tracing or live TLS endpoint inspection (deferred to post-MVP).

### 2.2 Dynamic Cryptographic Invocations & Reflection
* **Limitation:** Cryptographic algorithms loaded dynamically via runtime reflection, environment variables, or remote configuration services cannot be definitively resolved by static AST parsers.
  * *Example:* `Cipher.getInstance(System.getenv("ALGO_NAME"))` or Java `Class.forName(...)`.
* **Impact:** Static scanners may see the call site but cannot determine the underlying algorithm or key length.
* **Mitigation:** ECDAT flags such call sites as `NEEDS_REVIEW` with an `AmbiguousDynamicInvocation` tag, alerting human analysts rather than reporting a false negative.

### 2.3 Code Obfuscation & Commercial Protectors
* **Limitation:** Code processed by commercial bytecode or binary obfuscators (e.g., ProGuard, DexGuard, Themida, string encryptors) obscures API signatures and control flows.
* **Impact:** AST and regex discovery engines will fail to detect embedded cryptographic primitives.
* **Mitigation:** The system documents that static analysis assumes non-obfuscated source code. De-obfuscation is out of scope.

### 2.4 Proprietary Enterprise Wrappers
* **Limitation:** Enterprises frequently wrap cryptographic calls inside internal utility classes (e.g., `CommonCryptoService.encrypt(data)`).
* **Impact:** If the wrapper implementation is stored in a closed pre-compiled binary dependency without source, static analysis sees the wrapper invocation but cannot inspect the underlying primitive.
* **Mitigation:** Call-graph traversal resolves wrappers within the same repository. Third-party binary wrappers are tagged with dependency evidence and flagged for manual parameter confirmation.

### 2.5 Machine-Generated Code
* **Limitation:** Auto-generated client stubs (e.g., OpenAPI generators, gRPC protoc, ORM templates) often contain large volumes of boilerplate cryptographic or hashing tokens.
* **Impact:** Potential false-positive flooding or dilution of high-priority application findings.
* **Mitigation:** Configurable path exclusion filters (e.g., ignoring `**/generated/**`, `**/proto/**`) and tagging generated findings with separate metadata classifications.

### 2.6 Transitive Dependency Visibility
* **Limitation:** Package manifest scanners (Maven, npm, PyPI) inspect direct and transitive declared dependencies, but cannot statically guarantee whether an application actually invokes the cryptographic classes packaged inside a transitive library.
* **Impact:** May lead to over-reporting of library presence without functional risk.
* **Mitigation:** ECDAT explicitly separates `DirectSourceEvidence` from `TransitiveDependencyEvidence`.

### 2.7 Incomplete Context & External Key Material
* **Limitation:** Static code analysis cannot determine the cryptographic strength of externally provisioned keys (e.g., keys injected via HashiCorp Vault or AWS KMS at runtime).
* **Impact:** Key generation parameter assessment is limited to hardcoded or statically declared constants.
* **Mitigation:** ECDAT evaluates key lengths where statically declared; otherwise, key strength is marked as `EXTERNAL_CONFIGURATION_REQUIRED`.
