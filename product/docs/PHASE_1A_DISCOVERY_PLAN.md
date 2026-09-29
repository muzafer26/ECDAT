# ECDAT Phase 1A — Discovery Intelligence & Benchmark Plan

**Document Version:** 1.1.0 (Phase 1A Correction Pass)  
**Phase:** Phase 1A (Discovery Intelligence & Benchmark Specification)  
**Governance Directive:** Documentation & Research Synthesis Only. Zero production code, zero tool downloads, zero scanner installations.  
**Authoritative Scope:** Defines the enterprise cryptographic evidence-acquisition strategy, discovery surfaces, candidate tool profiles, benchmark criteria, licensing boundaries, and strict download gating.

---

## 1. Executive Objective of Phase 1 / Phase 1A

### 1.1 Fundamental Purpose
**Phase 1 is formally defined as:**  
$$\textbf{"Establishing the evidence-acquisition strategy for enterprise cryptographic discovery."}$$

**Phase 1 is explicitly NOT:**  
* ❌ "Choosing one winner scanner."
* ❌ "Declaring an external tool as the authoritative core of ECDAT."
* ❌ "Embedding a third-party discovery binary into ECDAT's codebase."

### 1.2 The Scanner-Agnostic Principle
ECDAT operates as an **evidence-fusion and cryptographic intelligence platform**, not an individual scanner. Third-party tools are treated strictly as **replaceable evidence producers**.

ECDAT retains exclusive architectural ownership of:
1. **Evidence Normalization:** Transforming proprietary, heterogeneous scanner events into standard evidence schemas.
2. **Provenance Preservation:** Maintaining unbroken chains of custody (file, line range, code snippet, scanner ID/version, timestamp).
3. **Asset Identity & Canonical Modeling:** Defining the canonical representation of algorithms, parameters, certificates, protocols, and keys.
4. **Derived Interpretation:** Deriving operational role, algorithm variants, and classification parameters independently of scanner labels.
5. **Confidence Modeling:** Evaluating detection certainty (`CONFIRMED`, `LIKELY`, `POSSIBLE`, `NEEDS_REVIEW`).
6. **Contextual Relationships:** Mapping call graphs, data classifications, and network exposures.
7. **Deterministic Risk Scoring:** Calculating quantum and classical cryptographic risk.
8. **PQC Migration Intelligence:** Generating role-aware transition roadmaps and verification diffs.

---

## 2. Cryptographic Discovery Surfaces

To comprehensively inventory enterprise cryptography, ECDAT categorizes discovery surfaces into three distinct implementation horizons:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ENTERPRISE DISCOVERY SURFACES                      │
├────────────────────────────────┬────────────────────────────────────────────┤
│ HORIZON 1: DISCOVERABLE NOW    │ • Source Code (AST & Syntax Patterns)      │
│ (Phase 1–3 Baseline Scope)     │ • Package Manifests & Direct Dependencies   │
│                                │ • Application Configuration Files          │
├────────────────────────────────┼────────────────────────────────────────────┤
│ HORIZON 2: DISCOVERABLE LATER  │ • Compiled Build Artifacts (.jar, .war)    │
│ (Phase 4–9 Enhanced Scope)     │ • Container Filesystems & Image Layers     │
│                                │ • X.509 Certificates & Static PKI Stores   │
│                                │ • Cryptographic Key Material Metadata      │
├────────────────────────────────┼────────────────────────────────────────────┤
│ HORIZON 3: OUT OF CURRENT MVP  │ • Active Network / Live TLS Probing        │
│ (Post-MVP Enterprise Scaling)  │ • Active SSH Endpoint Auditing             │
│                                │ • Live HSM / KMS Runtime Telemetry         │
│                                │ • Kernel / Hardware Cryptographic Devices  │
└────────────────────────────────┴────────────────────────────────────────────┘
```

### Detailed Discovery Surface Specifications:

| Surface ID | Surface Name | Description | Current Horizon | Implementation Readiness |
| :--- | :--- | :--- | :--- | :--- |
| **DS-A** | **Source Code** | Application source files (Java, Python, Go, C/C++, Rust, JS/TS) containing cryptographic API calls, algorithm instantiations, and cipher parameters. | **DISCOVERABLE NOW** | Baseline target for Phase 1 Seed Corpus and static discovery adapters. |
| **DS-B** | **Dependencies & Lockfiles** | Declared direct and transitive library dependencies in build manifests (`pom.xml`, `package-lock.json`, `requirements.txt`, `go.mod`, `Cargo.lock`). | **DISCOVERABLE NOW** | Baseline target for Phase 1 dependency analysis adapters. |
| **DS-C** | **Build Artifacts** | Compiled packages, archives (`.jar`, `.war`, `.whl`, `.dll`, `.so`), and intermediate build outputs. | **DISCOVERABLE LATER** | Scheduled for Phase 4/8 deep-inspection adapters. |
| **DS-D** | **Container Images / Layers** | OCI/Docker container image filesystems, base OS packages, and packaged runtime environments. | **DISCOVERABLE LATER** | Scheduled for Phase 8 container-agent inspection. |
| **DS-E** | **Certificates / PKI Material** | Static X.509 certificate files (`.crt`, `.pem`, `.cer`), Java KeyStores (`.jks`), and truststores checked into repositories or configurations. | **DISCOVERABLE LATER** | Scheduled for Phase 3/4 PKI discovery module. |
| **DS-F** | **Key Material Metadata** | Static public key files (`.pub`), private key headers (masked/redacted), and key parameter descriptors. | **DISCOVERABLE LATER** | Scheduled for Phase 3/4 key metadata catalog. |
| **DS-G** | **Configuration** | Environment variables, YAML/JSON configs, Kubernetes manifests, Helm charts, and web server configs (`nginx.conf`). | **DISCOVERABLE NOW** | Baseline target for heuristic configuration parsing in Phase 1. |
| **DS-H** | **Network / Live TLS** | Active network probing of external and internal HTTPS/TLS endpoints for cipher suites, handshakes, and certificate chains. | **OUT OF CURRENT MVP** | Explicitly out of scope for static MVP; deferred to active network scanner plugins. |
| **DS-I** | **SSH Endpoints** | Live probing of SSH daemon configurations, host key algorithms, and key exchange algorithms. | **OUT OF CURRENT MVP** | Explicitly out of scope for static MVP. |
| **DS-J** | **Other Crypto Assets** | HSMs, Cloud KMS (AWS KMS, Azure Vault), PKCS#11 hardware tokens, and kernel crypto APIs (`/proc/crypto`). | **OUT OF CURRENT MVP** | Deferred to enterprise cloud integration phase. |

---

## 3. Candidate Tool Evaluation Matrix & Ecosystem Mapping

### 3.1 The CBOMkit Ecosystem Structure
A critical finding of Phase 1A research is that **CBOMkit, Sonar Cryptography, and CBOMkit-theia are related components of the unified CBOMkit project ecosystem**, rather than three unrelated, independent scanner engines:

1. **Sonar Cryptography (`github.com/IBM/sonar-cryptography`):**
   * A SonarQube plugin that performs AST-level detection of cryptographic assets and generates CycloneDX CBOM files during Sonar analysis runs.
2. **CBOMkit (`github.com/IBM/cbomkit`):**
   * The overarching CBOM generation and orchestration ecosystem developed by IBM Research to coordinate cryptographic bill of materials extraction.
3. **CBOMkit-theia (`github.com/IBM/cbomkit-theia`):**
   * A discovery and extraction component specialized in analyzing container images and filesystem directories to detect cryptographic assets and generate CBOMs.

### 3.2 Candidate Tool Evaluation Matrix
*(Note: All capability and performance descriptions derived from project documentation are marked as vendor/project claims until empirically verified by ECDAT benchmarks).*

| Metric / Dimension | 1. IBM CBOMkit | 2. Sonar Cryptography (IBM) | 3. CBOMkit-theia (IBM) | 4. CryptoScan | 5. pqaudit | 6. pqcscan | 7. sslscan2 | 8. CodeQL (GitHub) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Official Source** | `github.com/IBM/cbomkit` | `github.com/IBM/sonar-cryptography` | `github.com/IBM/cbomkit-theia` | Open-source community repos | `github.com/pqaudit/pqaudit` (or community forks) | Open-source community repos | `github.com/rbsec/sslscan` | `github.com/github/codeql` / GitHub CLI |
| **License** | Apache-2.0 | Apache-2.0 | Apache-2.0 | MIT / Apache-2.0 | **MIT** | MIT / Apache-2.0 | **GPLv3 (Copyleft)** | **Dual Profile:** Queries: MIT; CLI Engine: GitHub CodeQL Terms |
| **Current Version** | Active Research Release | v1.x (Plugin) | v0.x (Discovery tool) | **v1.4.0** (Released 2026-07-28) | Community release | Community release | v2.1.x | v2.18.x+ (CLI Engine) |
| **Ecosystem Role** | CBOM orchestration & generation. | SonarQube AST detection plugin. | Filesystem/container image crypto discovery. | Static AST analysis for crypto misuse & rules. | Post-quantum audit for source & binaries. | Lightweight source & lockfile PQC scanner. | Live network TLS endpoint cipher suite probe. | Semantic AST/data-flow query engine. |
| **Discovery Surface** | Source code, manifests *(Claim)*. | Source code AST *(Claim)*. | **Filesystem directories & container images** *(Claim)*. | Source code AST *(Claim)*. | Compiled binaries, source code *(Claim)*. | Source code, manifest lockfiles *(Claim)*. | **Network / Live TLS endpoints only.** | Source code AST, data-flow, taint tracking. |
| **Supported Languages** | Java, Python (C/C++ exp.) *(Claim)*. | Java, Python *(Claim)*. | Container layers, multi-language binaries *(Claim)*. | Java, Python, C/C++ *(Claim)*. | C/C++, compiled binaries, Go/Python *(Claim)*. | Python, Java, Go *(Claim)*. | N/A (Network protocol only). | C/C++, Java, Python, Go, JS/TS, C#, Ruby, Swift. |
| **Supported Libraries** | JCA, BouncyCastle, PyCryptodome *(Claim)*. | JCA/JCE, PyCryptodome *(Claim)*. | Containerized shared libraries *(Claim)*. | JCA, OpenSSL, PyCrypto *(Claim)*. | OpenSSL, libcrypto, standard crypto APIs *(Claim)*. | Standard crypto libraries *(Claim)*. | OpenSSL backend cipher suites. | Broad language standard libraries & packages. |
| **Dependency Analysis** | Limited manifest parsing *(Claim)*. | Minimal (relies on SonarQube). | Inspects packaged container dependencies *(Claim)*. | Variable by fork. | Binary symbol inspection *(Claim)*. | Package lockfile inspection *(Claim)*. | None. | Yes (via manifest & dependency graph queries). |
| **Container / FS Support** | Filesystem directory scan. | Filesystem via Sonar. | **Native container image & directory inspection.** | Filesystem directory scan. | Binary filesystem scan. | Filesystem directory scan. | None (network only). | Filesystem directory scan during DB creation. |
| **Certificate Support** | Basic static cert parsing *(Claim)*. | Limited. | Static certs in images/dirs *(Claim)*. | Rare / format-dependent. | X.509 cert extraction in binaries *(Claim)*. | Limited. | **Extensive** (Live X.509 chain inspection, SANs). | Broad (via custom QL queries). |
| **Configuration Support** | Limited. | None. | Container config inspection *(Claim)*. | Heuristic regex. | Minimal. | Basic YAML/JSON regex. | Extensive for server TLS config. | Extensive via structured config queries. |
| **Network / TLS / SSH** | None. | None. | None. | None. | None. | None. | **Extensive TLS / SSL.** (No SSH). | None (Static code analysis only). |
| **Primary Output Format** | **CycloneDX CBOM JSON.** | SonarQube Issues / JSON. | **CycloneDX CBOM JSON.** | Custom JSON / CLI text / SARIF. | Textual reports / JSON. | Textual reports / JSON. | XML, JSON, stdout. | **SARIF (Static Analysis Results Interchange Format).** |
| **JSON Support** | Yes. | Yes. | Yes. | Yes. | Yes. | Yes. | Yes. | Yes. |
| **Native CBOM Support** | **Yes (Direct CycloneDX).** | Exportable via CBOMkit. | **Yes (Direct CycloneDX).** | No (requires adapter translation). | No (requires adapter translation). | Partial / developing. | No. | No (requires SARIF-to-CBOM adapter). |
| **Evidence Quality** | High: File, line, snippet, API name *(Claim)*. | High: Sonar issue coordinates. | File/container layer offset coordinates *(Claim)*. | Moderate to high (v1.4.0 improvements). | Moderate (binary offsets or source lines). | Moderate (source line hits). | High for TLS connection; zero source code lines. | **Exceptional:** Exact AST node, line, column, flow path. |
| **Confidence Model** | Rule-based certainty *(Claim)*. | Severity/Rule based. | Asset identification confidence *(Claim)*. | Severity based (High/Med/Low). | Binary (PQC-vulnerable or safe). | Warning/Alert levels. | Deterministic connection state. | Query precision (High/Medium/Low). |
| **Deterministic Behavior** | Yes (AST based). | Yes (Sonar AST). | Yes (Static inspection). | Yes (v1.4.0 deterministic ordering). | Yes. | Yes. | Network dependent (cipher negotiation). | **100% Deterministic.** |
| **Offline Operation** | Yes. | Yes (if Sonar is local). | Yes (Local image/dir scan). | Yes. | Yes. | Yes. | Requires live target network port. | **Yes (Local CLI database scan).** |
| **Runtime Requirements** | Java 17+, Python 3.10+. | SonarQube runtime / Java. | Node.js / container runtime. | Python 3.x or compiled binary. | C runtime / Python. | Python 3.x. | C compiler / OpenSSL dev libs. | CodeQL CLI bundle (~500MB+). |
| **Security Concerns & Warnings**| Malformed source AST parser crash. | SonarQube process overhead. | **SECURITY WARNING: Reads filesystem based on input; possible file-content output to stderr; untrusted input requires strict isolation.** | Subprocess execution bounds; docs-path scanning behavior. | Binary parser exploits; memory corruption. | Malformed input crashes. | Live network connection required; firewall triggers. | Subprocess execution overhead; build interception for compiled code. |
| **Known Limitations** | Language coverage varies; immature C support. | Tied to SonarQube architecture. | Early research stage; stderr leakage risk. | Narrative finding behavior; docs-path scanning limitation. | **Severity/migration suggestions must NOT bypass ECDAT model.** | Narrow rule set; developing maturity. | Cannot inspect source code or dependencies. | Database creation requires build interception. |
| **Licensing Profile** | Permissive (Apache-2.0). | Permissive (Apache-2.0). | Permissive (Apache-2.0). | Permissive (MIT / Apache-2.0). | **Permissive (MIT).** | Permissive (MIT / Apache-2.0). | **GPLv3 (Copyleft): Cannot link statically; must isolate.** | **Dual Profile: Queries MIT; CLI Engine under GitHub CodeQL Terms.** |
| **Phase 1A Pre-Benchmark Status** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION CANDIDATE** | **EVALUATION / BENCHMARK-REFERENCE CANDIDATE** |
| **Final Integration Status** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** | **UNDECIDED — requires benchmark evidence.** |

---

## 4. Formal Tool Classification & Post-Benchmark Outcomes

### 4.1 Pre-Benchmark Status Rule
**Under Phase 1A governance, NO tool is marked as "selected for integration".**  
All tools are currently classified as:
$$\textbf{Current Status: EVALUATION CANDIDATE}$$
$$\textbf{Final Integration Status: UNDECIDED — Requires Benchmark Evidence}$$

### 4.2 Candidate Groupings for Phase 1B Evaluation
The candidate tools are grouped by their targeted evaluation focus:

1. **Source & CBOM Generation Evaluation Candidates:**
   * **IBM CBOMkit:** Source AST discovery and CycloneDX CBOM serialization.
   * **Sonar Cryptography (IBM):** SonarQube-integrated cryptographic detection rules.
2. **Filesystem & Container Evaluation Candidates:**
   * **CBOMkit-theia (IBM):** Filesystem and container image layer cryptographic discovery.
3. **Static AST & Rule-Based Discovery Candidates:**
   * **CryptoScan (v1.4.0):** Static AST discovery of cryptographic API usage and misconfigurations.
4. **Post-Quantum Vulnerability Evaluation Candidates:**
   * **pqaudit:** Binary and source audit for non-PQC primitives.
   * **pqcscan:** Lightweight source and manifest lockfile PQC rule discovery.
5. **Protocol & Network Baseline Candidates:**
   * **sslscan2:** Live TLS cipher suite and handshake discovery baseline.
6. **Semantic & Deep Query Baseline Candidates:**
   * **CodeQL:** Semantic AST and data-flow analysis baseline (licensing review required).

### 4.3 Post-Benchmark Decision Outcomes
Following the execution of the Phase 1C benchmarks against the Seed Corpus, each candidate will be definitively assigned to exactly one post-benchmark outcome:
* **Integrate:** Implement a production adapter for live pipeline ingestion.
* **Benchmark-Only:** Retain as an external comparative verification baseline (never distributed in core).
* **Reference-Only:** Ingest architectural patterns or rule models without code coupling.
* **Reject:** Disqualify due to unacceptable false positives, licensing incompatibility, or security risks.

---

## 5. Architectural Rule: Evidence vs. Authoritative Interpretation

### 5.1 The Authoritative Pipeline
$$\textbf{"Scanner output is empirical evidence, NOT authoritative domain interpretation."}$$

External discovery tools are imperfect sensors. They report raw syntactic occurrences, vendor-specific rule triggers, or loose string matches. **Under no circumstances may a raw scanner event automatically dictate an authoritative cryptographic asset classification, operational role, risk tier, or migration path.**

```
[ External Scanner Output ]
           │
           ▼
[ Raw Empirical Evidence ] ──► (File, line range, code snippet, scanner ID, raw finding)
           │
           ▼
[ ECDAT Interpretation ]   ──► (Normalized algorithm family, parameters, cryptographic role, confidence)
           │
           ▼
[ Contextual Analysis ]    ──► (Exposure, data sensitivity, call-graph relationships)
           │
           ▼
[ Deterministic Risk ]     ──► (Multi-factor risk scoring, role-aware PQC roadmap)
```

### 5.2 Explicit Boundary for pqaudit & Specialized Scanners
Tools like `pqaudit` emit their own severity ratings, quantum vulnerability labels, and migration recommendations.
* **Mandatory Constraint:** pqaudit's scanner-produced severity, quantum classification, migration suggestions, and confidence are treated strictly as **scanner-produced evidence/metadata**. They **MUST NOT** bypass ECDAT's domain model or become ECDAT's authoritative risk evaluation automatically.
* ECDAT's deterministic risk engine independently computes risk scores and migration paths based on canonical attributes and operational context.

### 5.3 Handling Unknown and Ambiguous Information
* **Strict Preservation of Uncertainty:** If an AST scanner detects `Cipher.getInstance(algoVariable)` where `algoVariable` cannot be statically resolved:
  * ECDAT records: `Algorithm = UNKNOWN (Dynamic Parameter)`
  * Confidence: `NEEDS_REVIEW`
  * Operational Role: `AMBIGUOUS_CIPHER`
  * Risk: Calculated with an explicit `DynamicPatternUncertainty` penalty.
* **Prohibition:** ECDAT must **NEVER** guess or invent parameters (e.g. assuming default 2048-bit key size) when evidence does not provide it.

---

## 6. CryptoScan v1.4.0 Specific Evaluation Profile

For the benchmark harness, CryptoScan is formally recorded at version **v1.4.0** (Release Date: **2026-07-28**).

### 6.1 Known v1.4.0 Behaviors & Verification Points
Benchmark test cases in Phase 1C will specifically evaluate:
1. **False-Negative Fixes:** Verify whether previously reported misses in modern cryptographic wrapper patterns are resolved in v1.4.0.
2. **Deterministic Finding Ordering:** Verify that identical consecutive scans produce identical finding ordering and hashes across runs.
3. **Output-Version Consistency:** Verify stability of JSON/SARIF output structures across target repositories.
4. **CBOM/SARIF Schema Validation:** Evaluate the structural validity of exported reports against official JSON and SARIF schemas.
5. **Docs-Path Scanning Limitation:** Specifically test how v1.4.0 handles non-code documentation directories (e.g., `/docs/`, markdown files containing code examples) to measure false-positive rates on documentation snippets.
6. **Narrative Finding Behavior:** Test how narrative/textual explanations emitted by v1.4.0 map into ECDAT's structured `EvidenceRecord` without loss of parameter clarity.

---

## 7. Candidate Benchmark Matrix & Evaluation Framework

To evaluate candidate adapters in Phase 1C, ECDAT establishes a comprehensive multi-dimensional benchmark matrix:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BENCHMARK EVALUATION DIMENSIONS                      │
├───────────────────┬─────────────────────────────────────────────────────────┤
│ 1. DETECTION      │ • Algorithm name & family extraction accuracy           │
│    ACCURACY       │ • Variant & parameter extraction (key size, curve, mode)│
│                   │ • Operational role differentiation (exchange vs sign)   │
│                   │ • Context detection (source vs dependency vs config)    │
├───────────────────┼─────────────────────────────────────────────────────────┤
│ 2. EVIDENCE       │ • Exact file path accuracy (relative to repo root)      │
│    INTEGRITY      │ • Line number accuracy (start line, end line)           │
│                   │ • Code context snippet validity (bounded <= 5 lines)    │
│                   │ • Provenance metadata (scanner ID, version, method)     │
├───────────────────┼─────────────────────────────────────────────────────────┤
│ 3. DETECTION      │ • True Positives (TP), False Positives (FP)             │
│    QUALITY        │ • False Negatives (FN), Duplicate Finding Rate          │
│                   │ • Ambiguous Detection Handling (flags vs crashes)       │
├───────────────────┼─────────────────────────────────────────────────────────┤
│ 4. OPERATIONAL    │ • Scan latency per 10,000 LOC (seconds)                 │
│    PERFORMANCE    │ • Peak Memory consumption (RAM MB) & CPU usage          │
│                   │ • Determinism (identical output across 10 runs)         │
│                   │ • Offline execution fidelity (zero network calls)       │
│                   │ • Clean fault handling on malformed/corrupted files     │
├───────────────────┼─────────────────────────────────────────────────────────┤
│ 5. OUTPUT &       │ • JSON / SARIF output structure parsing clean           │
│    COMPLIANCE     │ • CycloneDX 1.7 CBOM schema validity                    │
│                   │ • Provenance preservation during normalization          │
└───────────────────┴─────────────────────────────────────────────────────────┘
```

---

## 8. Phase 1 Seed Corpus & Benchmark Expansion Design

### 8.1 Baseline Phase 1 Seed Corpus (TC-01..TC-11)
The 11 seed cases defined in Phase 0 are retained as the **calibration starting point**:
* `TC-01`: Direct RSA (2048-bit, PKCS1)
* `TC-02`: Direct AES (256-bit GCM)
* `TC-03`: Direct ECC (ECDSA P-256)
* `TC-04`: Diffie-Hellman Key Exchange
* `TC-05`: Wrapper Pattern (Custom class wrapping legacy cipher)
* `TC-06`: Dependency-Only Crypto (BouncyCastle declared in pom.xml)
* `TC-07`: Configuration Crypto (TLS cipher suite string in YAML)
* `TC-08`: Misleading Comments (RSA mentioned in comment; only AES used)
* `TC-09`: Decoy String Literals (`log.info("Connecting to RSATerminal")`)
* `TC-10`: Ambiguous Dynamic Usage (`Cipher.getInstance(envVar)`)
* `TC-11`: Multi-Asset Pipeline (Combined TLS + DB encryption + Hashing)

### 8.2 Benchmark Expansion Design (26 Expansion Categories)
The Seed Corpus is explicitly **not comprehensive**. The following 26 benchmark expansion categories are defined for incremental implementation during benchmarking:

1. **RSA Key Transport vs. RSA Signatures:** Distinguishing `Cipher.getInstance("RSA")` from `Signature.getInstance("SHA256withRSA")`.
2. **RSA in X.509 Certificates:** Direct parsing of static `.crt` / `.pem` files.
3. **ECDSA Digital Signatures:** Signature generation vs verification call sites.
4. **ECDH Key Agreement:** Ephemeral vs static curve key establishment.
5. **Ed25519 / Curve25519:** Modern high-speed curve detection.
6. **Classic Diffie-Hellman Parameter Strengths:** Distinguishing weak DH (1024-bit / Logjam) from safe DH (2048-bit+).
7. **AES-GCM Authenticated Encryption:** Verification of IV/nonce parameter handling.
8. **AES-CBC Unauthenticated Mode:** Detection of padding oracle risks.
9. **Legacy Symmetric (3DES / DES / Blowfish):** Obsolete 64-bit block ciphers (Sweet32 vulnerability).
10. **Broken Hash Functions (MD5 / SHA-1):** Legacy hashing in signature vs checksum contexts.
11. **Cryptographic Hashes (SHA-256 / SHA-384 / SHA-512):** Classical resilience verification.
12. **HMAC Constructs:** Keyed hashing (`HmacSHA256`) parameter verification.
13. **Key Derivation Functions (KDFs):** PBKDF2, scrypt, argon2, HKDF detection with iteration counts.
14. **TLS Configuration Directives:** Apache / Nginx / Traefik SSL protocol versions and cipher strings.
15. **SSH Configuration Directives:** `sshd_config` `KexAlgorithms` and `HostKeyAlgorithms`.
16. **Transitive Dependency Crypto:** Crypto library imported by a dependency of a dependency.
17. **Deep Enterprise Wrappers:** Multi-layer facade classes hiding cryptographic calls.
18. **Macro & Preprocessor Crypto:** C/C++ `#define` and conditional compilation cryptographic blocks.
19. **Generated Client Stubs:** gRPC and OpenAPI generated cryptographic tokens.
20. **Dynamic String Reflection:** Java `Class.forName("org.bouncycastle...")` and Python `getattr()`.
21. **Dead Code Invocations:** Cryptographic calls inside unreferenced private methods.
22. **Duplicate Multi-Engine Findings:** The same asset detected by both AST and lockfile scanners.
23. **Conflicting Scanner Results:** Scanner A reports AES-128; Scanner B reports AES-256.
24. **Decoy Variable Names:** Variables named `rsa_key` holding arbitrary non-cryptographic strings.
25. **Hardcoded Private Key Material:** Private key headers (`-----BEGIN RSA PRIVATE KEY-----`) in source files.
26. **Post-Quantum Hybrid Schemes:** Early implementations combining X25519 + ML-KEM.

---

## 9. Ground-Truth Establishment Methodology

To prevent circular logic, **no external scanner is assumed to represent ground truth**. Ground truth for every test corpus repository will be established through an **authoritative human-verified Answer Key specification**:

For every file in the test corpus, the Answer Key formally defines:
1. **Asset Identity:** Exact cryptographic primitive (e.g. Algorithm, Protocol, Key, Certificate).
2. **Location:** Exact file path and line coordinates $[L_{\text{start}}, L_{\text{end}}]$.
3. **Canonical Attributes:** Algorithm family, variant, key size, mode of operation, padding scheme, elliptic curve name.
4. **Operational Role:** Definitive operational role (Key Exchange, Digital Signature, Bulk Encryption, Password Hashing, Integrity Check).
5. **Usage Mechanism:** Direct API call, custom wrapper, dependency declaration, configuration directive, or decoy/non-crypto.
6. **Target Confidence:** The expected confidence score that a sound analysis engine must assign (`CONFIRMED` for direct calls; `NEEDS_REVIEW` for dynamic variables; `FALSE_POSITIVE` for decoy comments).

---

## 10. Multi-Source Discovery: The Evidence-Fusion Architecture

ECDAT's discovery pipeline is structured around an **Evidence-Fusion Architecture**:

```
[ Target Repository / Environment ]
   │
   ├──► [ Source AST Scanner Adapter ] ────────┐
   │                                           │
   ├──► [ Dependency Manifest Scanner Adapter ] ─┼──► [ Raw Evidence Bus ]
   │                                           │             │
   ├──► [ Configuration Parser Adapter ] ──────┤             ▼
   │                                           │    [ Canonical Normalization ]
   ├──► [ Certificate / PKI Scanner Adapter ] ─┤             │
   │                                           │             ▼
   └──► [ (Future) Network / TLS Adapter ] ────┘    [ Deduplication Engine ]
                                                             │
                                                             ▼
                                                    [ Entity Correlation ]
                                                             │
                                                             ▼
                                                [ Canonical Crypto Assets ]
                                                             │
                                                             ▼
                                                 [ CycloneDX 1.7 CBOM ]
```

---

## 11. CycloneDX 1.7 CBOM Standard Alignment

1. **Standardized Representation:** CycloneDX 1.7 remains ECDAT's primary external export format. It defines standardized JSON schemas for cryptographic components (`cryptoProperties`), covering algorithm type, key length, mode, padding, and NIST quantum security levels.
2. **Domain Model Distinction:**
   $$\textbf{CycloneDX 1.7 CBOM Schema} \neq \textbf{ECDAT Canonical Domain Model}$$
   * CycloneDX is a data-exchange format.
   * ECDAT's internal model maintains rich operational graphs, multi-scanner provenance links, analyst review audit trails, and multi-factor risk scores that exceed the storage scope of a standard CBOM.
   * The CBOM serializer produces valid CycloneDX 1.7 JSON from the internal domain model without loss of cryptographic fidelity.

---

## 12. Security Evaluation & Sandboxing Requirements

Before any candidate discovery engine is executed, the integration harness is **REQUIRED** to enforce and verify the following security controls:

| Security Domain | Evaluation Check & Mitigation Requirement |
| :--- | :--- |
| **Untrusted Input Handling** | The tool must safely parse malformed, truncated, or hostile source files without memory corruption or uncontrolled crashes. |
| **Filesystem Access Limits** | The tool is **REQUIRED** to execute with read-only access to the source directory. Temporary writes are restricted to ephemeral scratch directories. |
| **Subprocess Execution** | Invocations must use direct argument vectors (`shell=False`). Zero string-concatenated shell commands. |
| **Privilege Boundaries** | The tool is **REQUIRED** to execute under an unprivileged user profile (`ecdat_worker`) with zero administrative/root access. |
| **Network Egress Isolation** | The tool must execute with network access disabled (air-gapped execution) to prevent source code telemetry leakage. |
| **Docker Socket Restrictions** | Scanners must **NEVER** require access to `/var/run/docker.sock` on the host system, preventing container breakout attacks. |
| **Source Retention Verification**| The tool must not cache, retain, or store target source files outside the designated ephemeral scratch space. |
| **Resource Quotas** | Strict execution deadlines (default: 300s) and memory caps (default: 2GB RAM) must be enforced via process supervision. |
| **CBOMkit-theia Security Warning** | **Reads filesystem based on input; possible file-content output to stderr; must NOT be treated as safe for untrusted input without isolation. Risk is not claimed to be solved.** |

---

## 13. Licensing & Legal Review Matrix

The following legal and licensing assessment governs candidate evaluation:

| Candidate Tool | Declared License | License Profile | Commercial / Distribution Implications | Phase 1A Architectural Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **IBM CBOMkit** | Apache-2.0 | **Permissive** | Permissive open source. Clean out-of-process boundary. | Evaluation Candidate |
| **Sonar Cryptography**| Apache-2.0 | **Permissive** | Permissive open source. Rule sets can be referenced cleanly. | Evaluation Candidate |
| **CBOMkit-theia** | Apache-2.0 | **Permissive** | Permissive open source. Filesystem/container discovery candidate. | Evaluation Candidate |
| **CryptoScan (v1.4.0)**| MIT / Apache-2.0 | **Permissive** | Standard permissive license. Safe for adapter subprocess execution. | Evaluation Candidate |
| **pqaudit** | **MIT** | **Permissive** | Standard permissive license. Safe for adapter subprocess execution. | Evaluation Candidate |
| **pqcscan** | MIT / Apache-2.0 | **Permissive** | Standard permissive license. Safe for adapter subprocess execution. | Evaluation Candidate |
| **sslscan2** | **GPLv3** | **Strong Copyleft** | Viral copyleft restrictions forbid static linking or embedding inside proprietary/permissive codebases. Out-of-process CLI execution across network boundaries is permissible, but bundling poses legal risks. | **Evaluation Candidate (Benchmark-Only)** |
| **CodeQL** | **Dual Profile: Queries MIT; CLI Engine GitHub Terms** | **Commercial / GitHub Terms** | Open-source/public-code use may be permitted; academic research may be permitted; closed-source/private enterprise analysis requires appropriate licensing; distribution/hosting/integration requires separate review. | **EVALUATION / BENCHMARK-REFERENCE CANDIDATE — licensing review required (not a legal determination)** |

---

## 14. Formal Download & Installation Gate

To ensure zero unvetted software enters the environment, ECDAT enforces an explicit **Phase 1 Download Gate**:

$$\begin{array}{|c|}
\hline
\textbf{PHASE 1 DOWNLOAD GATE: NO EXTERNAL TOOLS MAY BE DOWNLOADED OR INSTALLED} \\
\hline
\end{array}$$

No binary, package, repository, or toolchain may be downloaded or installed until **ALL SEVEN CRITERIA** are satisfied:

1. ✅ **Candidate Ecosystem Structure Accurately Mapped:** CBOMkit ecosystem, versions, and licenses verified in `PHASE_1A_DISCOVERY_PLAN.md`.
2. ✅ **Benchmark Criteria & Evaluation Dimensions Defined:** Fully specified across 5 dimensions.
3. ✅ **Security Concerns & Isolation Requirements Documented:** Documented including CBOMkit-theia filesystem/stderr warnings.
4. ✅ **Licensing Boundaries & Dual-Profile Rules Documented:** Documented for CodeQL, sslscan2, and permissive tools.
5. ✅ **No Tool Prematurely Selected:** All candidates assigned `EVALUATION CANDIDATE` status.
6. ⏳ **Phase 1B Seed Corpus & Answer Keys Approved:** Human review and sign-off on test corpus answer keys.
7. ⏳ **Formal Human Gate Authorization:** Explicit human authorization to proceed past Phase 1A.

---

## 15. Phase 1 Execution Status

* **Phase 1A (Current):** Discovery Intelligence, Candidate Profiling & Benchmark Specification.  
  $$\textbf{STATUS: COMPLETED / READY FOR HUMAN REVIEW}$$
* **Phase 1B (Next Gate):** Benchmark Harness & Phase 1 Seed Corpus Construction.  
  $$\textbf{STATUS: NOT STARTED}$$
* **Phase 1C:** Controlled Tool Download, Adapter Prototyping & Benchmark Execution. `[GATED]`
* **Phase 1D:** Benchmark Scorecard Generation & Adapter Selection Report. `[GATED]`
