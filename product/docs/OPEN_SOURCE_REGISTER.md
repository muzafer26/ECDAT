# ECDAT Open-Source Tool Evaluation Register

**Document Version:** 1.3.1 (Phase 1C-A Correction & Provenance Pass)  
**Phase:** Phase 1C-A (Controlled Tool Acquisition & Benchmark Environment)  
**Governance Directive:** Document, verify, and sandbox before benchmarking. Zero unvetted third-party tool installation in product core.  
**Primary References:** [`PROJECT_SPEC.md`](./PROJECT_SPEC.md), [`PHASE_1C_ENVIRONMENT.md`](./PHASE_1C_ENVIRONMENT.md), [`PHASE_1C_ACQUISITION_REPORT.md`](./PHASE_1C_ACQUISITION_REPORT.md).

---

## 1. Candidate Tool Evaluation Register

The following register catalogs candidate discovery tools, orchestrators, and benchmark baselines investigated and acquired under controlled conditions for empirical evaluation against the human-verified seed corpus (TC-01 through TC-11).

* **Pre-Benchmark Evaluation Status:** All tools are categorized strictly by their evaluation role:
  * **Evaluation Candidate:** Permissive license, potential integration subject to benchmark evidence.
  * **Benchmark / Reference Only:** Copyleft (GPL-3.0) or proprietary tools used exclusively as comparative baselines; strictly quarantined from core product integration.
  * **Supplemental Candidate:** Evaluated for secondary discovery (e.g., component SBOM), not standalone cryptographic detection.
  * **Rejected / Blocked:** Scope mismatch, safety violations, or unverified community forks.
* **Final Integration Status:** Remains **UNDECIDED** for all candidates pending empirical benchmark evidence.

| Candidate Project / Component | Official Repository / Source | Evaluated Release / Tag | Declared License | Primary Capabilities | Input Scope | Output Formats | Acquisition & Execution Status | Evaluation Role | Final Integration Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CryptoScan** | `https://github.com/csnp/cryptoscan` | **v1.4.0** (Release) | Apache-2.0 | Static AST discovery of cryptographic API usage, algorithms, key sizes, and misconfigurations. | Source files (Java, Python, Go, C/C++) | Custom JSON, SARIF, CycloneDX CBOM | **Acquired & Staged (Ready)** *(SHA-256 verified against upstream `checksums.txt`)* | **Evaluation Candidate** | **UNDECIDED — requires benchmark evidence** |
| **pqaudit** | `https://github.com/PQCWorld/pqaudit` | **v0.5.0** (npm pkg / tag) | MIT | Audits codebases for quantum-vulnerable cryptography (RSA, ECDSA, Ed25519, ECDH) before Q-Day. | Source trees, manifest lockfiles | CycloneDX CBOM JSON, SARIF, Text | **Acquired & Staged (Ready)** *(Integrity verified against npm registry metadata)* | **Evaluation Candidate** | **UNDECIDED — requires benchmark evidence** |
| **Sonar Cryptography Plugin** *(CBOMkit Ecosystem)* | `https://github.com/cbomkit/sonar-cryptography` | **v1.6.1 JAR** (Release 1.6.1 / tag 1.7.0) | Apache-2.0 | SonarQube plugin for deep AST cryptographic asset detection and CBOM generation. | Java, Python source code | SonarQube Issues, CycloneDX CBOM | **Acquired but execution dependency unavailable** *(Requires SonarScanner CLI / SonarQube)* | **Evaluation Candidate** | **UNDECIDED — requires benchmark evidence** |
| **CBOMkit Orchestrator** *(CBOMkit Ecosystem)* | `https://github.com/cbomkit/cbomkit` | **2.3.0** (Official Release) | Apache-2.0 | Automated CBOM generation and scanner orchestration via Quarkus/Java. | Source trees, package manifests (PURL) | CycloneDX CBOM JSON | **Inspected & Pinned (Source repo)** *(Requires Quarkus/Postgres service environment)* | **Evaluation Candidate** | **UNDECIDED — requires benchmark evidence** |
| **CBOMkit Theia** *(CBOMkit Ecosystem)* | `https://github.com/cbomkit/cbomkit-theia` | Main / Tagged releases | Apache-2.0 | Discovery of certificates, keys, and secrets in container images and directory trees. | Filesystem directories, container images | CycloneDX CBOM JSON | **Inspected & Documented** *(Does NOT scan source code; Docker missing on host)* | **Evaluation Candidate (Container/FS)** | **UNDECIDED — requires benchmark evidence** |
| **Anchore Syft** | `https://github.com/anchore/syft` | **v1.51.1** (Release) | Apache-2.0 | Software Bill of Materials (SBOM) cataloger across manifests and file systems. | Package manifests (pom.xml, package.json, go.mod), filesystems | CycloneDX SBOM, SPDX JSON, Syft JSON | **Acquired & Staged (Ready)** *(SHA-256 verified against upstream `checksums.txt`)* | **Supplemental Candidate (Dependency SBOM only)** | **UNDECIDED — requires benchmark evidence** |
| **CodeQL CLI** | `https://github.com/github/codeql-cli-binaries` | **v2.27.0** (Release) | GitHub CodeQL Terms (Proprietary Engine; Queries MIT) | Declarative semantic code query engine over AST and data-flow graphs. | Source code repositories (compiled & interpreted) | SARIF 2.1.0, BQRS, CSV, JSON | **Version Pinned & Documented** *(Quarantined; bundle ingestion deferred)* | **Benchmark / Reference Only** *(Strictly quarantined from core bundling)* | **NOT ELIGIBLE FOR CORE EMBEDDING — Reference Baseline Only** |
| **sslscan2** | `https://github.com/rbsec/sslscan` | **2.2.2** (Release) | GPL-3.0 (Copyleft) | Active TLS/SSL cipher suite negotiation testing on live network sockets. | Live TCP network endpoints (host:port) | XML, JSON, stdout | **Acquired & Staged (Ready)** *(SHA-256 verified against GitHub API digest; quarantined)* | **Benchmark / Reference Only (Network-Layer)** *(Quarantined from core)* | **NOT ELIGIBLE FOR CORE EMBEDDING — GPL-3.0 Isolation** |
| **pqcscan** | `https://github.com/SaadBaig/pqcscan` | Commit `5d17208` | BSD-2-Clause | Probes live network SSH/TLS servers for Post-Quantum Cryptography algorithm support. | Live network SSH/TLS host:port | Terminal text output | **Rejected / Blocked for Static Benchmark** *(Active network prober; cannot scan code)* | **Rejected (Scope Mismatch)** | **REJECTED for static core discovery** |

---

## 2. Integration & Licensing Policy

1. **Permissive License Preference:** Tools licensed under permissive open-source licenses (Apache-2.0, MIT, BSD-2/3-Clause) will be benchmarked for potential adapter integration into the core product distribution.
2. **Copyleft (GPL-3.0) Isolation:** Tools licensed under GPL-3.0 (such as `sslscan2`) must **NEVER** be statically linked or bundled into the core product codebase. If evaluated, they must be executed strictly as out-of-process subprocesses across standard CLI boundaries, or used strictly as external reference tools.
3. **Proprietary / GitHub CodeQL Terms:** While CodeQL query libraries are MIT, the CodeQL CLI engine is governed by GitHub CodeQL Terms of Use. It cannot be bundled or redistributed in commercial/enterprise products without separate licensing review. It is evaluated strictly as an authoritative **benchmark-reference baseline** on public open-source corpora.
4. **Mandatory Parser Isolation:** All third-party scanners operate within the `product/benchmark/tools/` sandbox. No scanner is allowed direct write access to project sources or corpus test fixtures.
5. **Pre-Benchmark Lock:** No scanner output is treated as ground truth. Ground truth is established solely by the human-verified answer keys in `product/benchmark/answer_keys/`.
