# ECDAT Architecture Decision Records (ADRs)

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Governance Directive:** Document all structural decisions with explicit validation status, alternatives considered, and trade-off rationales.  

---

## Decision Status Legend
* **[VALIDATED]:** Validated against an external authoritative specification or actual project verification.
* **[APPROVED / ARCHITECTURAL DECISION]:** Chosen by the project architecture but not yet empirically validated through implementation.
* **[PROVISIONAL]:** Requires implementation, experimental verification, or benchmark validation.

---

### ADR-001: Standardization on CycloneDX 1.7 CBOM Specification
* **Status:** `[VALIDATED]`
* **Context:** The project requires a standardized, interoperable output format for Cryptographic Bill of Materials (CBOM) to avoid proprietary lock-in.
* **Decision:** Adopt the official **CycloneDX 1.7 specification** and its cryptographic asset extensions (`cryptoProperties`) as ECDAT's primary CBOM export format.
* **Validation Basis:** Validated against the published, authoritative CycloneDX 1.7 schema specifications (published by OWASP/Ecma).
* **Alternatives Considered:**
  1. *Custom ECDAT JSON Schema:* Simpler to implement initially, but proprietary and unadoptable by enterprise tooling.
  2. *SPDX 3.0:* Emerging standard, but cryptographic asset profile tooling is less mature than CycloneDX 1.7.
* **Consequences:** Guarantees international compliance and interoperability with downstream enterprise vulnerability and compliance scanners. Requires rigorous schema validation against official CycloneDX JSON schemas.

---

### ADR-002: Decoupled Internal Canonical Domain Model vs Export CBOM
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** Using CycloneDX JSON directly as ECDAT's internal memory and database representation introduces friction during risk calculation, graph analysis, and multi-scanner deduplication.
* **Decision:** Maintain an independent **Internal Canonical Domain Model** (`CryptoAsset`, `EvidenceRecord`, `AlgorithmParameters`) optimized for analysis, with dedicated serialization adapters translating to/from CycloneDX 1.7.
* **Alternatives Considered:**
  1. *Direct In-Memory CycloneDX Schema:* High impedance mismatch; cumbersome graph queries; tightly couples core logic to external schema updates.
* **Consequences:** Clear architectural separation of concerns. Requires maintaining a bidirectional translation/validation layer. Must be validated upon domain model implementation in Phase 2.

---

### ADR-003: Deterministic Rule-Based Risk Engine Over Machine Learning
* **Status:** `[PROVISIONAL / APPROVED ARCHITECTURAL DIRECTION]`
* **Context:** Evaluators and enterprise CISOs demand explainable, reproducible, and verifiable risk scores for compliance and PQC migration planning.
* **Decision:** Implement a **100% deterministic, rule-based risk scoring engine** based on transparent criteria: algorithm vulnerability class (Shor vs Grover), key length, operational role, data exposure, and detection confidence.
* **Alternatives Considered:**
  1. *LLM-Assigned Risk Scoring:* Non-deterministic, hallucination-prone, unexplainable to auditors, and vulnerable to prompt injection.
  2. *Heuristic ML Classifier:* Opaque decision boundaries; requires massive labelled training datasets that do not exist for enterprise crypto.
* **Consequences:** Risk scores are completely explainable, reproducible, and verifiable without external API dependencies. AI is restricted strictly to read-only summarization assistance. Status remains provisional until the multi-factor scoring formula is implemented and verified against benchmark test cases in Phase 5.

---

### ADR-004: Explicit Multi-Tier Detection Confidence Model
* **Status:** `[PROVISIONAL]`
* **Context:** Static analysis tools produce varying degrees of certainty. Presenting all findings with equal weight creates false confidence or analyst fatigue.
* **Decision:** Tag every finding with an explicit confidence classification:
  * `CONFIRMED`: Direct AST invocation with literal parameters.
  * `LIKELY`: Strong contextual or dependency indicators.
  * `POSSIBLE`: Heuristic regex or configuration string match.
  * `NEEDS_REVIEW`: Ambiguous dynamic pattern or wrapper invocation.
* **Alternatives Considered:**
  1. *Binary (Found / Not Found):* Deceptive; misrepresents static analysis limitations.
  2. *Floating-point Probability ($0.00 - 1.00$):* Implies mathematical precision that heuristic static rules cannot justify.
* **Consequences:** Sets realistic expectations for analysts and prevents false certainty. Status remains provisional until calibrated against the Phase 1 Seed Corpus.

---

### ADR-005: Pluggable Scanner-Agnostic Adapter Pattern
* **Status:** `[PROVISIONAL]`
* **Context:** Relying on any single discovery scanner creates a single point of failure if that project is abandoned, license-restricted, or inaccurate.
* **Decision:** Establish an explicit `IScannerAdapter` contract. The ECDAT core interacts exclusively with normalized evidence records, treating external discovery engines as replaceable plugins.
* **Alternatives Considered:**
  1. *Forking and Embedding a Scanner (e.g. CryptoScan) directly into Core:* Causes architectural rot, licensing contamination, and prevents switching scanners later.
* **Consequences:** Isolates the platform from upstream scanner volatility; enables multi-scanner aggregation and easy addition of custom enterprise scanners. Status remains provisional pending empirical adapter integration and benchmark execution in Phase 1.

---

### ADR-006: Two-Layer Repository Architecture (`product/` vs `learning/`)
* **Status:** `[APPROVED PROJECT STRUCTURE]`
* **Context:** The project must deliver production-grade cybersecurity software while providing an accessible educational foundation for human team members and viva preparation.
* **Decision:** Establish a strict two-layer physical directory separation:
  * `product/`: Authoritative engineering codebase, documentation, tests, and configurations.
  * `learning/`: Educational curriculum, cryptographic fundamentals, architectural rationales, and viva defense preparation.
* **Alternatives Considered:**
  1. *Mixing Tutorial Files in Product Code:* Pollutes production code and confuses reviewers.
  2. *Separate Git Repositories:* Fragmented context; harder to synchronize learning material with architectural updates.
* **Consequences:** Clean separation of concerns; learning files never pollute production packaging or CI/CD pipelines.

---

### ADR-007: Authoritative ECDAT Canonical Domain Model as Primary Source of Truth Over CBOM
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** CycloneDX 1.7 CBOM is an external serialization and exchange standard. Using CBOM as the internal domain model introduces schema impedance mismatch, restricts internal analysis attributes (e.g. detailed AST bounds, raw scanner attributes, multi-phase risk parameters), and forces early loss of analytical nuance.
* **Decision:** The internal ECDAT Canonical Domain Model (`AnalysisRun`, `ScannerExecution`, `RawScannerOutput`, `EvidenceRecord`, `Finding`, `CryptoAsset`) is the sole authoritative source of truth. CycloneDX 1.7 CBOM is strictly a downstream projection (one-way projection from ECDAT $\rightarrow$ CBOM).
* **Alternatives Considered:**
  1. *Using CycloneDX 1.7 JSON as the internal runtime model:* Rejected because CycloneDX schemas do not accommodate runtime intermediate analysis states, execution metadata, raw stdout captures, or deterministic correlation logic.
* **Consequences:** The internal domain model remains richer than the exported CBOM. Any information that cannot be directly mapped into standard CycloneDX fields is projected into structured `properties` extensions or retained internally without mutating the canonical source model.

---

### ADR-008: Deterministic CBOM `bom-ref` Derivation from `CryptoAsset.asset_id`
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** CycloneDX requires unique `bom-ref` attributes for components to enable inter-component referencing and dependency graphing. If `bom-ref` is non-deterministic (e.g. random UUID4 or sequential integer), re-exporting the same analysis run or comparing CBOMs produces artificial diffs.
* **Decision:** Component `bom-ref` values for cryptographic assets MUST be deterministically derived from ECDAT's canonical asset identity: `bom-ref = "ecdat:asset:" + CryptoAsset.asset_id`. For library components discovered from manifests, `bom-ref = "ecdat:pkg:" + purl`.
* **Alternatives Considered:**
  1. *Random UUIDv4:* Breaks CBOM diffing and reproducibility across repeated exports.
  2. *Evidence-based `bom-ref` (`ecdat:evidence:{id}`):* Violates cardinality invariants, as multiple pieces of evidence support a single asset.
* **Consequences:** CBOM component references are deterministic, reproducible, and trace directly to the underlying canonical asset.

---

### ADR-009: Separation of Physical Key/Object Identity from Semantic Asset Identity
* **Status:** `[VALIDATED / ARCHITECTURAL DECISION]`
* **Context:** Conflating a cryptographic algorithm invocation or key configuration observed in static source code with an actual physical runtime key instance (e.g. HSM token, private key memory buffer) creates severe security misunderstandings.
* **Decision:** `CryptoAsset.asset_id` and its projected CBOM component represent a **semantic cryptographic asset** (a specific algorithm, key size, and operational role instantiated at a specific source coordinate). It does NOT represent a physical runtime key object or HSM token instance.
* **Alternatives Considered:**
  1. *Inferring runtime key instances from static key generation calls:* Rejected as scientifically invalid for static analysis.
* **Consequences:** Protects ECDAT against false claims of runtime hardware or key-state introspection.

---

### ADR-010: Zero Silent Information Loss Projection Policy & Property Extension Taxonomy
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** CycloneDX 1.7 provides rich `cryptoProperties`, but lacks native fields for some ECDAT analytical attributes (e.g. discovery confidence, analyst disposition, correlation basis, raw scanner output references, and specific sub-line coordinates). Silently discarding this data impairs auditability.
* **Decision:** Enforce a strict "Zero Silent Information Loss" policy. All ECDAT attributes lacking a native CycloneDX 1.7 schema field MUST be projected into the standardized `properties` array using the `ecdat:` namespace prefix (e.g., `ecdat:confidence`, `ecdat:correlation_basis`, `ecdat:finding_ids`, `ecdat:raw_output_ref`). An explicit Information Loss Ledger must catalog any unavoidable format conversions.
* **Alternatives Considered:**
  1. *Silently dropping unmapped fields:* Destroys provenance and auditability.
  2. *Inventing custom JSON root fields:* Violates official CycloneDX 1.7 schema validation.
* **Consequences:** Ensures CycloneDX 1.7 structural alignment while preserving 100% of ECDAT analytical and provenance data in standard name-value property pairs.

---

### ADR-011: Strict Non-Inference for UNKNOWN / AMBIGUOUS States in CBOM Export
* **Status:** `[VALIDATED / ARCHITECTURAL DECISION]`
* **Context:** When static discovery encounters dynamic runtime cipher instantiation (e.g. `Cipher.getInstance(algoVar)`), the exact algorithm, key size, or role may be unknown. Guessing standard algorithms (e.g. assuming AES or 2048-bit keys) creates severe compliance vulnerabilities.
* **Decision:** When an ECDAT attribute is `UNKNOWN` or `NEEDS_REVIEW`, the CBOM projection MUST faithfully serialize `primitive: "unknown"`, `algorithmFamily: "UNKNOWN"`, omit unverified optional parameters, and attach explicit `ecdat:confidence = "NEEDS_REVIEW"` properties. It MUST NEVER fabricate algorithms, key sizes, or modes.
* **Alternatives Considered:**
  1. *Fallback to common enterprise defaults (e.g. AES-256):* Catastrophic security failure; falsifies compliance audit results.
* **Consequences:** Eliminates fabricated certainty. Consumers of the CBOM can unambiguously identify unverified or dynamic cryptography requiring manual code review.

---

### ADR-012: Separation of Discovery Dependency (`provides`) from Code Usage (`dependsOn`) in CycloneDX 1.7
* **Status:** `[VALIDATED / ARCHITECTURAL DECISION]`
* **Context:** Manifest scanners (such as Syft) discover cryptographic libraries (e.g. Bouncy Castle) that declare capability, whereas static AST scanners discover code usage. Conflating library presence with active algorithm usage produces deceptive false positives.
* **Decision:** In the CycloneDX 1.7 dependency graph, libraries discovered in dependency manifests are modeled as `type: "library"` components. Their declared cryptographic capabilities are linked using the official CycloneDX 1.7 `dependency.provides` array. Active source-code cryptographic assets are linked via `dependency.dependsOn` only when actual source-level invocation is evidenced.
* **Alternatives Considered:**
  1. *Treating all algorithms in a library's catalog as active code assets:* Grossly inflates false positives (e.g. claiming an app uses 50+ algorithms simply because it imports Bouncy Castle).
* **Consequences:** Faithfully represents the supply chain without fabricating active code usage. Validated against official CycloneDX 1.7 schema definitions for `dependency.provides`.

---

### ADR-013: Sensitive Evidence Bounding & Isolation Boundary for CBOM Exports
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** Raw scanner emissions and captured source code snippets may contain confidential intellectual property, authorization tokens, or sensitive credentials. Exporting unbounded raw data in public CBOM files introduces data leakage risks.
* **Decision:** 
  1. Code snippets in `component.evidence.occurrences.additionalContext` MUST be strictly bounded to $\le 500$ characters and $\le 10$ lines.
  2. Full raw scanner outputs (`RawScannerOutput`) MUST remain in internal storage and MUST NEVER be embedded directly as raw byte payloads in exported CBOMs; they are referenced solely by content-addressable hash (`ecdat:raw_output_ref = "sha256:..."`).
  3. Secret detection and redaction is formally noted as NOT IMPLEMENTED in Phase 2B/3A.
* **Alternatives Considered:**
  1. *Embedding raw scanner JSON/XML directly in CBOM attachments:* Severe file bloat and confidentiality leakage.
* **Consequences:** Minimizes sensitive evidence exposure while maintaining an auditable cryptographic reference link.

---

### ADR-014: Two-Tier CBOM Validation Architecture
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** Generating a CBOM that satisfies JSON Schema validation does not guarantee that the cryptographic facts within the CBOM are accurate or faithful to the underlying discoveries.
* **Decision:** Phase 3 implementation must enforce two independent validation tiers:
  1. **Structural Schema Validation:** Automated validation against the official `bom-1.7.schema.json` draft-07 specification, verifying types, enums, required fields, and unique `bom-ref` constraints.
  2. **Semantic Preservation Validation:** Programmatic validation verifying that the exported CBOM preserves exact cryptographic facts (algorithm, family, key size, curve, role, coordinates) established by ECDAT domain models without loss, modification, or hallucination.
* **Alternatives Considered:**
  1. *Schema validation only:* Fails to detect semantic bugs (e.g. serializing RSA-1024 as RSA-2048 or dropping key sizes).
* **Consequences:** Guarantees both external interoperability and internal analytical integrity.

---

### ADR-015: Multi-Scanner Observation Aggregation and Tool Provenance Projection
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** ECDAT aggregates discoveries from multiple heterogeneous scanners (e.g. CryptoScan for AST, Syft for dependencies, future scanners for network/binaries). The exported CBOM must preserve which scanner(s) contributed to each asset.
* **Decision:** 
  1. The CBOM header (`metadata.tools.components`) MUST list all participating scanners with their specific versions.
  2. Each cryptographic component MUST record its contributing scanner identities and evidence IDs in its `properties` array (`ecdat:scanners = "cryptoscan:1.4.0,..."`).
  3. If scanners disagree on parameters or roles, conservative deduplication prevents unsafe merging, retaining separate assets with distinct provenance.
* **Alternatives Considered:**
  1. *Crediting only ECDAT as the tool:* Erases external scanner attribution and hampers reproducibility audits.
* **Consequences:** Transparent, auditable multi-scanner provenance across the entire CBOM.

---

### ADR-016: Phase 3C Contextual Risk and Prioritization Engine Architecture
* **Status:** `[APPROVED / ARCHITECTURAL DECISION]`
* **Context:** Following the completion and freezing of the Phase 3B CBOM export layer, ECDAT requires a downstream analytical engine to calculate cryptographic risk, assess quantum exposure, and prioritize remediation actions without modifying Phase 3B or relying on lossy CycloneDX JSON.
* **Decision:**
  1. **Canonical Source of Truth:** Risk analysis and prioritization are performed strictly on canonical `CryptoAsset` entities, `Finding` records, and immutable `EvidenceRecord`s. The engine NEVER computes risk from lossy CycloneDX CBOM files.
  2. **Separation of Risk and Priority Pipeline:** Risk assesses cryptographic and contextual business exposure (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEEDS_REVIEW`). Priority determines operational scheduling urgency (`P0` to `P4`, plus `P_REVIEW_REQUIRED`). Priority strictly follows the four-stage decoupled pipeline:
     $$\mathbf{Facts\ \&\ Context} \longrightarrow \mathbf{Technical\ Risk} \longrightarrow \mathbf{Default\ Technical\ Priority} \longrightarrow \mathbf{Enterprise\ Policy} \longrightarrow \mathbf{Final\ Actionable\ Priority}$$
     - HNDL status is an intermediate contextual factor (under R-RISK-02); it does NOT automatically determine overall risk or priority.
     - Mosca status does NOT independently determine priority; it feeds into default technical priority alongside technical risk and migration complexity ($Y$).
  3. **Rejection of Pseudo-Scientific Scalar Weights:** Rejects arbitrary linear combinations in favor of a deterministic, multi-dimensional categorical rule matrix citing calibrated formal authorities (NIST SP 800-131A Rev 2, NIST FIPS 203/204/205, BSI TR-02102-1). Standards applicability distinguishes mandatory agency rules (e.g. FISMA non-national security systems) from guidance and contextual references (e.g. CNSA 2.0 for NSS).
  4. **Mosca Planning Heuristic & Terminology Separation:** Implements $X + Y > Z$ strictly as an algebraic planning heuristic, not a CRQC date predictor or proof of security collapse. Consistently separates canonical literature variables ($x, y, z$) from ECDAT adapted planning variables ($X = \text{Data Lifetime}$, $Y = \text{Migration Time}$, $Z = \text{Planning Horizon / Standards Deadline}$). Documents the limitation that using a regulatory transition deadline as an adapted $Z$ models compliance schedule rather than physical quantum hardware emergence. If any parameter is unknown, the engine preserves `MOSCA_INDETERMINATE`.
  5. **Safe Propagation of UNKNOWN:** Missing facts or context dimensions never default to favorable assumptions; they evaluate to `HIGH_UNCERTAINTY` or `NEEDS_REVIEW` and route to `P_REVIEW_REQUIRED`.
  6. **Zero Authoritative AI in Core Engine:** The analytical risk and prioritization engine operates with 100% deterministic code without external LLMs or third-party dependencies.
* **Alternatives Considered:**
  1. *Computing risk directly on CycloneDX CBOM JSON:* Rejected because CBOM strips domain nuance (such as non-algorithm crypto material distinctions and unmapped asset types).
  2. *Single scalar 1-100 score:* Rejected because linear weights mask critical vulnerabilities behind favorable operational scores and lack explainability.
  3. *AI-generated risk scores:* Rejected to prevent non-deterministic hallucinations in security-critical audit trails.
* **Consequences:** Provides a transparent, repeatable, and audit-defensible foundation for enterprise post-quantum cryptographic risk analysis and remediation planning.

