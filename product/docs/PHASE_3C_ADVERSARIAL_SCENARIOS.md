# PHASE 3C — ADVERSARIAL SCENARIOS & TEST MATRICES

---

## Scenario 1: Attacker Attempts to Suppress Risk by Tagging Data as "Public"

* **Context & Attack Vector:** An adversarial committer introduces hardcoded DES into `src/payment/gateway.py`. To avoid triggering CI/CD alerts, the attacker adds a `.ecdat-context.json` file annotating `gateway.py` with `sensitivity: "public"` and `environment: "test_fixture"`.
* **Domain Behavior:**
  - The discovery engine captures the empirical DES usage (`AssetType.ALGORITHM`, `family: DES`).
  - The Context Ingestion Layer marks the context source as `ContextSource.EXPLICIT_REPO_CONFIG` (untrusted local repo metadata).
  - Rule `R-01` (Legacy Broken Classical) executes: classical broken status overrides local environment downgrades for core payment files.
* **Expected Output:**
  - `RiskCategory` = **`CRITICAL`**
  - `PriorityTier` = **`P0_IMMEDIATE_ACTION`**
  - Triggered Rule: `R-CLASSICAL-BROKEN-DES` citing NIST SP 800-131A Rev 2.
  - Warning: `SUSPICIOUS_CONTEXT_DOWNGRADE` attached to explanation.
* **Failure Mode Prevented:** Untrusted repository configuration suppressing a critical cryptographic vulnerability.

---

## Scenario 2: Fabricated Short Data Lifetime to Evade HNDL Alert

* **Context & Attack Vector:** An internet-facing authentication service uses `ECDH (secp256r1)` for session key exchange. An engineer under pressure to meet a deployment deadline configures `data_lifetime: "short_under_1y"` in config metadata to avoid an executive HNDL audit flag.
* **Domain Behavior:**
  - The engine accepts the context value but records its lineage: `author: "dev_user"`, `source: EXPLICIT_REPO_CONFIG`.
  - Because `exposure == INTERNET_FACING_PUBLIC` and `role == KEY_AGREEMENT`, the engine evaluates the Mosca condition:
    - With $Y = 1$, $X = 1$, $Z = 10$, $X + Y \le Z$ numerically.
    - However, the engine flags a **`PLAUSIBILITY_AUDIT_WARNING`**: Session tokens in public auth services frequently authenticate persistent user identity; the explanation explicitly discloses: *"Data lifetime is claimed as <1 year by local config. If user records or session master keys persist past this window, HNDL risk applies."*
  - `RiskCategory` = **`HIGH`** (due to Shor-vulnerable asymmetric in production).
  - `PriorityTier` = **`P1_NEAR_TERM_MIGRATION`**.
* **Failure Mode Prevented:** Silent evasion of quantum migration deadlines through unverified developer claims.

---

## Scenario 3: Dynamic Unknown Algorithm Call (`Cipher.getInstance(algoVar)`)

* **Context & Attack Vector:** Source code contains `Cipher.getInstance(System.getenv("CIPHER_SPEC"))`. Scanner reports `algorithm: "UNKNOWN"`, `confidence: NEEDS_REVIEW`.
* **Domain Behavior:**
  - Asset has `asset_type == AssetType.ALGORITHM`, `family == AlgorithmFamily.UNKNOWN`.
  - The engine refuses to guess an algorithm (e.g. will not assume AES).
  - Quantum classification cannot be performed (it is unknown whether the cipher is symmetric, asymmetric, or broken).
* **Expected Output:**
  - `RiskCategory` = **`NEEDS_REVIEW`**
  - `PriorityTier` = **`P_REVIEW_REQUIRED`**
  - `UncertaintyLevel` = **`HIGH`**
  - Missing facts: `["algorithm_name", "algorithm_family", "parameters"]`
  - Actionable triage question: *"Identify runtime values of CIPHER_SPEC environment variable in deployment manifests."*
* **Failure Mode Prevented:** Either guessing an algorithm to provide a fake score, or ignoring the dynamic invocation entirely.

---

## Scenario 4: Broken Classical Cipher (DES) vs Quantum-Vulnerable Cipher (RSA-2048)

* **Context:** An organization compares two assets in production:
  - Asset A: `DES` (56-bit symmetric cipher, broken classically).
  - Asset B: `RSA-2048` (2048-bit asymmetric key agreement, secure classically, broken by CRQC).
* **Domain Behavior:**
  - Asset A: Broken today under classical attacks. Risk = `CRITICAL`, Priority = `P0_IMMEDIATE_ACTION`.
  - Asset B: Secure against classical adversaries today; vulnerable to future quantum cryptanalysis. Risk = `HIGH` (or `CRITICAL` if persistent HNDL), Priority = `P1_NEAR_TERM_MIGRATION`.
* **Failure Mode Prevented:** Conflating immediate classical exploits with future quantum horizons. An organization must not prioritize replacing working RSA-2048 ahead of active DES vulnerabilities.

---

## Scenario 5: Harvest Now, Decrypt Later (HNDL) with Mosca Evaluation

* **Context:** Healthcare database records encrypted with `RSAES-OAEP-2048` stored on AWS S3 with public API endpoint exposure. Regulatory context requires patient record confidentiality for 25 years ($X = 25$). Estimated migration to ML-KEM requires 2 years ($Y = 2$). Enterprise planning horizon assumes transition planning timeline of 10 years ($Z = 10$, provenance: `ENTERPRISE_CONFIG`), without asserting a prediction of quantum computer arrival.
* **Domain Behavior:**
  - $X + Y = 25 + 2 = 27\text{ years}$.
  - $Z = 10\text{ years}$ (explicitly labeled as an enterprise transition planning horizon).
  - Condition: $X + Y > Z$ ($27 > 10$) evaluates to **`MOSCA_DEFICIT`**.
* **Expected Output:**
  - `RiskCategory` = **`CRITICAL`** (synthesized from Tier-1 mission-critical health records, public exposure, persistent 25y data lifetime, and active HNDL threat)
  - `PriorityTier` = **`P0_IMMEDIATE_ACTION`**
  - Rationale: *"Post-quantum transition/planning horizon is insufficient to protect patient data for its required 25-year confidentiality lifetime (Mosca planning deficit: 17 years against 10-year enterprise horizon)."*
* **Failure Mode Prevented:** Treating future quantum threats as a "future problem" when data shelf-life creates an immediate compromise window today.

---

## Scenario 6: High-Risk Complex Migration vs Low-Risk Easy Hygiene Fix

* **Context:**
  - Asset 1: Custom proprietary Core Banking protocol using `Diffie-Hellman-2048` across 2,000 ATM devices. Migration complexity is `VERY_HIGH` ($Y = 5\text{ years}$).
  - Asset 2: Internal microservice logging utility using `MD5` to hash transaction trace IDs. Migration complexity is `TRIVIAL_QUICK_WIN` ($Y = 1\text{ hour}$).
* **Domain Behavior:**
  - Asset 1: Risk = `HIGH`, Priority = `P1_NEAR_TERM_MIGRATION` (requires multi-year project initiation, architectural design).
  - Asset 2: Risk = `MEDIUM` (internal non-security hash), Priority = `P3_OPPORTUNISTIC_QUICK_WIN` (can be fixed in the current sprint via a one-line SHA-256 swap).
* **Failure Mode Prevented:** Forcing the security team to either block all releases waiting for the ATM overhaul, or ignoring simple hygiene wins.

---

## Scenario 7: Missing Context Evaluation (All Context UNKNOWN)

* **Context:** A raw scanner discovers `AES-128-CBC` on `CryptoUtil.java:12`. No `.ecdat-context.json` or enterprise policy exists.
* **Domain Behavior:**
  - `sensitivity` = `UNKNOWN`, `data_lifetime` = `UNKNOWN`, `criticality` = `UNKNOWN`, `exposure` = `UNKNOWN`.
  - The engine evaluates technical algorithm posture: AES-128 is classical secure, Grover-reduced quantum security.
  - The engine refuses to assume either worst-case (Top Secret Public) or best-case (Test Airgapped).
* **Expected Output:**
  - `RiskCategory` = **`MEDIUM`** (baseline technical cryptographic posture).
  - `PriorityTier` = **`P_REVIEW_REQUIRED`**.
  - `UncertaintyLevel` = **`PARTIAL`** (algorithm verified; operational context unannotated).
  - Actionable prompt: *"Provide environment and exposure context to finalize prioritization."*
* **Failure Mode Prevented:** Fabricating context or failing silently when metadata is absent.

---

## Scenario 8: Conflicting Context Annotations

* **Context:** Repo config declares `environment: "development"`, while CI/CD pipeline deployment metadata tags the artifact as `environment: "production"`.
* **Domain Behavior:**
  - Context Provider detects authoritative conflict between `CI_ENVIRONMENT_METADATA` and `EXPLICIT_REPO_CONFIG`.
  - Conflict policy triggers: CI pipeline deployment metadata takes precedence for operational environment, and a `CONTEXT_SOURCE_CONFLICT` warning is recorded.
* **Expected Output:**
  - Environment evaluates to `PRODUCTION`.
  - Explanation lists conflicting sources and records resolution rule.
* **Failure Mode Prevented:** Silent overriding of operational reality by stale developer repository files.

---

## Scenario 9: Symmetric Cipher Evaluation (AES-128 vs AES-256 Grover Resilience)

* **Context:**
  - Component 1: `AES-128-GCM` protecting long-term archived backups.
  - Component 2: `AES-256-GCM` protecting long-term archived backups.
* **Domain Behavior:**
  - Under Grover's algorithm, symmetric key search complexity is halved:
    - AES-128 provides 64 bits of quantum security (below NIST SP 800-57 112-bit minimum).
    - AES-256 provides 128 bits of quantum security (meets NIST PQC security standards).
* **Expected Output:**
  - Component 1: Quantum Class = `GROVER_REDUCED_SYMMETRIC_LOW`. Risk = `HIGH` (for persistent data). Priority = `P2_PLANNED_TRANSITION` (re-key to AES-256).
  - Component 2: Quantum Class = `GROVER_RESILIENT_SYMMETRIC_HIGH`. Risk = `LOW`. Priority = `P4_DEFERRED_MONITORING`.
* **Failure Mode Prevented:** Treating all symmetric ciphers as equally "quantum-safe" or conversely panicking about AES-256.

---

## Scenario 10: Ingested External CBOM Attempting to Drive Risk Analysis

* **Context:** A third-party supplier provides an exported CycloneDX 1.7 CBOM JSON file. The supplier's tool mapped an unclassified algorithm to `cryptoProperties.assetType: "algorithm"` and omitted `algorithmProperties`.
* **Domain Behavior:**
  - The Risk Engine refuses to compute risk directly from the external CBOM JSON.
  - Ingestion boundary enforces: External CBOMs are ingested through the Phase 2A adapter boundary into `EvidenceRecord`s and `Finding`s.
  - The missing algorithm identity is normalized as `AlgorithmFamily.UNKNOWN` and evaluated under ECDAT's strict uncertainty policy.
* **Expected Output:**
  - Evaluated as `AssetType.UNKNOWN` / `NEEDS_REVIEW`.
  - No speculative risk assigned.
* **Failure Mode Prevented:** External tool serialization bugs or schema approximations polluting internal risk assessments.

---

## Scenario 11: Authorized Enterprise Policy Priority Override (Case J)

* **Context & Business Reality:** A legacy internal microservice uses Shor-vulnerable key exchange (`Diffie-Hellman-2048`) in an internal VPC for business-operational workloads.
  - Cryptographic Primitive: `SHOR_VULNERABLE_ASYMMETRIC`, classical status `ACCEPTABLE`.
  - Operational Context: `environment = PRODUCTION`, `exposure = INTERNAL_VPC`, `criticality = TIER2_BUSINESS_OPERATIONAL`.
  - Retention & Migration Planning Inputs: Data lifetime $X = 3\text{y}$ (`MEDIUM_1_TO_5Y`), migration complexity $Y = 2\text{y}$ (`MEDIUM`), enterprise planning horizon $Z = 10\text{y}$ (`ENTERPRISE_CONFIG`).
  - Technical Risk Derivation: Evaluated strictly under Rule R-RISK-03 as **`HIGH`** (Shor-vulnerable key exchange in production Tier-2 system).
  - Mosca Planning Heuristic: $X + Y = 3 + 2 = 5\text{y} \le Z = 10\text{y}$ evaluates to **`MOSCA_ADEQUATE`** (5-year planning margin remains).
  - Default Technical Priority: Derived strictly from the derivation table (`HIGH` risk + `MEDIUM` complexity + `MOSCA_ADEQUATE`) as exactly **`P2_PLANNED_TRANSITION`**.
  - Operational Constraint: The service is scheduled for complete decommissioning in 6 months (`2027-03-31`), protected by an active network air-gap.
* **Domain Behavior:**
  - The enterprise applies an auditable `PolicyOverride`:
    - `author`: "Chief Information Security Officer"
    - `policy_ref`: "DEC-2026-DECOM-882"
    - `reason`: "Service decommissioning scheduled for Q1 2027; compensating air-gap active."
    - `effective_until`: "2027-03-31"
  - The engine validates override invariants:
    1. Cryptographic facts are confirmed (not `NEEDS_REVIEW`), so mandatory triage is not bypassed.
    2. The underlying `RiskCategory` remains strictly **`HIGH`** (immutable technical fact).
    3. Baseline `default_technical_priority` (**`P2_PLANNED_TRANSITION`**) is recorded and visible in `MigrationPriorityRecord`.
    4. Operational scheduling urgency is adjusted to **`P4_DEFERRED_MONITORING`**.
    5. The `RiskExplanation` includes full `PolicyOverrideDisclosure` with author, reference, rationale, and expiry.
    6. Expiration reversion is documented as a future engine requirement (to be executed in Phase 3C-B runtime; not claimed as active in Phase 3C-A).
* **Expected Output:**
  - `RiskCategory` = **`HIGH`** (technical fact intact).
  - `DefaultTechnicalPriority` = **`P2_PLANNED_TRANSITION`** (baseline preserved).
  - `FinalPriorityTier` = **`P4_DEFERRED_MONITORING`** (audited schedule).
  - `PolicyOverrideDisclosure`: Active until 2027-03-31.
* **Failure Mode Prevented:** Falsifying cryptographic risk scores to accommodate enterprise scheduling, while preventing untracked, indefinite security debt accumulation.
