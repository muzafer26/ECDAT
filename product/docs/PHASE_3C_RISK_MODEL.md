# PHASE 3C — DETERMINISTIC RISK MODEL SPECIFICATION (REVISED)

---

## 1. Separation of Cryptographic Posture from Overall Risk

A core defect in legacy security tools is conflating an algorithm's mathematical properties directly with enterprise risk:
* Asserting that `AES-256` is automatically `LOW` risk ignores whether it is executed in an insecure mode (e.g. `ECB`), initialized with a static IV, used in an unauthenticated construction, or configured with hardcoded keys.
* Asserting that `RSA-2048` is automatically `HIGH` or `CRITICAL` risk ignores whether it is running inside an isolated, air-gapped test fixture on synthetic data with zero exposure.

### Five Distinct Analytical Levels:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Classical Security Status (NIST SP 800-131A Rev 2)                  │
│    • DISALLOWED (Broken: DES, 3DES, MD5, RC4)                          │
│    • DEPRECATED (SHA-1 verification only)                              │
│    • ACCEPTABLE (AES, SHA-256, RSA-2048+)                              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 2. Quantum Exposure Class (Primitive Cryptanalysis)                   │
│    • SHOR_VULNERABLE_ASYMMETRIC (RSA, ECC, DH, DSA)                    │
│    • GROVER_REDUCED_SYMMETRIC_LOW (Key < 128-bit quantum security)     │
│    • GROVER_RESILIENT_SYMMETRIC_HIGH (Key >= 128-bit quantum security) │
│    • PQC_STANDARDIZED (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 3. Cryptographic Posture Vector (Instantiation Nuance)                 │
│    • Parameter adequacy (Key length >= baseline)                       │
│    • Mode security (Authenticated AEAD vs Unauthenticated ECB/CBC)     │
│    • Curve authorization (NIST curves vs deprecated curves)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 4. Contextual Impact (Operational Reality)                             │
│    • Deployment Environment (Production vs Dev/Test)                   │
│    • Data Sensitivity & Criticality                                    │
│    • Network Exposure (Public Internet vs Isolated Airgap)             │
│    • Data Lifetime (Transient vs Persistent)                           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. Overall Risk Assessment (Synthesized Vector)                        │
│    • CRITICAL / HIGH / MEDIUM / LOW / NEEDS_REVIEW                     │
│    • Factor Breakdown & Uncertainty Disclosures                        │
└────────────────────────────────────────────────────────────────────────┘
```

An algorithm classification **contributes** to risk, but **never automatically determines overall risk**.

---

## 2. Deterministic Primitive-Level Quantum Classification

Quantum classification is derived strictly from the **mathematical primitive and algorithm identity**, never from operational role:

| Quantum Classification | Mathematical Basis | Concrete Primitives | Quantum Threat Mechanism |
|:---|:---|:---|:---|
| **`SHOR_VULNERABLE_ASYMMETRIC`** | Hidden Subgroup Problem over abelian groups | RSA, DSA, ECDSA, ECDH, Ed25519, X25519, DH, ElGamal | Solvable in polynomial time $\mathcal{O}((\log N)^3)$ via Shor's algorithm. Total break of private key confidentiality and signature forgery. |
| **`GROVER_REDUCED_SYMMETRIC_LOW`** | Quantum Database Search | AES-128, 3DES, Blowfish, CAST5 | Grover's algorithm provides quadratic speedup $\mathcal{O}(\sqrt{N})$. 128-bit key drops to 64-bit effective quantum security. |
| **`GROVER_RESILIENT_SYMMETRIC_HIGH`**| Quantum Database Search | AES-256, ChaCha20, Camellia-256 | Grover's quadratic speedup reduces 256-bit key to 128-bit quantum security (meets and exceeds NIST PQC security criteria). |
| **`GROVER_AFFECTED_HASH`** | Quantum Collision / Preimage Search | SHA-256, SHA-384, SHA-512, SHA-3 | Preimage resistance is $2^{n/2}$; collision resistance is $2^{n/3}$. SHA-256+ remains operationally robust. |
| **`PQC_STANDARDIZED`** | Lattice-based (MLWE / MSIS), State-free Hash | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS, XMSS | Explicitly standardized post-quantum schemes designed to resist both classical and quantum cryptanalysis. |
| **`UNCLASSIFIED_QUANTUM_POSTURE`** | Dynamic / Unknown Algorithm | Dynamic calls, unclassified algorithms | Posture indeterminate; increases uncertainty. |

### Strict Non-Inference Invariant:
* **Primitive $\rightarrow$ Threat Class:** The cryptographic primitive alone determines quantum susceptibility.
* **Role $\rightarrow$ Operational Consequence:** `CryptographicRole` provides context on what is at stake (e.g. session confidentiality vs authentication), but **MUST NOT** manufacture or alter the quantum threat class.

---

## 3. Explicit HNDL Assessment Model

ECDAT strictly rejects presenting arbitrary numbers (such as "5 years") as universal scientific constants for "Harvest Now, Decrypt Later" (HNDL) exposure. 

### 3.1 Multi-Dimensional HNDL Evaluation Matrix
An HNDL threat is an intersection of six verifiable components:

$$\text{HNDL Threat} = f(\text{Observed Mechanism}, \text{Operational Consequence}, \text{Adversary Collection Feasibility}, \text{Data Confidentiality Requirement}, \text{Policy Threshold}, \text{Uncertainty})$$

1. **Observed Cryptographic Mechanism:** The asset employs a quantum-vulnerable public-key mechanism (`SHOR_VULNERABLE_ASYMMETRIC`).
2. **Operational Consequence (Role):** The operational role is confidentiality-bearing (`KEY_AGREEMENT` or `ENCRYPTION`). Digital signatures have zero historical HNDL confidentiality exposure because decrypting historical session transcripts cannot be achieved by breaking an authentication signature after session keys have expired.
3. **Adversary Collection Feasibility (Exposure):** The encrypted traffic traverses accessible channels (`INTERNET_FACING_PUBLIC` or `PARTNER_DMZ`), enabling passive adversary interception and long-term storage today.
4. **Data Confidentiality Requirement (Data Lifetime $X$):** The data protected must remain secret across a substantial operational window.
5. **Configurable Policy Threshold:**
   - **Critical Baseline Clarification:** 5 years is an **ECDAT policy/demo default** and is **NOT** a universal scientific or standards-mandated threshold.
   - Neither NIST, NSA, nor BSI mandates a universal 5-year threshold.
   - The threshold is **explicitly configurable** via `EnterprisePolicyThresholds.hndl_data_lifetime_threshold_years` with policy provenance recorded (`ENTERPRISE_CONFIG` or `DEMO_DEFAULT`).
   - `STANDARDS_GUIDANCE` provenance can ONLY be used if a specific cited standard explicitly mandates a numeric retention horizon for that specific regulatory domain.
6. **Uncertainty Factor:** If data lifetime, exposure, or role is unknown, the engine flags `POTENTIAL_HIGH_UNCERTAINTY`, precluding false safety claims.

### 3.2 HNDL Assessment Status (Factor Level, Not Overall Risk)
HNDL evaluation produces an explicit factor status:
* `HNDL_ACTIVE_THREAT`: Shor-vulnerable key exchange/encryption, public/DMZ exposure, data lifetime $\ge T_\text{HNDL}$ in production.
* `HNDL_MONITOR`: Shor-vulnerable key exchange/encryption, public/DMZ exposure, but data lifetime $< T_\text{HNDL}$.
* `HNDL_LOW_EXPOSURE`: Shor-vulnerable key exchange/encryption, but strictly internal or air-gapped.
* `NOT_APPLICABLE`: Symmetric cipher (Grover-only), hash function, digital signature, or non-production fixture.
* `POTENTIAL_HIGH_UNCERTAINTY`: Relevant primitive observed, but exposure or data lifetime is unknown.

> [!IMPORTANT]
> **HNDL Status Does NOT Directly Determine Overall Risk or Priority:**
> 1. **No Automatic Overall Risk:** HNDL is an intermediate contextual quantum-risk factor. It feeds into contextual impact synthesis under Rule R-RISK-02. It does **NOT** mechanically force Overall Risk to `CRITICAL` (e.g., synthesizing with Tier-2 criticality yields `HIGH`, and Tier-3 yields `MEDIUM`).
> 2. **No Automatic Priority:** HNDL status does **NOT** directly assign or elevate a priority tier (`P0` or `P1`).
> 3. **No Independent Mosca Priority:** Mosca status does **NOT** independently determine priority.
> 4. **Strict Architectural Pipeline:** Remediation priority MUST follow the documented deterministic pipeline:
>    $$\mathbf{Cryptographic\ Facts\ \&\ Context} \longrightarrow \mathbf{Technical\ Risk} \longrightarrow \mathbf{Default\ Technical\ Priority} \longrightarrow \mathbf{Enterprise\ Policy} \longrightarrow \mathbf{Final\ Priority}$$

---

## 4. Mosca Planning Heuristic Specification

ECDAT implements Michele Mosca's theorem strictly as an **algebraic planning heuristic**:

$$\text{Mosca Condition: } \quad X + Y > Z$$

### 4.1 Authoritative Source Mapping & Terminology Separation
* **Primary Source:** Dr. Michele Mosca, *"Cybersecurity in an Era with Quantum Computers: Will We Be Ready?"*, IEEE Security & Privacy, Vol. 16, Issue 5, 2018 (and ETSI White Paper No. 8, 2015).
* **Canonical / Source Mosca Variable Meanings:**
  - $x$: "how long do you need your cryptographic keys/data to be secure? Let's call this $x$ years." (Shelf-life / Security requirement duration).
  - $y$: "how long will it take to retool our current infrastructure to be quantum-safe? Let's call this $y$ years." (Migration time / Infrastructure retooling runway).
  - $z$: "how long will it take until a quantum computer is built that can break our current cryptographic tools? Let's call this $z$ years." (Time until Cryptanalytically Relevant Quantum Computer [CRQC] availability).
* **ECDAT's Adapted Planning-Horizon Terminology:**
  - $X$: **Shelf-Life / Required Secrecy Duration** (backed by empirical `DataLifetime` context).
  - $Y$: **Migration Time** (backed by engineering `MigrationComplexity` / estimated migration runway).
  - $Z$: **Post-Quantum Transition Planning Horizon / Regulatory Standards Deadline** (backed by `EnterprisePolicyThresholds` with explicit provenance).
* **Source and Rationale for Adapted $Z$:**
  - In Dr. Mosca's original theorem, $z$ represents the unknown date when a physical CRQC emerges. Because predicting the exact calendar date of a CRQC is scientifically unprovable and speculative, ECDAT adapts $Z$ strictly to represent an operational, auditable **enterprise transition planning horizon** (e.g., 5–10 years) or an applicable **regulatory transition deadline** (e.g., NSA CNSA 2.0 2035 milestone for National Security Systems).
  - ECDAT **never** describes adapted $Z$ as canonical Mosca $z$.
  - ECDAT **never** presents adapted $Z$ as a physical prediction of quantum computer arrival.
* **Limitations of Using a Standards Deadline as a Planning Input:**
  - A standards or policy transition deadline (e.g. CNSA 2.0 2035 or NIST IR 8547 phase milestones) reflects an administrative, jurisdictional, or compliance target schedule for specific categories of systems; it does **not** reflect physical quantum hardware progression.
  - Relying on a standards deadline as an adapted $Z$ models *compliance runway*, not physical cryptographic margin against an adversary who may possess a CRQC earlier or later than policy assumptions.
* **Interpretation of $X + Y > Z$:**
  - ECDAT interprets $X + Y > Z$ strictly as: **"the post-quantum transition/planning horizon is insufficient to protect data for its required confidentiality lifetime"** (a planning deficit).
  - ECDAT does **NOT** describe $X + Y > Z$ as proof of "security collapse" or as an empirical CRQC prediction.
* **Limitations & Indeterminate States:**
  - The inequality is strictly an advisory planning heuristic. If $X$, $Y$, or $Z$ is unannotated or missing, Mosca evaluation produces **`MOSCA_INDETERMINATE`** with categorical uncertainty documented, preventing unsafe downstream assumptions.

---

## 5. Overall Risk Determination Rules

Overall risk synthesizes classical status, quantum exposure, instantiation posture, and contextual impact into an actionable category:

```python
class RiskCategory(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEEDS_REVIEW = "needs_review"
```

### Deterministic Multi-Factor Synthesis Rules:

1. **R-RISK-01 (Classical Broken Cipher in Production):**
   - *Condition:* Classical status is `DISALLOWED` (DES, 3DES, MD5 in signatures, RC4) AND Environment is `PRODUCTION`.
   - *Result:* Risk = **`CRITICAL`**.
   - *Citation:* NIST SP 800-131A Rev 2 Section 2 & 9 (Mandatory for US Federal civil executive agencies under FISMA; widely referenced commercial baseline).
2. **R-RISK-02 (Active HNDL Threat Synthesis — Multi-Dimensional):**
   - *Condition:* HNDL status is `HNDL_ACTIVE_THREAT` (Quantum class is `SHOR_VULNERABLE_ASYMMETRIC`, Role is `KEY_AGREEMENT` or `ENCRYPTION`, Exposure is `INTERNET_FACING_PUBLIC` / `PARTNER_DMZ`, Data Lifetime $X \ge T_\text{HNDL}$, Environment is `PRODUCTION`).
   - *Synthesis with Contextual Impact:*
     - If `SystemCriticality` is `TIER1_MISSION_CRITICAL` AND `DataSensitivity` is `RESTRICTED` / `CONFIDENTIAL`: Risk = **`CRITICAL`**.
     - If `SystemCriticality` is `TIER2_BUSINESS_OPERATIONAL` OR `DataSensitivity` is `INTERNAL`: Risk = **`HIGH`**.
     - If `SystemCriticality` is `TIER3_PERIPHERAL` OR `DataSensitivity` is `PUBLIC`: Risk = **`MEDIUM`**.
   - *Important:* HNDL does not mechanically equal CRITICAL. The contextual blast radius is synthesized to determine the final category.
   - *Citation:* Sector data retention governance & NIST PQC Transition Guidance (NIST IR 8547 / SP 800-227 initial public drafts, advisory planning guidance).
3. **R-RISK-03 (Shor-Vulnerable Core Asymmetric in Production):**
   - *Condition:* Quantum class is `SHOR_VULNERABLE_ASYMMETRIC` AND Environment is `PRODUCTION` (without active HNDL conditions, e.g., digital signatures or internal VPC).
   - *Result:* Risk = **`HIGH`** (if Tier-1/2) or **`MEDIUM`** (if Tier-3).
   - *Citation:* NIST FIPS 203 / 204 / 205 (Standardized post-quantum algorithms for US Federal FIPS 140 compliance; migration timing guided by OMB M-23-02).
4. **R-RISK-04 (Grover-Reduced Symmetric for Persistent Data):**
   - *Condition:* Quantum class is `GROVER_REDUCED_SYMMETRIC_LOW` (e.g. AES-128) AND Data Lifetime is `LONG` or `PERSISTENT` AND Environment is `PRODUCTION`.
   - *Result:* Risk = **`HIGH`** (if Tier-1) or **`MEDIUM`** (if Tier-2/3).
   - *Citation:* NIST SP 800-57 Part 1 Rev 5 Section 5.6 (Recommendation for key management; guidance for 128-bit security margin).
5. **R-RISK-05 (Weak Classical or Grover-Reduced in Non-Production / Isolated Fixtures):**
   - *Condition:* Broken/deprecated cipher in `DEVELOPMENT` or `TEST_FIXTURE`, OR AES-128 with `TRANSIENT_UNDER_1Y` data lifetime, OR air-gapped test fixture.
   - *Result:* Risk = **`LOW`** (or **`MEDIUM`** if classical break in shared pre-prod).
6. **R-RISK-06 (Uncertain / Missing Facts):**
   - *Condition:* Algorithm is `UNKNOWN` OR Confidence is `NEEDS_REVIEW` OR Categorical uncertainty is `HIGH_UNCERTAINTY`.
   - *Result:* Risk = **`NEEDS_REVIEW`**.
