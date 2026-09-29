# PHASE 3C — EXPLAINABILITY & REASONING MODEL SPECIFICATION (REVISED)

---

## 1. The Seven-Part Explainability Structure

Every risk assessment and priority determination emitted by ECDAT must explicitly decompose its reasoning into seven distinct, verifiable categories:

$$\text{Risk Reasoning} = \langle \text{OBSERVED\_FACTS}, \text{DERIVED\_CLASSIFICATIONS}, \text{CONTEXT}, \text{RULES}, \text{ASSUMPTIONS}, \text{UNCERTAINTY}, \text{RESULT} \rangle$$

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. OBSERVED FACTS (Empirical Code/Manifest Ground Truth)               │
│    • File path, line numbers, matched text, raw token, scanner origin  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 2. DERIVED CLASSIFICATIONS (Deterministic Domain Mappings)             │
│    • Normalized algorithm name, key size, cipher mode, primitive       │
│    • Quantum exposure class (Shor-vulnerable / Grover-reduced / PQC)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 3. CONTEXT (Enterprise & Environmental Declarations)                   │
│    • Environment (Prod/Dev), Exposure (Public/VPC), Lifetime, Critical │
│    • Authority and provenance of context (Signed Policy vs Local Repo) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 4. RULES (Deterministic Policy & Standard Triggers)                    │
│    • Concrete rule IDs and authoritative citations (NIST, FIPS, BSI)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 5. ASSUMPTIONS (Explicit Planning Parameters)                          │
│    • Mosca planning horizon (Z) and justification                      │
│    • HNDL enterprise lifetime threshold                                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│ 6. UNCERTAINTY (Disclosed Gaps and Unknowns)                           │
│    • Categorical uncertainty tier (Confirmed / Partial / Review)       │
│    • Explicit list of unverified or missing attributes                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 7. RESULT (Final Actionable Determination)                             │
│    • Technical Risk Category + Final Priority Tier + Target Window     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Rigorous Standards Citation Registry

All rules and explanations must cite **strictly verified standards** without exaggerating recommendations into mandates:

| Rule ID | Formal Authority | Document Title & Reference | Nature of Authority & Scope Calibration |
|:---|:---|:---|:---|
| `R-CLASSICAL-DISALLOWED` | NIST SP 800-131A Rev 2 | *Transitioning the Use of Cryptographic Algorithms and Key Lengths* (Table 1 & 2) | **Mandatory Requirement** for US Federal executive branch non-national security systems under FISMA/FIPS; widely adopted baseline guidance for commercial systems. Formally disallows 2-key 3DES, DES, MD5, and SHA-1 for digital signatures. |
| `R-PQC-STANDARDS-MLKEM` | NIST FIPS 203 | *Module-Lattice-Based Key-Encapsulation Mechanism Standard* | **Federal Information Processing Standard:** Defines and standardizes ML-KEM for cryptographic module validation under FIPS 140 in US Federal agencies. Does not itself mandate migration dates (timelines are set by policy guidance such as OMB M-23-02). |
| `R-PQC-STANDARDS-MLDSA` | NIST FIPS 204 | *Module-Lattice-Based Digital Signature Standard* | **Federal Information Processing Standard:** Defines and standardizes ML-DSA for cryptographic module validation under FIPS 140 in US Federal agencies. |
| `R-PQC-STANDARDS-SLHDSA` | NIST FIPS 205 | *Stateless Hash-Based Digital Signature Standard* | **Federal Information Processing Standard:** Defines and standardizes SLH-DSA as a hash-based backup signature scheme for cryptographic module validation under FIPS 140 in US Federal agencies. |
| `R-PQC-TRANSITION-GUIDANCE` | NIST IR 8547 / SP 800-227 Initial Public Drafts | *Transition to Post-Quantum Cryptography Standards* | **Advisory Planning Guidance:** Recommends phases, hybrid mechanisms, and deprecation timelines for legacy public-key schemes. Voluntary planning guidance, not self-executing statutory requirement. |
| `R-BSI-KEY-LENGTH-GUIDANCE` | BSI TR-02102-1 (2024) | *Cryptographic Mechanisms: Recommendations and Key Lengths* | **National Technical Guideline:** Mandatory for German Federal Government IT systems (Bundesverwaltung); technical recommendation / advisory internationally. |
| `R-CNSA-2-TIMELINE` | NSA CNSA 2.0 | *Commercial National Security Algorithm Suite 2.0 Cybersecurity Advisory* | **Government Policy Timeline:** Prescribes transition requirements mandatory **strictly** for National Security Systems (NSS) under CNSS authority. Advisory contextual reference for non-NSS and commercial environments; never represents a CRQC prediction. |

---

## 3. Structured Data Contract for `RiskExplanation`

```python
@dataclass(frozen=True)
class RiskExplanation:
    """Complete, seven-part auditable explanation accompanying every assessment."""
    asset_id: str
    
    # 1. Observed Facts
    observed_facts: Sequence[str]
    evidence_ids: Sequence[str]
    code_locations: Sequence[str]
    
    # 2. Derived Classifications
    algorithm_identity: str
    classical_status: str              # DISALLOWED, DEPRECATED, ACCEPTABLE
    quantum_exposure_class: str        # SHOR_VULNERABLE, GROVER_REDUCED, PQC_STANDARDIZED
    
    # 3. Context & Provenance
    context_summary: Dict[str, str]
    context_authority: str
    
    # 4. Rules Triggered
    triggered_rules: Sequence[Dict[str, str]]  # rule_id, authority, section, citation_url
    
    # 5. Explicit Assumptions
    assumptions: Sequence[str]         # e.g. "Mosca horizon Z=10y based on CNSA 2.0 guidelines"
    
    # 6. Uncertainty & Missing Gaps
    uncertainty_level: str             # CONFIRMED, PARTIAL, HIGH_UNCERTAINTY, NEEDS_REVIEW
    missing_facts_and_questions: Sequence[str]
    
    # 7. Final Result
    risk_category: str
    final_priority_tier: str
    actionable_remediation_summary: str
```
