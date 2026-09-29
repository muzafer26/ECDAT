# PHASE 3C — UNKNOWN PROPAGATION & UNCERTAINTY POLICY (REVISED)

---

## 1. Rejection of Arbitrary Numerical Uncertainty Thresholds

In Phase 3C Part A initial draft, uncertainty was scored via numerical ratios (e.g., $\ge 0.85$, $0.50 - 0.85$, $< 0.50$).
Following architectural review, **arbitrary numerical uncertainty thresholds are formally rejected**:
1. **Lack of Empirical Basis:** A ratio of 8 out of 10 arbitrary fields being populated has no mathematical or cryptographic equivalence to "low uncertainty" if the two missing fields are the algorithm identity and the network exposure.
2. **Explainability Breakdown:** Categorical states grounded in cryptographic necessity provide far clearer auditability than decimal fractions.

---

## 2. Categorical Uncertainty Model

ECDAT defines an explicit, explainable **Categorical Uncertainty Model**:

```python
class UncertaintyLevel(str, Enum):
    """Categorical classification of analytical uncertainty."""
    CONFIRMED = "confirmed"              # All required cryptographic facts and operational context verified
    PARTIAL = "partial"                  # Cryptographic facts verified; operational context unannotated or default
    HIGH_UNCERTAINTY = "high_uncertainty"# Core cryptographic parameters missing or contradictory
    NEEDS_REVIEW = "needs_review"        # Dynamic invocation, unclassified algorithm, or critical context conflict
```

### 2.1 Deterministic Uncertainty Assignment Rules:

| Uncertainty Level | Cryptographic Facts State | Context State | Resulting Engine Behavior |
|:---|:---|:---|:---|
| **`CONFIRMED`** | Algorithm, family, key size, mode, and role verified from evidence. | Environment, exposure, and data lifetime explicitly annotated by an authoritative source. | Full deterministic risk and priority evaluation executed with maximum confidence. |
| **`PARTIAL`** | Algorithm and key parameters verified from evidence. | Context is default or unannotated. | Evaluates baseline technical cryptographic posture; flags missing context in explanation. |
| **`HIGH_UNCERTAINTY`** | Generic family (bare `RSA`, bare `EC`) without key size or mode; or scanner disagreement. | Any. | Technical risk assigned conditionally; forces `P_REVIEW_REQUIRED` priority until resolved. |
| **`NEEDS_REVIEW`** | Algorithm is `UNKNOWN` (dynamic call); or conflicting context sources detected. | Any. | Risk evaluates to `NEEDS_REVIEW`; priority evaluates to `P_REVIEW_REQUIRED`. Zero risk suppression permitted. |

---

## 3. Strict Rules of Non-Favorable Propagation

The rule **$\text{UNKNOWN} \neq \text{ZERO}$** governs all engine operations:

1. **Unknown Algorithm Identity:**
   - **Prohibited:** Assuming standard AES or any other benign cipher.
   - **Mandated:** Quantum classification evaluates to `UNCLASSIFIED_QUANTUM_POSTURE`; risk evaluates to `NEEDS_REVIEW`; priority evaluates to `P_REVIEW_REQUIRED`.
2. **Unknown Data Lifetime ($X$):**
   - **Prohibited:** Assuming transient or short lifetime to bypass HNDL.
   - **Mandated:** If the algorithm is Shor-vulnerable key agreement or encryption, Mosca evaluation produces `MOSCA_INDETERMINATE`, uncertainty evaluates to `HIGH_UNCERTAINTY`, priority routes to `P_REVIEW_REQUIRED`, and an HNDL review alert is raised for human triage.
3. **Unknown Network Exposure:**
   - **Prohibited:** Assuming internal VPC or air-gapped isolation.
   - **Mandated:** Evaluated as `UNVERIFIED_EXPOSURE`; cannot be used to mitigate risk.
4. **Unknown Business Criticality:**
   - **Prohibited:** Assuming peripheral utility or low business impact.
   - **Mandated:** Evaluated as `CRITICALITY_UNASSESSED`.
5. **Unknown Migration Complexity ($Y$):**
   - **Prohibited:** Assuming trivial or quick-win refactoring.
   - **Mandated:** Complexity evaluated as `COMPLEXITY_UNASSESSED`; scheduled conservatively under `P_REVIEW_REQUIRED` if risk is elevated.
