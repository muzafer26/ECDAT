# PHASE 3C — CONTEXTUAL PRIORITIZATION MODEL SPECIFICATION (REVISED)

---

## 1. Prioritization Architecture: From Technical Risk to Policy Urgency

ECDAT models prioritization as a multi-tier pipeline separating **technical risk facts** from **enterprise policy decisions**:

$$\begin{matrix}
\mathbf{Technical Risk Vector} & \longrightarrow & \mathbf{Default Technical Priority} & \longrightarrow & \mathbf{Enterprise Policy Layer} & \longrightarrow & \mathbf{Final Actionable Priority} \\
\text{(Cryptographic Facts,} & & \text{(Deterministic Baseline,} & & \text{(Explicit Overrides,} & & \text{(Auditable Queue,} \\
\text{Quantum Susceptibility,} & & \text{Standardized Heuristic,} & & \text{Attributable Provenance,} & & \text{Target Sprints,} \\
\text{Empirical Evidence)} & & \text{Mosca Evaluation)} & & \text{Regulatory Constraints)} & & \text{Actionable Guidance)}
\end{matrix}$$

### Fundamental Principles:
* **No Hidden Policy:** Enterprise priorities are **never hidden inside deterministic cryptographic rules**. 
* **Transparency:** An algorithm's risk does not artificially change because an enterprise decides to defer its remediation. Rather, the risk remains accurate (`HIGH`), while the enterprise policy layer explicitly records a deferred schedule with an attributable audit reason.
* **Strict Priority Pipeline Flow:** Priority derivation is decoupled into four auditable steps:
  1. **HNDL must not automatically determine overall risk.** (HNDL is an intermediate factor synthesized under Rule R-RISK-02).
  2. **HNDL must not automatically determine priority.** (HNDL does not jump directly to P0/P1).
  3. **Mosca status must not independently determine priority.** (Mosca condition is an input to default technical priority alongside risk and complexity).
  4. **Priority must follow the documented pipeline:**
     $$\mathbf{Cryptographic\ Facts\ \&\ Context} \longrightarrow \mathbf{Technical\ Risk} \longrightarrow \mathbf{Default\ Technical\ Priority} \longrightarrow \mathbf{Enterprise\ Policy} \longrightarrow \mathbf{Final\ Actionable\ Priority}$$

---

## 2. Priority Tiers as Explicit Policy Classifications

ECDAT establishes five operational priority tiers and one triage state:

```python
class PriorityTier(str, Enum):
    P0_IMMEDIATE_ACTION = "P0_immediate_action"          # Active security failure or critical deficit; current sprint
    P1_NEAR_TERM_MIGRATION = "P1_near_term_migration"    # Core quantum transition project; next 1-2 quarters
    P2_PLANNED_TRANSITION = "P2_planned_transition"      # Strategic modernization; 12-24 month roadmap
    P3_OPPORTUNISTIC_QUICK_WIN = "P3_opportunistic_quick_win" # Low-effort hygiene remediation; backlog/sprint fill
    P4_DEFERRED_MONITORING = "P4_deferred_monitoring"    # Low exposure or quantum-safe; annual review
    P_REVIEW_REQUIRED = "P_review_required"              # Missing facts or context; immediate human triage
```

---

## 3. Technical Default Priority Derivation

Before enterprise policy overrides are applied, the engine derives a **Default Technical Priority** strictly from the synthesized `Technical Risk`, data shelf-life ($X$), migration complexity/time ($Y$), and the adapted Mosca status ($X + Y > Z$):

| Technical Risk | Migration Complexity ($Y$) | Mosca Status ($X + Y > Z$) | Default Technical Priority | Technical Rationale |
|:---|:---|:---|:---|:---|
| **`CRITICAL`** | Any Complexity | `MOSCA_DEFICIT` or Classical Break | **`P0_IMMEDIATE_ACTION`** | Immediate operational failure or critical secrecy deficit. |
| **`CRITICAL`** | Any Complexity | `MOSCA_ADEQUATE` | **`P1_NEAR_TERM_MIGRATION`** | Critical system priority; adequate runway permits organized near-term transition. |
| **`HIGH`** | `TRIVIAL_QUICK_WIN` / `LOW` | `MOSCA_DEFICIT` | **`P1_NEAR_TERM_MIGRATION`** | High risk combined with planning deficit demands near-term project execution. |
| **`HIGH`** | `TRIVIAL_QUICK_WIN` / `LOW` | `MOSCA_ADEQUATE` | **`P3_OPPORTUNISTIC_QUICK_WIN`** | High risk, but trivial to fix and adequate runway ($X + Y \le Z$): execute as an early quick win in upcoming sprints without multi-quarter program overhead. |
| **`HIGH`** | `MEDIUM` / `HIGH` | `MOSCA_DEFICIT` | **`P1_NEAR_TERM_MIGRATION`** | Deficit demands near-term project initiation and resource allocation. |
| **`HIGH`** | `MEDIUM` / `HIGH` | `MOSCA_ADEQUATE` | **`P2_PLANNED_TRANSITION`** | Adequate runway permits roadmap-based planned modernization (12–24 months). |
| **`HIGH`** | `VERY_HIGH` | Any | **`P2_PLANNED_TRANSITION`** | Multi-year protocol engineering requires strategic roadmap placement. |
| **`MEDIUM`** | `TRIVIAL_QUICK_WIN` | Any | **`P3_OPPORTUNISTIC_QUICK_WIN`** | Low-effort hygiene fix to reduce overall attack surface. |
| **`MEDIUM`** | `MEDIUM` / `HIGH` | Any | **`P2_PLANNED_TRANSITION`** | Standard architectural modernization cycle. |
| **`LOW`** | Any | Any | **`P4_DEFERRED_MONITORING`** | Continuous monitoring; annual review. |
| **`NEEDS_REVIEW`**| Any | `MOSCA_INDETERMINATE` or High Uncertainty | **`P_REVIEW_REQUIRED`** | Missing cryptographic facts or operational context prevent safe prioritization; routes to human triage. |

### 3.1 Case H Resolution and Formal Policy Alignment
Case H evaluates an asset with active HNDL (`HNDL_ACTIVE_THREAT`), Tier 2 business operational criticality, $X = 7\text{y}$, $Y \approx 0.1\text{y}$ (`TRIVIAL_QUICK_WIN`), and $Z = 10\text{y}$.
* **Risk Evaluation:** Under R-RISK-02, `HNDL_ACTIVE_THREAT` synthesized with `TIER2_BUSINESS_OPERATIONAL` assigns `RiskCategory = HIGH` (HNDL does **not** force `CRITICAL`).
* **Priority Derivation:** In accordance with the table above, `HIGH` risk + `TRIVIAL_QUICK_WIN` + `MOSCA_ADEQUATE` ($7.1 \le 10$) assigns `P3_OPPORTUNISTIC_QUICK_WIN`.
* **Reconciliation:** HNDL does not directly dictate priority. Because the transition runway is adequate ($X + Y \le Z$, a 2.9-year margin before the 10-year horizon) and implementation is trivial ($Y \approx 0.1\text{y}$, e.g. enabling a hybrid PQC cipher suite via configuration flag), scheduling as `P3_OPPORTUNISTIC_QUICK_WIN` provides optimal operational value without creating false panic or unneeded multi-quarter roadmap bureaucracy.
* **Absence of Override:** If the enterprise requires immediate remediation regardless of runway, an auditable `PolicyOverride` can elevate `P3` to `P0` or `P1` with attributable provenance, preserving the integrity of the underlying technical risk vector.

---

## 4. Enterprise Policy Override Layer

Organizations operate under business, contractual, and regulatory realities that require adjusting default priorities.

### 4.1 Strict Policy Override Invariants:
Priority overrides allow organizations to adjust operational scheduling urgency (both priority elevations and priority deferrals/downgrades) based on legitimate business realities (such as planned system decommissioning, contractual milestones, or active compensating controls).

Every priority override **MUST** satisfy:
1. **Attributability:** Signed or authored by an identified, authorized enterprise role (`author`, e.g. "CISO", "Lead Cryptographic Architect").
2. **Provenance & Rationale:** Traced to an explicit policy reference (`policy_ref`, e.g., "Board Risk Acceptance 2026-Q3", "PCI-DSS Exception #401", "DEC-2026-DECOM-882") with a documented business/technical justification (`reason`).
3. **Defined Scope:** Explicitly bounded to a target asset ID (`asset_id`) or verified architectural group; unbounded global wildcard downgrades are prohibited.
4. **Immutability of Technical Risk:** The underlying `RiskCategory` remains strictly unchanged. The override alters **only** the scheduling urgency (`PriorityTier`).
5. **Visibility of Original Baseline:** The default technical priority remains visible and immutable in `MigrationPriorityRecord.default_technical_priority`.
6. **Temporal Expiration (Future Engine Requirement):** Every override MUST specify an expiration date (`effective_until: ISO-8601 UTC`). As a Phase 3C-B engine implementation requirement, the runtime system must evaluate this timestamp against execution time and revert expired overrides to `default_technical_priority` unless explicitly re-certified. (This is a design requirement for Phase 3C-B and is not claimed as currently implemented in Phase 3C-A).
7. **Non-Overridable Controls & Safety Boundaries:**
   - **No Suppression of Triage on Missing Facts:** An override **CANNOT** downgrade or bypass `P_REVIEW_REQUIRED` when cryptographic facts are `UNKNOWN` or categorical uncertainty is `NEEDS_REVIEW` / `HIGH_UNCERTAINTY`. Required triage to identify the cipher must occur before policy scheduling can be applied.
   - **No Erasure of Compliance Obligations:** An override **CANNOT** alter or silence underlying compliance findings (e.g., NIST SP 800-131A `DISALLOWED` status). The violation and triggered rule remain fully disclosed in the explanation; the override records only the organization's formal risk acceptance or temporary exception.
8. **Audit Trail:** The `RiskExplanation` includes an explicit `PolicyOverrideDisclosure` recording:
   - Original default technical priority
   - Adjusted final enterprise priority
   - Author, policy reference, and justification
   - Expiration date and active status

```python
@dataclass(frozen=True)
class PolicyOverride:
    """Explicit, auditable enterprise adjustment to a default priority tier."""
    original_default_priority: PriorityTier
    final_assigned_priority: PriorityTier
    reason: str
    author: str
    policy_ref: str
    effective_until: str  # ISO-8601 date
```

---

## 5. Output Migration Priority Record

```python
@dataclass(frozen=True)
class MigrationPriorityRecord:
    """Actionable prioritization intelligence feeding downstream migration planning."""
    asset_id: str
    final_priority: PriorityTier
    default_technical_priority: PriorityTier
    risk_category: str
    mosca_status: str
    migration_complexity: str
    primary_rationale: str
    policy_override: Optional[PolicyOverride] = None
    target_planning_window: str       # e.g. "Current Sprint", "Q4 2026", "2027-2028 Modernization"
    missing_context_gaps: Sequence[str]
```
