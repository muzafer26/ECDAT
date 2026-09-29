# PHASE 3C — RELATIONSHIP & BLAST RADIUS POLICY

---

## 1. Conservative Architectural Boundary on Relationships

In many static analysis and security tools, graph relationships are loosely inferred:
* Two functions in the same file are assumed to share cryptographic data.
* An asset named `KeyManager` is assumed to control an asset named `CipherUtil`.
* A package in `pom.xml` is assumed to be invoked by every cryptographic statement in the repository.

**ECDAT explicitly prohibits speculative, heuristic, or proximity-based relationship inference.**

### Fundamental Boundary Invariants:
1. **Phase 1D Correlation Boundary Preserved:**
   Phase 1D correlation is **strictly limited to same-source-statement finding deduplication**. It does not perform cross-file dataflow, taint tracking, runtime call-graph synthesis, or lifecycle correlation.
2. **Evidence-Grounded Relationships Only:**
   No relationship may exist between two cryptographic assets unless supported by **direct, verifiable empirical evidence** (e.g. an explicit lockfile declaration, an explicit wrapper delegation in code, or a shared variable reference in an AST scope).
3. **No Name or Proximity Inference:**
   Assets are never linked merely because they have similar names, exist in the same directory, or are discovered in the same scanner run.

---

## 2. Canonical Relationship Domain Model

When Phase 3C models dependencies and blast radius, it uses a dedicated, immutable `AssetRelationship` entity:

```python
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence


class RelationshipType(str, Enum):
    """Authoritative, evidence-backed relationship categories."""
    
    # 1. Dependency Provider: A package declared in manifests provides algorithms
    PROVIDES = "provides"
    
    # 2. Key Usage: An explicit key material asset is supplied to an algorithm instance
    USES_KEY = "uses_key"
    
    # 3. Certificate Usage: A certificate provides the public key or identity for an algorithm
    USES_CERTIFICATE = "uses_certificate"
    
    # 4. Protocol Wrapping: A transport protocol (TLS, SSH) encapsulates an underlying cipher
    ENCAPSULATES = "encapsulates"
    
    # 5. Wrapper Abstraction: A custom internal class wraps and delegates to an external crypto primitive
    WRAPS_PRIMITIVE = "wraps_primitive"


@dataclass(frozen=True)
class AssetRelationship:
    """
    Explicit, evidence-backed relationship between two cryptographic assets.
    Immutable proof connecting providers to consumers or keys to algorithms.
    """
    relationship_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    evidence_ids: Sequence[str]       # Direct empirical proof supporting the connection
    confidence: str                  # CONFIRMED, LIKELY, NEEDS_REVIEW
    provenance_rule: str             # Deterministic rule establishing the connection
```

---

## 3. Supported Relationship Types & Proof Thresholds

### 3.1 `PROVIDES` (Library Dependency $\longrightarrow$ Algorithm)
* **Definition:** A library package discovered in a manifest/lockfile (e.g., `bcprov-jdk18on@1.78.1`) provides a known set of cryptographic algorithms.
* **Proof Threshold Required:**
  1. An `AssetType.LIBRARY_DEPENDENCY` asset discovered via lockfile/manifest evidence.
  2. A verified registry mapping (or scanner coordinate) proving the library exports the target capability.
  3. Mapped in the CycloneDX CBOM strictly as `dependency.provides` (ADR-012).
* **Negative Invariant:** Does **not** prove that the application code invokes the algorithm. It establishes the *capability provider* blast radius.

### 3.2 `USES_KEY` (Algorithm $\longrightarrow$ Crypto Key)
* **Definition:** An algorithm execution explicitly takes a `CryptoAsset` of type `CRYPTO_KEY` as its initialization key parameter.
* **Proof Threshold Required:**
  1. Both assets reside within the same AST method/block scope, or
  2. An AST data-flow edge explicitly links the key instantiation variable to `cipher.init(mode, key)`.
* **Prohibition:** Passing a generic string or variable across unverified function calls cannot be assumed to be `USES_KEY` without AST dataflow proof.

### 3.3 `WRAPS_PRIMITIVE` (Wrapper Class $\longrightarrow$ Standard Algorithm)
* **Definition:** An enterprise wrapper class (e.g. `CompanyCryptoHelper.java`) encapsulates standard JCA/BouncyCastle calls.
* **Proof Threshold Required:**
  1. Discovery engine detection method is `WRAPPER_INSPECTION`.
  2. Direct method delegation call observed in wrapper class body.

---

## 4. Blast Radius Determination

When prioritizing remediation in Phase 3C:
* **Blast Radius** is evaluated strictly as the count of verified incoming `PROVIDES` and `WRAPS_PRIMITIVE` edges.
* **High Blast Radius Asset:** If an enterprise wrapper (e.g., `EnterpriseCryptoService`) is wrapped by 40 internal services, migrating that single wrapper has high positive leverage (a high-leverage architectural quick win).
* **Isolated Asset:** A one-off script calling `DES` in an isolated utility file has a blast radius of 1.
* In the absence of verified relationship evidence, the blast radius defaults to `1 (ISOLATED_OBSERVATION)` with uncertainty documented.
