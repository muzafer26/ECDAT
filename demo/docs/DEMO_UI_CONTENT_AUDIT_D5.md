# ECDAT — Demo UI Content Audit (Phase D5)

**Status:** AUTHORITATIVE AUDIT & REPLACEMENT SPECIFICATION  
**Scope:** Complete Presentation Layer Audit (`demo/frontend/index.html`, `demo/frontend/app.js`, `demo/scenarios/registry.py`, `demo/adapters/registry.py`)  
**Audit Criteria:** Elimination of unsupported claims, coaching language, benchmark conflation, and unevidenced parameter assertions.  

---

## 1. Executive Audit Summary

The working demo has a sound underlying architecture that correctly consumes the frozen `product/core/` engine. However, several presentation elements in the UI and configuration layers introduce assumptions that are stronger than what the empirical scanner evidence establishes. 

This audit itemizes every defective text snippet, unsupported assertion, coaching phrase, or misleading classification, and provides the **exact, mandatory replacement wording** required before visual redesign begins.

---

## 2. Comprehensive Content Audit Table

| Current Content | Source File & Location | Current Provenance | Identified Problem | Required Replacement Wording |
| :--- | :--- | :--- | :--- | :--- |
| `<!-- TAB 1: OVERVIEW & PIPELINE (Orient Judge) -->` | `demo/frontend/index.html:52` | Internal comment | Presentation-coaching language targeting the evaluator instead of professional product architecture. | `<!-- TAB 1: OVERVIEW & PIPELINE ARCHITECTURE -->` |
| `Answers the judge's fundamental question: "Why does ECDAT believe this cryptographic asset exists?"` | `demo/frontend/index.html:328` | Presentation lead text | Meta-coaching phrasing; detracts from executive control plane authority. | `Exposes the empirical scanner observations substantiating this cryptographic asset, preserving raw AST matches and detection provenance.` |
| `To guarantee scientific reproducibility and air-gapped security, demonstration scenarios execute real pipeline processing...` | `demo/frontend/index.html:135` | Section description | "Guarantee" and "air-gapped security" are broad, unsupported absolute claims. | `Demonstration scenarios execute real core analytical pipelines on verified offline benchmark fixtures from product/benchmark/.` |
| `Actionable asymmetric RSA-2048 key exchange in Java source.` | `demo/scenarios/registry.py:27` & `demo/frontend/index.html:148` | Scenario description | Conflates benchmark ground truth (2048 bits) and unobserved network usage (key exchange) with scanner evidence. | `Asymmetric RSA key generation in Java source. Demonstrates evidence-driven uncertainty: CryptoScan captured algorithm instantiation without key size; benchmark ground truth indicates 2048-bit modulus, but ECDAT evaluates classical security to INDETERMINATE and routes to P_REVIEW_REQUIRED.` |
| `// Transition to Inventory view to guide the judge` | `demo/frontend/app.js:261` | Code comment | Coaching terminology in client controller. | `// Transition to Inventory view upon successful pipeline execution` |
| `classification=ScenarioClassification.LIVE` (on TC01, TC02, TC06) | `demo/scenarios/registry.py:31,60,89` | Scenario registration | Conflates live core execution with live repository scanning. The input fixtures are controlled benchmark files. | `classification=ScenarioClassification.CONTROLLED_DEMO` (with core execution classified as `IMPLEMENTED_CORE_INTEGRATED`) |
| `ctxSystem.textContent = ${asset.system \|\| 'Payment Gateway API'}` | `demo/frontend/app.js:603` | Fallback default logic | Hardcoded fallback invents plausible system name if scenario metadata is omitted. | `ctxSystem.textContent = asset.system ? ${asset.system} (${asset.organization \|\| 'Unannotated Org'}) : 'Not Specified';` |
| `ctxComponent.textContent = asset.component \|\| 'Session Key Negotiation Service'` | `demo/frontend/app.js:604` | Fallback default logic | Hardcoded fallback invents usage role if missing from metadata. | `ctxComponent.textContent = asset.component \|\| 'Unannotated Component';` |
| `ctxCriticality.textContent = asset.business_criticality \|\| 'Tier 1 Mission-Critical'` | `demo/frontend/app.js:605` | Fallback default logic | Hardcoded fallback invents high business criticality if missing. | `ctxCriticality.textContent = asset.business_criticality \|\| 'Unassigned Tier';` |
| `ctxSensitivity.textContent = ${asset.data_sensitivity \|\| 'Financial Secrets'}...` | `demo/frontend/app.js:606` | Fallback default logic | Hardcoded fallback invents financial data sensitivity. | `ctxSensitivity.textContent = asset.data_sensitivity ? ${asset.data_sensitivity} (Horizon: ${asset.data_lifetime \|\| 'Indeterminate'}) : 'Not Specified';` |
| `ctxExposure.textContent = ${asset.network_exposure \|\| 'Internet-Facing'}...` | `demo/frontend/app.js:607` | Fallback default logic | Hardcoded fallback invents public internet exposure. | `ctxExposure.textContent = asset.network_exposure ? ${asset.network_exposure} [${asset.environment \|\| 'unspecified'}] : 'Unknown Exposure';` |
| `Enterprise Operational Deployment Context (Lineage & Protection Scope)` | `demo/frontend/index.html:450` | Box header | Displays operational context without disclosing provenance source, implying scanner discovered it. | `Enterprise Operational Deployment Context (Source: Controlled Scenario Configuration)` |
| `Analyst confirmation of 2048-bit modulus before release ticket approval.` | `demo/frontend/index.html:726` | Review Gate HTML | Hardcodes "2048-bit modulus" into static HTML template instead of rendering dynamic triage requirement. | `Analyst confirmation of verified cryptographic modulus bit-length and operational role before release ticket approval.` |
| `AES-128 (GCM) — 64-bit Grover security` | `demo/frontend/index.html:824` | Phase 9 Diff Table | TC02 scanner output did NOT establish 128-bit key size (key length was unevidenced in AST). | `AES (GCM) — Grover-vulnerable symmetric primitive (key size unevidenced in AST)` |
| `Agility Level: HARDCODED` (static fallback) | `demo/frontend/app.js:675` & `index.html:558` | Agility rendering | Forces `HARDCODED` label even if core agility evaluator returns `None`. | `Agility Level: ${asset.agility_level \|\| 'NOT_ESTABLISHED'}` |
| `CryptoScan v1.4.0 (Static AST Analyzer)` (hardcoded table) | `demo/frontend/app.js:515` | Evidence table HTML | Hardcodes CryptoScan scanner name in evidence inspector rather than reading `ev.scanner_name`. | Read dynamically: `${evidence?.scanner_name \|\| 'Discovery Scanner'} (v${evidence?.scanner_version \|\| '1.0'})` |
| `Static Java AST Token Analysis` (hardcoded table) | `demo/frontend/app.js:516` | Evidence table HTML | Hardcodes Java AST detection method rather than reading `ev.detection_method`. | Read dynamically: `${evidence?.detection_method \|\| 'AST Token Analysis'}` |
| `// tc01_direct_rsa/DirectRSAKeyGen.java\n...hardcoded snippet` | `demo/frontend/app.js:527` | Code viewer | Hardcodes static Java code snippet in JS rather than displaying the real AST `ev.code_snippet`. | Display actual snippet: `heroCodeSnippet.textContent = evidence?.code_snippet \|\| '// Snippet unevidenced in scanner record';` |
| `Candidate proposal; not a universal mandate` (in parenthetical) | `demo/frontend/app.js:664` | Target details | Good clarification, but lacks authoritative standards citation. | `NIST FIPS 203 / 204 / 205 Candidate Target (Role-aware advisory proposal; subject to human review gate)` |
| `PROJECTED: QUANTUM-RESILIENT (PHASE 9)` | `demo/frontend/index.html:820` | Phase 9 Diff Table | Accurate projection, but must reinforce that no code changes occurred. | `PROJECTED PHASE 9 VERDICT: RESCAN DELTA RESOLVED (Not executed in Phase D5 demo)` |
