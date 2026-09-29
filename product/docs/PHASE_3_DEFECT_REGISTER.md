# ECDAT Phase 3 Defect & Finding Register

**Document Version:** 1.0.0  
**Status:** COMPLETE / REMEDIATED  
**Author:** Principal Software Architect, Cryptography Engineer, QA Lead & Technical Auditor  
**Scope:** Phase 3 Deliverables (3A, 3B, 3C-A, 3C-B, 3C-C), Benchmark Harness (TC01–TC11), Security & Operational Boundaries  

---

## 1. Classification Taxonomy

Every issue discovered during the deep verification mission is classified under the authoritative taxonomy:
* **CONFIRMED DEFECT:** Reproduced incorrect behavior or demonstrable contract violation.
* **REQUIREMENT GAP:** Approved requirement missing or incompletely implemented.
* **SECURITY FINDING:** Concrete vulnerability, unsafe boundary, or insufficiently enforced security requirement.
* **TEST GAP:** Important behavior or boundary condition not adequately verified.
* **DOCUMENTATION DEFECT:** Documentation makes a claim unsupported by implementation or empirical evidence.
* **DESIGN LIMITATION:** Known limitation acceptable within approved scope.
* **EXTERNAL TOOL LIMITATION:** Limitation in an integrated scanner or external dependency.
* **UNRESOLVED:** Evidence is insufficient to determine correctness.

---

## 2. Comprehensive Defect Register

### DEF-01: `EvidenceRecord.from_dict` Type Error on Non-Source Locations
* **Unique ID:** `DEF-01`
* **Classification:** CONFIRMED DEFECT
* **Severity & Rationale:** High. Prevents deserialization and round-trip persistence of any evidence record originating from non-source discovery (such as package dependencies from Syft in TC-09, network scans, container images, or certificates).
* **File & Component:** `product/core/evidence/evidence.py` (`EvidenceRecord.from_dict`)
* **Reproduction Steps / Evidence:**
  ```python
  from product.core.evidence.evidence import EvidenceLocation, EvidenceRecord, LocationType, DetectionMethod
  loc = EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:maven/bcprov@1.78")
  ev = EvidenceRecord(evidence_id="ev1", location=loc, scanner_name="syft", scanner_version="1.51.1", detection_method=DetectionMethod.LOCKFILE_PARSE, scanner_category="dependency")
  EvidenceRecord.from_dict(ev.to_dict())  # Raised TypeError: SourceLocation.__init__() got unexpected keyword argument 'location_type'
  ```
* **Expected Behavior:** Deserializes into an appropriate `EvidenceLocation` preserving non-source fields (`package_coordinate`, `endpoint`, etc.). Source: `PHASE_1D_NORMALIZATION_ARCHITECTURE.md` §4.
* **Actual Behavior:** Hardcoded call to `SourceLocation.from_dict` failed with `TypeError`.
* **Root Cause:** Incomplete refactoring when generalized `EvidenceLocation` was introduced in Phase 1D; `EvidenceRecord.from_dict` continued invoking `SourceLocation.from_dict`.
* **Downstream Impact:** Ingestion pipeline failure if serialized evidence records containing non-source locations were restored.
* **Proposed Correction:** Invoke `EvidenceLocation.from_dict(data["location"])`.
* **Regression Tests:** `TestEvidenceModel.test_def01_non_source_location_deserialization_round_trip` in `product/tests/test_evidence_model.py`.
* **Blocks Closure / Phase 4:** Yes (Closed-blocking defect).
* **Verification Result After Correction:** **VERIFIED FIXED.** Round-trips for dependency and network locations pass cleanly.

---

### DEF-02: `EvidenceRecord.__post_init__` Omits `detection_method` String Coercion
* **Unique ID:** `DEF-02`
* **Classification:** CONFIRMED DEFECT
* **Severity & Rationale:** Medium. Passing `detection_method` as a string (allowed in other domain models) broke serialization via `to_dict()`.
* **File & Component:** `product/core/evidence/evidence.py` (`EvidenceRecord.__post_init__`, `EvidenceRecord.to_dict`)
* **Reproduction Steps / Evidence:**
  ```python
  ev = EvidenceRecord(evidence_id="e1", location=loc, scanner_name="scan", scanner_version="1.0", detection_method="ast_analysis", scanner_category="RSA")
  ev.to_dict()  # Raised AttributeError: 'str' object has no attribute 'value'
  ```
* **Expected Behavior:** String inputs for `detection_method` are coerced into `DetectionMethod` enum during `__post_init__`, consistent with `Finding` and `CryptoAsset`.
* **Actual Behavior:** `self.detection_method` remained a string, crashing `to_dict()` when accessing `.value`.
* **Root Cause:** Missing `DetectionMethod.from_str` coercion check in `EvidenceRecord.__post_init__`.
* **Downstream Impact:** Runtime failure whenever adapters or caller scripts instantiate evidence with string literals.
* **Proposed Correction:** Add `DetectionMethod.from_str` coercion in `__post_init__`.
* **Regression Tests:** `TestEvidenceModel.test_def02_string_detection_method_coercion_and_to_dict` in `product/tests/test_evidence_model.py`.
* **Blocks Closure / Phase 4:** Yes.
* **Verification Result After Correction:** **VERIFIED FIXED.** String coercion and serialization pass cleanly.

---

### DEF-03: `CBOMSerializer` Evidence Cross-Contamination Across Distinct Assets
* **Unique ID:** `DEF-03`
* **Classification:** CONFIRMED DEFECT
* **Severity & Rationale:** High. Violates core provenance contracts (ADR-010, ADR-015). In scans with multiple findings and assets, every CBOM component was populated with all evidence records across the entire scan.
* **File & Component:** `product/core/cbom/serializer.py` (`CBOMSerializer.serialize_to_dict`)
* **Reproduction Steps / Evidence:**
  In multi-finding fixture `tc05_ecdh`, executing `ECDATWorkflowEngine.run()` generated a CBOM where every component (including 6 distinct certificate usages and 1 ECDH key agreement) contained the exact same list of 8 evidence IDs in `ecdat:evidence_ids`.
* **Expected Behavior:** Each projected CBOM component must contain strictly the evidence records that support its constituent findings. Source: ADR-015 and `PHASE_3A_PROVENANCE_MODEL.md` §3.
* **Actual Behavior:** `serialize_to_dict` checked `if fid in finding_to_evidence:` where `fid` was an asset `finding_id` and `finding_to_evidence` keys were `evidence_id`s. Because they never matched, `asset_evidence` was always empty, triggering a fallback that attached all evidence records to every component.
* **Root Cause:** Cardinality impedance mismatch: `CryptoAsset` references `finding_ids`, whereas `Finding` references `evidence_ids`. The serializer lacked access to the `findings` collection to bridge `asset.finding_ids` $\to$ `finding.evidence_ids` $\to$ `evidence_records`.
* **Downstream Impact:** Severe provenance bleed. Auditors inspecting a CBOM component could not determine which specific code line or scanner rule produced the finding.
* **Proposed Correction:** Accept `findings: Optional[Sequence[Finding]] = None` in `serialize_to_dict`, resolve the chain `asset.finding_ids` $\to$ `finding.evidence_ids` $\to$ `evidence_records`, and pass `findings=findings` from `ECDATWorkflowEngine.run`.
* **Regression Tests:** `TestCBOMAdversarial.test_def03_multi_asset_evidence_isolation` in `product/tests/test_cbom_adversarial.py`.
* **Blocks Closure / Phase 4:** Yes (Closed-blocking defect).
* **Verification Result After Correction:** **VERIFIED FIXED.** In `tc05_ecdh`, `ECDH` receives strictly `['cryptoscan:ECC-001-16-55']`, and each certificate usage receives strictly its own evidence record.

---

### DEF-04: Generic Rijndael Incorrectly Classified as Standardized AES Without Evidence
* **Unique ID:** `DEF-04`
* **Classification:** REQUIREMENT GAP / POLICY VIOLATION
* **Severity & Rationale:** Medium. Rijndael is a variable block-size cipher family (128, 160, 192, 224, 256 bits). Only Rijndael with a 128-bit block size is standardized as NIST FIPS 197 AES. Classifying generic Rijndael as AES without parameter evidence violates the explicit non-inference requirement.
* **File & Component:** `product/core/risk/posture.py` (`AES_APPROVED_ALIASES`)
* **Reproduction Steps / Evidence:**
  In `posture.py`, `AES_APPROVED_ALIASES` included `"RIJNDAEL"`. An asset with algorithm `"Rijndael"` without block size was classified as `ClassicalSecurityStatus.ACCEPTABLE` and `QuantumExposureClass.GROVER_REDUCED_SYMMETRIC_LOW`.
* **Expected Behavior:** Bare `"Rijndael"` without evidenced 128-bit block size or explicit AES family classification must evaluate to `ClassicalSecurityStatus.INDETERMINATE` and `UncertaintyLevel.NEEDS_REVIEW`. Source: Phase 3 Mission Specification §10: *"Do not classify generic Rijndael as AES without sufficient evidence."*
* **Actual Behavior:** Generic Rijndael was unconditionally classified as FIPS 197 AES.
* **Root Cause:** Overly permissive alias whitelist in `AES_APPROVED_ALIASES`.
* **Downstream Impact:** Potential false sense of compliance for non-standard Rijndael implementations.
* **Proposed Correction:** Remove `"RIJNDAEL"` from `AES_APPROVED_ALIASES`. Allow bare Rijndael to fail closed to `INDETERMINATE` / `NEEDS_REVIEW` under rule branch 5.
* **Regression Tests:** `TestRiskSlice.test_case_07b_bare_rijndael_rejected_without_evidence` in `product/tests/test_risk_slice.py`.
* **Blocks Closure / Phase 4:** Yes (Policy requirement).
* **Verification Result After Correction:** **VERIFIED FIXED.** Bare Rijndael evaluates to `INDETERMINATE`, `UNCLASSIFIED_QUANTUM_POSTURE`, `NEEDS_REVIEW`, and `P_REVIEW_REQUIRED`.

---

### DEF-05: Stale Deferred Capabilities Notice in Technical Report
* **Unique ID:** `DEF-05`
* **Classification:** DOCUMENTATION DEFECT / WORKFLOW NOTICE
* **Severity & Rationale:** Low. `deferred_capabilities` in the generated technical report claimed that classical policies for RSA and SHA-1 were deferred, contradicting Phase 3C-C implementation.
* **File & Component:** `product/core/workflow/report.py` (`TechnicalReportGenerator.generate`)
* **Reproduction Steps / Evidence:**
  Generated technical report included notice: `"DEFERRED: Extended asymmetric and hash primitives (RSA, DH, ECDSA, ECDH, Ed25519, X25519, SHA-1/2/3, PQC)"`.
* **Expected Behavior:** Notice must distinguish implemented Phase 3C-C policies (RSA & SHA-1 fail-safe classifications) from remaining deferred primitives (DH/FFDH, ECDSA, ECDH, Ed25519, X25519, SHA-2/3, PQC). Source: `PROJECT_STATE.md` v1.26.0.
* **Actual Behavior:** Notice erroneously claimed RSA and SHA-1 were deferred.
* **Root Cause:** Report generator template was not updated after completing Phase 3C-C.
* **Downstream Impact:** Misleads analysts reading the executive report into believing RSA and SHA-1 findings were not evaluated.
* **Proposed Correction:** Update `deferred_capabilities` list to cite Phase 3C-C classical policies as implemented while preserving genuine deferred scopes.
* **Regression Tests:** `TestWorkflowE2E.test_01_known_positive_tc02_symmetric_aes` in `product/tests/test_workflow_e2e.py`.
* **Blocks Closure / Phase 4:** No (Non-blocking documentation fix).
* **Verification Result After Correction:** **VERIFIED FIXED.** Reports accurately cite Phase 3C-C active status.

---

### DEF-06: Weak Assertions in CBOM Evidence Isolation Tests
* **Unique ID:** `DEF-06`
* **Classification:** TEST GAP
* **Severity & Rationale:** Medium. Prior test `test_adv_12_disagreeing_scanners_separate_provenance` verified component count (`len == 2`) and names (`AES`, `DES`), but failed to assert that component properties were properly segregated.
* **File & Component:** `product/tests/test_cbom_adversarial.py`
* **Reproduction Steps / Evidence:**
  Prior test suite passed 213/213 even while DEF-03 was present in `serializer.py`.
* **Expected Behavior:** Tests must assert strict property-level evidence segregation.
* **Actual Behavior:** Assertions were too coarse to detect provenance cross-contamination.
* **Root Cause:** Test assertions stopped at component count and name without inspecting property extensions.
* **Downstream Impact:** Masked DEF-03 bug.
* **Proposed Correction:** Add explicit assertions on `ecdat:evidence_ids` and `ecdat:scanners` per component.
* **Regression Tests:** `test_def03_multi_asset_evidence_isolation` in `test_cbom_adversarial.py`.
* **Blocks Closure / Phase 4:** Yes.
* **Verification Result After Correction:** **VERIFIED FIXED.**

---

### DEF-07: Validator Missing Property Placement Exclusivity and Non-Crypto Typings
* **Unique ID:** `DEF-07`
* **Classification:** DESIGN & VALIDATION LIMITATION
* **Severity & Rationale:** Medium. Tier 1 structural validation checked `algorithmProperties` exclusivity, but omitted exclusivity checks for `relatedCryptoMaterialProperties`, `certificateProperties`, `protocolProperties`, and non-crypto component types (`type: "library"`).
* **File & Component:** `product/core/cbom/validator.py` (`CBOMValidator.validate_tier1_structure`)
* **Reproduction Steps / Evidence:**
  Injecting `relatedCryptoMaterialProperties` into an `assetType="algorithm"` component passed Tier 1 validation.
* **Expected Behavior:** Incompatible property objects must trigger validation errors. Non-cryptographic components (`type != "cryptographic-asset"`) must not possess `cryptoProperties`. Source: CycloneDX 1.7 specification.
* **Actual Behavior:** Omitted placement checks allowed invalid component property combinations to pass.
* **Root Cause:** Incomplete property validation rules in `validator.py`.
* **Downstream Impact:** Potentially allowed schema-non-compliant CBOM generation without flagging errors.
* **Proposed Correction:** Add exclusivity checks for all four crypto property objects and forbid `cryptoProperties` on non-crypto component types.
* **Regression Tests:** `TestCBOMAdversarial.test_def07_validator_structural_property_exclusivity` in `product/tests/test_cbom_adversarial.py`.
* **Blocks Closure / Phase 4:** Yes.
* **Verification Result After Correction:** **VERIFIED FIXED.** Three adversarial malformed CBOM structures are correctly caught and rejected.

---

### DEF-08: Scanner Omission in TC-08 (DES Wrapper) and TC-11 (Dynamic JCA)
* **Unique ID:** `DEF-08`
* **Classification:** EXTERNAL TOOL LIMITATION
* **Severity & Rationale:** Medium. CryptoScan v1.4.0 emits 0 findings for TC-08 (constant indirection wrapper) and TC-11 (dynamic cipher lookup).
* **File & Component:** `product/benchmark/tools/raw_outputs/cryptoscan/tc08_crypto_wrapper/`, `tc11_ambiguous_dynamic/`
* **Reproduction Steps / Evidence:**
  Inspect raw scanner outputs; both contain `{"findings": []}`.
* **Expected Behavior:** Ground truth defines DES (TC-08) and UNKNOWN dynamic cipher (TC-11). Downstream pipeline must NOT invent findings, but must explicitly disclose the tool coverage limitation.
* **Actual Behavior:** ECDAT correctly returns `IngestionStatus.NO_FINDINGS` and attaches `"NOTICE (ZERO CONFIRMED FINDINGS)"`.
* **Root Cause:** Static analysis limitations of CryptoScan v1.4.0 (inability to resolve constant cross-class indirection or dynamic string variables).
* **Downstream Impact:** Disclosed coverage limitation. Discovery recall across TC01–TC11 is 70.0% (7/10 active cryptographic cases discovered).
* **Proposed Correction:** Retain accurate disclosure in benchmark reports and pipeline notices. Do not manufacture synthetic findings in core pipeline. For future Phase 4/8 production, incorporate supplemental dataflow or taint analysis tools.
* **Regression Tests:** `test_04_ambiguous_zero_finding_tc11_dynamic` and `test_09_all_11_benchmark_cases_coverage` in `test_workflow_e2e.py`.
* **Blocks Closure / Phase 4:** No (Documented scanner limitation; pipeline integrity is preserved).
* **Verification Result After Correction:** **VERIFIED PRESERVED.**

---

### DEF-09: CycloneDX Full Draft-07 JSON Schema Runtime Validation Not Executed
* **Unique ID:** `DEF-09`
* **Classification:** DESIGN & DEPENDENCY LIMITATION
* **Severity & Rationale:** Medium. Full Draft-07 JSON Schema validation requires `jsonschema` library, which is not installed in the environment to preserve the strict zero-external-dependencies policy.
* **File & Component:** `product/core/cbom/validator.py`, `product/docs/PROJECT_STATE.md`
* **Reproduction Steps / Evidence:**
  `python -c "import jsonschema"` raises `ModuleNotFoundError`.
* **Expected Behavior:** Full schema compliance must be verified either offline via custom checks or via external tooling without compromising runtime dependency boundaries.
* **Actual Behavior:** Two-Tier custom validator enforces structural and semantic rules against official schemas (`bom-1.7.schema.json`, SHA-256 `c94ef3...`). Full Draft-07 schema compliance is NOT claimed.
* **Root Cause:** Zero third-party dependency directive for core product.
* **Downstream Impact:** Requires honest disclosure so evaluators do not mistake custom validation for full schema validator execution.
* **Proposed Correction:** Document limitation clearly across all reports. Author an independent CLI validation procedure for external environments equipped with `jsonschema` or `cyclonedx-cli`.
* **Regression Tests:** Custom two-tier validator tests (`test_cbom_projection.py`).
* **Blocks Closure / Phase 4:** No (Explicitly accepted and documented gating limitation).
* **Verification Result After Correction:** **DOCUMENTED & BOUNDED.**

---

### DEF-10: Version Control Unavailable in Execution Workspace
* **Unique ID:** `DEF-10`
* **Classification:** EXTERNAL / ENVIRONMENT LIMITATION
* **Severity & Rationale:** Low. `d:\SIH` is not a Git repository (`fatal: not a git repository`).
* **File & Component:** Repository Root (`d:\SIH`)
* **Reproduction Steps / Evidence:**
  `git status` returns error code 1.
* **Expected Behavior:** Git change tracking available.
* **Actual Behavior:** Git absent.
* **Root Cause:** Workspace initialized without `.git` directory.
* **Downstream Impact:** Version control tracking must be achieved through baseline hashing and explicit artifact ledger tracking.
* **Proposed Correction:** Document limitation in verification report; verify integrity against frozen benchmark SHA-256 hashes.
* **Regression Tests:** Benchmark hash verification script.
* **Blocks Closure / Phase 4:** No.
* **Verification Result After Correction:** **DOCUMENTED.**
