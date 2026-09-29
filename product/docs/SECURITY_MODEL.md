# ECDAT Security Model & Trust Boundaries

**Document Version:** 1.1.0 (Phase 0 Correction Pass)  
**Phase:** Phase 0 (Foundation & Constitution)  
**Security Posture:** Zero-Trust Ingestion & Defense-in-Depth  
**Specification Standard:** All security controls are documented as explicit engineering requirements that must be verified by implementation and automated tests before claiming operational enforcement.  

---

## 1. Threat Environment & Ingestion Security

ECDAT processes arbitrary source code, dependencies, binary libraries, and archive bundles provided by enterprise users or automated pipelines. **All scanned targets are treated as hostile, untrusted inputs.**

Under no circumstances may the ingestion or discovery subsystem assume that a target repository is safe, well-formed, or non-adversarial.

---

## 2. Archive Ingestion & Extraction Hardening Requirements

When archives (ZIP, TAR, GZ) are ingested in Upload Mode or by backend workers, the extraction engine is **REQUIRED** to enforce strict defenses:

1. **Path Traversal Protection (`Zip Slip` Defense — Requirement):**
   * Before writing any extracted file to disk, the destination path is **REQUIRED** to be canonicalized and verified to lie strictly within the assigned ephemeral sandbox directory.
   * Any archive entry containing `../`, absolute paths (`/etc/`, `C:\Windows\`), or drive designators is **REQUIRED** to be rejected immediately, aborting the scan. This must be validated by automated adversarial path tests.
2. **Symlink and Hardlink Restrictions (Requirement):**
   * Extraction of symbolic links or hardlinks pointing outside the sandbox boundary is **REQUIRED** to be blocked.
   * All symlinks must either be ignored or resolved strictly within the sandbox jail. Symlinks targeting `/dev/`, `/proc/`, or host system configurations must be dropped.
3. **Decompression Bomb (`Zip Bomb` Defense — Requirement):**
   * **Maximum File Count Quota:** The extraction engine is **REQUIRED** to abort scans exceeding 100,000 files.
   * **Maximum Total Uncompressed Size Quota:** The extraction engine is **REQUIRED** to abort scans exceeding 2 GB uncompressed (configurable per tenant).
   * **Maximum Compression Ratio Quota:** Individual files exceeding a 100:1 compression ratio are **REQUIRED** to be rejected.
   * **Streaming Limit:** Decompression is **REQUIRED** to execute via size-bounded streams rather than buffering entire archives in memory.

---

## 3. Sandboxing & Process Execution Restrictions (Requirements)

When external discovery engines (e.g., CLI binaries, AST scanners) are invoked:

1. **No Arbitrary Shell Invocation (Requirement):**
   * External processes are **REQUIRED** to be invoked using direct argument arrays (e.g., `subprocess.run(["scanner", "--arg", val])` with `shell=False`).
   * String-concatenated command lines that allow command injection via malicious repository filenames or parameters are strictly forbidden.
2. **Execution Privileges & Network Isolation (Requirement):**
   * Scanner worker processes are **REQUIRED** to execute under an unprivileged user account (e.g., `ecdat_worker`) with no administrative rights.
   * Scanner processes are **REQUIRED** to have network connectivity disabled during repository scanning to prevent telemetry exfiltration. This must be verified by network-level tests.
3. **Execution Timeouts (Requirement):**
   * Every scanner process is **REQUIRED** to enforce a non-overridable execution deadline (default: 300 seconds per repository). Unresponsive processes must be terminated immediately via `SIGKILL`.
4. **Filesystem Isolation & Ephemeral Scratch (Requirement):**
   * Scanners are **REQUIRED** to receive read-only access to the sandboxed target source directory.
   * Scanners are **REQUIRED** to restrict temporary file writes strictly to an ephemeral scratch directory (`/tmp/ecdat_run_<uuid>`), which is **REQUIRED** to be cryptographically shredded and deleted immediately post-execution. This must be verified by filesystem lifecycle tests.

---

## 4. Source Code Retention & Data Boundary Requirements

To establish and maintain enterprise trust, the following controls are mandatory engineering requirements:

1. **Source Code Transmission Restrictions (Requirement):**
   * **Local CLI Mode:** Source code is **REQUIRED** to remain entirely on the developer's workstation. Zero bytes of source code may be transmitted over any network interface. This must be verified by network packet capture tests.
   * **Agent Mode:** Source code is **REQUIRED** to remain within the customer's CI/CD network boundary. Only normalized CBOM metadata and finding summaries may leave the perimeter. This must be verified by egress network traffic inspection.
   * **Upload Mode:** Uploaded archives and extracted source directories are **REQUIRED** to exist exclusively in an ephemeral scratch volume. The entire sandbox directory is **REQUIRED** to be cryptographically purged immediately upon scan completion or error. This must be verified by automated filesystem lifecycle validation.
2. **Evidence Minimization (Requirement):**
   * ECDAT is **REQUIRED** to store only the minimal evidence necessary to prove a finding: relative file path, line numbers, and a small snippet of the matching line (capped at 5 lines).
   * Non-cryptographic proprietary application source code must never be persisted in ECDAT databases.
3. **Secrets Handling (Requirement):**
   * Discovered cryptographic keys, private certificates, or seed tokens are **REQUIRED** to be automatically masked or redacted before display or database storage (e.g., `-----BEGIN PRIVATE KEY-----[REDACTED]-----`).
   * ECDAT is **REQUIRED** to forbid the logging of raw secret key material in application logs or unencrypted audit trails.

---

## 5. External Scanner Integrity & Supply Chain (Requirements)

1. **SHA-256 Binary Verification (Requirement):**
   * Any third-party scanner binary or downloaded utility integrated via adapters is **REQUIRED** to have its cryptographic hash (SHA-256) pinned and verified prior to execution. This must be enforced by automated build and runtime integrity checks.
2. **Dependency Isolation (Requirement):**
   * External scanner dependencies are **REQUIRED** to be isolated inside dedicated virtual environments or containerized sidecars to prevent dependency collisions or supply chain poisoning of the core ECDAT service.

---

## 6. AI Security Boundary Specification

Where generative AI assistance is configured for advisory explanation:
1. **Air-Gap Capable (Requirement):** All core discovery, CBOM export, and risk scoring operations are **REQUIRED** to function with 100% fidelity without an AI connection.
2. **Prompt Injection Sanitization (Requirement):** Source code, variable names, and code comments are treated as untrusted input. They are **REQUIRED** to be escaped and wrapped in strict boundary delimiters before being presented to LLMs, preventing instruction hijacking.
3. **Zero Decision Authority (Requirement):** AI is strictly an explanation generation utility. It is **REQUIRED** to have zero programmatic access to alter database records, update risk scores, suppress findings, or modify permissions.

---

## 7. Multi-Tenancy & Authorization Requirements

1. **Tenant Isolation (Requirement):** In multi-tenant deployments, each tenant's findings, CBOMs, and scan histories are **REQUIRED** to be strictly partitioned by cryptographic tenant identifiers (`tenant_id`) enforced via database row-level security (RLS). This must be validated by automated cross-tenant penetration tests before multi-tenancy readiness claims.
2. **Role-Based Access Control (RBAC — Requirement):**
   * `Viewer`: Can view CBOMs and aggregated risk scores.
   * `Analyst`: Can triage findings, review evidence, and record human annotations.
   * `Admin`: Can configure discovery adapters, trigger scans, and manage user permissions.
