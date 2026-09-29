# Controlled Evaluation Tool Isolation Area

**Path:** `product/benchmark/tools/`  
**Governance Directive:** Phase 1C-A Controlled Tool Acquisition  
**Scope:** Evaluation & Benchmark Reference Only. Zero Production Integration.

---

## 1. Directory Structure

```text
product/benchmark/tools/
├── candidates/          # Pinned, downloaded candidate packages, archives, or binaries
├── verified/            # Checksum-verified and sandbox-inspected tools ready for benchmark evaluation
├── runs/                # Execution runner configurations, invocation scripts, and run logs
├── raw_outputs/         # Untransformed, original output artifacts emitted by tools during benchmark
├── normalized_outputs/  # Parser adapters converting raw findings to ECDAT Normalized Evidence Schema
└── reports/             # Empirical benchmark evaluation metrics, accuracy reports, and comparative analysis
```

---

## 2. Safety & Security Invariants

1. **Isolation from Product Core:**  
   Third-party source code, candidate binaries, and vendor dependencies must NEVER be placed in `product/core/` or `product/src/`. All evaluation tooling resides strictly within this benchmark boundary.
2. **Untrusted Input Policy:**  
   Scanned test fixtures and corpus code must be treated as untrusted data. Scanner execution must never execute, interpret, or dynamically compile arbitrary seed corpus files.
3. **No Network Telemetry:**  
   During local benchmarking, scanners must run with outbound network disabled or monitored to prevent data exfiltration of scanned code.
4. **License Isolation:**  
   Tools licensed under GPL-3.0 (e.g., `sslscan2`) or governed by GitHub CodeQL terms are classified as **Benchmark-Reference Only** and are strictly forbidden from being embedded into ECDAT core deliverables.
5. **No Direct Production Selection:**  
   Tool presence in this directory represents evaluation candidature only. Integration decisions require empirical benchmark scoring and explicit Phase 1C sign-off.
