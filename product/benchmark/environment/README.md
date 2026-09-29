# ECDAT Benchmark Execution Environment Specification

**Document Version:** 1.0.0  
**Phase:** Phase 1B (Benchmark Environment & Seed Corpus)  
**Status:** PROPOSED & REQUIRED ENVIRONMENT SPECIFICATION  
**Strict Compliance Notice:** This document specifies environmental and operational requirements for future benchmark execution. Zero external tooling or scanner packages have been installed.

---

## 1. Operating System & Host Platform Requirements

To ensure repeatable and unbiased benchmarks during Phase 1C, the execution environment must conform to the following specifications:

* **Primary Evaluation OS (Host):** Windows 11 Pro / Enterprise (x86_64) or Linux (Ubuntu 22.04 LTS x86_64).
* **Cross-Platform Canonicalization Requirement:** All benchmark path comparisons must use canonical forward-slash separators (`/`) regardless of whether the runner executes on Windows (`\` converted to `/`) or POSIX platforms.
* **Locale & File Encoding:** All corpus fixtures and answer keys are **REQUIRED** to be encoded in strict `UTF-8` with standardized `LF` line endings to prevent line count drift.

---

## 2. Runtime & Toolchain Requirements (Proposed Baseline)

The following runtimes are required for benchmark orchestration:

| Runtime / Tool | Minimum Version | Current Host State | Role in Benchmark |
| :--- | :--- | :--- | :--- |
| **Python** | 3.12.x | Installed (`Python 3.12.4`) | Benchmark assertion runner & schema validation. |
| **Node.js** | 20.x / 24.x LTS | Installed (`Node v24.15.0`) | CycloneDX JSON-schema validator runner. |
| **Java JDK** | 17 LTS or 21 LTS | Host environment check | JCA fixture compilation & Java scanner targets. |
| **Git** | 2.40+ | Installed (`2.54.0.windows.1`) | Seed corpus commit tracking & diff verification. |

---

## 3. Network Policy (Strict Air-Gap Requirement)

1. **Air-Gap Enforcement:** During benchmark execution against candidate scanners, the host network interface is **REQUIRED** to be disabled or blocked via firewall rules:
   * Zero outbound internet calls.
   * Zero telemetry transmission to external cloud services.
2. **Offline Dependency Verification:** Candidate discovery tools must function 100% offline without attempting to fetch vulnerability feeds or remote model weights.

---

## 4. Process Isolation & Resource Governance Requirements

When external discovery engines are evaluated in Phase 1C:

1. **Subprocess Isolation (`shell=False`):**
   * External tools are **REQUIRED** to be spawned using direct vector argument lists:
     `subprocess.run(["scanner_bin", "--target", corpus_dir], shell=False, capture_output=True)`
2. **Execution Quotas:**
   * **Execution Timeout:** Capped at 60 seconds per seed corpus micro-project. Unresponsive processes must be terminated via `SIGKILL`.
   * **Memory Cap:** Monitored and capped at 2048 MB RAM peak consumption.
3. **Filesystem Mount Isolation:**
   * Target corpus directory is mounted as **READ-ONLY**. Candidate tools are forbidden from creating, modifying, or deleting files within `product/benchmark/corpus/`.
   * All temporary scratch data must be written to an isolated, ephemeral scratch folder (`/tmp/ecdat_bench_<uuid>`), which is **REQUIRED** to be deleted immediately upon run completion.

---

## 5. Output Collection & Determinism Protocol

1. **Stdout / Stderr Redirection:**
   * Standard output and error streams from candidate tools are captured directly to memory or isolated log artifacts in `product/benchmark/reports/`.
2. **Deterministic Run Invariance:**
   * Each candidate tool will be executed across **10 identical consecutive runs** on the Seed Corpus.
   * The benchmark harness requires **100% identical finding counts, line coordinates, and ordering** across all 10 runs. Any run-to-run variation will be flagged as non-deterministic behavior.
