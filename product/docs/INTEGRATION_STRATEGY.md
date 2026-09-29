# ECDAT Scanner Integration Strategy & Adapter Framework

**Document Version:** 1.0.0  
**Phase:** Phase 0 (Foundation & Constitution)  
**Core Requirement:** Absolute Scanner Independence & Adapter Decoupling  

---

## 1. Scanner-Agnostic Philosophy

ECDAT does not hardcode itself to any single third-party discovery tool or scanner. Existing tools (such as IBM CBOMkit, CryptoScan, pqaudit, or AST analyzers) are treated strictly as **replaceable discovery plugins** residing behind an adapter boundary.

* **Independence Guarantee:** If a third-party discovery tool becomes unmaintained, introduces licensing conflicts, or exhibits unacceptable false-positive rates, it can be replaced by implementing a new adapter without modifying ECDAT's core domain model, risk engine, database, or UI.
* **Multi-Engine Aggregation:** ECDAT can orchestrate multiple complementary adapters concurrently (e.g., AST analyzer for Java/Python + lockfile scanner for dependencies + regex heuristics for configuration files) and unify their outputs.

---

## 2. Standard Adapter Contract (`IScannerAdapter`)

All discovery engines must conform to a strict programmatic interface:

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class ScanTarget:
    target_id: str
    filesystem_path: str
    target_type: str  # 'source_dir', 'archive', 'repo'
    options: Dict[str, Any]

@dataclass
class RawDiscoveryOutput:
    adapter_id: str
    adapter_version: str
    execution_time_ms: int
    exit_code: int
    raw_payload: Any
    errors: List[str]

@dataclass
class NormalizedEvidence:
    asset_name: str
    asset_type: str        # 'algorithm', 'protocol', 'certificate', 'key'
    sub_category: str      # 'asymmetric', 'symmetric', 'hash', 'signature'
    file_path: str         # Relative to target root
    start_line: int
    end_line: int
    code_snippet: str
    detection_method: str  # 'ast_analysis', 'semantic_regex', 'lockfile_parse'
    confidence: str        # 'CONFIRMED', 'LIKELY', 'POSSIBLE', 'NEEDS_REVIEW'
    raw_attributes: Dict[str, Any]

class IScannerAdapter(ABC):
    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Unique identifier of the adapter."""
        pass

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Version of the adapter implementation."""
        pass

    @abstractmethod
    def check_prerequisites(self) -> bool:
        """Verify runtime requirements (e.g., binaries present, dependencies met)."""
        pass

    @abstractmethod
    def execute_scan(self, target: ScanTarget) -> RawDiscoveryOutput:
        """Execute discovery against target with isolated execution and timeout bounds."""
        pass

    @abstractmethod
    def normalize(self, raw_output: RawDiscoveryOutput) -> List[NormalizedEvidence]:
        """Transform proprietary scanner output into normalized ECDAT evidence records."""
        pass
```

---

## 3. Integration Lifecycle & Fault Isolation

```
[ Scan Orchestrator ]
         │
         ▼
[ Check Prerequisites ] ──(Fails)──► [ Log Warning & Gracefully Skip Adapter ]
         │ (Passes)
         ▼
[ Isolate Sandbox & Spawn Process ]
         │
         ├──(Exceeds Timeout / Memory)──► [ SIGKILL & Record Adapter Error ]
         │
         ▼
[ Capture Raw Output & Exit Code ]
         │
         ├──(Non-Zero Exit / Malformed)──► [ Safe Degradation: Log Raw Error ]
         │
         ▼
[ Execute Normalize() Transform ]
         │
         ▼
[ Emit NormalizedEvidence Records to Normalization Bus ]
```

### Fault Handling Rules:
1. **Zero Core Crash:** An adapter failure (crash, uncaught exception, or timeout) must NEVER terminate the main ECDAT scan pipeline. The failure is recorded as an `AdapterExecutionWarning` and scanning continues with remaining adapters.
2. **Path Relativization:** The adapter must strip absolute host paths (e.g., `/tmp/ecdat_run_123/src/App.java` $\rightarrow$ `src/App.java`) before returning evidence records.
3. **Snippet Truncation:** Raw code snippets are bounded to a maximum of 5 lines to prevent excessive memory consumption.

---

## 4. Candidate Engine Integration Blueprint

The following blueprint defines integration requirements for candidate tools evaluated in Phase 1:

### 4.1 IBM CBOMkit Candidate Integration
* **Integration Method:** CLI binary invocation or containerized runner.
* **Input:** Target source repository or directory.
* **Expected Output:** CycloneDX CBOM JSON.
* **Normalization Requirement:** Parse CycloneDX `cryptoProperties` and map into internal ECDAT domain entities while verifying evidence completeness.
* **Isolation Profile:** Non-root execution with read-only source mount; execution deadline capped at 300 seconds.
* **Licensing & Security:** Apache-2.0; review third-party AST parser dependencies for CVEs.

### 4.2 CryptoScan Candidate Integration
* **Integration Method:** Python module integration or CLI runner.
* **Input:** Source directory (specialized language support: Java, Python, Go, C/C++).
* **Expected Output:** JSON finding reports.
* **Normalization Requirement:** Map rule IDs and matched AST nodes to ECDAT `NormalizedEvidence` with confidence mapping.
* **Isolation Profile:** Sandboxed subprocess execution without network access.
* **Licensing & Security:** Review license terms and check for unmaintained dependencies.

### 4.3 pqaudit Candidate Integration
* **Integration Method:** CLI executable invocation.
* **Input:** Source code or compiled binaries.
* **Expected Output:** Textual or structured audit report flagging non-PQC primitives.
* **Normalization Requirement:** Parse PQC vulnerability tags and map to ECDAT quantum risk classifications.
* **Isolation Profile:** Read-only access to target binaries in isolated container.
* **Licensing & Security:** Permissive open source; verify tool stability against large codebases.

---

## 5. Scanner Selection Policy

**No scanner is chosen as "the" authoritative ECDAT engine during Phase 0.**  
Final integration decisions will be made in Phase 1 following empirical benchmarking against the controlled test corpus defined in `EVALUATION_PLAN.md`.
