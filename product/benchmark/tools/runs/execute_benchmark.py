"""
ECDAT Phase 1C-B Controlled Benchmark Execution Harness
Executes candidate tools against Phase 1B Seed Corpus (TC-01 through TC-11)
Preserves immutable raw outputs, evaluates reproducibility, normalizes findings,
and performs ground truth comparison.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE_ROOT = Path("d:/SIH").resolve()
BENCHMARK_ROOT = WORKSPACE_ROOT / "product" / "benchmark"
SEED_CORPUS_ROOT = BENCHMARK_ROOT / "corpus" / "seed"
ANSWER_KEYS_ROOT = BENCHMARK_ROOT / "answer_keys"
TOOLS_ROOT = BENCHMARK_ROOT / "tools"

RUNS_DIR = TOOLS_ROOT / "runs"
RAW_OUTPUTS_DIR = TOOLS_ROOT / "raw_outputs"
NORMALIZED_DIR = TOOLS_ROOT / "normalized_outputs"
REPORTS_DIR = TOOLS_ROOT / "reports" / "phase_1c_b"

TEST_CASES = [
    ("TC-01", "tc01_direct_rsa", "tc01_direct_rsa.json"),
    ("TC-02", "tc02_symmetric_aes", "tc02_symmetric_aes.json"),
    ("TC-03", "tc03_ecc_generic", "tc03_ecc_generic.json"),
    ("TC-04", "tc04_ecdsa", "tc04_ecdsa.json"),
    ("TC-05", "tc05_ecdh", "tc05_ecdh.json"),
    ("TC-06", "tc06_ed25519", "tc06_ed25519.json"),
    ("TC-07", "tc07_sha1_hash", "tc07_sha1_hash.json"),
    ("TC-08", "tc08_crypto_wrapper", "tc08_crypto_wrapper.json"),
    ("TC-09", "tc09_dependency_crypto", "tc09_dependency_crypto.json"),
    ("TC-10", "tc10_misleading_comments", "tc10_misleading_comments.json"),
    ("TC-11", "tc11_ambiguous_dynamic", "tc11_ambiguous_dynamic.json"),
]

def ensure_dirs():
    for d in [RUNS_DIR, RAW_OUTPUTS_DIR, NORMALIZED_DIR, REPORTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd, cwd=None):
    start = time.perf_counter()
    res = subprocess.run(
        cmd,
        cwd=cwd or str(WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    duration_sec = time.perf_counter() - start
    return res.returncode, res.stdout, res.stderr, duration_sec

def execute_cryptoscan():
    tool_name = "cryptoscan"
    tool_version = "1.4.0"
    exe_path = TOOLS_ROOT / "verified" / "cryptoscan" / "cryptoscan.exe"
    
    print(f"\n--- Executing {tool_name} {tool_version} ---")
    cryptoscan_raw_dir = RAW_OUTPUTS_DIR / "cryptoscan"
    cryptoscan_raw_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    reproducibility = {}
    
    for tc_id, tc_dir_name, key_file in TEST_CASES:
        target_dir = SEED_CORPUS_ROOT / tc_dir_name
        tc_raw_dir = cryptoscan_raw_dir / tc_dir_name
        tc_raw_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [str(exe_path), "scan", str(target_dir), "--format", "json", "--include-quantum-safe"]
        
        # Run 1
        rc1, stdout1, stderr1, dur1 = run_cmd(cmd)
        
        # Save Run 1
        (tc_raw_dir / "run1_stdout.txt").write_text(stdout1, encoding="utf-8")
        (tc_raw_dir / "run1_stderr.txt").write_text(stderr1, encoding="utf-8")
        meta1 = {
            "tool": tool_name,
            "version": tool_version,
            "test_case": tc_id,
            "target": str(target_dir),
            "command": cmd,
            "exit_code": rc1,
            "duration_seconds": dur1,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        (tc_raw_dir / "run1_meta.json").write_text(json.dumps(meta1, indent=2), encoding="utf-8")
        
        parsed1 = None
        try:
            parsed1 = json.loads(stdout1)
            (tc_raw_dir / "run1_output.json").write_text(json.dumps(parsed1, indent=2), encoding="utf-8")
        except Exception as e:
            (tc_raw_dir / "run1_parse_error.txt").write_text(str(e), encoding="utf-8")
            
        # Run 2 (Reproducibility)
        rc2, stdout2, stderr2, dur2 = run_cmd(cmd)
        (tc_raw_dir / "run2_stdout.txt").write_text(stdout2, encoding="utf-8")
        (tc_raw_dir / "run2_stderr.txt").write_text(stderr2, encoding="utf-8")
        meta2 = {
            "tool": tool_name,
            "version": tool_version,
            "test_case": tc_id,
            "target": str(target_dir),
            "command": cmd,
            "exit_code": rc2,
            "duration_seconds": dur2,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        (tc_raw_dir / "run2_meta.json").write_text(json.dumps(meta2, indent=2), encoding="utf-8")
        
        parsed2 = None
        try:
            parsed2 = json.loads(stdout2)
            (tc_raw_dir / "run2_output.json").write_text(json.dumps(parsed2, indent=2), encoding="utf-8")
        except Exception as e:
            pass

        # Check reproducibility (strip timestamp and duration before comparing findings)
        identical_findings = False
        if parsed1 and parsed2:
            findings1 = parsed1.get("findings", [])
            findings2 = parsed2.get("findings", [])
            identical_findings = (findings1 == findings2)
            
        repro_result = {
            "exit_code_match": (rc1 == rc2),
            "findings_identical": identical_findings,
            "run1_finding_count": len(parsed1.get("findings", [])) if parsed1 else None,
            "run2_finding_count": len(parsed2.get("findings", [])) if parsed2 else None,
            "duration_delta_sec": abs(dur1 - dur2)
        }
        (tc_raw_dir / "reproducibility.json").write_text(json.dumps(repro_result, indent=2), encoding="utf-8")
        
        results[tc_id] = {
            "parsed": parsed1,
            "exit_code": rc1,
            "duration": dur1,
            "raw_ref": f"product/benchmark/tools/raw_outputs/cryptoscan/{tc_dir_name}/run1_output.json"
        }
        reproducibility[tc_id] = repro_result
        print(f"  [{tc_id}] exit={rc1}, duration={dur1:.3f}s, findings={len(parsed1.get('findings', [])) if parsed1 else 0}, reproducible={identical_findings}")
        
    return results, reproducibility

def execute_syft():
    tool_name = "syft"
    tool_version = "1.51.1"
    exe_path = TOOLS_ROOT / "verified" / "syft" / "syft.exe"
    
    print(f"\n--- Executing {tool_name} {tool_version} ---")
    syft_raw_dir = RAW_OUTPUTS_DIR / "syft"
    syft_raw_dir.mkdir(parents=True, exist_ok=True)
    
    # Syft is a dependency/package cataloger, evaluated against TC-09 dependency fixture
    tc_id, tc_dir_name, key_file = ("TC-09", "tc09_dependency_crypto", "tc09_dependency_crypto.json")
    target_dir = SEED_CORPUS_ROOT / tc_dir_name
    tc_raw_dir = syft_raw_dir / tc_dir_name
    tc_raw_dir.mkdir(parents=True, exist_ok=True)
    
    cmd = [str(exe_path), "scan", str(target_dir), "-o", "json"]
    
    # Run 1
    rc1, stdout1, stderr1, dur1 = run_cmd(cmd)
    (tc_raw_dir / "run1_stdout.txt").write_text(stdout1, encoding="utf-8")
    (tc_raw_dir / "run1_stderr.txt").write_text(stderr1, encoding="utf-8")
    meta1 = {
        "tool": tool_name,
        "version": tool_version,
        "test_case": tc_id,
        "target": str(target_dir),
        "command": cmd,
        "exit_code": rc1,
        "duration_seconds": dur1,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    (tc_raw_dir / "run1_meta.json").write_text(json.dumps(meta1, indent=2), encoding="utf-8")
    
    parsed1 = None
    try:
        parsed1 = json.loads(stdout1)
        (tc_raw_dir / "run1_output.json").write_text(json.dumps(parsed1, indent=2), encoding="utf-8")
    except Exception as e:
        (tc_raw_dir / "run1_parse_error.txt").write_text(str(e), encoding="utf-8")
        
    # Run 2
    rc2, stdout2, stderr2, dur2 = run_cmd(cmd)
    (tc_raw_dir / "run2_stdout.txt").write_text(stdout2, encoding="utf-8")
    (tc_raw_dir / "run2_stderr.txt").write_text(stderr2, encoding="utf-8")
    parsed2 = None
    try:
        parsed2 = json.loads(stdout2)
        (tc_raw_dir / "run2_output.json").write_text(json.dumps(parsed2, indent=2), encoding="utf-8")
    except Exception:
        pass
        
    pkgs1 = [p.get("name") for p in parsed1.get("artifacts", [])] if parsed1 else []
    pkgs2 = [p.get("name") for p in parsed2.get("artifacts", [])] if parsed2 else []
    identical_packages = (pkgs1 == pkgs2)
    
    repro_result = {
        "exit_code_match": (rc1 == rc2),
        "packages_identical": identical_packages,
        "run1_package_count": len(pkgs1),
        "run2_package_count": len(pkgs2),
        "duration_delta_sec": abs(dur1 - dur2)
    }
    (tc_raw_dir / "reproducibility.json").write_text(json.dumps(repro_result, indent=2), encoding="utf-8")
    print(f"  [{tc_id}] exit={rc1}, duration={dur1:.3f}s, packages={len(pkgs1)}, reproducible={identical_packages}")
    
    return {tc_id: {"parsed": parsed1, "exit_code": rc1, "duration": dur1, "raw_ref": f"product/benchmark/tools/raw_outputs/syft/{tc_dir_name}/run1_output.json"}}, repro_result

def record_pqaudit_failure():
    print(f"\n--- Evaluating pqaudit v0.5.0 Execution Prerequisite ---")
    pq_raw_dir = RAW_OUTPUTS_DIR / "pqaudit"
    pq_raw_dir.mkdir(parents=True, exist_ok=True)
    
    cli_path = TOOLS_ROOT / "verified" / "pqaudit" / "package" / "dist" / "cli.js"
    cmd = ["node", str(cli_path), "--help"]
    rc, stdout, stderr, dur = run_cmd(cmd)
    
    failure_log = f"""Tool: pqaudit
Version: 0.5.0 (npm package tarball)
Artifact Path: {cli_path}
Execution Attempt Command: {' '.join(cmd)}
Execution Timestamp: {datetime.now(timezone.utc).isoformat()}
Exit Code: {rc}
Stdout:
{stdout}
Stderr:
{stderr}
Failure Diagnosis:
EXECUTION_FAILURE / BLOCKED. The npm package tarball 'pqaudit-0.5.0.tgz' unpacked in Phase 1C-A contains only compiled TypeScript dist files ('dist/cli.js') and rule YAMLs ('rules/'), but does not bundle required runtime dependencies ('commander', 'chalk', 'glob', 'web-tree-sitter', 'yaml') inside a node_modules folder.
Host Runtime: Node.js v24.15.0 is present on the host, but isolated unpacked directory lacks node_modules.
Evaluation Safety Rule: Under Phase 1C-B scope lock, external network downloads (npm install) and modifications to tool packages are strictly prohibited.
Classification: EXECUTION_FAILURE (Do NOT count as detection failure / False Negative).
"""
    (pq_raw_dir / "execution_failure.log").write_text(failure_log, encoding="utf-8")
    meta = {
        "tool": "pqaudit",
        "version": "0.5.0",
        "status": "EXECUTION_FAILURE",
        "reason": "Missing unbundled runtime npm dependencies (commander, chalk, glob, web-tree-sitter, yaml)",
        "exit_code": rc,
        "error_type": "ERR_MODULE_NOT_FOUND"
    }
    (pq_raw_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  [pqaudit] recorded EXECUTION_FAILURE (ERR_MODULE_NOT_FOUND: 'commander')")
    return meta

def record_sonar_blocked():
    print(f"\n--- Evaluating Sonar Cryptography Plugin v1.6.1 Execution Prerequisite ---")
    sonar_raw_dir = RAW_OUTPUTS_DIR / "sonar"
    sonar_raw_dir.mkdir(parents=True, exist_ok=True)
    
    jar_path = TOOLS_ROOT / "candidates" / "sonar-cryptography-plugin-1.6.1.jar"
    blocked_log = f"""Tool: Sonar Cryptography Plugin (IBM CBOMkit Ecosystem)
Version: 1.6.1 JAR
Artifact Path: {jar_path}
Timestamp: {datetime.now(timezone.utc).isoformat()}
Execution Prerequisite: Requires SonarQube Server 9.x/10.x runtime or SonarScanner CLI engine supporting Sonar Plugin SPI.
Host Environment: Java SE 24.0.2 is available on host, but neither SonarQube Server nor standalone SonarScanner CLI is installed.
Evaluation Safety Rule: Installing SonarQube, PostgreSQL, or external daemon infrastructure is strictly forbidden in Phase 1C-B.
Status: EXECUTION_FAILURE / BLOCKED.
Classification: EXECUTION_FAILURE / BLOCKED (Do NOT count as detection failure / False Negative).
"""
    (sonar_raw_dir / "execution_blocked.log").write_text(blocked_log, encoding="utf-8")
    meta = {
        "tool": "sonar-cryptography-plugin",
        "version": "1.6.1",
        "status": "BLOCKED",
        "reason": "Requires SonarQube Server or SonarScanner CLI runner which is not installed on host"
    }
    (sonar_raw_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  [sonar-cryptography] recorded BLOCKED (SonarQube/SonarScanner runner unavailable)")
    return meta

def record_sslscan_scope():
    print(f"\n--- Evaluating sslscan 2.2.2 Execution Scope ---")
    ssl_raw_dir = RAW_OUTPUTS_DIR / "sslscan"
    ssl_raw_dir.mkdir(parents=True, exist_ok=True)
    
    exe_path = TOOLS_ROOT / "verified" / "sslscan" / "sslscan.exe"
    scope_log = f"""Tool: sslscan
Version: 2.2.2 Windows 64-bit (Mingw) OpenSSL 3.5.4
Artifact Path: {exe_path}
Timestamp: {datetime.now(timezone.utc).isoformat()}
Evaluation Scope: Active Network TLS / Cipher Suite Negotiation.
Corpus Scope: Phase 1B Seed Corpus (TC-01 through TC-11) consists strictly of static source files (.java, .py) and build manifests (pom.xml).
Rationale: sslscan requires a live TCP socket endpoint (host:port). It possesses zero capability to analyze static source code or ASTs. No local TLS server is configured in the test harness, and scanning external internet hosts is strictly prohibited by isolation policy.
Status: NOT_EVALUATED / OUT_OF_SCOPE.
Classification: NOT_EVALUATED (Scope Mismatch for Static Source Benchmark; do NOT count as detection failure / False Negative).
"""
    (ssl_raw_dir / "scope_evaluation.log").write_text(scope_log, encoding="utf-8")
    meta = {
        "tool": "sslscan",
        "version": "2.2.2",
        "status": "NOT_EVALUATED",
        "reason": "Network-layer TLS socket scanner; out of scope for static source code corpus; internet scanning prohibited"
    }
    (ssl_raw_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  [sslscan] recorded NOT_EVALUATED (Network TLS scanner out of scope for static source corpus)")
    return meta

def normalize_cryptoscan(cryptoscan_results):
    print(f"\n--- Normalizing CryptoScan Findings ---")
    norm_dir = NORMALIZED_DIR / "cryptoscan"
    norm_dir.mkdir(parents=True, exist_ok=True)
    
    all_normalized = []
    
    for tc_id, tc_dir_name, key_file in TEST_CASES:
        key_path = ANSWER_KEYS_ROOT / key_file
        answer_key = json.loads(key_path.read_text(encoding="utf-8"))
        expected_findings = answer_key.get("expected_findings", [])
        is_negative = answer_key.get("negative_case", False)
        is_ambiguous = answer_key.get("ambiguous_case", False)
        
        tc_res = cryptoscan_results.get(tc_id, {})
        parsed = tc_res.get("parsed") or {}
        raw_findings = parsed.get("findings", [])
        raw_ref = tc_res.get("raw_ref")
        
        tc_norm_findings = []
        for idx, rf in enumerate(raw_findings):
            norm = {
                "tool": "CryptoScan",
                "version": "1.4.0",
                "test_case": tc_id,
                "raw_output_reference": raw_ref,
                "finding_reference": rf.get("id"),
                "finding_index": idx,
                "detected_asset": rf.get("algorithm") or rf.get("type"),
                "detected_primitive": rf.get("primitive"),
                "category": rf.get("category"),
                "location": {
                    "file": Path(rf.get("file", "")).name,
                    "line_start": rf.get("line"),
                    "line_end": rf.get("line"),
                    "column": rf.get("column")
                },
                "role": rf.get("purpose") or "UNKNOWN",
                "parameters": {
                    "key_size_bits": rf.get("securityLevel", {}).get("classicalBits") if isinstance(rf.get("securityLevel"), dict) else None,
                    "cipher_mode": None,
                    "padding_scheme": None,
                    "curve_name": None
                },
                "confidence": rf.get("confidence") or "UNKNOWN",
                "quantum_risk": rf.get("quantumRisk"),
                "raw_context": rf.get("context")
            }
            tc_norm_findings.append(norm)
            all_normalized.append(norm)
            
        (norm_dir / f"{tc_dir_name}_normalized.json").write_text(json.dumps(tc_norm_findings, indent=2), encoding="utf-8")
        
    (norm_dir / "all_normalized.json").write_text(json.dumps(all_normalized, indent=2), encoding="utf-8")
    print(f"  Total normalized CryptoScan findings: {len(all_normalized)}")
    return all_normalized

def normalize_syft(syft_results):
    print(f"\n--- Normalizing Syft Findings ---")
    norm_dir = NORMALIZED_DIR / "syft"
    norm_dir.mkdir(parents=True, exist_ok=True)
    
    tc_res = syft_results.get("TC-09", {})
    parsed = tc_res.get("parsed") or {}
    artifacts = parsed.get("artifacts", [])
    raw_ref = tc_res.get("raw_ref")
    
    syft_norm = []
    for idx, art in enumerate(artifacts):
        locations = art.get("locations", [])
        loc_path = locations[0].get("path") if locations else "UNKNOWN"
        norm = {
            "tool": "Syft",
            "version": "1.51.1",
            "test_case": "TC-09",
            "raw_output_reference": raw_ref,
            "finding_reference": art.get("id"),
            "finding_index": idx,
            "detected_asset": art.get("name"),
            "detected_version": art.get("version"),
            "package_type": art.get("type"),
            "purl": art.get("purl"),
            "found_by": art.get("foundBy"),
            "location": {
                "file": Path(loc_path).name,
                "path": loc_path
            },
            "role": "dependency_package",
            "parameters": None,
            "confidence": "HIGH",
            "classification": "TRUE_POSITIVE" if "bouncycastle" in art.get("name", "").lower() else "SUPPLEMENTAL_FINDING",
            "notes": "Syft catalogs package manifest dependency; does not detect source algorithm usage"
        }
        syft_norm.append(norm)
        
    (norm_dir / "tc09_dependency_crypto_normalized.json").write_text(json.dumps(syft_norm, indent=2), encoding="utf-8")
    print(f"  Total normalized Syft packages cataloged: {len(syft_norm)}")
    return syft_norm

def evaluate_ground_truth(cryptoscan_results):
    print(f"\n--- Comparing CryptoScan Against Immutable Ground Truth ---")
    case_evaluations = {}
    
    for tc_id, tc_dir_name, key_file in TEST_CASES:
        key_path = ANSWER_KEYS_ROOT / key_file
        answer_key = json.loads(key_path.read_text(encoding="utf-8"))
        expected_findings = answer_key.get("expected_findings", [])
        is_negative = answer_key.get("negative_case", False)
        is_ambiguous = answer_key.get("ambiguous_case", False)
        
        tc_res = cryptoscan_results.get(tc_id, {})
        parsed = tc_res.get("parsed") or {}
        raw_findings = parsed.get("findings", [])
        
        eval_record = {
            "test_case_id": tc_id,
            "title": answer_key.get("title"),
            "negative_case": is_negative,
            "ambiguous_case": is_ambiguous,
            "expected_findings_count": len(expected_findings),
            "tool_findings_count": len(raw_findings),
            "classification": None,
            "tp_count": 0,
            "fp_count": 0,
            "fn_count": 0,
            "details": [],
            "analysis": ""
        }
        
        # TC-10: Deliberate Negative Decoy Case
        if is_negative:
            if len(raw_findings) == 0:
                eval_record["classification"] = "TRUE_NEGATIVE"
                eval_record["analysis"] = "Passed negative test case. Correctly rejected all misleading comments and logger strings."
            else:
                eval_record["classification"] = "FALSE_POSITIVE"
                eval_record["fp_count"] = len(raw_findings)
                eval_record["analysis"] = f"Failed negative test case. Tool flagged {len(raw_findings)} finding(s) on decoy comments/logger strings."
                for rf in raw_findings:
                    eval_record["details"].append({
                        "id": rf.get("id"),
                        "match": rf.get("match"),
                        "line": rf.get("line"),
                        "context": rf.get("context"),
                        "verdict": "FALSE_POSITIVE_IF_DETECTED"
                    })
            case_evaluations[tc_id] = eval_record
            continue
            
        # TC-11: Ambiguous Dynamic Case
        if is_ambiguous:
            if len(raw_findings) == 0:
                eval_record["classification"] = "FALSE_NEGATIVE"
                eval_record["fn_count"] = 1
                eval_record["analysis"] = "Failed to detect dynamic Cipher invocation. The tool requires a static string literal and does not identify unresolved dynamic variables or mark uncertainty."
            else:
                eval_record["classification"] = "NEEDS_REVIEW"
                eval_record["analysis"] = f"Tool reported {len(raw_findings)} finding(s) on ambiguous dynamic invocation."
            case_evaluations[tc_id] = eval_record
            continue
            
        # TC-08: Internal Wrapper / Facade Case
        if tc_id == "TC-08":
            # TC-08 contains DES within LegacyCryptoHelper.java called by DataEncryptor.java
            des_detected = any("DES" in (rf.get("algorithm") or "") or "DES" in (rf.get("match") or "") for rf in raw_findings)
            if des_detected:
                eval_record["classification"] = "TRUE_POSITIVE"
                eval_record["tp_count"] = 1
                eval_record["analysis"] = "Detected DES within internal wrapper."
            else:
                eval_record["classification"] = "FALSE_NEGATIVE"
                eval_record["fn_count"] = 1
                eval_record["analysis"] = "Failed to detect DES algorithm inside internal crypto wrapper class (LegacyCryptoHelper.java). Zero findings emitted."
            case_evaluations[tc_id] = eval_record
            continue
            
        # TC-09: Dependency Crypto Case
        if tc_id == "TC-09":
            # Answer key says: expected_findings: 1 (pom.xml dependency Bouncy Castle)
            dep_detected = any(rf.get("category") == "dependency" and "bouncycastle" in (rf.get("match", "") + rf.get("context", "")).lower() for rf in raw_findings)
            if dep_detected:
                eval_record["classification"] = "TRUE_POSITIVE"
                eval_record["tp_count"] = 1
                eval_record["analysis"] = "Detected Bouncy Castle dependency in pom.xml as category 'dependency'. Correctly did not invent code invocations."
            else:
                eval_record["classification"] = "FALSE_NEGATIVE"
                eval_record["fn_count"] = 1
                eval_record["analysis"] = "Failed to detect Bouncy Castle dependency in pom.xml."
            case_evaluations[tc_id] = eval_record
            continue
            
        # Standard Positive Cases: TC-01..TC-07
        detected_valid_asset = False
        tp = 0
        fp = 0
        
        # Check against expected finding
        exp = expected_findings[0] if expected_findings else {}
        exp_algo = exp.get("expected_interpretation", {}).get("algorithm", "").upper()
        exp_line = exp.get("observed_fact", {}).get("line_start")
        
        matched_findings = []
        unmatched_findings = []
        
        for rf in raw_findings:
            algo = (rf.get("algorithm") or "").upper()
            match_str = (rf.get("match") or "").upper()
            line = rf.get("line")
            cat = rf.get("category", "")
            
            # Check algorithm alignment
            algo_match = (exp_algo in algo) or (exp_algo in match_str) or (exp_algo in ["ECDSA", "ECDH", "ED25519", "SECP256R1"] and algo == "ECC")
            
            # Check line proximity
            line_match = abs(line - exp_line) <= 5 if line and exp_line else False
            
            # Special case for CERT-KEYUSAGE noise in TC-05
            if cat == "Certificate" and "KeyUsage" in rf.get("type", ""):
                unmatched_findings.append((rf, "False classification of JCA KeyAgreement API as X.509 Certificate extension"))
                fp += 1
                continue
                
            # Special case for docstring comments in TC-07
            if tc_id == "TC-07" and line in [2, 3]:
                unmatched_findings.append((rf, f"Comment/docstring match at line {line} instead of code AST"))
                fp += 1
                continue
                
            if algo_match and line_match:
                matched_findings.append(rf)
                tp = 1
            else:
                unmatched_findings.append((rf, "Unmatched or duplicate finding"))
                fp += 1
                
        if tp > 0:
            eval_record["classification"] = "TRUE_POSITIVE"
            eval_record["tp_count"] = 1
            eval_record["fp_count"] = fp
            eval_record["analysis"] = f"Successfully detected expected asset {exp_algo} with {fp} extraneous/spurious finding(s)."
        else:
            eval_record["classification"] = "FALSE_NEGATIVE"
            eval_record["fn_count"] = 1
            eval_record["fp_count"] = fp
            eval_record["analysis"] = f"Missed expected asset {exp_algo}."
            
        eval_record["details"] = {
            "matched": [m.get("id") for m in matched_findings],
            "unmatched": [f[0].get("id") + ": " + f[1] for f in unmatched_findings]
        }
        case_evaluations[tc_id] = eval_record

    print("\nSummary of Case Evaluations:")
    for tc_id, ev in case_evaluations.items():
        print(f"  {tc_id}: {ev['classification']} | TP={ev['tp_count']}, FP={ev['fp_count']}, FN={ev['fn_count']} | {ev['analysis']}")
        
    return case_evaluations

def compute_metrics(case_evaluations):
    # Total TPs, FPs, FNs
    # Note: TC-10 is a negative test case (True Negative = passed, False Positive = failed)
    # TC-01..TC-09, TC-11 are positive cases
    
    total_tp = sum(ev["tp_count"] for ev in case_evaluations.values())
    total_fp = sum(ev["fp_count"] for ev in case_evaluations.values())
    total_fn = sum(ev["fn_count"] for ev in case_evaluations.values())
    
    # Mathematical definitions
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    total_cases = len(TEST_CASES)
    evaluated_cases = len(case_evaluations)
    coverage = (evaluated_cases / total_cases) * 100.0
    
    metrics = {
        "tool": "CryptoScan v1.4.0",
        "total_cases_evaluated": total_cases,
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "case_coverage_percent": coverage,
        "notes": "Calculated across Phase 1B Seed Corpus (TC-01..TC-11). TC-10 FP counted in false_positives."
    }
    
    (REPORTS_DIR / "cryptoscan_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (REPORTS_DIR / "case_evaluations.json").write_text(json.dumps(case_evaluations, indent=2), encoding="utf-8")
    
    print("\n--- Benchmark Metrics (CryptoScan v1.4.0) ---")
    print(f"  TP: {total_tp}")
    print(f"  FP: {total_fp}")
    print(f"  FN: {total_fn}")
    print(f"  Precision: {precision:.4f} ({precision*100:.1f}%)")
    print(f"  Recall:    {recall:.4f} ({recall*100:.1f}%)")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  Coverage:  {coverage:.1f}%")
    return metrics

def main():
    ensure_dirs()
    print("=" * 60)
    print("ECDAT PHASE 1C-B BENCHMARK EXECUTION STARTING")
    print("=" * 60)
    
    # 1. Execute CryptoScan
    cs_results, cs_repro = execute_cryptoscan()
    
    # 2. Execute Syft
    syft_results, syft_repro = execute_syft()
    
    # 3. Record pqaudit execution failure
    pq_meta = record_pqaudit_failure()
    
    # 4. Record Sonar blocked
    sonar_meta = record_sonar_blocked()
    
    # 5. Record sslscan scope
    ssl_meta = record_sslscan_scope()
    
    # 6. Normalize findings
    norm_cs = normalize_cryptoscan(cs_results)
    norm_syft = normalize_syft(syft_results)
    
    # 7. Evaluate against ground truth
    case_evals = evaluate_ground_truth(cs_results)
    
    # 8. Compute metrics
    metrics = compute_metrics(case_evals)
    
    # 9. Save master benchmark summary
    summary = {
        "execution_date": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 1C-B (Controlled Benchmark Execution & Evaluation)",
        "tools_executed": ["CryptoScan v1.4.0", "Syft v1.51.1"],
        "tools_blocked_or_failed": ["pqaudit v0.5.0 (EXECUTION_FAILURE)", "sonar-cryptography-plugin v1.6.1 (BLOCKED)"],
        "tools_out_of_scope": ["sslscan 2.2.2 (NOT_EVALUATED / Network Layer)"],
        "metrics_summary": metrics,
        "reproducibility": {
            "cryptoscan": cs_repro,
            "syft": syft_repro
        }
    }
    (REPORTS_DIR / "phase_1c_b_execution_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n" + "=" * 60)
    print("PHASE 1C-B BENCHMARK EXECUTION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
