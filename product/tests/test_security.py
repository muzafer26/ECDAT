"""
Security and Adversarial Input Tests for ECDAT Normalization Layer.

Validates that untrusted scanner inputs (paths, snippets, categories) cannot
exploit path traversal, flood memory, or inject illegal control characters.
"""

import unittest

from product.core.evidence.sanitization import (
    sanitize_relative_path,
    bound_code_snippet,
    sanitize_bounded_string,
    SecurityValidationError,
    MAX_SNIPPET_LINES,
    MAX_SNIPPET_CHARS,
)


class TestSecurityAndSanitization(unittest.TestCase):

    def test_path_traversal_rejection(self) -> None:
        """Verifies that directory traversal sequences are strictly rejected."""
        malicious_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "src/../../../secret.key",
            "foo/bar/../../..",
            "../app.java",
        ]
        for path in malicious_paths:
            with self.assertRaises(SecurityValidationError, msg=f"Should reject {path}"):
                sanitize_relative_path(path)

    def test_absolute_paths_rejection(self) -> None:
        """Verifies that absolute Unix and Windows paths are rejected."""
        absolute_paths = [
            "/etc/shadow",
            "/var/log/syslog",
            "C:\\Windows\\System32",
            "D:/data/repo/App.java",
            "\\\\attacker-server\\share\\exploit.java",
        ]
        for path in absolute_paths:
            with self.assertRaises(SecurityValidationError, msg=f"Should reject {path}"):
                sanitize_relative_path(path)

    def test_valid_relative_path_canonicalization(self) -> None:
        """Verifies that valid relative paths are cleaned and normalized."""
        self.assertEqual(sanitize_relative_path("src/main/App.java"), "src/main/App.java")
        self.assertEqual(sanitize_relative_path(".\\src\\main\\App.java"), "src/main/App.java")
        self.assertEqual(sanitize_relative_path("./components/Crypto.go"), "components/Crypto.go")

    def test_snippet_bounding_by_lines(self) -> None:
        """Verifies code snippets exceeding MAX_SNIPPET_LINES are truncated."""
        many_lines = "\n".join([f"line_{i} = doSomething();" for i in range(20)])
        bounded = bound_code_snippet(many_lines, max_lines=MAX_SNIPPET_LINES)
        lines = bounded.split("\n")
        # 5 original lines + 1 truncation marker
        self.assertLessEqual(len(lines), MAX_SNIPPET_LINES + 1)
        self.assertIn("[truncated]", bounded)

    def test_snippet_bounding_by_characters(self) -> None:
        """Verifies code snippets exceeding MAX_SNIPPET_CHARS are capped."""
        huge_snippet = "x = 1;" * 500  # 3000 chars
        bounded = bound_code_snippet(huge_snippet, max_chars=MAX_SNIPPET_CHARS)
        self.assertLessEqual(len(bounded), MAX_SNIPPET_CHARS + 20)
        self.assertIn("[truncated]", bounded)

    def test_control_character_sanitization(self) -> None:
        """Verifies dangerous control characters are stripped from arbitrary scanner strings."""
        dirty_string = "Scanner\x00Category\x07Injection\x1b[31m"
        cleaned = sanitize_bounded_string(dirty_string)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x07", cleaned)
        self.assertNotIn("\x1b", cleaned)

    def test_l01_percent_encoded_traversal_rejection(self) -> None:
        """L-01: Verifies percent-encoded traversal sequences are strictly rejected."""
        encoded_payloads = [
            "%2e%2e/etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5cwindows%5csystem32",
            "src/%2e%2e/secret.key",
            "..%2fapp.java",
            "dir%2F..%2Fpasswords",
            "dir%5C..%5Cpasswords",
        ]
        for payload in encoded_payloads:
            with self.assertRaises(SecurityValidationError, msg=f"Should reject encoded traversal {payload}"):
                sanitize_relative_path(payload)

    def test_l01_legitimate_paths_preserved(self) -> None:
        """L-01: Verifies normal legitimate source paths are preserved without false rejection."""
        legit_paths = [
            "src/main/java/com/example/CryptoService.java",
            "crypto_v2/aes_gcm.py",
            "modules/sub-module/token_service.go",
            "include/openssl_wrapper.h",
        ]
        for p in legit_paths:
            self.assertEqual(sanitize_relative_path(p), p)

    def test_l03_no_benchmark_tc_identifiers_in_production_code(self) -> None:
        """L-03: Verifies no benchmark TC identifiers exist in production implementation files."""
        import os
        import re

        core_dir = os.path.join(os.path.dirname(__file__), "..", "core")
        tc_pattern = re.compile(r"\bTC-[0-9]{2}\b", re.IGNORECASE)

        violations = []
        for root, _, files in os.walk(core_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line_no, line in enumerate(f, 1):
                            if tc_pattern.search(line):
                                violations.append(f"{filepath}:{line_no} -> {line.strip()}")

        self.assertEqual(violations, [], f"Found benchmark TC identifiers in production code: {violations}")


if __name__ == "__main__":
    unittest.main()
