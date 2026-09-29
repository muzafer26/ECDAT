"""
ECDAT Evidence Sanitization and Defense Utilities.

Treats all external scanner outputs, file paths, and code snippets as untrusted inputs.
Enforces path traversal rejection, snippet bounding, and string size constraints.
"""

import os
import re
from types import MappingProxyType
from typing import Any, Dict, Optional


class SecurityValidationError(ValueError):
    """Raised when scanner-provided data violates security constraints."""
    pass


# Maximum allowed limits
MAX_SNIPPET_LINES: int = 5
MAX_SNIPPET_CHARS: int = 1000
MAX_STRING_CHARS: int = 500
MAX_PATH_CHARS: int = 1000

# Traversal and invalid path indicators
_TRAVERSAL_PATTERN = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)|^[a-zA-Z]:|^[\\/]")
_PERCENT_ENCODED_TRAVERSAL = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


def freeze_value(val: Any) -> Any:
    """
    Recursively converts collections to immutable representations:
    dict -> MappingProxyType
    list -> tuple
    set -> frozenset
    """
    if isinstance(val, dict):
        return MappingProxyType({k: freeze_value(v) for k, v in val.items()})
    elif isinstance(val, (list, tuple)):
        return tuple(freeze_value(x) for x in val)
    elif isinstance(val, (set, frozenset)):
        return frozenset(freeze_value(x) for x in val)
    return val


def sanitize_relative_path(path_str: str) -> str:
    """
    Validates and canonicalizes a relative file path provided by a scanner.

    Requirements:
    - Must be non-empty and bounded in length.
    - Must not contain path traversal elements (e.g. '../', '..\\', '%2e%2e').
    - Must not be an absolute path (Unix root, Windows drive, UNC share).
    - Returns forward-slash normalized relative path.

    Raises:
        SecurityValidationError: if path violates security constraints.
    """
    if not isinstance(path_str, str):
        raise SecurityValidationError(f"Path must be a string, got {type(path_str).__name__}")

    stripped = path_str.strip()
    if not stripped:
        raise SecurityValidationError("Path cannot be empty or pure whitespace")

    if len(stripped) > MAX_PATH_CHARS:
        raise SecurityValidationError(f"Path exceeds maximum length of {MAX_PATH_CHARS} characters")

    if _CONTROL_CHAR_PATTERN.search(stripped):
        raise SecurityValidationError("Path contains illegal control characters")

    # Reject percent-encoded traversal attempts (%2e = '.', %2f = '/', %5c = '\')
    if _PERCENT_ENCODED_TRAVERSAL.search(stripped):
        raise SecurityValidationError(f"Percent-encoded path traversal rejected: {stripped}")

    # Normalize backslashes to forward slashes for cross-platform consistency
    normalized = stripped.replace("\\", "/")

    # Check for drive designators (e.g. C:)
    if re.match(r"^[a-zA-Z]:", normalized):
        raise SecurityValidationError(f"Absolute path with drive designator rejected: {stripped}")

    # Check for absolute root paths (/ or //)
    if normalized.startswith("/"):
        raise SecurityValidationError(f"Absolute path rejected: {stripped}")

    # Check for path traversal elements
    parts = normalized.split("/")
    if any(part == ".." for part in parts):
        raise SecurityValidationError(f"Path traversal ('..') rejected: {stripped}")

    # Eliminate redundant './' components
    cleaned_parts = [p for p in parts if p and p != "."]
    if not cleaned_parts:
        raise SecurityValidationError(f"Invalid resolved path: {stripped}")

    return "/".join(cleaned_parts)


def bound_code_snippet(snippet: Optional[str], max_lines: int = MAX_SNIPPET_LINES, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    """
    Bounds a code snippet to a maximum number of lines and total characters.
    Prevents memory exhaustion, payload inflation, and log flooding.
    """
    if snippet is None:
        return ""

    if not isinstance(snippet, str):
        snippet = str(snippet)

    # Normalize line endings
    normalized = snippet.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = "\n".join(lines) + "\n[truncated]"
    else:
        truncated = "\n".join(lines)

    if len(truncated) > max_chars:
        truncated = truncated[:max_chars] + "...[truncated]"

    return truncated


def sanitize_bounded_string(value: Optional[str], max_chars: int = MAX_STRING_CHARS, default: str = "") -> str:
    """
    Sanitizes arbitrary text strings from scanners (e.g. category, identifier).
    Strips control characters (except common whitespace) and enforces character bounds.
    """
    if value is None:
        return default

    if not isinstance(value, str):
        value = str(value)

    # Strip dangerous control characters (\x00-\x08, \x0b-\x1f, \x7f)
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value).strip()

    if len(cleaned) > max_chars:
        return cleaned[:max_chars]

    return cleaned
