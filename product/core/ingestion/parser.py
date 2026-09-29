"""
ECDAT Defensive Parser.

Implements bounded, untrusted input parsing for JSON and XML payloads.
Enforces strict payload size, nesting depth, collection count, and string length limits.
Uses Python standard library only (zero external dependencies).
"""

import json
import re
from typing import Any, List, Optional, Tuple
import xml.etree.ElementTree as ET

from .adapter import IngestionError


class DefensiveJSONParser:
    """
    Defensive parser for untrusted JSON scanner output.
    
    Enforces:
    - Payload size <= max_bytes (default 100 MB)
    - Nesting depth <= max_depth (default 50 levels)
    - Collection element count <= max_collection_elements (default 100,000)
    - String length <= max_string_length (default 1 MB)
    - Controlled handling of malformed, truncated, or non-UTF-8 payloads.
    """

    def __init__(
        self,
        max_bytes: int = 100 * 1024 * 1024,      # 100 MB
        max_depth: int = 50,                     # 50 levels
        max_collection_elements: int = 100_000,  # 100,000 elements
        max_string_length: int = 1024 * 1024,    # 1 MB
    ) -> None:
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.max_collection_elements = max_collection_elements
        self.max_string_length = max_string_length

    def parse(self, raw_bytes: bytes) -> Tuple[bool, Optional[Any], Optional[IngestionError]]:
        """
        Parses raw bytes into structured JSON data under defensive bounds.
        Returns: (success, parsed_data, error)
        """
        if not isinstance(raw_bytes, bytes):
            return False, None, IngestionError(
                error_code="INVALID_INPUT_TYPE",
                error_message="Expected bytes for raw scanner output",
                error_source="parser",
            )

        # 1. Enforce payload size limit BEFORE loading/decoding
        if len(raw_bytes) > self.max_bytes:
            return False, None, IngestionError(
                error_code="PAYLOAD_TOO_LARGE",
                error_message=f"Raw output payload size ({len(raw_bytes)} bytes) exceeds maximum limit of {self.max_bytes} bytes",
                error_source="parser",
            )

        # 2. Decode UTF-8 with replacement characters to avoid crashing on malformed encoding
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            return False, None, IngestionError(
                error_code="DECODING_ERROR",
                error_message=f"Failed to decode bytes: {e}",
                error_source="parser",
            )

        # 3. Parse JSON with exception containment
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            return False, None, IngestionError(
                error_code="MALFORMED_JSON",
                error_message=f"Malformed or truncated JSON: {e.msg} at line {e.lineno}, column {e.colno}",
                error_source="parser",
            )
        except RecursionError:
            return False, None, IngestionError(
                error_code="RECURSION_LIMIT_EXCEEDED",
                error_message="JSON recursion limit exceeded during parsing (hostile nesting)",
                error_source="parser",
            )
        except Exception as e:
            return False, None, IngestionError(
                error_code="JSON_PARSE_EXCEPTION",
                error_message=f"Unexpected error during JSON parsing: {e}",
                error_source="parser",
            )

        # 4. Enforce structural limits (depth, collection size, string length)
        validation_error = self._validate_structure(parsed, current_depth=1)
        if validation_error:
            return False, None, validation_error

        return True, parsed, None

    def _validate_structure(self, obj: Any, current_depth: int) -> Optional[IngestionError]:
        """Validates nesting depth, collection size, and string length bounds iteratively/recursively."""
        if current_depth > self.max_depth:
            return IngestionError(
                error_code="MAX_DEPTH_EXCEEDED",
                error_message=f"JSON nesting depth exceeded limit of {self.max_depth} levels",
                error_source="parser",
            )

        if isinstance(obj, dict):
            if len(obj) > self.max_collection_elements:
                return IngestionError(
                    error_code="COLLECTION_LIMIT_EXCEEDED",
                    error_message=f"JSON object key count ({len(obj)}) exceeds limit of {self.max_collection_elements}",
                    error_source="parser",
                )
            for k, v in obj.items():
                if isinstance(k, str) and len(k) > self.max_string_length:
                    return IngestionError(
                        error_code="STRING_LENGTH_EXCEEDED",
                        error_message=f"JSON key string length ({len(k)}) exceeds limit of {self.max_string_length}",
                        error_source="parser",
                    )
                err = self._validate_structure(v, current_depth + 1)
                if err:
                    return err

        elif isinstance(obj, list):
            if len(obj) > self.max_collection_elements:
                return IngestionError(
                    error_code="COLLECTION_LIMIT_EXCEEDED",
                    error_message=f"JSON array element count ({len(obj)}) exceeds limit of {self.max_collection_elements}",
                    error_source="parser",
                )
            for item in obj:
                err = self._validate_structure(item, current_depth + 1)
                if err:
                    return err

        elif isinstance(obj, str):
            if len(obj) > self.max_string_length:
                return IngestionError(
                    error_code="STRING_LENGTH_EXCEEDED",
                    error_message=f"JSON string length ({len(obj)}) exceeds limit of {self.max_string_length}",
                    error_source="parser",
                )

        return None


class DefensiveXMLParser:
    """
    Defensive parser for untrusted XML scanner output.
    
    Enforces:
    - Pure Python standard library (`xml.etree.ElementTree`).
    - Absolute rejection of DOCTYPE declarations (XXE defense).
    - Absolute rejection of ENTITY declarations (billion laughs defense).
    - Maximum payload size bound.
    - Maximum element tree depth bound.
    - Fails closed safely if suspicious XML entities or excessive depths are detected.
    """

    def __init__(
        self,
        max_bytes: int = 100 * 1024 * 1024,  # 100 MB
        max_depth: int = 50,                 # 50 levels
    ) -> None:
        self.max_bytes = max_bytes
        self.max_depth = max_depth

    def parse(self, raw_bytes: bytes) -> Tuple[bool, Optional[ET.Element], Optional[IngestionError]]:
        """
        Parses raw bytes into an ElementTree root under strict XML security bounds.
        Returns: (success, root_element, error)
        """
        if not isinstance(raw_bytes, bytes):
            return False, None, IngestionError(
                error_code="INVALID_INPUT_TYPE",
                error_message="Expected bytes for raw XML scanner output",
                error_source="parser",
            )

        # 1. Enforce payload size limit
        if len(raw_bytes) > self.max_bytes:
            return False, None, IngestionError(
                error_code="PAYLOAD_TOO_LARGE",
                error_message=f"Raw XML payload size ({len(raw_bytes)} bytes) exceeds maximum limit of {self.max_bytes} bytes",
                error_source="parser",
            )

        # 2. Decode UTF-8 safely
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            return False, None, IngestionError(
                error_code="DECODING_ERROR",
                error_message=f"Failed to decode XML bytes: {e}",
                error_source="parser",
            )

        # 3. Multi-layer XML Injection / XXE / Entity Expansion Defense
        # Check for DOCTYPE declarations (external DTD or internal entity definitions)
        if re.search(r"<!DOCTYPE\b", text, re.IGNORECASE):
            return False, None, IngestionError(
                error_code="XML_DOCTYPE_FORBIDDEN",
                error_message="XML DOCTYPE declarations are strictly forbidden for untrusted scanner output",
                error_source="parser",
            )

        # Check for ENTITY declarations (XXE, parameter entity, billion laughs)
        if re.search(r"<!ENTITY\b", text, re.IGNORECASE):
            return False, None, IngestionError(
                error_code="XML_ENTITY_FORBIDDEN",
                error_message="XML ENTITY declarations are strictly forbidden (XXE / entity expansion defense)",
                error_source="parser",
            )

        # Check for entity references that could indicate entity expansion attempts
        # (allow standard XML built-in entities: &amp;, &lt;, &gt;, &quot;, &apos;)
        custom_entity_refs = re.findall(r"&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)([a-zA-Z0-9_-]+);", text)
        if custom_entity_refs:
            return False, None, IngestionError(
                error_code="XML_CUSTOM_ENTITY_REF_FORBIDDEN",
                error_message=f"Custom XML entity reference '{custom_entity_refs[0]}' forbidden",
                error_source="parser",
            )

        # 4. Parse using standard library ElementTree
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            return False, None, IngestionError(
                error_code="MALFORMED_XML",
                error_message=f"Malformed XML: {e}",
                error_source="parser",
            )
        except Exception as e:
            return False, None, IngestionError(
                error_code="XML_PARSE_EXCEPTION",
                error_message=f"Unexpected error during XML parse: {e}",
                error_source="parser",
            )

        # 5. Validate tree depth
        max_observed_depth = self._calculate_depth(root)
        if max_observed_depth > self.max_depth:
            return False, None, IngestionError(
                error_code="MAX_DEPTH_EXCEEDED",
                error_message=f"XML element tree depth ({max_observed_depth}) exceeds maximum limit of {self.max_depth}",
                error_source="parser",
            )

        return True, root, None

    def _calculate_depth(self, element: ET.Element, current_depth: int = 1) -> int:
        """Calculates element hierarchy depth."""
        if not list(element):
            return current_depth
        return max(self._calculate_depth(child, current_depth + 1) for child in element)
